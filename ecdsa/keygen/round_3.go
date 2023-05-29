// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"math/big"

	"github.com/hashicorp/go-multierror"
	errors2 "github.com/pkg/errors"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/commitments"
	"github.com/bnb-chain/tss-lib/crypto/vss"
	"github.com/bnb-chain/tss-lib/tss"
)

func (round *round3) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 3
	round.started = true
	round.resetOK()

	Ps := round.Parties().IDs()
	PIdx := round.PartyID().Index

	// 1,9. calculate xi， round3 计算出所有参与方都在时候的私钥。
	// 将其他parties 发过来的shares相加， x_i = f_a(ids[i]) + f_b(ids[i]) + f_c(ids[i]) + f_d(ids[i])
	xi := new(big.Int).Set(round.temp.shares[PIdx].Share) // 本地产生的share
	for j := range Ps {
		if j == PIdx {
			continue
		}
		r2msg1 := round.temp.kgRound2Message1s[j].Content().(*KGRound2Message1)
		share := r2msg1.UnmarshalShare()
		xi = new(big.Int).Add(xi, share) // 累加
	}
	round.save.Xi = new(big.Int).Mod(xi, round.Params().EC().Params().N) // Xi = f_a(ids[i]) + f_b(ids[i]) + f_c(ids[i]) + f_d(ids[i])

	// 2-3.
	Vc := make(vss.Vs, round.Threshold()+1) // 因为threshold+1能重构密钥的隐藏多项式，对隐藏多项式求和。
	for c := range Vc {                     // c = 0，..., len(vc)
		Vc[c] = round.temp.vs[c] // 获取本地隐藏多项式[g^a0, g^a1, ...]各项的值。Vc[0] = g^a0, Vc[1] = g^a1, Vc[2] = g^a2
	}

	// 4-11.
	type vssOut struct {
		unWrappedErr error
		pjVs         vss.Vs
	}
	chs := make([]chan vssOut, len(Ps)) // len(Ps) = 所有的参与方
	for i := range chs {
		if i == PIdx {
			continue
		}
		chs[i] = make(chan vssOut) // vssOut: verified secret share out
	}

	for j := range Ps { // 每一个party验证从其他party发过来的share是否正确,即party[i] 验证party[j](i!=j)在r2msg1发过来的share 是否是r2msg2中发布的[g^a0, g^a1,....]计算的结果
		if j == PIdx {
			continue // 不验证自己
		}
		// 6-8.
		// 所有的参与方，验证每个参与方私钥分片的fieldman_vss 分享方案
		go func(j int, ch chan<- vssOut) {
			// 4-9.
			KGCj := round.temp.KGCs[j] // 取出party[j] 隐藏多项式的hash
			r2msg2 := round.temp.kgRound2Message2s[j].Content().(*KGRound2Message2)
			KGDj := r2msg2.UnmarshalDeCommitment() // 从r2msg2中取出party[j] 隐藏多项式DeCommitment[r, g^a0, g^a1,....]
			cmtDeCmt := commitments.HashCommitDecommit{C: KGCj, D: KGDj}
			ok, flatPolyGs := cmtDeCmt.DeCommit() // 验证party[j] 提供的隐藏多项式的decommit
			if !ok || flatPolyGs == nil {
				ch <- vssOut{errors.New("de-commitment verify failed"), nil}
				return
			}

			PjVs, err := crypto.UnFlattenECPoints(round.Params().EC(), flatPolyGs) // PjVs = party[j]的隐藏多项式 [g^a0, g^a1, ....]，将flatPolyGs中的数组变成EC曲线上的点
			if err != nil {
				ch <- vssOut{err, nil}
				return
			}
			r2msg1 := round.temp.kgRound2Message1s[j].Content().(*KGRound2Message1)
			PjShare := vss.Share{
				Threshold: round.Threshold(),
				ID:        round.PartyID().KeyInt(),
				Share:     r2msg1.UnmarshalShare(),
			}

			if ok = PjShare.Verify(round.Params().EC(), round.Threshold(), PjVs); !ok { // r2msg1发过来的share是否是r2msg2中发布的[g^a0, g^a1,....]计算的结果
				ch <- vssOut{errors.New("vss verify failed"), nil}
				return
			}
			// (9) handled above
			ch <- vssOut{nil, PjVs} // 将party[j]的隐藏多项式 [g^a0, g^a1, ....]输出
		}(j, chs[j])
	}

	// consume unbuffered channels (end the goroutines)，用非buffer的channel实现同步
	// 检查其他party vss的检查的结果，如果有未通过检查的，收集后报错
	vssResults := make([]vssOut, len(Ps))
	{
		culprits := make([]*tss.PartyID, 0, len(Ps)) // who caused the error(s)
		for j, Pj := range Ps {
			if j == PIdx {
				continue
			}
			vssResults[j] = <-chs[j] // 获得party[j]的隐藏多项式，如果隐藏多项式的验证中出错，记为culprit。此处用非buffer的channel实现同步
			// collect culprits to error out with
			if err := vssResults[j].unWrappedErr; err != nil {
				culprits = append(culprits, Pj)
			}
		}
		var multiErr error
		if len(culprits) > 0 {
			for _, vssResult := range vssResults {
				if vssResult.unWrappedErr == nil {
					continue
				}
				multiErr = multierror.Append(multiErr, vssResult.unWrappedErr) // 将多个error汇总到一个multiErr中
			}
			return round.WrapError(multiErr, culprits...)
		}
	}

	// 检查 Vc[i] = g^ai + g^bi + g^ci 相加的结果是否在ecdsa 曲线上。
	{
		var err error
		culprits := make([]*tss.PartyID, 0, len(Ps)) // who caused the error(s)
		for j, Pj := range Ps {
			if j == PIdx {
				continue
			}
			// 10-11.
			PjVs := vssResults[j].pjVs // 获取DKG所有参与方的隐藏多项式。
			for c := 0; c <= round.Threshold(); c++ {
				// alice 的隐藏多项式:f_a(x)= a0 + a1*x + a2*x^2
				// bob 的隐藏多项式: f_b(x) = b0 + b1*x + b2*x^2
				// carol 的隐藏多项式:f_c(x)= c0 + c1*x + c2*x^2
				// dave 的隐藏多项式: f_d(x)= d0 + d1*x + d2*x^2
				// Vc[0] = g^a0 + g^b0 + g^c0 + g^d0，函数之和的常量部分
				// Vc[1] = g^a1 + g^b1 + g^c1 + g^d1，函数之和的一次项系数
				// Vc[2] = g^a2 + g^b2 + g^c2 + g^d2，函数之和的二次项系数

				Vc[c], err = Vc[c].Add(PjVs[c]) // Vc[i] = g^ai + g^bi + g^ci, 即Vc[j]= Sum(party_i[j]), 因为party_i[j]都在ecdsa的曲线上,所以他们的和也在ecdsa曲线上。如果相加的结果不在ecdsa的曲线上，则判断该party 作恶。
				if err != nil {
					culprits = append(culprits, Pj)
				}
			}
		}
		if len(culprits) > 0 {
			return round.WrapError(errors.New("adding PjVs[c] to Vc[c] resulted in a point not on the curve"), culprits...)
		}
	}

	// 12-16. compute Xj for each Pj
	{
		var err error
		modQ := common.ModInt(round.Params().EC().Params().N)
		culprits := make([]*tss.PartyID, 0, len(Ps)) // who caused the error(s)
		bigXj := round.save.BigXj                    // round.save.BigXj 为数组，之前未赋值，为nil
		for j := 0; j < round.PartyCount(); j++ {
			Pj := round.Parties().IDs()[j]
			kj := Pj.KeyInt() // party[j] 对应的ids[j]
			BigXj := Vc[0]
			z := new(big.Int).SetInt64(int64(1))
			for c := 1; c <= round.Threshold(); c++ {
				z = modQ.Mul(z, kj)
				BigXj, err = BigXj.Add(Vc[c].ScalarMult(z)) // bigXj = Vc[0] + Vc[1]*(ids[j]) + vc[2]*(ids[j])^2， 如果不再ecdsa 曲线上，判断为作恶
				if err != nil {
					culprits = append(culprits, Pj)
				}
			}
			// bigXj 为所有参与方隐藏多项式之和，在对应ids[j]的取值。各个party的 bigXj不同，即bigXj[i] != bigXj[j], 但是作为round.save.BigXj 存的数组是在各个party都是相同的。
			// bigXj[k] = (g^a0 + g^b0 + g^c0 + g^d0) + (g^a1 + g^b1 + g^c1 + g^d1) * ids[k] + (g^a2 + g^b2 + g^c2 + g^d2) * ids[k]^2
			// 即: bigXj[0] = (g^a0 + g^b0 + g^c0 + g^d0) + (g^a1 + g^b1 + g^c1 + g^d1)  * ids[0] +  (g^a2 + g^b2 + g^c2 + g^d2) * ids[0]^2
			bigXj[j] = BigXj
		}
		if len(culprits) > 0 {
			return round.WrapError(errors.New("adding Vc[c].ScalarMult(z) to BigXj resulted in a point not on the curve"), culprits...)
		}
		round.save.BigXj = bigXj
	}

	// 17. compute and SAVE the ECDSA public key `y`
	// 构造出公钥。 Vc[0] = g^a0 + g^b0 + g^c0 + g^d0, 其中(a0, b0, c0, d0)为每个party掌握的部分私钥，加起来之后就是公钥
	ecdsaPubKey, err := crypto.NewECPoint(round.Params().EC(), Vc[0].X(), Vc[0].Y())
	if err != nil {
		return round.WrapError(errors2.Wrapf(err, "public key is not on the curve"))
	}
	round.save.ECDSAPub = ecdsaPubKey

	// PRINT public key & private share
	common.Logger.Infof("%s public key: %x", round.PartyID(), ecdsaPubKey)

	// BROADCAST paillier proof for ecdsaPubKey, 将本地产生的公钥通过paillier证明广播出去  。
	ki := round.PartyID().KeyInt()
	proof := round.save.PaillierSK.Proof(ki, ecdsaPubKey)
	r3msg := NewKGRound3Message(round.PartyID(), proof)
	round.temp.kgRound3Messages[PIdx] = r3msg
	round.out <- r3msg
	return nil
}

func (round *round3) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound3Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round3) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.kgRound3Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		// proof check is in round 4
		round.ok[j] = true
	}
	return true, nil
}

func (round *round3) NextRound() tss.Round {
	round.started = false
	return &round4{round}
}
