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
	// 将其他parties 发过来的shares相加， x_1 = f_a(1) + f_b(1) + f_c(1) + f_d(1)
	xi := new(big.Int).Set(round.temp.shares[PIdx].Share) // 本地产生的share
	// 将其他party[j]的u[j]通过隐藏多项式产生的[ids[i], f_j(ids[i])]（通过r2msg1发送）累加起来
	for j := range Ps {
		if j == PIdx {
			continue
		}
		r2msg1 := round.temp.kgRound2Message1s[j].Content().(*KGRound2Message1)
		share := r2msg1.UnmarshalShare()
		xi = new(big.Int).Add(xi, share)
	}
	round.save.Xi = new(big.Int).Mod(xi, round.Params().EC().Params().N) // Xi = f_1(ids[i]) + f_2(ids[i]) + f_3(ids[i]) + f_(ids[i])
	// 至此，完成DKG的过程

	// 2-3.
	Vc := make(vss.Vs, round.Threshold()+1) // 因为threshold+1能重构密钥，隐藏多项式，对隐藏多项式求和。
	for c := range Vc {                     // c = 0，..., len(vc)
		Vc[c] = round.temp.vs[c] // 获取本地隐藏多项式[g^a0, g^a1, ...]各项的值。Vc[0] = g^a0, Vc[1] = g^a1, Vc[2] = g^a2
	}

	// 4-11.
	type vssOut struct {
		unWrappedErr error
		pjVs         vss.Vs
	}
	chs := make([]chan vssOut, len(Ps)) // 20个参与方的
	for i := range chs {
		if i == PIdx {
			continue
		}
		chs[i] = make(chan vssOut)
	}

	for j := range Ps { // 所有的参与方, party[i] 验证party[j]在r2msg1发过来的fj(ids[i])是否
		if j == PIdx {
			continue
		}
		// 6-8.
		// 所有的参与方，沿着每个参与方私钥分片的fieldman_vss 分享方案
		go func(j int, ch chan<- vssOut) {
			// 4-9.
			KGCj := round.temp.KGCs[j] // 取出party[j] 隐藏多项式的hash
			r2msg2 := round.temp.kgRound2Message2s[j].Content().(*KGRound2Message2)
			KGDj := r2msg2.UnmarshalDeCommitment() // 从r2msg2中取出party[j] 隐藏多项式[r, g^a0, g^a1,....]
			cmtDeCmt := commitments.HashCommitDecommit{C: KGCj, D: KGDj}
			ok, flatPolyGs := cmtDeCmt.DeCommit() // 验证party[j] 提供的隐藏多项式的decommit
			if !ok || flatPolyGs == nil {
				ch <- vssOut{errors.New("de-commitment verify failed"), nil}
				return
			}
			PjVs, err := crypto.UnFlattenECPoints(round.Params().EC(), flatPolyGs) // PjVs = party[j]的隐藏多项式 [g^a0, g^a1, ....]
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
			if ok = PjShare.Verify(round.Params().EC(), round.Threshold(), PjVs); !ok { // fieldman_vss 分享
				ch <- vssOut{errors.New("vss verify failed"), nil}
				return
			}
			// (9) handled above
			ch <- vssOut{nil, PjVs} // 将party[j]的隐藏多项式 [g^a0, g^a1, ....]输出
		}(j, chs[j])
	}

	// consume unbuffered channels (end the goroutines)，用非buffer的channel实现同步
	vssResults := make([]vssOut, len(Ps))
	{
		culprits := make([]*tss.PartyID, 0, len(Ps)) // who caused the error(s)
		for j, Pj := range Ps {
			if j == PIdx {
				continue
			}
			vssResults[j] = <-chs[j] // 获得party[j]的隐藏多项式，如果隐藏多项式的验证中出错，记为culprit。
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
	// 之所以用{ }分割是因为culprits的定义不同
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

				Vc[c], err = Vc[c].Add(PjVs[c]) // Vc[0] = g^a_1[0] + g^a_2[0] + g^a_3[0], 即Vc[j]= Sum(party_i[j]) Vc各项= 各个参与方该项相加，因为各项都在ecdsa的曲线上所有，他们的和也在ecdsa曲线上。
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
		bigXj := round.save.BigXj                    // round.save.BigXj 之前未赋值，为nil
		for j := 0; j < round.PartyCount(); j++ {
			Pj := round.Parties().IDs()[j]
			kj := Pj.KeyInt() // party[j] 对应的ids[j]
			BigXj := Vc[0]
			z := new(big.Int).SetInt64(int64(1))
			for c := 1; c <= round.Threshold(); c++ {
				z = modQ.Mul(z, kj)
				BigXj, err = BigXj.Add(Vc[c].ScalarMult(z)) // bigXj = Vc[0] + Vc[1]*(ids[j]) + vc[2]*(ids[j])^2
				if err != nil {
					culprits = append(culprits, Pj)
				}
			}
			// bigXj 为各参与方隐藏多项式之和，在对应ids[j]的取值。各个party的bigXj相同
			// bigXj = (g^a0 + g^b0 + g^c0 + g^d0) + (g^a1 + g^b1 + g^c1 + g^d1) * ids[j] + (g^a2 + g^b2 + g^c2 + g^d2) * ids[j]^2
			bigXj[j] = BigXj
		}
		if len(culprits) > 0 {
			return round.WrapError(errors.New("adding Vc[c].ScalarMult(z) to BigXj resulted in a point not on the curve"), culprits...)
		}
		round.save.BigXj = bigXj
	}

	// 17. compute and SAVE the ECDSA public key `y`
	// 构造出公钥。
	ecdsaPubKey, err := crypto.NewECPoint(round.Params().EC(), Vc[0].X(), Vc[0].Y())
	if err != nil {
		return round.WrapError(errors2.Wrapf(err, "public key is not on the curve"))
	}
	round.save.ECDSAPub = ecdsaPubKey

	// PRINT public key & private share
	common.Logger.Infof("%s public key: %x", round.PartyID(), ecdsaPubKey)

	// BROADCAST paillier proof for Pi, 比较奇怪，partyID 是在r1msg1就广播了的，为什么这里还要用paillier来证明。
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
