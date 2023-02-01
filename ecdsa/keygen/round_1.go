// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"errors"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	cmts "github.com/bnb-chain/tss-lib/crypto/commitments"
	"github.com/bnb-chain/tss-lib/crypto/dlnproof"
	"github.com/bnb-chain/tss-lib/crypto/vss"
	"github.com/bnb-chain/tss-lib/tss"
)

var (
	zero = big.NewInt(0)
)

// round 1 represents round 1 of the keygen part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
// round1: 广播party[i]产生的paillier 公钥，+ 隐藏多项式的hash[g^a0, g^a1,....], +safePrime的NTildei,H1i,H2i，以及他们的dlnProof。
// round2: party[i]将为party[j]产生的share[j] p2p发送给party[j], 广播party[i]的隐藏多项式[r, g^a0, g^a1, g^a2,....]
// round3: party[i]
// 1. 将在r1msg1中收到的party[j]的hash[g^a0, g^a1,....] 和r2msg2 收到的party[j]隐藏多项式[r, g^a0, g^a1, g^a2,....] 生成HashCommitDecommit，并验证
// 2. 将party[j] 通过 r2msg1中发来的share[i]，和party[j]通过r2msg2中发过来的生成多项式[g^a0, g^a1, g^a2,....] 验证。
// 3. 将各个party[j] 发过来的share[i]相加，得到save.Xi
// 4. 计算bigXj 为各参与方隐藏多项式之和，在对应ids[j]的取值。各个party的bigXj相同
// 4. 计算得到公钥
// 5. 产生(ids[i], ecdsaPubkey)的paillier证明
// round4: 验证(ids[i], ecdsaPubkey)的paillier是否正确，如果正确将round
func newRound1(params *tss.Parameters, save *LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- LocalPartySaveData) tss.Round {
	return &round1{
		&base{params, save, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 1
	round.started = true
	round.resetOK()

	Pi := round.PartyID()
	i := Pi.Index

	// 1. calculate "partial" key share ui
	// 随机产生部分私钥
	ui := common.GetRandomPositiveInt(round.Params().EC().Params().N)

	round.temp.ui = ui // 产生部分私钥

	// 2. compute the vss shares
	// f(x) = a0 + a1*x + a2*x^2 + ....
	// vs[0] = g^a0, vs[1] = g^a1, vs[i] = g^ai, 2个 commitment
	// shares = {xi, f(xi)}
	// 把party[i] 的部分私钥u[i] 通过一个多项式fa(x), 得到shares， shares = [(ids[0] f_a(ids[0])), (ids[1],fa(ids[1])), (ids[2],fa(ids[2]))]
	ids := round.Parties().IDs().Keys()
	vs, shares, err := vss.Create(round.Params().EC(), round.Threshold(), ui, ids)
	if err != nil {
		return round.WrapError(err, Pi)
	}
	round.save.Ks = ids

	// security: the original u_i may be discarded
	ui = zero // clears the secret data from memory
	_ = ui    // silences a linter warning

	// make commitment -> (C, D)
	// 将vs[0] = g ^a0, vs[1] = g^a1, 变成[]*big.Int数组，pGFlat = [vs[0], vs[1], vs[2].....]
	pGFlat, err := crypto.FlattenECPoints(vs) // 将party[i]的部分私钥u[i]的隐藏多项式g^a[0], g^[a1] flat
	if err != nil {
		return round.WrapError(err, Pi)
	}

	// 将vs[0] = g ^a0, vs[1] = g^a1, 变成 变成[]*big.Int数组 再做一个commitment.
	// pGFlat = [r, vs[0], vs[1], vs[2].....] cmt.C = hash(r, vs[0], vs[1], ...), cmt.D = [r, vs[0], vs[1], ...]
	cmt := cmts.NewHashCommitment(pGFlat...)

	// 4. generate Paillier public key E_i, private key and proof
	// 5-7. generate safe primes for ZKPs used later on
	// 9-11. compute ntilde, h1, h2 (uses safe primes)
	// use the pre-params if they were provided to the LocalParty constructor
	var preParams *LocalPreParams
	if round.save.LocalPreParams.Validate() && !round.save.LocalPreParams.ValidateWithProof() {
		return round.WrapError(
			errors.New("`optionalPreParams` failed to validate; it might have been generated with an older version of tss-lib"))
	} else if round.save.LocalPreParams.ValidateWithProof() {
		preParams = &round.save.LocalPreParams
	} else {
		preParams, err = GeneratePreParams(round.SafePrimeGenTimeout(), round.Concurrency())
		if err != nil {
			return round.WrapError(errors.New("pre-params generation failed"), Pi)
		}
	}
	round.save.LocalPreParams = *preParams
	round.save.NTildej[i] = preParams.NTildei
	round.save.H1j[i], round.save.H2j[i] = preParams.H1i, preParams.H2i

	// generate the dlnproofs for keygen
	h1i, h2i, alpha, beta, p, q, NTildei :=
		preParams.H1i,
		preParams.H2i,
		preParams.Alpha,
		preParams.Beta,
		preParams.P,
		preParams.Q,
		preParams.NTildei
	dlnProof1 := dlnproof.NewDLNProof(h1i, h2i, alpha, p, q, NTildei)
	dlnProof2 := dlnproof.NewDLNProof(h2i, h1i, beta, p, q, NTildei)

	// for this P: SAVE
	// - shareID
	// and keep in temporary storage:
	// - VSS Vs
	// - our set of Shamir shares
	round.save.ShareID = ids[i] // shareID，记录本party的ids
	round.temp.vs = vs          // 记录本party[i] 隐藏多项式系数的[g^a0, g^a1, g^a2,....]
	round.temp.shares = shares  // 记录party[i]产生的u[i]的隐藏多项式的[ids[1], f(ids[1])], [ids[2], f(ids[2])],[ids[3], f(ids[3])]

	// for this P: SAVE de-commitments, paillier keys for round 2
	round.save.PaillierSK = preParams.PaillierSK
	round.save.PaillierPKs[i] = &preParams.PaillierSK.PublicKey
	round.temp.deCommitPolyG = cmt.D // 记录本party[i] 隐藏多项式系数的[r,g^a0, g^a1, g^a2,....]

	// BROADCAST commitments, paillier pk + proof; round 1 message
	{
		msg, err := NewKGRound1Message(
			round.PartyID(), cmt.C, &preParams.PaillierSK.PublicKey, preParams.NTildei, preParams.H1i, preParams.H2i, dlnProof1, dlnProof2)
		if err != nil {
			return round.WrapError(err, Pi)
		}
		round.temp.kgRound1Messages[i] = msg
		round.out <- msg
	}
	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg := range round.temp.kgRound1Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		// vss check is in round 2
		round.ok[j] = true
	}
	return true, nil
}

// NextRound 将round 变量变成下一轮的round
func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
