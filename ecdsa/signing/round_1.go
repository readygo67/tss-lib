// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/commitments"
	"github.com/bnb-chain/tss-lib/crypto/mta"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

var (
	zero = big.NewInt(0)
)

// round 1 represents round 1 of the signing part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound1(params *tss.Parameters, key *keygen.LocalPartySaveData, data *common.SignatureData, temp *localTempData, out chan<- tss.Message, end chan<- common.SignatureData) tss.Round {
	return &round1{
		&base{params, key, data, temp, out, end, make([]bool, len(params.Parties().IDs())), false, 1}}
}

// round1,party[i] 随机产生k 和gamma,
// 1. r1msg1：将用mta对k加密后的密文cA 和rangeProof 发送给party[j]
// 2. r1msg2: 广播g^gamma[i]的commitment

// round2, 做了两次MtA
// 1. party[j] 将从party[i] 传过来的k[i] 和本地的gamma[j] 相乘，然后随机选择-beta[j]， 并将 (k[i] * gamma[j] - beta[j]) 的密文及其range证明发回给party[i]，为求k*gamma准备
// 2. party[j] 将从party[i] 传过来的k[i] 和本地的w[j] 相乘，然后随机选择v[j]， 并将 (k[i] * w[j] - v[j]) 的密文及其range证明发回给party[i], 为求si做准备

// round3,
// 1. party[i] 计算alpha[i]= k[i] * gamma[j] - beta[j], u[i]= k[i]*w[j] - v[j]
// 2. thelta[i] = ki*gammai + sum(alpha[i][i]) + sum(beta[j][i]), 为生成r做准备
// 3. sigma[i] = ki*wi + sum(u[i][j]) + sum(v[j][i])， 为生成s做准备
// 4. 将thelta[i]广播出去

// round4, party[i] 收集到所有的theta[i]之后，计算 k * gamma = Sum(theta[i]), 并将本地gamma[i] 将gamma[i]的ZKP 和 deCommitment 广播
// round5, party[i] 验证gamma[j]的proof之后，获得r, s[i], 计算s[i] 的proof并广播

// round6/7/8，party[i] 交互s[i]的proof, 没有看的太明白
// round9 将party[i] 的s[i]广播出去。
// finalize，将Sum(s[i]) 汇总形成签名s。

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}

	// Spec requires calculate H(M) here,
	// but considered different blockchain use different hash function we accept the converted big.Int
	// if this big.Int is not belongs to Zq, the client might not comply with common rule (for ECDSA):
	// https://github.com/btcsuite/btcd/blob/c26ffa870fd817666a857af1bf6498fabba1ffe3/btcec/signature.go#L263
	if round.temp.m.Cmp(round.Params().EC().Params().N) >= 0 {
		return round.WrapError(errors.New("hashed message is not valid"))
	}

	round.number = 1
	round.started = true
	round.resetOK()

	k := common.GetRandomPositiveInt(round.Params().EC().Params().N)     // 随机生成k[i]
	gamma := common.GetRandomPositiveInt(round.Params().EC().Params().N) // 随机生成gamma[i]

	pointGamma := crypto.ScalarBaseMult(round.Params().EC(), gamma) // pointGamma[i] = g^gamma[i]
	cmt := commitments.NewHashCommitment(pointGamma.X(), pointGamma.Y())
	round.temp.k = k
	round.temp.gamma = gamma
	round.temp.pointGamma = pointGamma
	round.temp.deCommit = cmt.D // pointGamma的commit.D

	i := round.PartyID().Index
	round.ok[i] = true // 本party[i], 这一轮的ok 记为true

	for j, Pj := range round.Parties().IDs() { // partyi 给partyj 发送 mta
		if j == i {
			continue
		}
		cA, rangProof, err := mta.AliceInit(round.Params().EC(), round.key.PaillierPKs[i], k, round.key.NTildej[j], round.key.H1j[j], round.key.H2j[j]) // 将k[i] 发送给 party[j]
		if err != nil {
			return round.WrapError(fmt.Errorf("failed to init mta: %v", err))
		}
		r1msg1 := NewSignRound1Message1(Pj, round.PartyID(), cA, rangProof) // to Pj, from: Pi, cA 为密文， rangProof 为cA的proof。
		round.temp.cis[j] = cA                                              // cis[j] 记录发给Pj 的密文。
		round.out <- r1msg1
	}

	r1msg2 := NewSignRound1Message2(round.PartyID(), cmt.C) // 广播g^gamma[i]的commitment
	round.temp.signRound1Message2s[i] = r1msg2
	round.out <- r1msg2

	return nil
}

func (round *round1) Update() (bool, *tss.Error) {
	for j, msg1 := range round.temp.signRound1Message1s {
		if round.ok[j] { // 对party[j]发送的消息已经登记过了，continue
			continue
		}
		if msg1 == nil || !round.CanAccept(msg1) { // 在所有的待接收的11个消息中， 如果接收到5，但是没有接收到2，在2的时候就会return false。
			return false, nil
		}
		msg2 := round.temp.signRound1Message2s[j]
		if msg2 == nil || !round.CanAccept(msg2) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

// 看消息的类型是否正确，看消息的广播属性是否正确，如果两者都正确，
func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound1Message1); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*SignRound1Message2); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}

// ----- //

// helper to call into PrepareForSigning()
func (round *round1) prepare() error {
	i := round.PartyID().Index

	xi := round.key.Xi       // threshold+1个参与方，Xi
	ks := round.key.Ks       // 记录每个party的ids
	bigXs := round.key.BigXj // bigXj = Vc[0] + Vc[1]*(ids[j]) + vc[2]*(ids[j])^2

	if round.temp.keyDerivationDelta != nil {
		// adding the key derivation delta to the xi's
		// Suppose x has shamir shares x_0,     x_1,     ..., x_n
		// So x + D has shamir shares  x_0 + D, x_1 + D, ..., x_n + D
		mod := common.ModInt(round.Params().EC().Params().N)
		xi = mod.Add(round.temp.keyDerivationDelta, xi)
		round.key.Xi = xi
	}

	if round.Threshold()+1 > len(ks) {
		return fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks))
	}
	wi, bigWs := PrepareForSigning(round.Params().EC(), i, len(ks), xi, ks, bigXs)

	round.temp.w = wi
	round.temp.bigWs = bigWs
	return nil
}
