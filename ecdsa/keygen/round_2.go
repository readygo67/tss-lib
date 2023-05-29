// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"encoding/hex"
	"errors"
	"sync"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/tss"
)

const (
	paillierBitsLen = 2048
)

// round2 首先验证各个节点发过了r1msg是否正确，保存其他个节点发送过来的paillier 公钥，多项式的承诺， 然后发送两个消息
// r2msg1: 将本party 通过隐藏多项式 f(x)= a0+a1*x+a2*x^2, x = party[j].key得到的share[j] 点对点的发送Pj
// r2msg2: 把本party的 [r, g^a0,g^a1,g^a2,...]的commitment.D

func (round *round2) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 2
	round.started = true
	round.resetOK() // resetok数组，标明没有收到其他parties 的消息。

	common.Logger.Debugf(
		"%s Setting up DLN verification with concurrency level of %d",
		round.PartyID(),
		round.Concurrency(),
	)
	dlnVerifier := NewDlnProofVerifier(round.Concurrency()) // 构造一个DLNProofVerifier,

	i := round.PartyID().Index

	// 6. verify dln proofs, store r1 message pieces, ensure uniqueness of h1j, h2j
	h1H2Map := make(map[string]struct{}, len(round.temp.kgRound1Messages)*2)
	dlnProof1FailCulprits := make([]*tss.PartyID, len(round.temp.kgRound1Messages))
	dlnProof2FailCulprits := make([]*tss.PartyID, len(round.temp.kgRound1Messages))
	wg := new(sync.WaitGroup)
	// 检查收到的r1msg，
	// 1. 要求所有收到的h1/h2 都不能相同
	for j, msg := range round.temp.kgRound1Messages {
		r1msg := msg.Content().(*KGRound1Message)
		H1j, H2j, NTildej, paillierPKj :=
			r1msg.UnmarshalH1(),
			r1msg.UnmarshalH2(),
			r1msg.UnmarshalNTilde(),
			r1msg.UnmarshalPaillierPK()
		if paillierPKj.N.BitLen() != paillierBitsLen {
			return round.WrapError(errors.New("got paillier modulus with insufficient bits for this party"), msg.GetFrom())
		}
		if H1j.Cmp(H2j) == 0 {
			return round.WrapError(errors.New("h1j and h2j were equal for this party"), msg.GetFrom())
		}
		if NTildej.BitLen() != paillierBitsLen {
			return round.WrapError(errors.New("got NTildej with insufficient bits for this party"), msg.GetFrom())
		}
		h1JHex, h2JHex := hex.EncodeToString(H1j.Bytes()), hex.EncodeToString(H2j.Bytes())
		if _, found := h1H2Map[h1JHex]; found {
			return round.WrapError(errors.New("this h1j was already used by another party"), msg.GetFrom())
		}
		if _, found := h1H2Map[h2JHex]; found {
			return round.WrapError(errors.New("this h2j was already used by another party"), msg.GetFrom())
		}
		h1H2Map[h1JHex], h1H2Map[h2JHex] = struct{}{}, struct{}{}

		wg.Add(2)
		_j := j
		_msg := msg
		// 如果验证h2 != h1^ alpha, 记录作恶的节点
		dlnVerifier.VerifyDLNProof1(r1msg, H1j, H2j, NTildej, func(isValid bool) {
			if !isValid {
				dlnProof1FailCulprits[_j] = _msg.GetFrom() // 如果无效，记录作恶的那个party
			}
			wg.Done()
		})
		// 如果验证h1 != h1^ alpha, 记录作恶的节点 h1i = h2i^beta
		dlnVerifier.VerifyDLNProof2(r1msg, H2j, H1j, NTildej, func(isValid bool) {
			if !isValid {
				dlnProof2FailCulprits[_j] = _msg.GetFrom() // /如果无效，记录作恶的那个party
			}
			wg.Done()
		})
	}
	wg.Wait()
	for _, culprit := range append(dlnProof1FailCulprits, dlnProof2FailCulprits...) {
		if culprit != nil {
			return round.WrapError(errors.New("dln proof verification failed"), culprit)
		}
	}
	// save NTilde_j, h1_j, h2_j, ..., 在round1中收到其他parties过来的消息，验证过后将其保存在
	for j, msg := range round.temp.kgRound1Messages {
		if j == i {
			continue
		}
		r1msg := msg.Content().(*KGRound1Message)
		paillierPK, H1j, H2j, NTildej, KGC :=
			r1msg.UnmarshalPaillierPK(),
			r1msg.UnmarshalH1(),
			r1msg.UnmarshalH2(),
			r1msg.UnmarshalNTilde(),
			r1msg.UnmarshalCommitment()
		round.save.PaillierPKs[j] = paillierPK // used in round 4
		round.save.NTildej[j] = NTildej
		round.save.H1j[j], round.save.H2j[j] = H1j, H2j
		round.temp.KGCs[j] = KGC
	}

	// 5. p2p send share ui 的share[j] to Pj， 将本地ui 的share[(ids[j], f_i(ids[j]))]发给peer
	shares := round.temp.shares
	for j, Pj := range round.Parties().IDs() {
		r2msg1 := NewKGRound2Message1(Pj, round.PartyID(), shares[j])
		// do not send to this Pj, but store for round 3
		if j == i {
			round.temp.kgRound2Message1s[j] = r2msg1 // 将本party的r2msg1保存起来。
			continue
		}
		round.out <- r2msg1
	}

	// 7. BROADCAST de-commitments of Shamir poly*G,
	// 广播本party 隐藏多项式[r, g^a0,g^a1,g^a2,...]的commitment。
	r2msg2 := NewKGRound2Message2(round.PartyID(), round.temp.deCommitPolyG)
	round.temp.kgRound2Message2s[i] = r2msg2
	round.out <- r2msg2

	return nil
}

func (round *round2) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*KGRound2Message1); ok {
		return !msg.IsBroadcast()
	}
	if _, ok := msg.Content().(*KGRound2Message2); ok {
		return msg.IsBroadcast()
	}
	return false
}

// 当收到所有party的 r2msg1和r2msg2b之后，
func (round *round2) Update() (bool, *tss.Error) {
	// guard - VERIFY de-commit for all Pj
	for j, msg := range round.temp.kgRound2Message1s {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			return false, nil
		}
		msg2 := round.temp.kgRound2Message2s[j]
		if msg2 == nil || !round.CanAccept(msg2) {
			return false, nil
		}
		round.ok[j] = true
	}
	return true, nil
}

func (round *round2) NextRound() tss.Round {
	round.started = false
	return &round3{round}
}
