// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/tss"
)

type (
	LocalPreParams struct {
		PaillierSK *paillier.PrivateKey //
		NTildei,   // 两个safePrime p1/p2的乘积
		H1i, H2i, // H1i随机数 f1的平方, H2i随机数 f1的平方 * 另一个随机数alpha 的乘积
		Alpha, Beta, // 随机数alpha, beta = 1/alpha
		P, Q *big.Int // 第一个safePrime的q, 第二个safePrime的q
	}

	LocalSecrets struct {
		// secret fields (not shared, but stored locally)
		Xi, ShareID *big.Int // xi, kj  //Xi= Sum(f_1(ids[i], f_1(ids[2], ...))) 各个party的隐藏多项式计算得到的share[i] 之和。ShareID是ids[i]
	}

	// Everything in LocalPartySaveData is saved locally to user's HD when done
	LocalPartySaveData struct {
		LocalPreParams // party[i] 产生的PreParams
		LocalSecrets   // party[i] 的Sum(f_1(ids[i], f_1(ids[2], ...))), 和ids[i]

		// original indexes (ki in signing preparation phase)
		Ks []*big.Int // Keys，//Keys 记录各个party的key

		// n-tilde, h1, h2 for range proofs
		NTildej, H1j, H2j []*big.Int // 记录每一个party的n-tilde,h1, h2

		// public keys (Xj = uj*G for each Pj)
		BigXj       []*crypto.ECPoint     // 记录每一个party的私钥分片u[j]对应的隐藏多项式之和对各个ids[]的结果
		PaillierPKs []*paillier.PublicKey // pkj 记录每一个party的paillier publickey

		// used for test assertions (may be discarded)
		ECDSAPub *crypto.ECPoint // y
	}
)

// 分配partyCount个Ks,NTildej, H1j, H@=2j, BigXj, PaillierPKs个以存储所有party的数据。
func NewLocalPartySaveData(partyCount int) (saveData LocalPartySaveData) {
	saveData.Ks = make([]*big.Int, partyCount)
	saveData.NTildej = make([]*big.Int, partyCount)
	saveData.H1j, saveData.H2j = make([]*big.Int, partyCount), make([]*big.Int, partyCount)
	saveData.BigXj = make([]*crypto.ECPoint, partyCount)
	saveData.PaillierPKs = make([]*paillier.PublicKey, partyCount)
	return
}

func (preParams LocalPreParams) Validate() bool {
	return preParams.PaillierSK != nil &&
		preParams.NTildei != nil &&
		preParams.H1i != nil &&
		preParams.H2i != nil
}

func (preParams LocalPreParams) ValidateWithProof() bool {
	return preParams.Validate() &&
		preParams.Alpha != nil &&
		preParams.Beta != nil &&
		preParams.P != nil &&
		preParams.Q != nil
}

// BuildLocalSaveDataSubset re-creates the LocalPartySaveData to contain data for only the list of signing parties.
func BuildLocalSaveDataSubset(sourceData LocalPartySaveData, sortedIDs tss.SortedPartyIDs) LocalPartySaveData {
	keysToIndices := make(map[string]int, len(sourceData.Ks))
	for j, kj := range sourceData.Ks {
		keysToIndices[hex.EncodeToString(kj.Bytes())] = j
	}
	newData := NewLocalPartySaveData(sortedIDs.Len())
	newData.LocalPreParams = sourceData.LocalPreParams
	newData.LocalSecrets = sourceData.LocalSecrets
	newData.ECDSAPub = sourceData.ECDSAPub
	for j, id := range sortedIDs {
		savedIdx, ok := keysToIndices[hex.EncodeToString(id.Key)]
		if !ok {
			panic(errors.New("BuildLocalSaveDataSubset: unable to find a signer party in the local save data"))
		}
		newData.Ks[j] = sourceData.Ks[savedIdx]
		newData.NTildej[j] = sourceData.NTildej[savedIdx]
		newData.H1j[j] = sourceData.H1j[savedIdx]
		newData.H2j[j] = sourceData.H2j[savedIdx]
		newData.BigXj[j] = sourceData.BigXj[savedIdx]
		newData.PaillierPKs[j] = sourceData.PaillierPKs[savedIdx]
	}
	return newData
}
