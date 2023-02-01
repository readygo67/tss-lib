// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
)

// PrepareForSigning(), GG18Spec (11) Fig. 14
// i:本party的id
// pax: len(ks),参与
func PrepareForSigning(ec elliptic.Curve, i, pax int, xi *big.Int, ks []*big.Int, bigXs []*crypto.ECPoint) (wi *big.Int, bigWs []*crypto.ECPoint) {
	modQ := common.ModInt(ec.Params().N)
	if len(ks) != len(bigXs) {
		panic(fmt.Errorf("PrepareForSigning: len(ks) != len(bigXs) (%d != %d)", len(ks), len(bigXs)))
	}
	if len(ks) != pax {
		panic(fmt.Errorf("PrepareForSigning: len(ks) != pax (%d != %d)", len(ks), pax))
	}
	if len(ks) <= i {
		panic(fmt.Errorf("PrepareForSigning: len(ks) <= i (%d <= %d)", len(ks), i))
	}

	// 2-4.
	wi = xi // additive sharing, 可以通过拉格朗日系数乘以xi得到 wi = [(0 - ks[j])/(ks[i] - ks[j])]
	for j := 0; j < pax; j++ {
		if j == i {
			continue
		}
		ksj := ks[j]
		ksi := ks[i]
		if ksj.Cmp(ksi) == 0 {
			panic(fmt.Errorf("index of two parties are equal"))
		}
		// big.Int Div is calculated as: a/b = a * modInv(b,q)
		coef := modQ.Mul(ks[j], modQ.ModInverse(new(big.Int).Sub(ksj, ksi)))
		wi = modQ.Mul(wi, coef)
	}

	// 5-10. 看起来是bigWj= g^aj
	bigWs = make([]*crypto.ECPoint, len(ks)) // len(ks)= threshold +1
	for j := 0; j < pax; j++ {               // pax = threshold +1
		bigWj := bigXs[j] // bigXj = Vc[0] + Vc[1]*(ids[j]) + vc[2]*(ids[j])^2
		for c := 0; c < pax; c++ {
			if j == c {
				continue
			}
			ksc := ks[c]
			ksj := ks[j]
			if ksj.Cmp(ksc) == 0 { // 如果参与签名的两个party， party[c] 的ids[c] 和party[j]的ids[j]相同，则报错。
				panic(fmt.Errorf("index of two parties are equal"))
			}
			// big.Int Div is calculated as: a/b = a * modInv(b,q)   ids[c]/(ids[c] - ids[j]), 具体的作用不明确
			iota := modQ.Mul(ksc, modQ.ModInverse(new(big.Int).Sub(ksc, ksj))) // bigWj = bigXj * ids[k]/(ids[k] - ids[j]) * ids[c]/(ids[c] - ids[j])
			bigWj = bigWj.ScalarMult(iota)
		}
		bigWs[j] = bigWj
	}
	return
}
