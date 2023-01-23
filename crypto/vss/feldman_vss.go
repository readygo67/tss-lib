// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Feldman VSS, based on Paul Feldman, 1987., A practical scheme for non-interactive verifiable secret sharing.
// In Foundations of Computer Science, 1987., 28th Annual Symposium on. IEEE, 427–43
//

package vss

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
)

type (
	Share struct {
		Threshold int
		ID,       // xi
		Share *big.Int // Sigma i
	}

	Vs []*crypto.ECPoint // v0..vt

	Shares []*Share
)

var (
	ErrNumSharesBelowThreshold = fmt.Errorf("not enough shares to satisfy the threshold")

	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

// Check share ids of Shamir's Secret Sharing, return error if duplicate or 0 value found
// 检查是否有重复或者为0的的indexs
// 为0的地方， 能够直接得到a0(即秘密)， duplicated 的indexes 会让有效参与方数量减少一个
func CheckIndexes(ec elliptic.Curve, indexes []*big.Int) ([]*big.Int, error) {
	visited := make(map[string]struct{})
	for _, v := range indexes {
		vMod := new(big.Int).Mod(v, ec.Params().N)
		if vMod.Cmp(zero) == 0 {
			return nil, errors.New("party index should not be 0")
		}
		vModStr := vMod.String()
		if _, ok := visited[vModStr]; ok {
			return nil, fmt.Errorf("duplicate indexes %s", vModStr)
		}
		visited[vModStr] = struct{}{}
	}
	return indexes, nil
}

// Returns a new array of secret shares created by Shamir's Secret Sharing Algorithm,
// requiring a minimum number of shares to recreate, of length shares, from the input secret
// indexes， 总共n个shares
// threshold， t个分片就能恢复出私钥。
// Vs[i]=C[i]= g^ai, 为ai的多项式承诺，
// shares[i] = (xi, yi)，为每个参与方掌握的私钥分片。
// feldman 私钥分配算法
func Create(ec elliptic.Curve, threshold int, secret *big.Int, indexes []*big.Int) (Vs, Shares, error) {
	if secret == nil || indexes == nil {
		return nil, nil, fmt.Errorf("vss secret or indexes == nil: %v %v", secret, indexes)
	}
	if threshold < 1 {
		return nil, nil, errors.New("vss threshold < 1")
	}

	ids, err := CheckIndexes(ec, indexes) //
	if err != nil {
		return nil, nil, err
	}

	num := len(indexes)
	if num < threshold {
		return nil, nil, ErrNumSharesBelowThreshold
	}

	poly := samplePolynomial(ec, threshold, secret) // threshold = 3,
	poly[0] = secret                                // becomes sigma*G in v
	v := make(Vs, len(poly))
	fmt.Printf("poly:%v\n", poly)

	for i, ai := range poly {
		v[i] = crypto.ScalarBaseMult(ec, ai) // c0 = g^a0, c1=g^a1, ....
	}

	shares := make(Shares, num)
	for i := 0; i < num; i++ {
		share := evaluatePolynomial(ec, threshold, poly, ids[i])           // yi = a0+ a1 * xi + a2 *xi^2 +...,
		shares[i] = &Share{Threshold: threshold, ID: ids[i], Share: share} // ids[i] 为多项式中的xi，share 为多项式中的yi
	}
	return v, shares, nil
}

// 每一个share验证自己share的有效性，
// vs[i] = c[i] //commitment， c[i] = g^ai
func (share *Share) Verify(ec elliptic.Curve, threshold int, vs Vs) bool {
	if share.Threshold != threshold || vs == nil {
		return false
	}
	var err error
	modQ := common.ModInt(ec.Params().N)
	// v = c0 * c1^(xj) * c2 ^(xj^2) * c3 ^ (xj^3) *....
	v, t := vs[0], one // YRO : we need to have our accumulator outside of the loop
	for j := 1; j <= threshold; j++ {
		// t = k_i^j
		t = modQ.Mul(t, share.ID) // t = xi^j
		// v = v * v_j^t
		vjt := vs[j].SetCurve(ec).ScalarMult(t) // vjt = cj^(xj^t)
		v, err = v.SetCurve(ec).Add(vjt)
		if err != nil {
			return false
		}
	}

	sigmaGi := crypto.ScalarBaseMult(ec, share.Share)
	return sigmaGi.Equals(v)
}

func (shares Shares) ReConstruct(ec elliptic.Curve) (secret *big.Int, err error) {
	if shares != nil && shares[0].Threshold+1 > len(shares) {
		return nil, ErrNumSharesBelowThreshold
	}
	modN := common.ModInt(ec.Params().N)

	// x coords， xs = [x1,x2,x3,...]
	xs := make([]*big.Int, 0)
	for _, share := range shares {
		xs = append(xs, share.ID)
	}

	secret = zero
	for i, share := range shares {
		times := one
		for j := 0; j < len(xs); j++ {
			if j == i {
				continue
			}
			/*
				(0-xj)/(xi-xj) = xj/(xj-xi)
			*/
			sub := modN.Sub(xs[j], share.ID) // = (xj-xj)
			subInv := modN.ModInverse(sub)   // = 1/(xj-xi)
			div := modN.Mul(xs[j], subInv)   // = xj/(xj-xi)
			times = modN.Mul(times, div)     // = 累乘
		}

		fTimes := modN.Mul(share.Share, times) // = f(xi) * 拉格朗日系数
		secret = modN.Add(secret, fTimes)      //
	}

	return secret, nil
}

// 随机产生多项式y = a0+a1*x +a2 *x^2 + a3 *x^3 + ... 中的系数， a0 = secret, a1 = xxx
func samplePolynomial(ec elliptic.Curve, threshold int, secret *big.Int) []*big.Int {
	// q := ec.Params().N
	v := make([]*big.Int, threshold+1)
	v[0] = secret
	for i := 1; i <= threshold; i++ {
		ai := common.GetRandomPositiveInt(ec.Params().N)
		v[i] = ai
	}
	return v
}

// Evauluates a polynomial with coefficients such that:
// evaluatePolynomial([a, b, c, d], x):
//
//	returns a + bx + cx^2 + dx^3, //y=a0 +(a1 * x) + (a2 * x^2) + (a3 * x^3) + (a4 * x^4), 其中
func evaluatePolynomial(ec elliptic.Curve, threshold int, v []*big.Int, id *big.Int) (result *big.Int) {
	q := ec.Params().N
	modQ := common.ModInt(q)
	result = new(big.Int).Set(v[0]) // result = a0
	X := big.NewInt(int64(1))
	for i := 1; i <= threshold; i++ { // 逐项累加
		ai := v[i]
		X = modQ.Mul(X, id) // x = x^i
		aiXi := new(big.Int).Mul(ai, X)
		result = modQ.Add(result, aiXi)
	}
	return
}
