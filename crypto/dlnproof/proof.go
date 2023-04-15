// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Zero-knowledge proof of knowledge of the discrete logarithm over safe prime product

// A proof of knowledge of the discrete log of an element h2 = hx1 with respect to h1.
// In our protocol, we will run two of these in parallel to prove that two elements h1,h2 generate the same group modN.

package dlnproof

import (
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	cmts "github.com/bnb-chain/tss-lib/crypto/commitments"
)

const Iterations = 128

type (
	Proof struct {
		Alpha,
		T [Iterations]*big.Int
	}
)

var (
	one = big.NewInt(1)
)

// 产生关于 h1,h2 的一个proof。
/*
   dlnproof.NewDLNProof(h1i, h2i, alpha, p, q, NTildei)
	preParams := &LocalPreParams{
		PaillierSK: paiSK,   // paillier 的私钥
		NTildei:    NTildei, // 两个safePrime p1/p2的乘积
		H1i:        h1i,     // 随机数 f1的平方
		H2i:        h2i,     // 随机数 f1的平方 * 另一个随机数alpha 的幂
		Alpha:      alpha,   // 随机数alpha
		Beta:       beta,    // 随机数 alpha的倒数
		P:          p,       // 第一个safePrime的q
		Q:          q,       // 第二个safePrime的q
	}

h1i, h2i, alpha, beta, p, q, NTildei :=
		preParams.H1i,
		preParams.H2i,
		preParams.Alpha,
		preParams.Beta,
		preParams.P,
		preParams.Q,
		preParams.NTildei
	dlnProof1 := dlnproof.NewDLNProof(h1i, h2i, alpha, p, q, NTildei)
*/

// 输入参数为 h1=h1i, h2= h2i, x= alpha, p=第一个safePrime，q= 第二个safePrime， N= 两个safePrime p1/p2的乘积
func NewDLNProof(h1, h2, x, p, q, N *big.Int) *Proof {
	pMulQ := new(big.Int).Mul(p, q)
	modN, modPQ := common.ModInt(N), common.ModInt(pMulQ)
	a := make([]*big.Int, Iterations)
	alpha := [Iterations]*big.Int{}
	for i := range alpha {
		a[i] = common.GetRandomPositiveInt(pMulQ)
		alpha[i] = modN.Exp(h1, a[i]) // h1^a[i] mod N
	}
	msg := append([]*big.Int{h1, h2, N}, alpha[:]...) // 获得msg
	c := common.SHA512_256i(msg...)                   // 得到msg的hash
	t := [Iterations]*big.Int{}
	cIBI := new(big.Int)
	for i := range t {
		cI := c.Bit(i)
		cIBI = cIBI.SetInt64(int64(cI))
		t[i] = modPQ.Add(a[i], modPQ.Mul(cIBI, x)) // t[i]= a[i] + 0/1 * x
	}
	return &Proof{alpha, t} // alpha[i] = h1^ai 作为， t[i]也包含a[i], x 的信息
}

func (p *Proof) Verify(h1, h2, N *big.Int) bool {
	if p == nil {
		return false
	}
	if N.Sign() != 1 {
		return false
	}
	modN := common.ModInt(N)
	h1_ := new(big.Int).Mod(h1, N)
	if h1_.Cmp(one) != 1 || h1_.Cmp(N) != -1 { // h1
		return false
	}
	h2_ := new(big.Int).Mod(h2, N)
	if h2_.Cmp(one) != 1 || h2_.Cmp(N) != -1 {
		return false
	}
	if h1_.Cmp(h2_) == 0 {
		return false
	}
	for i := range p.T {
		a := new(big.Int).Mod(p.T[i], N)
		if a.Cmp(one) != 1 || a.Cmp(N) != -1 {
			return false
		}
	}
	for i := range p.Alpha {
		a := new(big.Int).Mod(p.Alpha[i], N)
		if a.Cmp(one) != 1 || a.Cmp(N) != -1 {
			return false
		}
	}
	msg := append([]*big.Int{h1, h2, N}, p.Alpha[:]...)
	c := common.SHA512_256i(msg...)
	cIBI := new(big.Int)
	for i := 0; i < Iterations; i++ {
		if p.Alpha[i] == nil || p.T[i] == nil {
			return false
		}
		cI := c.Bit(i)
		cIBI = cIBI.SetInt64(int64(cI))
		h1ExpTi := modN.Exp(h1, p.T[i])
		h2ExpCi := modN.Exp(h2, cIBI)
		alphaIMulH2ExpCi := modN.Mul(p.Alpha[i], h2ExpCi)
		if h1ExpTi.Cmp(alphaIMulH2ExpCi) != 0 {
			return false
		}
	}
	return true
}

func (p *Proof) Serialize() ([][]byte, error) {
	cb := cmts.NewBuilder()
	cb = cb.AddPart(p.Alpha[:])
	cb = cb.AddPart(p.T[:])
	ints, err := cb.Secrets()
	if err != nil {
		return nil, err
	}
	bzs := make([][]byte, len(ints))
	for i, part := range ints {
		if part == nil {
			bzs[i] = []byte{}
			continue
		}
		bzs[i] = part.Bytes()
	}
	return bzs, nil
}

func UnmarshalDLNProof(bzs [][]byte) (*Proof, error) {
	bis := make([]*big.Int, len(bzs))
	for i := range bis {
		bis[i] = new(big.Int).SetBytes(bzs[i])
	}
	parsed, err := cmts.ParseSecrets(bis)
	if err != nil {
		return nil, err
	}
	if len(parsed) != 2 {
		return nil, fmt.Errorf("UnmarshalDLNProof expected %d parts but got %d", 2, len(parsed))
	}
	pf := new(Proof)
	if len1 := copy(pf.Alpha[:], parsed[0]); len1 != Iterations {
		return nil, fmt.Errorf("UnmarshalDLNProof expected %d but copied %d", Iterations, len1)
	}
	if len2 := copy(pf.T[:], parsed[1]); len2 != Iterations {
		return nil, fmt.Errorf("UnmarshalDLNProof expected %d but copied %d", Iterations, len2)
	}
	return pf, nil
}
