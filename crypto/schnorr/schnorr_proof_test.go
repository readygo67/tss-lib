// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package schnorr_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	. "github.com/bnb-chain/tss-lib/crypto/schnorr"
	"github.com/bnb-chain/tss-lib/tss"
)

func TestSchnorrProof(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(q)      // 私钥:x
	uG := crypto.ScalarBaseMult(tss.EC(), u) // 公钥:x*G
	proof, _ := NewZKProof(u, uG)            // 产生x的NIZK。

	assert.True(t, proof.Alpha.IsOnCurve())
	assert.NotZero(t, proof.Alpha.X())
	assert.NotZero(t, proof.Alpha.Y())
	assert.NotZero(t, proof.T)
}

func TestSchnorrProofVerify(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(tss.EC(), u)

	proof, _ := NewZKProof(u, X)
	res := proof.Verify(X)

	assert.True(t, res, "verify result must be true")
}

func TestSchnorrProofVerifyBadX(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(q)
	u2 := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(tss.EC(), u)
	X2 := crypto.ScalarBaseMult(tss.EC(), u2)

	proof, _ := NewZKProof(u2, X2)
	res := proof.Verify(X) // 实际公钥是X2

	assert.False(t, res, "verify result must be false")

	res = proof.Verify(X2) // 实际公钥是X2
	assert.True(t, res, "verify result must be true")
}

func TestSchnorrVProofVerify(t *testing.T) {
	q := tss.EC().Params().N
	k := common.GetRandomPositiveInt(q)
	s := common.GetRandomPositiveInt(q)
	l := common.GetRandomPositiveInt(q)
	R := crypto.ScalarBaseMult(tss.EC(), k) // k_-1 * G
	Rs := R.ScalarMult(s)
	lG := crypto.ScalarBaseMult(tss.EC(), l)
	V, _ := Rs.Add(lG)

	proof, _ := NewZKVProof(V, R, s, l)
	res := proof.Verify(V, R)

	assert.True(t, res, "verify result must be true")
}

func TestSchnorrVProofVerifyBadPartialV(t *testing.T) {
	q := tss.EC().Params().N
	k := common.GetRandomPositiveInt(q)
	s := common.GetRandomPositiveInt(q)
	l := common.GetRandomPositiveInt(q)
	R := crypto.ScalarBaseMult(tss.EC(), k) // k_-1 * G
	Rs := R.ScalarMult(s)
	V := Rs

	proof, _ := NewZKVProof(V, R, s, l)
	res := proof.Verify(V, R)

	assert.False(t, res, "verify result must be false")
}

func TestSchnorrVProofVerifyBadS(t *testing.T) {
	q := tss.EC().Params().N
	k := common.GetRandomPositiveInt(q)
	s := common.GetRandomPositiveInt(q)
	s2 := common.GetRandomPositiveInt(q)
	l := common.GetRandomPositiveInt(q)
	R := crypto.ScalarBaseMult(tss.EC(), k) // k_-1 * G
	Rs := R.ScalarMult(s)
	lG := crypto.ScalarBaseMult(tss.EC(), l)
	V, _ := Rs.Add(lG)

	proof, _ := NewZKVProof(V, R, s2, l)
	res := proof.Verify(V, R)

	assert.False(t, res, "verify result must be false")
}
