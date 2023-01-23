// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package vss_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	. "github.com/bnb-chain/tss-lib/crypto/vss"
	"github.com/bnb-chain/tss-lib/tss"
)

func TestCheckIndexesDup(t *testing.T) {
	indexes := make([]*big.Int, 0)
	for i := 0; i < 1000; i++ {
		indexes = append(indexes, common.GetRandomPositiveInt(tss.EC().Params().N))
	}
	_, e := CheckIndexes(tss.EC(), indexes)
	assert.NoError(t, e)

	indexes = append(indexes, indexes[99])
	_, e = CheckIndexes(tss.EC(), indexes)
	assert.Error(t, e)
}

func TestCheckIndexesZero(t *testing.T) {
	indexes := make([]*big.Int, 0)
	for i := 0; i < 1000; i++ {
		indexes = append(indexes, common.GetRandomPositiveInt(tss.EC().Params().N))
	}
	_, e := CheckIndexes(tss.EC(), indexes)
	assert.NoError(t, e)

	indexes = append(indexes, tss.EC().Params().N)
	_, e = CheckIndexes(tss.EC(), indexes)
	assert.Error(t, e)
}

func TestCreate(t *testing.T) {
	num, threshold := 5, 3

	secret := common.GetRandomPositiveInt(tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(tss.EC().Params().N))
	}

	vs, _, err := Create(tss.EC(), threshold, secret, ids)
	assert.Nil(t, err)

	assert.Equal(t, threshold+1, len(vs))
	// assert.Equal(t, num, params.NumShares)

	assert.Equal(t, threshold+1, len(vs))

	// ensure that each vs has two points on the curve
	for i, pg := range vs {
		assert.NotZero(t, pg.X())
		assert.NotZero(t, pg.Y())
		assert.True(t, pg.IsOnCurve())
		assert.NotZero(t, vs[i].X())
		assert.NotZero(t, vs[i].Y())
	}
}

func TestVerify(t *testing.T) {
	num, threshold := 5, 3

	secret := common.GetRandomPositiveInt(tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(tss.EC().Params().N))
	}

	vs, shares, err := Create(tss.EC(), threshold, secret, ids)

	assert.NoError(t, err)

	for i := 0; i < num; i++ {
		assert.True(t, shares[i].Verify(tss.EC(), threshold, vs)) // 每一个碎片验证是否
	}
}

func TestReconstruct(t *testing.T) {
	num, threshold := 5, 3

	secret := common.GetRandomPositiveInt(tss.EC().Params().N)
	fmt.Printf("secret:%v\n", secret.String()) // 私钥
	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(tss.EC().Params().N))
	}

	_, shares, err := Create(tss.EC(), threshold, secret, ids)
	assert.NoError(t, err)

	secret2, err2 := shares[:threshold-1].ReConstruct(tss.EC())
	assert.Error(t, err2) // not enough shares to satisfy the threshold
	assert.Nil(t, secret2)

	secret3, err3 := shares[:threshold].ReConstruct(tss.EC())
	assert.NoError(t, err3)
	assert.NotZero(t, secret3)
	fmt.Printf("secret3:%v\n", secret3.String())

	secret4, err4 := shares[:threshold+1].ReConstruct(tss.EC())
	assert.NoError(t, err4)
	assert.NotZero(t, secret4)
	fmt.Printf("secret4:%v\n", secret4.String())

	secret5, err5 := shares[:num].ReConstruct(tss.EC())
	assert.NoError(t, err5)
	assert.NotZero(t, secret5)
	fmt.Printf("secret5:%v\n", secret5.String())
}

func TestReconstruct1(t *testing.T) {
	num, threshold := 4, 3

	secret := common.GetRandomPositiveInt(tss.EC().Params().N)
	secretStr := secret.String()
	fmt.Printf("secret:%v\n", secretStr)

	ids := make([]*big.Int, 0)
	idsStr := make([]string, 0)
	for i := 0; i < num; i++ {
		r := common.GetRandomPositiveInt(tss.EC().Params().N)
		ids = append(ids, r)
		idsStr = append(idsStr, r.String())
	}

	_, shares, err := Create(tss.EC(), threshold, secret, ids)
	assert.NoError(t, err)

	secret2, err2 := shares[:threshold-1].ReConstruct(tss.EC())
	assert.Error(t, err2) // not enough shares to satisfy the threshold
	assert.Nil(t, secret2)

	secret3, err3 := shares[:threshold].ReConstruct(tss.EC())
	assert.NoError(t, err3)
	assert.NotZero(t, secret3)
	fmt.Printf("secret3:%v\n", secret3.String())

	secret4, err4 := shares[:num].ReConstruct(tss.EC())
	assert.NoError(t, err4)
	assert.NotZero(t, secret4)
	fmt.Printf("secret4:%v\n", secret4.String())
}

func TestReconstruct2(t *testing.T) {
	num, threshold := 4, 2

	secret := big.NewInt(100)
	secretStr := secret.String()
	fmt.Printf("secret:%v\n", secretStr)

	ids := make([]*big.Int, 0)
	idsStr := make([]string, 0)
	for i := 0; i < num; i++ {
		r := big.NewInt(int64(i + 1))
		ids = append(ids, r)
		idsStr = append(idsStr, r.String())
	}
	fmt.Printf("idsStr:%v\n", idsStr)

	_, shares, err := Create(tss.EC(), threshold, secret, ids)
	assert.NoError(t, err)

	for i := 0; i < len(shares); i++ {
		fmt.Printf("id:%v, share:%v\n", shares[i].ID, shares[i].Share.String())
	}

	secret2, err2 := shares[:threshold-1].ReConstruct(tss.EC())
	assert.Error(t, err2) // not enough shares to satisfy the threshold
	assert.Nil(t, secret2)

	secret3, err3 := shares[:threshold].ReConstruct(tss.EC())
	assert.Error(t, err3) // not enough shares to satisfy the threshold
	assert.Nil(t, secret3)

	secret4, err4 := shares[:num].ReConstruct(tss.EC())
	assert.NoError(t, err4)
	assert.NotZero(t, secret4)
	fmt.Printf("secret4:%v\n", secret4.String())

	secret5, err5 := shares[1:].ReConstruct(tss.EC())
	assert.NoError(t, err5)
	assert.NotZero(t, secret5)
	fmt.Printf("secret5:%v\n", secret5.String())
}
