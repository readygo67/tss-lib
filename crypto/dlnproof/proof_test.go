// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package dlnproof

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/common"
)

func Test1(t *testing.T) {
	c := common.SHA512_256iOne(big.NewInt(100))
	fmt.Printf("hash:%b\n", c)
	x := [Iterations]*big.Int{}
	cIBI := new(big.Int)
	for i := range x {
		cI := c.Bit(i)                  // 取hash 结果的第i个bit的值，0 or 1
		cIBI = cIBI.SetInt64(int64(cI)) // 得到bigInt(0) or bigInt(1)
		fmt.Printf("cI:%v, CIBI:%v\n", cI, cIBI)
	}
}
