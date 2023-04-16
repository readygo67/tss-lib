// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"fmt"
	"math/big"
	"testing"
)

// Z/nZ中的所有具有乘法逆元的元素组成的群被称为模n的乘法群，记为$(Z/nZ)^* $或$ \mathbb{Z}_n^* $，它是一个由{n}中与n互质的正整数构成的循环群。
//
// 例如，考虑模15的剩余类环Z/15Z，其中所有元素可以表示为{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}。其中，具有乘法逆元的元素有1、2、4、7、8、11、13、14，它们可以组成一个由八个元素构成的群，即$(Z/15Z)^* = \{1,2,4,7,8,11,13,14\}$。需要注意的是，群的乘法操作是模n下的乘法运算，即对于任意的$a,b \in (Z/nZ)^*$，乘法运算$ab$是指$a$和$b$在模$n$下的乘积，即$ab \equiv c \pmod{n}$，其中$c$是$b$在模$n$下的逆元素，即$bc \equiv 1\pmod {n}$。
func TestModInverse(t *testing.T) {
	mod15 := ModInt(big.NewInt(15))

	result := mod15.ModInverse(big.NewInt(2))
	fmt.Println(result)

	result = mod15.ModInverse(big.NewInt(4))
	fmt.Println(result)

	result = mod15.ModInverse(big.NewInt(7))
	fmt.Println(result)

	result = mod15.ModInverse(big.NewInt(8))
	fmt.Println(result)

	result = mod15.ModInverse(big.NewInt(11))
	fmt.Println(result)

	result = mod15.ModInverse(big.NewInt(13))
	fmt.Println(result)

	result = mod15.ModInverse(big.NewInt(14))
	fmt.Println(result)

}
