// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/pkg/errors"
)

const (
	mustGetRandomIntMaxBits = 5000
)

// MustGetRandomInt panics if it is unable to gather entropy from `rand.Reader` or when `bits` is <= 0
func MustGetRandomInt(bits int) *big.Int {
	if bits <= 0 || mustGetRandomIntMaxBits < bits {
		panic(fmt.Errorf("MustGetRandomInt: bits should be positive, non-zero and less than %d", mustGetRandomIntMaxBits))
	}
	// Max random value e.g. 2^256 - 1
	max := new(big.Int)
	max = max.Exp(two, big.NewInt(int64(bits)), nil).Sub(max, one)

	// Generate cryptographically strong pseudo-random int between 0 - max
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(errors.Wrap(err, "rand.Int failure in MustGetRandomInt!"))
	}
	return n
}

func GetRandomPositiveInt(lessThan *big.Int) *big.Int {
	if lessThan == nil || zero.Cmp(lessThan) != -1 {
		return nil
	}
	var try *big.Int
	for {
		try = MustGetRandomInt(lessThan.BitLen())
		if try.Cmp(lessThan) < 0 && try.Cmp(zero) >= 0 {
			break
		}
	}
	return try
}

func GetRandomPrimeInt(bits int) *big.Int {
	if bits <= 0 {
		return nil
	}
	try, err := rand.Prime(rand.Reader, bits)
	if err != nil ||
		try.Cmp(zero) == 0 {
		// fallback to older method
		for {
			try = MustGetRandomInt(bits)
			if probablyPrime(try) {
				break
			}
		}
	}
	return try
}

// Generate a random element in the group of all the elements in Z/nZ that
// has a multiplicative inverse.
// 此函数的作用是生成一个大于0且与n互质的随机整数。在密码学中，这种随机整数在许多算法中都有广泛应用，例如RSA密钥生成中，需要选择两个大素数p和q，使得它们乘积n = pq成为一个Safeprime，同时要选择两个正整数e和d满足ed ≡ 1 (mod φ(n))，其中φ(n) = (p-1)(q-1)，那么e就是一个大于1且与φ(n)互质的整数，而且e必须小于φ(n)。因此，需要使用类似GetRandomPositiveRelativelyPrimeInt函数来生成满足条件的随机正整数e。另外，在ElGamal加密也需要随机选择一个与n互质的整数作为加密算法的参数之一。
func GetRandomPositiveRelativelyPrimeInt(n *big.Int) *big.Int {
	if n == nil || zero.Cmp(n) != -1 {
		return nil
	}
	var try *big.Int
	for {
		try = MustGetRandomInt(n.BitLen())
		if IsNumberInMultiplicativeGroup(n, try) {
			break
		}
	}
	return try
}

// Z/nZ中的所有具有乘法逆元的元素组成的群被称为模n的乘法群，记为$(Z/nZ)^* $或$ \mathbb{Z}_n^* $，它是一个由{n}中与n互质的正整数构成的循环群。
// 例如，考虑模15的剩余类环Z/15Z，其中所有元素可以表示为{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}。其中，具有乘法逆元的元素有1、2、4、7、8、11、13、14，它们可以组成一个由八个元素构成的群，
// 即$(Z/15Z)^* = \{1,2,4,7,8,11,13,14\}$。需要注意的是，群的乘法操作是模n下的乘法运算，即对于任意的$a,b \in (Z/nZ)^*$，乘法运算$ab$是指$a$和$b$在模$n$下的乘积，即$ab \equiv c \pmod{n}$，其中$c$是$b$在模$n$下的逆元素，即$bc \equiv 1\pmod {n}$。
// 例如 4*7 === 13 mod 15，乘法群有封闭性
// 这里只要n，v 互质就满足条件。
func IsNumberInMultiplicativeGroup(n, v *big.Int) bool {
	if n == nil || v == nil || zero.Cmp(n) != -1 {
		return false
	}
	gcd := big.NewInt(0)
	return v.Cmp(n) < 0 && v.Cmp(one) >= 0 &&
		gcd.GCD(nil, nil, v, n).Cmp(one) == 0
}

//	Return a random generator of RQn with high probability.
//	THIS METHOD ONLY WORKS IF N IS THE PRODUCT OF TWO SAFE PRIMES!
//
// https://github.com/didiercrunch/paillier/blob/d03e8850a8e4c53d04e8016a2ce8762af3278b71/utils.go#L39
func GetRandomGeneratorOfTheQuadraticResidue(n *big.Int) *big.Int {
	f := GetRandomPositiveRelativelyPrimeInt(n)
	fSq := new(big.Int).Mul(f, f)
	return fSq.Mod(fSq, n)
}
