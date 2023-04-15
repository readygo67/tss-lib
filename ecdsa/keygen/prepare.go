// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"context"
	"errors"
	"math/big"
	"runtime"
	"time"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
)

const (
	// Using a modulus length of 2048 is recommended in the GG18 spec
	paillierModulusLen = 2048
	// Two 1024-bit safe primes to produce NTilde
	safePrimeBitLen = 1024
	// Ticker for printing log statements while generating primes/modulus
	logProgressTickInterval = 8 * time.Second
)

// GeneratePreParams finds two safe primes and computes the Paillier secret required for the protocol.
// This can be a time consuming process so it is recommended to do it out-of-band.
// If not specified, a concurrency value equal to the number of available CPU cores will be used.
// If pre-parameters could not be generated before the timeout, an error is returned.
func GeneratePreParams(timeout time.Duration, optionalConcurrency ...int) (*LocalPreParams, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return GeneratePreParamsWithContext(ctx, optionalConcurrency...)
}

// GeneratePreParams finds two safe primes and computes the Paillier secret required for the protocol.
// This can be a time consuming process so it is recommended to do it out-of-band.
// If not specified, a concurrency value equal to the number of available CPU cores will be used.
// If pre-parameters could not be generated before the context is done, an error is returned.
func GeneratePreParamsWithContext(ctx context.Context, optionalConcurrency ...int) (*LocalPreParams, error) {
	var concurrency int
	if 0 < len(optionalConcurrency) {
		if 1 < len(optionalConcurrency) {
			panic(errors.New("GeneratePreParams: expected 0 or 1 item in `optionalConcurrency`"))
		}
		concurrency = optionalConcurrency[0]
	} else {
		concurrency = runtime.NumCPU()
	}
	if concurrency /= 3; concurrency < 1 {
		concurrency = 1
	}

	// prepare for concurrent Paillier and safe prime generation
	paiCh := make(chan *paillier.PrivateKey, 1)       // 产生paillier 私钥
	sgpCh := make(chan []*common.GermainSafePrime, 1) // 产生GermainSafePrime

	// 4. generate Paillier public key E_i, private key and proof
	go func(ch chan<- *paillier.PrivateKey) {
		common.Logger.Info("generating the Paillier modulus, please wait...")
		start := time.Now()
		// more concurrency weight is assigned here because the paillier primes have a requirement of having "large" P-Q
		PiPaillierSk, _, err := paillier.GenerateKeyPair(ctx, paillierModulusLen, concurrency*2)
		if err != nil {
			ch <- nil
			return
		}
		common.Logger.Infof("paillier modulus generated. took %s\n", time.Since(start))
		ch <- PiPaillierSk
	}(paiCh)

	// 5-7. generate safe primes for ZKPs used later on
	go func(ch chan<- []*common.GermainSafePrime) {
		var err error
		common.Logger.Info("generating the safe primes for the signing proofs, please wait...")
		start := time.Now()
		sgps, err := common.GetRandomSafePrimesConcurrent(ctx, safePrimeBitLen, 2, concurrency)
		if err != nil {
			ch <- nil
			return
		}
		common.Logger.Infof("safe primes generated. took %s\n", time.Since(start))
		ch <- sgps
	}(sgpCh)

	// this ticker will print a log statement while the generating is still in progress
	logProgressTicker := time.NewTicker(logProgressTickInterval)

	// errors can be thrown in the following code; consume chans to end goroutines here
	var sgps []*common.GermainSafePrime
	var paiSK *paillier.PrivateKey
consumer:
	for {
		select {
		case <-logProgressTicker.C:
			common.Logger.Info("still generating primes...")
		case sgps = <-sgpCh:
			if sgps == nil ||
				sgps[0] == nil || sgps[1] == nil ||
				!sgps[0].Prime().ProbablyPrime(30) || !sgps[1].Prime().ProbablyPrime(30) ||
				!sgps[0].SafePrime().ProbablyPrime(30) || !sgps[1].SafePrime().ProbablyPrime(30) {
				return nil, errors.New("timeout or error while generating the safe primes")
			}
			if paiSK != nil {
				break consumer
			}
		case paiSK = <-paiCh:
			if paiSK == nil {
				return nil, errors.New("timeout or error while generating the Paillier secret key")
			}
			if sgps != nil {
				break consumer
			}
		}
	}
	logProgressTicker.Stop()

	P, Q := sgps[0].SafePrime(), sgps[1].SafePrime() // 产生两对safePrime, 取P1，P2 的名字更加符合  p1= 2q1+1, p2=2q2+1
	NTildei := new(big.Int).Mul(P, Q)                // p1 * p2
	modNTildeI := common.ModInt(NTildei)

	p, q := sgps[0].Prime(), sgps[1].Prime()                  // 产生两对safePrime, 取q1，q2 的名字更加符合
	modPQ := common.ModInt(new(big.Int).Mul(p, q))            // q1 * q2
	f1 := common.GetRandomPositiveRelativelyPrimeInt(NTildei) // f1 和 alpha 为一个和NTildei 的最大公约是1的数。
	alpha := common.GetRandomPositiveRelativelyPrimeInt(NTildei)
	beta := modPQ.ModInverse(alpha)   // beta = 1/alaph
	h1i := modNTildeI.Mul(f1, f1)     // h1 = f1^2
	h2i := modNTildeI.Exp(h1i, alpha) // h2 = h1 ^ alpha

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
	return preParams, nil
}
