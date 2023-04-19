// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/vss"
	"github.com/bnb-chain/tss-lib/test"
	"github.com/bnb-chain/tss-lib/tss"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/stretchr/testify/assert"
)

func buildP2PConnections(pIDs tss.SortedPartyIDs) [][]network.Stream {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prvStrs := []string{
		"659c9dd58b8464676d95ca358c40f0eba281e5344e1bba336a7df8c10a8e4edc",
		"37db260492a73cda835d297669db8449e1648d8126dfa4885ea636ec59da7d4c",
		"00ec12a6bac08410276e3d86760eab997d153dbde1a7eeea3872eaf8ca5e2d1a",
		"8677d9720accbe178088777f3d41bfe653b9c5348eb6e8c78333e708a5f9ceef",
	}
	ports := []int{20000, 20001, 20002, 20003}
	hosts := make([]host.Host, 0)
	conns := make([][]network.Stream, 0)
	for i := range pIDs {
		h, err := makeHost(ports[i], prvStrs[i])
		if err != nil {
			log.Println(err)
			return nil
		}
		hosts = append(hosts, h)
	}

	for _, h := range hosts {
		// log.Printf("%v's ID:%v", i, h.ID())
		startPeer(ctx, h, handleStreamWithHash)
		// fmt.Printf("%v privatekey:%v\n", i, h.Peerstore().PrivKey(h.ID()))
	}

	// h1 concect to h2，建立全连接
	for i, h1 := range hosts {
		temp := make([]network.Stream, 0)
		for j, h2 := range hosts {
			if i == j {
				temp = append(temp, nil) // 自己到自己的connection 为nil
			} else {
				addrs := strings.Split(h2.Addrs()[0].String(), "/")
				dest := fmt.Sprintf("/ip4/127.0.0.1/tcp/%v/p2p/%s", addrs[len(addrs)-1], h2.ID().Pretty())
				conn, err := startPeerAndConnect(ctx, h1, dest)
				if err != nil {
					log.Println(err)
					return nil
				}
				temp = append(temp, conn)
			}
		}
		conns = append(conns, temp)
	}

	return conns
}

func buildP2PConnectionsBWParties(parties []*LocalParty) [][]network.Stream {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prvStrs := []string{
		"659c9dd58b8464676d95ca358c40f0eba281e5344e1bba336a7df8c10a8e4edc",
		"37db260492a73cda835d297669db8449e1648d8126dfa4885ea636ec59da7d4c",
		"00ec12a6bac08410276e3d86760eab997d153dbde1a7eeea3872eaf8ca5e2d1a",
		"8677d9720accbe178088777f3d41bfe653b9c5348eb6e8c78333e708a5f9ceef",
	}
	ports := []int{20000, 20001, 20002, 20003}
	hosts := make([]host.Host, 0)
	conns := make([][]network.Stream, 0)
	for i := range parties {
		h, err := makeHost(ports[i], prvStrs[i])
		if err != nil {
			log.Println(err)
			return nil
		}
		hosts = append(hosts, h)
	}

	for _, h := range hosts {
		// log.Printf("%v's ID:%v", i, h.ID())
		startPeer(ctx, h, handleStreamWithHash)
		// fmt.Printf("%v privatekey:%v\n", i, h.Peerstore().PrivKey(h.ID()))
	}

	// h1 concect to h2，建立全连接
	for i, h1 := range hosts {
		temp := make([]network.Stream, 0)
		for j, h2 := range hosts {
			if i == j {
				continue
			}

			addrs := strings.Split(h2.Addrs()[0].String(), "/")
			dest := fmt.Sprintf("/ip4/127.0.0.1/tcp/%v/p2p/%s", addrs[len(addrs)-1], h2.ID().Pretty())
			conn, err := startPeerAndConnect(ctx, h1, dest)
			if err != nil {
				log.Println(err)
				return nil
			}
			temp = append(temp, conn)
		}
		conns = append(conns, temp)
	}

	return conns
}

// TODO(keep), 通过pIDs 建立P2P 连接
func Test2PConnections(t *testing.T) {
	setUp("debug")

	threshold := 2
	partyCount := 4
	fixtures, pIDs, err := LoadKeygenTestFixtures(partyCount)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(partyCount)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*LocalParty, 0, len(pIDs))

	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan LocalPartySaveData, len(pIDs))

	// build the parties
	for i := 0; i < len(pIDs); i++ {
		var P *LocalParty
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], len(pIDs), threshold)
		if i < len(fixtures) {
			P = NewLocalParty(params, outCh, endCh, fixtures[i].LocalPreParams).(*LocalParty)
		} else {
			P = NewLocalParty(params, outCh, endCh).(*LocalParty)
		}
		parties = append(parties, P)
	}

	conns := buildP2PConnections(pIDs)

	h1Conns := conns[0][:]

	// h1 send message to others
	for _, conn := range h1Conns {
		if conn != nil {
			// writeData1(conn, "hello")
			writeDataWithHash(conn, "hello")
		}
	}

	time.Sleep(10 * time.Second)

	for _, conn := range h1Conns {
		if conn != nil {
			writeDataWithHash(conn, "nice to see you, miss you so much")
		}
	}

	select {}
}

func Test2PConnectionsBWParties(t *testing.T) {
	setUp("debug")

	threshold := 2
	partyCount := 4
	fixtures, pIDs, err := LoadKeygenTestFixtures(partyCount)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(partyCount)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*LocalParty, 0, len(pIDs))

	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan LocalPartySaveData, len(pIDs))

	// build the parties
	for i := 0; i < len(pIDs); i++ {
		var P *LocalParty
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], len(pIDs), threshold)
		if i < len(fixtures) {
			P = NewLocalParty(params, outCh, endCh, fixtures[i].LocalPreParams).(*LocalParty)
		} else {
			P = NewLocalParty(params, outCh, endCh).(*LocalParty)
		}
		parties = append(parties, P)
	}

	conns := buildP2PConnectionsBWParties(parties)

	h1Conns := conns[0][:]

	// h1 send message to others
	for _, conn := range h1Conns {
		if conn != nil {
			// writeData1(conn, "hello")
			writeDataWithHash(conn, "hello")
		}
	}

	time.Sleep(10 * time.Second)

	for _, conn := range h1Conns {
		if conn != nil {
			writeDataWithHash(conn, "nice to see you, miss you so much")
		}
	}

	select {}
}

func Test_DKG_3_4_WithLocalTestData(t *testing.T) {
	setUp("debug")

	threshold := 2
	partyCount := 4
	fixtures, pIDs, err := LoadKeygenTestFixtures(partyCount)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(partyCount)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan LocalPartySaveData, len(pIDs))

	updater := test.SharedPartyUpdater

	startGR := runtime.NumGoroutine()

	// init the parties
	for i := 0; i < len(pIDs); i++ {
		var P *LocalParty
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], len(pIDs), threshold)
		if i < len(fixtures) {
			P = NewLocalParty(params, outCh, endCh, fixtures[i].LocalPreParams).(*LocalParty)
		} else {
			P = NewLocalParty(params, outCh, endCh).(*LocalParty)
		}
		parties = append(parties, P)

	}

	// start  the parties
	for _, P := range parties {
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	// PHASE: keygen
	var ended int32
keygen:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break keygen

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil { // broadcast!
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else { // point-to-point!
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case save := <-endCh:
			// SAVE a test fixture file for this P (if it doesn't already exist)
			// .. here comes a workaround to recover this party's index (it was removed from save data)
			index, err := save.OriginalIndex()
			assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
			tryWriteTestFixtureFile(t, index, save)

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)

				// combine shares for each Pj to get u
				u := new(big.Int)
				for j, Pj := range parties {
					pShares := make(vss.Shares, 0)
					for _, P := range parties {
						vssMsgs := P.temp.kgRound2Message1s
						share := vssMsgs[j].Content().(*KGRound2Message1).Share
						shareStruct := &vss.Share{
							Threshold: threshold,
							ID:        P.PartyID().KeyInt(),
							Share:     new(big.Int).SetBytes(share),
						}
						pShares = append(pShares, shareStruct)
					}
					uj, err := pShares[:threshold+1].ReConstruct(tss.S256())
					assert.NoError(t, err, "vss.ReConstruct should not throw error")

					// uG test: u*G[j] == V[0]
					assert.Equal(t, uj, Pj.temp.ui)
					uG := crypto.ScalarBaseMult(tss.EC(), uj)
					assert.True(t, uG.Equals(Pj.temp.vs[0]), "ensure u*G[j] == V_0")

					// xj tests: BigXj == xj*G
					xj := Pj.data.Xi
					gXj := crypto.ScalarBaseMult(tss.EC(), xj)
					BigXj := Pj.data.BigXj[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")

					// fails if threshold cannot be satisfied (bad share)
					{
						badShares := pShares[:threshold]
						badShares[len(badShares)-1].Share.Set(big.NewInt(0))
						uj, err := pShares[:threshold].ReConstruct(tss.S256())
						assert.NoError(t, err)
						assert.NotEqual(t, parties[j].temp.ui, uj)
						BigXjX, BigXjY := tss.EC().ScalarBaseMult(uj.Bytes())
						assert.NotEqual(t, BigXjX, Pj.temp.vs[0].X())
						assert.NotEqual(t, BigXjY, Pj.temp.vs[0].Y())
					}
					u = new(big.Int).Add(u, uj)
				}

				// build ecdsa key pair
				pkX, pkY := save.ECDSAPub.X(), save.ECDSAPub.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     pkX,
					Y:     pkY,
				}
				sk := ecdsa.PrivateKey{
					PublicKey: pk,
					D:         u,
				}
				// test pub key, should be on curve and match pkX, pkY
				assert.True(t, sk.IsOnCurve(pkX, pkY), "public key must be on curve")

				// public key tests
				assert.NotZero(t, u, "u should not be zero")
				ourPkX, ourPkY := tss.EC().ScalarBaseMult(u.Bytes())
				assert.Equal(t, pkX, ourPkX, "pkX should match expected pk derived from u")
				assert.Equal(t, pkY, ourPkY, "pkY should match expected pk derived from u")
				t.Log("Public key tests done.")

				// make sure everyone has the same ECDSA public key
				for _, Pj := range parties {
					assert.Equal(t, pkX, Pj.data.ECDSAPub.X())
					assert.Equal(t, pkY, Pj.data.ECDSAPub.Y())
				}
				t.Log("Public key distribution test done.")

				// test sign/verify
				data := make([]byte, 32)
				for i := range data {
					data[i] = byte(i)
				}
				r, s, err := ecdsa.Sign(rand.Reader, &sk, data)
				assert.NoError(t, err, "sign should not throw an error")
				ok := ecdsa.Verify(&pk, data, r, s)
				assert.True(t, ok, "signature should be ok")
				t.Log("ECDSA signing test done.")

				t.Logf("Start goroutines: %d, End goroutines: %d", startGR, runtime.NumGoroutine())

				break keygen
			}
		}
	}
}

func Test_DKG_3_4(t *testing.T) {
	setUp("debug")

	// tss.SetCurve(elliptic.P256())

	threshold := 2
	pIDs := tss.GenerateTestPartyIDs(4)

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan LocalPartySaveData, len(pIDs))

	updater := test.SharedPartyUpdater

	startGR := runtime.NumGoroutine()

	// init the parties
	for i := 0; i < len(pIDs); i++ {
		var P *LocalParty
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], len(pIDs), threshold)
		P = NewLocalParty(params, outCh, endCh).(*LocalParty)

		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	// PHASE: keygen
	var ended int32
keygen:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break keygen

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil { // broadcast!
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else { // point-to-point!
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case save := <-endCh:
			// SAVE a test fixture file for this P (if it doesn't already exist)
			// .. here comes a workaround to recover this party's index (it was removed from save data)
			index, err := save.OriginalIndex()
			assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
			tryWriteTestFixtureFile(t, index, save)

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)

				// combine shares for each Pj to get u
				u := new(big.Int)
				for j, Pj := range parties {
					pShares := make(vss.Shares, 0)
					for _, P := range parties {
						vssMsgs := P.temp.kgRound2Message1s
						share := vssMsgs[j].Content().(*KGRound2Message1).Share
						shareStruct := &vss.Share{
							Threshold: threshold,
							ID:        P.PartyID().KeyInt(),
							Share:     new(big.Int).SetBytes(share),
						}
						pShares = append(pShares, shareStruct)
					}
					uj, err := pShares[:threshold+1].ReConstruct(tss.S256())
					assert.NoError(t, err, "vss.ReConstruct should not throw error")

					// uG test: u*G[j] == V[0]
					assert.Equal(t, uj, Pj.temp.ui)
					uG := crypto.ScalarBaseMult(tss.EC(), uj)
					assert.True(t, uG.Equals(Pj.temp.vs[0]), "ensure u*G[j] == V_0")

					// xj tests: BigXj == xj*G
					xj := Pj.data.Xi
					gXj := crypto.ScalarBaseMult(tss.EC(), xj)
					BigXj := Pj.data.BigXj[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")

					// fails if threshold cannot be satisfied (bad share)
					{
						badShares := pShares[:threshold]
						badShares[len(badShares)-1].Share.Set(big.NewInt(0))
						uj, err := pShares[:threshold].ReConstruct(tss.S256())
						assert.NoError(t, err)
						assert.NotEqual(t, parties[j].temp.ui, uj)
						BigXjX, BigXjY := tss.EC().ScalarBaseMult(uj.Bytes())
						assert.NotEqual(t, BigXjX, Pj.temp.vs[0].X())
						assert.NotEqual(t, BigXjY, Pj.temp.vs[0].Y())
					}
					u = new(big.Int).Add(u, uj)
				}

				// build ecdsa key pair
				pkX, pkY := save.ECDSAPub.X(), save.ECDSAPub.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     pkX,
					Y:     pkY,
				}
				sk := ecdsa.PrivateKey{
					PublicKey: pk,
					D:         u,
				}
				// test pub key, should be on curve and match pkX, pkY
				assert.True(t, sk.IsOnCurve(pkX, pkY), "public key must be on curve")

				// public key tests
				assert.NotZero(t, u, "u should not be zero")
				ourPkX, ourPkY := tss.EC().ScalarBaseMult(u.Bytes())
				assert.Equal(t, pkX, ourPkX, "pkX should match expected pk derived from u")
				assert.Equal(t, pkY, ourPkY, "pkY should match expected pk derived from u")
				t.Log("Public key tests done.")

				// make sure everyone has the same ECDSA public key
				for _, Pj := range parties {
					assert.Equal(t, pkX, Pj.data.ECDSAPub.X())
					assert.Equal(t, pkY, Pj.data.ECDSAPub.Y())
				}
				t.Log("Public key distribution test done.")

				// test sign/verify
				data := make([]byte, 32)
				for i := range data {
					data[i] = byte(i)
				}
				r, s, err := ecdsa.Sign(rand.Reader, &sk, data)
				assert.NoError(t, err, "sign should not throw an error")
				ok := ecdsa.Verify(&pk, data, r, s)
				assert.True(t, ok, "signature should be ok")
				t.Log("ECDSA signing test done.")

				t.Logf("Start goroutines: %d, End goroutines: %d", startGR, runtime.NumGoroutine())

				break keygen
			}
		}
	}
}

func Test_DKG_3_4_WithP2PConnections(t *testing.T) {
	setUp("debug")

	threshold := 2
	partyCount := 4
	fixtures, pIDs, err := LoadKeygenTestFixtures(partyCount)
	if err != nil {
		common.Logger.Info("No test fixtures were found, so the safe primes will be generated from scratch. This may take a while...")
		pIDs = tss.GenerateTestPartyIDs(partyCount)
	}

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan LocalPartySaveData, len(pIDs))

	updater := test.SharedPartyUpdater

	startGR := runtime.NumGoroutine()

	// init the parties
	for i := 0; i < len(pIDs); i++ {
		var P *LocalParty
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], len(pIDs), threshold)
		if i < len(fixtures) {
			P = NewLocalParty(params, outCh, endCh, fixtures[i].LocalPreParams).(*LocalParty)
		} else {
			P = NewLocalParty(params, outCh, endCh).(*LocalParty)
		}
		parties = append(parties, P)

	}

	conns := buildP2PConnectionsBWParties(parties)

	// start  the parties
	for _, P := range parties {
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	// PHASE: keygen
	var ended int32
keygen:
	for {
		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break keygen

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil { // broadcast!
				for _, P := range parties {
					fromIndex := msg.GetFrom().Index
					toIndex := P.PartyID().Index
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}

					writeDataWithHash(conns[fromIndex][toIndex], msg.String())

					go updater(P, msg, errCh)
				}
			} else { // point-to-point!
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
					return
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case save := <-endCh:
			// SAVE a test fixture file for this P (if it doesn't already exist)
			// .. here comes a workaround to recover this party's index (it was removed from save data)
			index, err := save.OriginalIndex()
			assert.NoErrorf(t, err, "should not be an error getting a party's index from save data")
			tryWriteTestFixtureFile(t, index, save)

			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				t.Logf("Done. Received save data from %d participants", ended)

				// combine shares for each Pj to get u
				u := new(big.Int)
				for j, Pj := range parties {
					pShares := make(vss.Shares, 0)
					for _, P := range parties {
						vssMsgs := P.temp.kgRound2Message1s
						share := vssMsgs[j].Content().(*KGRound2Message1).Share
						shareStruct := &vss.Share{
							Threshold: threshold,
							ID:        P.PartyID().KeyInt(),
							Share:     new(big.Int).SetBytes(share),
						}
						pShares = append(pShares, shareStruct)
					}
					uj, err := pShares[:threshold+1].ReConstruct(tss.S256())
					assert.NoError(t, err, "vss.ReConstruct should not throw error")

					// uG test: u*G[j] == V[0]
					assert.Equal(t, uj, Pj.temp.ui)
					uG := crypto.ScalarBaseMult(tss.EC(), uj)
					assert.True(t, uG.Equals(Pj.temp.vs[0]), "ensure u*G[j] == V_0")

					// xj tests: BigXj == xj*G
					xj := Pj.data.Xi
					gXj := crypto.ScalarBaseMult(tss.EC(), xj)
					BigXj := Pj.data.BigXj[j]
					assert.True(t, BigXj.Equals(gXj), "ensure BigX_j == g^x_j")

					// fails if threshold cannot be satisfied (bad share)
					{
						badShares := pShares[:threshold]
						badShares[len(badShares)-1].Share.Set(big.NewInt(0))
						uj, err := pShares[:threshold].ReConstruct(tss.S256())
						assert.NoError(t, err)
						assert.NotEqual(t, parties[j].temp.ui, uj)
						BigXjX, BigXjY := tss.EC().ScalarBaseMult(uj.Bytes())
						assert.NotEqual(t, BigXjX, Pj.temp.vs[0].X())
						assert.NotEqual(t, BigXjY, Pj.temp.vs[0].Y())
					}
					u = new(big.Int).Add(u, uj)
				}

				// build ecdsa key pair
				pkX, pkY := save.ECDSAPub.X(), save.ECDSAPub.Y()
				pk := ecdsa.PublicKey{
					Curve: tss.EC(),
					X:     pkX,
					Y:     pkY,
				}
				sk := ecdsa.PrivateKey{
					PublicKey: pk,
					D:         u,
				}
				// test pub key, should be on curve and match pkX, pkY
				assert.True(t, sk.IsOnCurve(pkX, pkY), "public key must be on curve")

				// public key tests
				assert.NotZero(t, u, "u should not be zero")
				ourPkX, ourPkY := tss.EC().ScalarBaseMult(u.Bytes())
				assert.Equal(t, pkX, ourPkX, "pkX should match expected pk derived from u")
				assert.Equal(t, pkY, ourPkY, "pkY should match expected pk derived from u")
				t.Log("Public key tests done.")

				// make sure everyone has the same ECDSA public key
				for _, Pj := range parties {
					assert.Equal(t, pkX, Pj.data.ECDSAPub.X())
					assert.Equal(t, pkY, Pj.data.ECDSAPub.Y())
				}
				t.Log("Public key distribution test done.")

				// test sign/verify
				data := make([]byte, 32)
				for i := range data {
					data[i] = byte(i)
				}
				r, s, err := ecdsa.Sign(rand.Reader, &sk, data)
				assert.NoError(t, err, "sign should not throw an error")
				ok := ecdsa.Verify(&pk, data, r, s)
				assert.True(t, ok, "signature should be ok")
				t.Log("ECDSA signing test done.")

				t.Logf("Start goroutines: %d, End goroutines: %d", startGR, runtime.NumGoroutine())

				break keygen
			}
		}
	}
}
