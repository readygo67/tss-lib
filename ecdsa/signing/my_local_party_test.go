// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

// func Test_KeySign_3_4(t *testing.T) {
// 	setUp("info")
// 	threshold := 2
//
// 	// PHASE: load keygen fixtures
// 	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(threshold+1, 4)
// 	assert.NoError(t, err, "should load keygen fixtures")
// 	assert.Equal(t, threshold+1, len(keys))
// 	assert.Equal(t, threshold+1, len(signPIDs))
//
// 	// PHASE: signing
// 	// use a shuffled selection of the list of parties for this test
// 	p2pCtx := tss.NewPeerContext(signPIDs)
// 	parties := make([]*LocalParty, 0, len(signPIDs))
//
// 	errCh := make(chan *tss.Error, len(signPIDs))
// 	outCh := make(chan tss.Message, len(signPIDs))
// 	endCh := make(chan common.SignatureData, len(signPIDs))
//
// 	updater := test.SharedPartyUpdater
//
// 	// init the parties
// 	for i := 0; i < len(signPIDs); i++ {
// 		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), threshold)
//
// 		P := NewLocalParty(big.NewInt(42), params, keys[i], outCh, endCh).(*LocalParty)
// 		parties = append(parties, P)
// 		go func(P *LocalParty) {
// 			if err := P.Start(); err != nil {
// 				errCh <- err
// 			}
// 		}(P)
// 	}
//
// 	var ended int32
// signing:
// 	for {
// 		fmt.Printf("ACTIVE GOROUTINES: %d\n", runtime.NumGoroutine())
// 		select {
// 		case err := <-errCh:
// 			common.Logger.Errorf("Error: %s", err)
// 			assert.FailNow(t, err.Error())
// 			break signing
//
// 		case msg := <-outCh:
// 			dest := msg.GetTo()
// 			if dest == nil {
// 				for _, P := range parties {
// 					if P.PartyID().Index == msg.GetFrom().Index {
// 						continue
// 					}
// 					go updater(P, msg, errCh)
// 				}
// 			} else {
// 				if dest[0].Index == msg.GetFrom().Index {
// 					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
// 				}
// 				go updater(parties[dest[0].Index], msg, errCh)
// 			}
//
// 		case <-endCh:
// 			atomic.AddInt32(&ended, 1)
// 			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
// 				t.Logf("Done. Received signature data from %d participants", ended)
// 				R := parties[0].temp.bigR
// 				r := parties[0].temp.rx
// 				fmt.Printf("sign result: R(%s, %s), r=%s\n", R.X().String(), R.Y().String(), r.String())
//
// 				modN := common.ModInt(tss.S256().Params().N)
//
// 				// BEGIN check s correctness
// 				sumS := big.NewInt(0)
// 				for _, p := range parties {
// 					sumS = modN.Add(sumS, p.temp.si)
// 				}
// 				fmt.Printf("S: %s\n", sumS.String())
// 				// END check s correctness
//
// 				// BEGIN ECDSA verify
// 				pkX, pkY := keys[0].ECDSAPub.X(), keys[0].ECDSAPub.Y()
// 				pk := ecdsa.PublicKey{
// 					Curve: tss.EC(),
// 					X:     pkX,
// 					Y:     pkY,
// 				}
// 				ok := ecdsa.Verify(&pk, big.NewInt(42).Bytes(), R.X(), sumS)
// 				assert.True(t, ok, "ecdsa verify must pass")
// 				t.Log("ECDSA signing test done.")
// 				// END ECDSA verify
//
// 				break signing
// 			}
// 		}
// 	}
// }
