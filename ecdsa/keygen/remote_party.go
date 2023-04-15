//// Copyright © 2019 Binance
////
//// This file is part of Binance. The full Binance copyright notice, including
//// terms governing use, modification, and redistribution, is contained in the
//// file LICENSE at the root of the source code distribution tree.
//
//package keygen
//
//import (
//	"crypto/rand"
//	"encoding/hex"
//	"errors"
//	"fmt"
//	"log"
//
//	"github.com/libp2p/go-libp2p"
//	"github.com/bnb-chain/tss-lib/common"
//	cmt "github.com/bnb-chain/tss-lib/crypto/commitments"
//	"github.com/bnb-chain/tss-lib/tss"
//	"github.com/libp2p/go-libp2p/core/host"
//	"github.com/libp2p/go-libp2p/core/crypto"
//	"github.com/multiformats/go-multiaddr"
//	tls "github.com/libp2p/go-libp2p/p2p/security/tls"
//)
//
//// Implements Party
//// Implements Stringer
//var _ tss.Party = (*RemoteParty)(nil)
//var _ fmt.Stringer = (*RemoteParty)(nil)
//
//type (
//	RemoteParty struct {
//		*tss.BaseParty
//		params *tss.Parameters
//
//		temp localTempData
//		data LocalPartySaveData
//
//		// outbound messaging
//		out chan<- tss.Message
//		end chan<- LocalPartySaveData
//
//		// in message
//		in  chan tss.Message
//		p2p host.Host
//	}
//
//	P2PParams struct {
//		port   int
//		prvKey string
//	}
//)
//
//// Exported, used in `tss` client
//func NewRemoteParty(
//	params *tss.Parameters,
//	out chan<- tss.Message,
//	end chan<- LocalPartySaveData,
//	in chan tss.Message,
//	p2pParams P2PParams,
//	optionalPreParams ...LocalPreParams,
//) tss.Party {
//	partyCount := params.PartyCount()
//	data := NewLocalPartySaveData(partyCount)
//	// when `optionalPreParams` is provided we'll use the pre-computed primes instead of generating them from scratch
//	// 如果提供了预先生成的preParams, 那么preParams的个数只能是一个。
//	if 0 < len(optionalPreParams) {
//		if 1 < len(optionalPreParams) {
//			panic(errors.New("keygen.NewLocalParty expected 0 or 1 item in `optionalPreParams`"))
//		}
//		if !optionalPreParams[0].ValidateWithProof() {
//			panic(errors.New("`optionalPreParams` failed to validate; it might have been generated with an older version of tss-lib"))
//		}
//		data.LocalPreParams = optionalPreParams[0]
//	}
//
//	p2p, err := makeP2PHost(p2pParams.port, p2pParams.prvKey)
//	if err != nil{
//		panic(err)
//	}
//
//	p := &RemoteParty{
//		BaseParty: new(tss.BaseParty),
//		params:    params,
//		temp:      localTempData{},
//		data:      data,
//		out:       out,
//		in:        in,
//		end:       end,
//		p2p: p2p,
//	}
//	// msgs init，初始化message 存储空间。
//	p.temp.kgRound1Messages = make([]tss.ParsedMessage, partyCount)
//	p.temp.kgRound2Message1s = make([]tss.ParsedMessage, partyCount)
//	p.temp.kgRound2Message2s = make([]tss.ParsedMessage, partyCount)
//	p.temp.kgRound3Messages = make([]tss.ParsedMessage, partyCount)
//	// temp data init
//	p.temp.KGCs = make([]cmt.HashCommitment, partyCount) // KGC是什么??
//	return p
//}
//
//func (p *RemoteParty) FirstRound() tss.Round {
//	return newRound1(p.params, &p.data, &p.temp, p.out, p.end) // 输入params，savdata 空间，tempdata空间，out channels，end channel
//}
//
//func (p *RemoteParty) Start() *tss.Error {
//	return tss.BaseStart(p, TaskName)
//}
//
//func (p *RemoteParty) Update(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
//	return tss.BaseUpdate(p, msg, TaskName)
//}
//
//func (p *RemoteParty) UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (bool, *tss.Error) {
//	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
//	if err != nil {
//		return false, p.WrapError(err)
//	}
//	return p.Update(msg)
//}
//
//func (p *RemoteParty) ValidateMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
//	if ok, err := p.BaseParty.ValidateMessage(msg); !ok || err != nil {
//		return ok, err
//	}
//	// check that the message's "from index" will fit into the array
//	if maxFromIdx := p.params.PartyCount() - 1; maxFromIdx < msg.GetFrom().Index {
//		return false, p.WrapError(fmt.Errorf("received msg with a sender index too great (%d <= %d)",
//			p.params.PartyCount(), msg.GetFrom().Index), msg.GetFrom())
//	}
//	return true, nil
//}
//
//func (p *RemoteParty) StoreMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
//	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
//	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
//		return ok, err
//	}
//	fromPIdx := msg.GetFrom().Index
//
//	// switch/case is necessary to store any messages beyond current round
//	// this does not handle message replays. we expect the caller to apply replay and spoofing protection.
//	switch msg.Content().(type) {
//	case *KGRound1Message:
//		p.temp.kgRound1Messages[fromPIdx] = msg
//	case *KGRound2Message1:
//		p.temp.kgRound2Message1s[fromPIdx] = msg
//	case *KGRound2Message2:
//		p.temp.kgRound2Message2s[fromPIdx] = msg
//	case *KGRound3Message:
//		p.temp.kgRound3Messages[fromPIdx] = msg
//	default: // unrecognised message, just ignore!
//		common.Logger.Warningf("unrecognised message ignored: %v", msg)
//		return false, nil
//	}
//	return true, nil
//}
//
//func (p *RemoteParty) PartyID() *tss.PartyID {
//	return p.params.PartyID()
//}
//
//func (p *RemoteParty) String() string {
//	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
//}
//
//
//func makeP2PHost(port int, str string) (host.Host, error) {
//	var prvKey crypto.PrivKey
//	var err error
//	if str != "" {
//		bz, err := hex.DecodeString(str)
//		if err != nil {
//			return nil, err
//		}
//
//		prvKey, err = crypto.UnmarshalSecp256k1PrivateKey(bz)
//		if err != nil {
//			return nil, err
//		}
//
//	} else {
//		prvKey, _, err = crypto.GenerateKeyPairWithReader(crypto.Secp256k1, -1, rand.Reader)
//		if err != nil {
//			log.Println(err)
//			return nil, err
//		}
//	}
//
//	// 0.0.0.0 will listen on any interface device.
//	sourceMultiAddr, _ := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port))
//
//	// libp2p.New constructs a new libp2p Host.
//	// Other options can be added here.
//	return libp2p.New(
//		libp2p.ListenAddrs(sourceMultiAddr),
//		libp2p.Identity(prvKey),
//		libp2p.DisableRelay(),
//		libp2p.Security(tls.ID, tls.New),
//	)
//}