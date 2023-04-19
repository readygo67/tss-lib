package keygen

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

const (
	LengthHeader        = 4 // LengthHeader represent how many bytes we used as header
	TimeoutReadPayload  = time.Second * 10
	TimeoutWritePayload = time.Second * 10
	MaxPayload          = 20000000 // 20M
)

// applyDeadline will be true , and only disable it when we are doing test
// the reason being the p2p network , mocknet, mock stream doesn't support SetReadDeadline ,SetWriteDeadline feature
var ApplyDeadline = false

func TestUnMarshal(t *testing.T) {
	str := "7b22436f6e74656e74223a2268656c6c6f222c2253656e6465724944223a2231365569753248416d4e5656385062744750724539554d50414c396631617231714174726d50776d543761705a395239616d65794d222c2248617368223a2231346339623361333864643064336335666636376665626537383931303130656330393532376261383566623330656638336639633363323137646363656634227d"

	bz, err := hex.DecodeString(str)
	require.NoError(t, err)
	fmt.Printf("%s", bz)
}

func TestGetPubkeyFromID(t *testing.T) {
	id, err := peer.Decode("16Uiu2HAmNVV8PbtGPrE9UMPAL9f1ar1qAtrmPwmT7apZ9R9ameyM")
	require.NoError(t, err)

	pubKey, err := id.ExtractPublicKey()
	require.NoError(t, err)

	bz, err := pubKey.Raw()
	require.NoError(t, err)

	fmt.Printf("%v\n", hex.EncodeToString(bz))
}

// 模拟建立4个节点全连接, 向连接中发消息。
func TestMultiPortWithHash(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	/*
		/ip4/127.0.0.1/tcp/20000/p2p/16Uiu2HAmNVV8PbtGPrE9UMPAL9f1ar1qAtrmPwmT7apZ9R9ameyM
		/ip4/127.0.0.1/tcp/20001/p2p/16Uiu2HAm75aah4bmfpXSUp6WQN3XpUrn3mX6Lhtq4q4CA3DtTyW1
		/ip4/127.0.0.1/tcp/20002/p2p/16Uiu2HAmRfFzyAN74ZBJKcu2uvSp92qeC1wJn8m6kFNZoPCXoBEz
		/ip4/127.0.0.1/tcp/20003/p2p/16Uiu2HAkxNnKxpc2kcXbZeSftuSfH7PWBg8a1DzCoQbUSfoYshyi
	*/
	prvStrs := []string{
		"659c9dd58b8464676d95ca358c40f0eba281e5344e1bba336a7df8c10a8e4edc",
		"37db260492a73cda835d297669db8449e1648d8126dfa4885ea636ec59da7d4c",
		"00ec12a6bac08410276e3d86760eab997d153dbde1a7eeea3872eaf8ca5e2d1a",
		"8677d9720accbe178088777f3d41bfe653b9c5348eb6e8c78333e708a5f9ceef",
	}
	ports := []int{20000, 20001, 20002, 20003}
	hosts := make([]host.Host, 0)
	conns := make([][]network.Stream, 0)
	for i, p := range ports {
		h, err := makeHost(p, prvStrs[i])
		if err != nil {
			log.Println(err)
			return
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
				return
			}
			temp = append(temp, conn)
		}
		conns = append(conns, temp)
	}

	h1Conns := conns[0][:]

	// h1 send message to others
	for _, conn := range h1Conns {
		// writeData1(conn, "hello")
		writeDataWithHash(conn, "hello")
	}

	time.Sleep(10 * time.Second)

	for _, conn := range h1Conns {
		writeDataWithHash(conn, "nice to see you, miss you so much")
	}

	// Wait forever
	select {}
}

// ChatMessage gets converted to/from JSON and sent in the body of pubsub messages.
type Message struct {
	Content string
	Hash    string
}

func WriteStream(msg []byte, stream network.Stream) error {
	length := uint32(len(msg))
	lengthBytes := make([]byte, LengthHeader)
	binary.LittleEndian.PutUint32(lengthBytes, length)
	if ApplyDeadline {
		if err := stream.SetWriteDeadline(time.Now().Add(TimeoutWritePayload)); nil != err {
			if errReset := stream.Reset(); errReset != nil {
				return errReset
			}
			return err
		}
	}
	w := bufio.NewWriter(stream)
	n, err := w.Write(lengthBytes)
	if n != LengthHeader || err != nil {
		return fmt.Errorf("fail to write head: %w", err)
	}
	n, err = w.Write(msg)
	if err != nil {
		return err
	}
	if uint32(n) != length {
		return fmt.Errorf("short write, we would like to write: %d, however we only write: %d", length, n)
	}
	err = w.Flush()
	if err != nil {
		return fmt.Errorf("fail to flush stream: %w", err)
	}
	return nil
}

func ReadStream(stream network.Stream) ([]byte, error) {
	if ApplyDeadline {
		if err := stream.SetReadDeadline(time.Now().Add(TimeoutReadPayload)); nil != err {
			if errReset := stream.Reset(); errReset != nil {
				return nil, errReset
			}
			return nil, err
		}
	}
	streamReader := bufio.NewReader(stream)
	lengthBytes := make([]byte, LengthHeader)
	n, err := io.ReadFull(streamReader, lengthBytes)
	if n != LengthHeader || err != nil {
		return nil, fmt.Errorf("error in read the message head %w", err)
	}
	length := binary.LittleEndian.Uint32(lengthBytes)
	if length > MaxPayload {
		return nil, fmt.Errorf("payload length:%d exceed max payload length:%d", length, MaxPayload)
	}
	dataBuf := make([]byte, length)
	n, err = io.ReadFull(streamReader, dataBuf)
	if uint32(n) != length || err != nil {
		return nil, fmt.Errorf("short read err(%w), we would like to read: %d, however we only read: %d", err, length, n)
	}
	return dataBuf, nil
}

func writeDataWithHash(s network.Stream, content string) error {
	hash := sha256.Sum256([]byte(content))
	msg := Message{
		Content: content,
		Hash:    hex.EncodeToString(hash[:]),
	}

	bz, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	return WriteStream(bz, s)
}

func handleStreamWithHash(s network.Stream) {
	log.Println("Got a new stream!")

	// Create a buffer stream for non blocking read and write.
	rw := bufio.NewReadWriter(bufio.NewReader(s), bufio.NewWriter(s))

	go readDataWithHash(s, rw) // 使用readData 从连接中读取数据。
	// stream 's' will stay open until you close it (or the other side closes it).
}

func readDataWithHash(s network.Stream, rw *bufio.ReadWriter) {
	for {
		bz, err := ReadStream(s)
		var msg Message
		err = json.Unmarshal(bz, &msg)
		if err != nil {
			log.Printf("err:%v", err)
		}

		hash := sha256.Sum256([]byte(msg.Content))
		if hex.EncodeToString(hash[:]) != msg.Hash {
			log.Println("mismatch hash")
		}

		fmt.Printf("from:%v, content:\x1b[32m%s\x1b[0m>\n", s.Conn().RemotePeer().String(), msg.Content)
	}
}
