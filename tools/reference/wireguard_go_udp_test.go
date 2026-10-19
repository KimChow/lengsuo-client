// Test-only adapter for the pinned official wireguard-go core; no system TUN.
// Copy into reference module/device, then go test -c ./device.
//
// Roles (select with -role, default "responder"):
//   - responder:  official core consumes an initiation, answers and exchanges
//     transport with a Rust initiator. Behavior unchanged from the original.
//   - initiator:  official core creates an initiation, consumes the response and
//     exchanges transport with a Rust responder (handles cookie replies too).
package device

import (
	"bytes"
	"encoding/binary"
	"flag"
	"net"
	"os"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

var role = flag.String("role", "responder", "noise role for the reference adapter: responder|initiator")

func TestLengsuoUDPReference(t *testing.T) {
	if *role == "initiator" {
		t.Skip("role is initiator")
	}
	addr, err := net.ResolveUDPAddr("udp4", os.Getenv("LENGSUO_WG_CLIENT"))
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	if err = socket.SetDeadline(time.Now().Add(8*time.Second)); err != nil {
		t.Fatal(err)
	}
	dev := NewDevice(tuntest.NewChannelTUN().TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, ""))
	defer dev.Close()
	var server, client NoisePrivateKey
	for i := range server {
		server[i] = 0x22
		client[i] = 0x11
	}
	if err = dev.SetPrivateKey(server); err != nil {
		t.Fatal(err)
	}
	peer, err := dev.NewPeer(client.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("LENGSUO_WG_PSK") == "1" {
		for i := range peer.handshake.presharedKey {
			peer.handshake.presharedKey[i] = 0x33
		}
	}
	peer.Start()
	if _, err = socket.Write([]byte("wireguard-reference-ready")); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 2048)
	n, err := socket.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	var initiation MessageInitiation
	if err = initiation.unmarshal(buffer[:n]); err != nil {
		t.Fatal(err)
	}
	if !dev.cookieChecker.CheckMAC1(buffer[:n]) {
		t.Fatal("initiation MAC1 rejected")
	}
	if dev.ConsumeMessageInitiation(&initiation) != peer {
		t.Fatal("initiation rejected")
	}
	response, err := dev.CreateMessageResponse(peer)
	if err != nil {
		t.Fatal(err)
	}
	responseWire := make([]byte, MessageResponseSize)
	if err = response.marshal(responseWire); err != nil {
		t.Fatal(err)
	}
	peer.cookieGenerator.AddMacs(responseWire)
	if _, err = socket.Write(responseWire); err != nil {
		t.Fatal(err)
	}
	if err = peer.BeginSymmetricSession(); err != nil {
		t.Fatal(err)
	}
	keypair := peer.keypairs.next.Load()
	if keypair == nil {
		t.Fatal("responder has no next keypair")
	}
	n, err = socket.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if n < 32 || binary.LittleEndian.Uint32(buffer[:4]) != MessageTransportType {
		t.Fatal("bad transport")
	}
	if binary.LittleEndian.Uint32(buffer[4:8]) != response.Sender {
		t.Fatal("receiver index mismatch")
	}
	counter := binary.LittleEndian.Uint64(buffer[8:16])
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	plain, err := keypair.receive.Open(nil, nonce[:], buffer[16:n], nil)
	if err != nil {
		t.Fatal("Rust transport authentication failed")
	}
	if !keypair.replayFilter.ValidateCounter(counter, RejectAfterMessages) {
		t.Fatal("counter rejected")
	}
	if keypair.replayFilter.ValidateCounter(counter, RejectAfterMessages) {
		t.Fatal("duplicate accepted")
	}
	expected := []byte("rust-go-payload!")
	if !bytes.Equal(plain, expected) {
		t.Fatal("Rust transport payload mismatch")
	}
	reply := make([]byte, 16)
	binary.LittleEndian.PutUint32(reply, MessageTransportType)
	binary.LittleEndian.PutUint32(reply[4:], initiation.Sender)
	reply = keypair.send.Seal(reply, make([]byte, 12), []byte("go-rust-payload!"), nil)
	if _, err = socket.Write(reply); err != nil {
		t.Fatal(err)
	}
	t.Log("official Noise responder accepted initiation; UDP transport passed both directions; replay rejected")
}

func TestLengsuoUDPReferenceInitiator(t *testing.T) {
	if *role != "initiator" {
		t.Skip("role is responder")
	}
	addr, err := net.ResolveUDPAddr("udp4", os.Getenv("LENGSUO_WG_CLIENT"))
	if err != nil {
		t.Fatal(err)
	}
	socket, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	if err = socket.SetDeadline(time.Now().Add(8*time.Second)); err != nil {
		t.Fatal(err)
	}
	dev := NewDevice(tuntest.NewChannelTUN().TUN(), conn.NewDefaultBind(), NewLogger(LogLevelError, ""))
	defer dev.Close()
	// Go 是发起方：本端用 0x11 假私钥（仅测试），对端为持有 0x22 假私钥的 Rust 响应方。
	var server, client NoisePrivateKey
	for i := range server {
		server[i] = 0x22
		client[i] = 0x11
	}
	if err = dev.SetPrivateKey(client); err != nil {
		t.Fatal(err)
	}
	peer, err := dev.NewPeer(server.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("LENGSUO_WG_PSK") == "1" {
		for i := range peer.handshake.presharedKey {
			peer.handshake.presharedKey[i] = 0x33
		}
	}
	peer.Start()
	if _, err = socket.Write([]byte("wireguard-reference-ready")); err != nil {
		t.Fatal(err)
	}

	initiation, err := dev.CreateMessageInitiation(peer)
	if err != nil {
		t.Fatal(err)
	}
	initiationWire := make([]byte, MessageInitiationSize)
	if err = initiation.marshal(initiationWire); err != nil {
		t.Fatal(err)
	}
	peer.cookieGenerator.AddMacs(initiationWire)
	if _, err = socket.Write(initiationWire); err != nil {
		t.Fatal(err)
	}

	buffer := make([]byte, 2048)
	n, err := socket.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	// Rust 响应方在过载/要求 MAC2 时会先回 cookie reply（type 3）：消费后带有效
	// MAC2 重新发起一次 initiation。
	if binary.LittleEndian.Uint32(buffer[:4]) == MessageCookieReplyType {
		var reply MessageCookieReply
		if err = reply.unmarshal(buffer[:n]); err != nil {
			t.Fatal(err)
		}
		if !peer.cookieGenerator.ConsumeReply(&reply) {
			t.Fatal("cookie reply rejected")
		}
		initiation, err = dev.CreateMessageInitiation(peer)
		if err != nil {
			t.Fatal(err)
		}
		if err = initiation.marshal(initiationWire); err != nil {
			t.Fatal(err)
		}
		peer.cookieGenerator.AddMacs(initiationWire)
		if _, err = socket.Write(initiationWire); err != nil {
			t.Fatal(err)
		}
		n, err = socket.Read(buffer)
		if err != nil {
			t.Fatal(err)
		}
	}
	var response MessageResponse
	if err = response.unmarshal(buffer[:n]); err != nil {
		t.Fatal(err)
	}
	if !dev.cookieChecker.CheckMAC1(buffer[:n]) {
		t.Fatal("response MAC1 rejected")
	}
	if dev.ConsumeMessageResponse(&response) != peer {
		t.Fatal("response rejected")
	}
	if err = peer.BeginSymmetricSession(); err != nil {
		t.Fatal(err)
	}
	keypair := peer.keypairs.current
	if keypair == nil {
		t.Fatal("initiator has no current keypair")
	}

	// 发送运输载荷，并重发一次相同包供 Rust 响应方断言重放被拒。
	transport := make([]byte, 16)
	binary.LittleEndian.PutUint32(transport, MessageTransportType)
	binary.LittleEndian.PutUint32(transport[4:], response.Sender)
	transport = keypair.send.Seal(transport, make([]byte, 12), []byte("go-init-payload!"), nil)
	if _, err = socket.Write(transport); err != nil {
		t.Fatal(err)
	}
	if _, err = socket.Write(transport); err != nil {
		t.Fatal(err)
	}

	n, err = socket.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if n < 32 || binary.LittleEndian.Uint32(buffer[:4]) != MessageTransportType {
		t.Fatal("bad transport")
	}
	if binary.LittleEndian.Uint32(buffer[4:8]) != initiation.Sender {
		t.Fatal("receiver index mismatch")
	}
	counter := binary.LittleEndian.Uint64(buffer[8:16])
	var nonce [12]byte
	binary.LittleEndian.PutUint64(nonce[4:], counter)
	plain, err := keypair.receive.Open(nil, nonce[:], buffer[16:n], nil)
	if err != nil {
		t.Fatal("Rust transport authentication failed")
	}
	if !keypair.replayFilter.ValidateCounter(counter, RejectAfterMessages) {
		t.Fatal("counter rejected")
	}
	if keypair.replayFilter.ValidateCounter(counter, RejectAfterMessages) {
		t.Fatal("duplicate accepted")
	}
	if !bytes.Equal(plain, []byte("rust-resp-payload!")) {
		t.Fatal("Rust transport payload mismatch")
	}
	t.Log("official Noise initiator completed handshake; msg2/msg4 verified; UDP transport passed both directions; replay handled")
}