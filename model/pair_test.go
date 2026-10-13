package model

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/soypat/lfuzzo/check"
	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/udp"
	"github.com/soypat/lneto/x/xnet"
)

// FuzzStackPair drives two stacks with independent MTUs through a script of
// pings, TCP and UDP traffic and closes. Neither stack may panic, write past its
// MTU, egress a malformed frame, fail to settle or return an unexpected error.
// TCP writes that fit must be accepted until the connection is closed, and the
// TCP bytes read must be a prefix of those written. No retransmission timer
// runs, so a segment dropped for a full buffer is never resent and delivery of
// every byte is not required. Echo requests may exceed the receiver's MTU.
//
//	go test -run XXX -fuzz 'FuzzStackPair$' -fuzztime 5m ./model/
func FuzzStackPair(f *testing.F) {
	f.Add(int64(1), uint16(1500), uint16(1500), []byte{0, 100, 2, 50, 3, 0, 4, 10, 5, 0})
	f.Add(int64(2), uint16(1500), uint16(576), []byte{0, 255, 1, 255, 2, 255, 3, 0})
	f.Add(int64(3), uint16(300), uint16(1500), []byte{2, 200, 2, 200, 3, 0, 6, 0, 3, 0})
	f.Add(int64(0x0f0f), uint16(1500-256), uint16(576-256), []byte{0, 100})        // Echo reply above the MTU, lneto#236.
	f.Add(int64(0x0f0f), uint16(1500-256), uint16(1500-256), []byte{0, 10, 1, 10}) // Echo replies both ways.
	f.Fuzz(func(t *testing.T, seed int64, mtu1, mtu2 uint16, script []byte) {
		if len(script) > 64 {
			script = script[:64]
		}
		testStackPair(t, seed, mtu1, mtu2, script)
	})
}

func backoffNone(uint) time.Duration { return 0 }

func testStackPair(t *testing.T, seed int64, mtu1, mtu2 uint16, script []byte) {
	const minMTU = 256
	clamp := func(m uint16) uint16 { return minMTU + m%(ethernet.MaxMTU-minMTU+1) }
	var stacks [2]xnet.StackAsync
	for i, mtu := range []uint16{clamp(mtu1), clamp(mtu2)} {
		id := byte(i + 1)
		randSeed := seed + int64(i)
		if randSeed == 0 {
			randSeed = 1 // Zero is invalid without an entropy source.
		}
		err := stacks[i].Reset(xnet.StackConfig{
			Hostname:          "pair-" + string('0'+id),
			RandSeed:          randSeed,
			StaticAddress4:    [4]byte{10, 0, 0, id},
			HardwareAddress:   [6]byte{0xbe, 0xef, 0, 0, 0, id},
			MTU:               mtu,
			MaxActiveTCPPorts: 1,
			MaxActiveUDPPorts: 1,
			ICMPQueueLimit:    1 + int(uint64(seed)>>(8*i)%16),
			Nanotime:          func() int64 { return 1 },
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := stacks[i].EnableICMP(true); err != nil {
			t.Fatal(err)
		}
	}
	s1, s2 := &stacks[0], &stacks[1]
	s1.SetGatewayHardwareAddr(s2.HardwareAddr())
	s2.SetGatewayHardwareAddr(s1.HardwareAddr())
	addr1, addr2 := netip.AddrFrom4(s1.Addr4()), netip.AddrFrom4(s2.Addr4())

	var c1, c2 tcp.Conn
	for _, c := range []*tcp.Conn{&c1, &c2} {
		err := c.Configure(tcp.ConnConfig{RxBuf: make([]byte, 512), TxBuf: make([]byte, 512), TxPacketQueueSize: 4, RWBackoff: backoffNone})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := s2.ListenTCP4(&c2, 80); err != nil {
		t.Fatal(err)
	}
	if err := s1.DialTCP(&c1, 1337, netip.AddrPortFrom(addr2, 80)); err != nil {
		t.Fatal(err)
	}
	var u1, u2 udp.Conn
	for i, u := range []*udp.Conn{&u1, &u2} {
		err := u.Configure(udp.ConnConfig{RxBuf: make([]byte, 512), TxBuf: make([]byte, 512), RxQueueSize: 2, TxQueueSize: 2, RWBackoff: backoffNone, MTU: uint16(stacks[i].MTU())})
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := s1.DialUDP(&u1, 5000, netip.AddrPortFrom(addr2, 5001)); err != nil {
		t.Fatal(err)
	}
	if err := s2.DialUDP(&u2, 5001, netip.AddrPortFrom(addr1, 5000)); err != nil {
		t.Fatal(err)
	}

	deliver := func(step int, dst *xnet.StackAsync, frame []byte) {
		err := dst.IngressEthernet(frame)
		dropped := err == lneto.ErrPacketDrop || err == lneto.ErrExhausted || err == lneto.ErrBufferFull
		if err != nil && !dropped {
			t.Fatalf("step %d: %s ingress: %v", step, dst.Hostname(), err)
		}
	}
	pump := func(step int) {
		for range 32 {
			moved := false
			for _, dir := range [2][2]*xnet.StackAsync{{s1, s2}, {s2, s1}} {
				// Exactly one frame of the sender's MTU with no spare capacity,
				// so a write past the MTU panics instead of going unnoticed.
				frame := make([]byte, dir[0].MTU()+ethernet.MaxOverheadSize)
				frame = frame[:len(frame):len(frame)]
				n, err := dir[0].EgressEthernet(frame)
				if err != nil {
					t.Fatalf("step %d: %s egress: %v", step, dir[0].Hostname(), err)
				} else if n == 0 {
					continue
				}
				check.Egress(t, frame[:n], dir[0].MTU())
				deliver(step, dir[1], frame[:n])
				moved = true
			}
			if !moved {
				return
			}
		}
		t.Fatalf("step %d: traffic did not settle", step)
	}
	var written, read []byte
	var serial byte
	closed := false
	buf := make([]byte, ethernet.MaxFrameLength)
	readTCP := func(step int) {
		if c2.BufferedInput() == 0 {
			return // Read blocks.
		}
		n, _ := c2.Read(buf)
		read = append(read, buf[:n]...)
		if !bytes.HasPrefix(written, read) {
			t.Fatalf("step %d: TCP read %x, not a prefix of written %x", step, read, written)
		}
	}
	pump(-1)
	for i := 0; i+1 < len(script); i += 2 {
		action, arg := script[i]%7, int(script[i+1])
		switch action {
		case 0, 1: // Echo request of up to the sender's MTU.
			src, dst := s1, s2
			if action == 1 {
				src, dst = s2, s1
			}
			deliver(i, dst, echoRequest(src, dst, arg*(src.MTU()-28)/255, uint16(i)))
		case 2: // TCP write.
			data := make([]byte, min(1+arg, c1.FreeOutput()))
			for k := range data {
				data[k] = serial
				serial++
			}
			n, err := c1.Write(data)
			if !closed && (err != nil || n != len(data)) {
				t.Fatalf("step %d: TCP write of %d octets that fit: %d, %v", i, len(data), n, err)
			}
			written = append(written, data[:n]...)
		case 3:
			readTCP(i)
		case 4: // UDP write below either MTU. A full queue refuses it, so its error is not checked.
			u1.Write(make([]byte, 1+arg%200))
		case 5:
			if u2.BufferedInput() > 0 {
				u2.Read(buf)
			}
		case 6:
			if err := c1.Close(); err != nil && !closed {
				t.Fatalf("step %d: close: %v", i, err)
			}
			closed = true
		}
		pump(i)
	}
	pump(len(script))
	readTCP(len(script))
}

// echoRequest returns an ICMP echo request from src to dst with size octets of
// data, in a frame of exact capacity.
func echoRequest(src, dst *xnet.StackAsync, size int, seq uint16) []byte {
	frame := make([]byte, 14+20+8+size)
	dstHW, srcHW := dst.HardwareAddr(), src.HardwareAddr()
	copy(frame[0:], dstHW[:])
	copy(frame[6:], srcHW[:])
	binary.BigEndian.PutUint16(frame[12:], 0x0800)
	ip := frame[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)))
	ip[8], ip[9] = 64, 1
	srcAddr, dstAddr := src.Addr4(), dst.Addr4()
	copy(ip[12:], srcAddr[:])
	copy(ip[16:], dstAddr[:])
	var c lneto.CRC791
	c.WriteEven(ip[:20])
	binary.BigEndian.PutUint16(ip[10:], c.Sum16())
	icmp := ip[20:]
	icmp[0] = 8 // Echo request.
	binary.BigEndian.PutUint16(icmp[4:], 0x1fe)
	binary.BigEndian.PutUint16(icmp[6:], seq)
	for k := range icmp[8:] {
		icmp[8+k] = byte(k)
	}
	var ic lneto.CRC791
	binary.BigEndian.PutUint16(icmp[2:], ic.PayloadSum16(icmp))
	return frame
}
