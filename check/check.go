// Package check holds oracles shared by fuzz strategies: assertions that
// egressed frames are well formed, independent of how inputs were generated.
package check

import (
	"encoding/binary"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/x/xnet"
)

// Drain egresses into a poisoned buffer, validates each frame with [Egress]
// and appends emitted frames to out.
func Drain(t testing.TB, s *xnet.StackAsync, mtu int, out *[]byte) {
	t.Helper()
	buf := make([]byte, mtu+14)
	for range 4 {
		for i := range buf {
			buf[i] = 0xa5 // Poison: catches fields left unwritten.
		}
		n, _ := s.EgressEthernet(buf)
		if n > 0 {
			Egress(t, buf[:n], mtu)
			*out = append(*out, buf[:n]...)
		}
	}
}

// Egress asserts an emitted frame is well formed: size, lengths and checksums.
func Egress(t testing.TB, f []byte, mtu int) {
	t.Helper()
	if len(f) > mtu+14 {
		t.Fatalf("egress frame %d > mtu+14 %d", len(f), mtu+14)
	} else if len(f) < 14 {
		t.Fatalf("runt egress %d", len(f))
	}
	ip := f[14:]
	switch et := binary.BigEndian.Uint16(f[12:]); et {
	case 0x0800:
		if len(ip) < 20 || ip[0]>>4 != 4 {
			t.Fatalf("bad ipv4 header % x", ip[:min(20, len(ip))])
		}
		ihl := int(ip[0]&0xf) * 4
		tl := int(binary.BigEndian.Uint16(ip[2:]))
		if ihl < 20 || tl < ihl || tl > len(ip) {
			t.Fatalf("ipv4 bad lengths ihl=%d tl=%d have=%d", ihl, tl, len(ip))
		}
		if len(f) > 60 && tl != len(ip) { // Short frames may be padded to 60.
			t.Fatalf("ipv4 totalLen %d != emitted %d", tl, len(ip))
		}
		var c lneto.CRC791
		c.WriteEven(ip[:ihl])
		if c.Sum16() != 0 {
			t.Fatal("ipv4 header crc bad")
		}
		Transport(t, ip[9], ip[12:20], ip[ihl:tl])
	case 0x86dd:
		if len(ip) < 40 {
			t.Fatal("short ipv6")
		}
		pl := int(binary.BigEndian.Uint16(ip[4:]))
		if 40+pl > len(ip) || (len(f) > 60 && 40+pl != len(ip)) {
			t.Fatalf("ipv6 payload len %d vs emitted %d", pl, len(ip)-40)
		}
		Transport(t, ip[6], ip[8:40], ip[40:40+pl])
	case 0x0806:
		if len(ip) < 28 {
			t.Fatal("short arp")
		}
	default:
		t.Fatalf("unexpected ethertype %#x", et)
	}
}

// Transport asserts transport length and checksum. addrs holds the IP source and
// destination addresses used for the pseudo-header.
func Transport(t testing.TB, proto uint8, addrs, tp []byte) {
	t.Helper()
	var c lneto.CRC791
	switch proto {
	case 17:
		if len(tp) < 8 {
			t.Fatalf("short udp %d", len(tp))
		}
		if ul := int(binary.BigEndian.Uint16(tp[4:])); ul != len(tp) {
			t.Fatalf("udp length %d != ip payload %d", ul, len(tp))
		}
		if binary.BigEndian.Uint16(tp[6:]) == 0 && len(addrs) == 8 {
			return // Checksum optional in IPv4.
		}
		c.WriteEven(addrs)
		c.AddUint16(uint16(len(tp)))
		c.AddUint16(17)
		if c.PayloadSum16(tp) != 0 {
			t.Fatal("udp crc bad")
		}
	case 6:
		if len(tp) < 20 {
			t.Fatal("short tcp")
		}
		c.WriteEven(addrs)
		c.AddUint16(uint16(len(tp)))
		c.AddUint16(6)
		if c.PayloadSum16(tp) != 0 {
			t.Fatal("tcp crc bad")
		}
	case 1:
		if c.PayloadSum16(tp) != 0 {
			t.Fatal("icmp crc bad")
		}
	case 58:
		c.WriteEven(addrs)
		c.AddUint16(uint16(len(tp)))
		c.AddUint16(58)
		if c.PayloadSum16(tp) != 0 {
			t.Fatal("icmpv6 crc bad")
		}
	}
}
