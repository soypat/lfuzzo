package synth

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/dns"
	"github.com/soypat/lneto/udp"
	"github.com/soypat/lneto/x/xnet"
)

// Structure-aware ingress fuzzers. Packets are built by buildPkt so they pass
// IP/UDP/ICMP checksums, target live service ports and carry the DHCP xid and
// DNS txid seen on egress, reaching deep parser code instead of dying at CRC checks.
//
//	go test -run XXX -fuzz 'FuzzIngress$' -fuzztime 5m ./synth/
//	go test -run XXX -fuzz 'FuzzIngressMulti$' -fuzztime 5m ./synth/

var (
	fzMAC  = [6]byte{2, 0, 0, 0, 0, 1}
	fzPeer = [6]byte{2, 0, 0, 0, 0, 2}
	fzIP4  = [4]byte{10, 0, 0, 1}
	fzPIP4 = [4]byte{10, 0, 0, 2}
	fzIP6  = [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 1}
	fzPIP6 = [16]byte{0x20, 0x01, 0x0d, 0xb8, 15: 2}
)

// Transaction IDs captured from the stack's own egress so fuzzed replies are accepted.
var (
	fzXID     uint32
	fzTXID    uint16
	fzDNSPort uint16
	fzNTPPort uint16
)

var fzProtos = [...]uint8{17, 6, 1, 58} // UDP, TCP, ICMPv4, ICMPv6.

func newFuzzStack(t testing.TB) (*xnet.StackAsync, []uint16) { return newFuzzStackCfg(t, 1500, 4) }

// newFuzzStackCfg returns a stack with every service active: DHCP, DNS and NTP
// in flight, ICMPv4/v6, NDP, ARP, passive peers and a UDP listener on port 53.
func newFuzzStackCfg(t testing.TB, mtu uint16, icmpq int) (*xnet.StackAsync, []uint16) {
	s := new(xnet.StackAsync)
	err := s.Reset(xnet.StackConfig{
		Hostname: "fz-1", RandSeed: 1, StaticAddress4: fzIP4, StaticAddress6: fzIP6,
		IPv6Stack: xnet.DefaultStack6(), HardwareAddress: fzMAC, MTU: mtu, ICMPQueueLimit: icmpq,
		MaxActiveTCPPorts: 4, MaxActiveUDPPorts: 4, PassivePeers: 4,
		AcceptMulticast: true, AcceptIPv4Broadcast: true,
		DNSServer: netip.AddrFrom4(fzPIP4),
	})
	if err != nil {
		t.Fatal(err)
	}
	s.EnableICMP(true)
	s.SetGatewayHardwareAddr(fzPeer)
	s.SetSubnet4(fzIP4, 24)
	var pc udp.PacketConn
	if pc.Configure(udp.PacketConnConfig{RxBuf: make([]byte, 4096), TxBuf: make([]byte, 4096), RxQueueSize: 4, TxQueueSize: 4}) == nil &&
		pc.Open(netip.AddrPortFrom(netip.Addr{}, 53)) == nil {
		s.RegisterListenerUDP(&pc)
	}
	s.StartDHCPv4Request([4]byte{})
	s.StartLookupIP(dns.MustNewName("example.com"))
	s.StartNTP(netip.AddrFrom4(fzPIP4))
	// Client ports are not exported: learn them from egress source ports.
	fzDNSPort, fzNTPPort = 0, 0
	buf := make([]byte, int(mtu)+14)
	for range 8 {
		n, _ := s.EgressEthernet(buf)
		if n < 14+20+8 || binary.BigEndian.Uint16(buf[12:]) != 0x0800 || buf[14+9] != 17 {
			continue
		}
		udpl := buf[14+20 : n]
		switch binary.BigEndian.Uint16(udpl[2:]) {
		case 67:
			fzXID = binary.BigEndian.Uint32(udpl[8+4:])
		case 53:
			fzTXID = binary.BigEndian.Uint16(udpl[8:])
			fzDNSPort = binary.BigEndian.Uint16(udpl[0:])
		case 123:
			fzNTPPort = binary.BigEndian.Uint16(udpl[0:])
		}
	}
	ports := []uint16{0, 68, fzDNSPort, fzNTPPort, 53, 80}
	return s, ports
}

func crcIP(pseudo [][]byte, plen int, proto uint8, b []byte) uint16 {
	var c lneto.CRC791
	for _, p := range pseudo {
		c.WriteEven(p)
	}
	c.AddUint16(uint16(plen))
	c.AddUint16(uint16(proto))
	return c.PayloadSum16(b)
}

// fixTransport patches ports, IDs, lengths and checksums of a fuzzed transport payload.
func fixTransport(proto uint8, tp []byte, port uint16, src, dst []byte) {
	switch proto {
	case 17:
		if len(tp) < 8 {
			return
		}
		if port != 0 {
			binary.BigEndian.PutUint16(tp[2:], port)
		}
		switch port {
		case 68:
			if len(tp) >= 8+8 {
				binary.BigEndian.PutUint32(tp[8+4:], fzXID)
			}
			if len(tp) >= 8+240 {
				binary.BigEndian.PutUint32(tp[8+236:], 0x63825363)
			}
		case fzDNSPort:
			if len(tp) >= 8+4 {
				binary.BigEndian.PutUint16(tp[8:], fzTXID)
				tp[8+2] |= 0x80
			}
		}
		binary.BigEndian.PutUint16(tp[4:], uint16(len(tp)))
		binary.BigEndian.PutUint16(tp[6:], 0)
		binary.BigEndian.PutUint16(tp[6:], crcIP([][]byte{src, dst}, len(tp), proto, tp))
	case 6:
		if len(tp) < 20 {
			return
		}
		if port != 0 {
			binary.BigEndian.PutUint16(tp[2:], port)
		}
		binary.BigEndian.PutUint16(tp[16:], 0)
		binary.BigEndian.PutUint16(tp[16:], crcIP([][]byte{src, dst}, len(tp), proto, tp))
	case 1:
		if len(tp) < 4 {
			return
		}
		binary.BigEndian.PutUint16(tp[2:], 0)
		var c lneto.CRC791
		binary.BigEndian.PutUint16(tp[2:], c.PayloadSum16(tp))
	case 58:
		if len(tp) < 4 {
			return
		}
		binary.BigEndian.PutUint16(tp[2:], 0)
		binary.BigEndian.PutUint16(tp[2:], crcIP([][]byte{src, dst}, len(tp), proto, tp))
	}
}

// buildPkt turns fuzz bytes into an ethernet frame with exact capacity.
// mode%3: 0=IPv4, 1=IPv6, 2=raw ethernet. sel low nibble picks the port, high nibble the protocol.
func buildPkt(mode, sel uint8, data []byte, ports []uint16) []byte {
	port := ports[int(sel&0xf)%len(ports)]
	proto := fzProtos[int(sel>>4)%len(fzProtos)]
	var pkt []byte
	switch mode % 3 {
	case 0:
		pkt = make([]byte, 14+20+len(data))
		ip := pkt[14:]
		binary.BigEndian.PutUint16(pkt[12:], 0x0800)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)))
		ip[8], ip[9] = 64, proto
		copy(ip[12:], fzPIP4[:])
		copy(ip[16:], fzIP4[:])
		var c lneto.CRC791
		c.WriteEven(ip[:20])
		binary.BigEndian.PutUint16(ip[10:], c.Sum16())
		copy(ip[20:], data)
		fixTransport(proto, ip[20:], port, ip[12:16], ip[16:20])
	case 1:
		pkt = make([]byte, 14+40+len(data))
		ip := pkt[14:]
		binary.BigEndian.PutUint16(pkt[12:], 0x86dd)
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:], uint16(len(data)))
		ip[6], ip[7] = proto, 255
		copy(ip[8:], fzPIP6[:])
		copy(ip[24:], fzIP6[:])
		copy(ip[40:], data)
		fixTransport(proto, ip[40:], port, ip[8:24], ip[24:40])
	case 2:
		pkt = append([]byte(nil), data...)
	}
	if mode%3 != 2 {
		copy(pkt[0:], fzMAC[:])
		copy(pkt[6:], fzPeer[:])
	}
	return pkt[:len(pkt):len(pkt)] // Exact cap: reads past len panic instead of hiding.
}

// splitStream decodes [mode, sel, len/8, data...] records into packets.
func splitStream(stream []byte, ports []uint16) (pkts [][]byte) {
	for len(stream) >= 3 {
		mode, sel, l := stream[0], stream[1], int(stream[2])*8
		stream = stream[3:]
		l = min(l, len(stream))
		pkts = append(pkts, buildPkt(mode, sel, stream[:l], ports))
		stream = stream[l:]
	}
	return pkts
}

func addStreamSeeds(f *testing.F) {
	f.Add(uint8(0), uint8(4), []byte{0, 0x20, 12, 8, 0, 0, 0, 0, 1, 0, 1, 'h', 'i', 'y', 'o'})
	f.Add(uint8(200), uint8(2), []byte{1, 0x30, 32, 135, 0, 0, 0, 0, 0, 0, 0, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 2, 0, 0, 0, 0, 2})
	f.Add(uint8(0), uint8(0), []byte{0, 0x01, 40, 0, 67, 0, 0, 0, 0, 0, 0, 2, 1, 6, 0})
	f.Add(uint8(0), uint8(0), []byte{0, 0x05, 3, 0, 53, 0, 53, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0})
}

// FuzzIngress: one crafted packet into a fully active stack, then egress and result readout.
func FuzzIngress(f *testing.F) {
	f.Add(uint8(0), uint8(0x01), []byte{0, 67, 0, 0, 0, 0, 0, 0, 2, 1, 6, 0})
	f.Add(uint8(0), uint8(0x02), []byte{0, 53, 0, 0, 0, 0, 0, 0, 0, 0, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0})
	f.Add(uint8(0), uint8(0x03), make([]byte, 56))
	f.Add(uint8(0), uint8(0x20), []byte{8, 0, 0, 0, 0, 1, 0, 1, 'h', 'i'})
	f.Add(uint8(1), uint8(0x30), []byte{135, 0, 0, 0, 0, 0, 0, 0, 0x20, 0x01, 0x0d, 0xb8, 15: 0, 1})
	f.Add(uint8(1), uint8(0x04), []byte{0, 1, 0, 0, 0, 0, 0, 0, 'x'})
	f.Add(uint8(2), uint8(0), []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0, 0, 0, 0, 2, 8, 6, 0, 1, 8, 0, 6, 4, 0, 2, 2, 0, 0, 0, 0, 2, 10, 0, 0, 2, 2, 0, 0, 0, 0, 1, 10, 0, 0, 1})
	f.Fuzz(func(t *testing.T, mode, sel uint8, data []byte) {
		s, ports := newFuzzStack(t)
		s.IngressEthernet(buildPkt(mode, sel, data, ports))
		buf := make([]byte, 1600)
		for range 4 {
			s.EgressEthernet(buf)
		}
		host := dns.MustNewName("example.com")
		s.ResultLookupIP(host) // Also walks the CNAME chain.
		if r, err := s.ResultDHCP(); err == nil {
			s.AssimilateDHCPResults(r)
		}
		s.ResultNTPOffset()
	})
}

// FuzzIngressMulti: a packet sequence with egress between packets, on a stack
// with fuzzed MTU (256..1531) and ICMP queue size (1..32).
func FuzzIngressMulti(f *testing.F) {
	addStreamSeeds(f)
	f.Fuzz(func(t *testing.T, mtuSel, icmpq uint8, stream []byte) {
		mtu := 256 + int(mtuSel)*5
		s, ports := newFuzzStackCfg(t, uint16(mtu), int(icmpq%32)+1)
		buf := make([]byte, mtu+14)
		for _, pkt := range splitStream(stream, ports) {
			s.IngressEthernet(pkt)
			for range 3 {
				s.EgressEthernet(buf)
			}
		}
	})
}
