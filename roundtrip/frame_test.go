package roundtrip

import (
	"slices"
	"testing"

	"github.com/soypat/lneto"
	"github.com/soypat/lneto/arp"
	"github.com/soypat/lneto/dhcp/dhcpv4"
	"github.com/soypat/lneto/dhcp/dhcpv6"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/ipv6"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/udp"
)

// Frame codec roundtrips: a frame that passes ValidateSize is decoded, its
// fields are written into a fresh buffer with the setters and the result must
// validate and decode to the same fields. Inputs have exact capacity, so reads
// past the frame panic.
//
//	go test -run XXX -fuzz 'FuzzEthernetRoundtrip$' -fuzztime 2m ./roundtrip/

func valid(validate func(*lneto.Validator)) bool {
	var v lneto.Validator
	validate(&v)
	return !v.HasError()
}

type ethernetFields struct {
	dst, src [6]byte
	etype    ethernet.Type
	tag      ethernet.VLANTag
	inner    ethernet.Type
	payload  string
}

func ethernetDecode(b []byte) (ethernetFields, bool) {
	frm, err := ethernet.NewFrame(b)
	if err != nil || !valid(frm.ValidateSize) {
		return ethernetFields{}, false
	}
	f := ethernetFields{dst: *frm.DestinationHardwareAddr(), src: *frm.SourceHardwareAddr(), etype: frm.EtherTypeOrSize(), payload: string(frm.Payload())}
	if frm.IsVLAN() {
		f.tag, f.inner = frm.VLAN()
	}
	return f, true
}

func FuzzEthernetRoundtrip(f *testing.F) {
	f.Add(append([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0, 0, 0, 0, 1, 0x08, 0x00}, make([]byte, 46)...))
	f.Add(append([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 2, 0, 0, 0, 0, 1, 0x81, 0x00, 0, 1, 0x08, 0x00}, make([]byte, 46)...))
	f.Add([]byte{2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0, 4, 'd', 'a', 't', 'a', 'x'}) // Length field.
	f.Fuzz(func(t *testing.T, b []byte) {
		f1, ok := ethernetDecode(slices.Clip(b))
		if !ok {
			return
		}
		out := make([]byte, len(b))
		frm, _ := ethernet.NewFrame(out)
		*frm.DestinationHardwareAddr() = f1.dst
		*frm.SourceHardwareAddr() = f1.src
		if f1.etype == ethernet.TypeVLAN {
			frm.SetVLAN(f1.tag, f1.inner)
		} else {
			frm.SetEtherType(f1.etype)
		}
		copy(frm.Payload(), f1.payload)
		f2, ok := ethernetDecode(out)
		if !ok || f1 != f2 {
			t.Fatalf("roundtrip mismatch (valid=%v):\n%+v\n%+v", ok, f1, f2)
		}
	})
}

type arpFields struct {
	htype            uint16
	hlen             uint8
	ptype            ethernet.Type
	plen             uint8
	op               arp.Operation
	shw, sp, thw, tp string
}

func arpDecode(b []byte) (arpFields, bool) {
	frm, err := arp.NewFrame(b)
	if err != nil || !valid(frm.ValidateSize) {
		return arpFields{}, false
	}
	var f arpFields
	f.htype, f.hlen = frm.Hardware()
	f.ptype, f.plen = frm.Protocol()
	f.op = frm.Operation()
	shw, sp := frm.Sender()
	thw, tp := frm.Target()
	f.shw, f.sp, f.thw, f.tp = string(shw), string(sp), string(thw), string(tp)
	_ = frm.String()
	return f, true
}

func FuzzARPRoundtrip(f *testing.F) {
	f.Add(append([]byte{0, 1, 0x08, 0x00, 6, 4, 0, 1}, make([]byte, 20)...))
	f.Add(append([]byte{0, 1, 0x86, 0xdd, 6, 16, 0, 2}, make([]byte, 44)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		f1, ok := arpDecode(slices.Clip(b))
		if !ok {
			return
		}
		out := make([]byte, len(b))
		frm, _ := arp.NewFrame(out)
		frm.SetHardware(f1.htype, f1.hlen)
		frm.SetProtocol(f1.ptype, f1.plen)
		frm.SetOperation(f1.op)
		shw, sp := frm.Sender()
		thw, tp := frm.Target()
		copy(shw, f1.shw)
		copy(sp, f1.sp)
		copy(thw, f1.thw)
		copy(tp, f1.tp)
		f2, ok := arpDecode(out)
		if !ok || f1 != f2 {
			t.Fatalf("roundtrip mismatch (valid=%v):\n%+v\n%+v", ok, f1, f2)
		}
	})
}

type ipv4Fields struct {
	version, ihl     uint8
	tos              ipv4.ToS
	totalLen, id     uint16
	flags            ipv4.Flags
	ttl              uint8
	proto            lneto.IPProto
	crc, crcComputed uint16
	src, dst         [4]byte
	options, payload string
}

func ipv4Decode(b []byte) (ipv4Fields, bool) {
	frm, err := ipv4.NewFrame(b)
	if err != nil || !valid(frm.ValidateExceptCRC) {
		return ipv4Fields{}, false
	}
	var f ipv4Fields
	f.version, f.ihl = frm.VersionAndIHL()
	f.tos, f.totalLen, f.id, f.flags, f.ttl, f.proto = frm.ToS(), frm.TotalLength(), frm.ID(), frm.Flags(), frm.TTL(), frm.Protocol()
	f.crc, f.crcComputed = frm.CRC(), frm.CalculateHeaderCRC()
	f.src, f.dst = *frm.SourceAddr(), *frm.DestinationAddr()
	f.options, f.payload = string(frm.Options()), string(frm.Payload())
	_ = frm.String()
	return f, true
}

func FuzzIPv4Roundtrip(f *testing.F) {
	f.Add([]byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2})
	f.Add([]byte{0x46, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, 1, 1, 1, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		f1, ok := ipv4Decode(slices.Clip(b))
		if !ok {
			return
		}
		out := make([]byte, len(b))
		frm, _ := ipv4.NewFrame(out)
		frm.SetVersionAndIHL(f1.version, f1.ihl)
		frm.SetToS(f1.tos)
		frm.SetTotalLength(f1.totalLen)
		frm.SetID(f1.id)
		frm.SetFlags(f1.flags)
		frm.SetTTL(f1.ttl)
		frm.SetProtocol(f1.proto)
		frm.SetCRC(f1.crc)
		*frm.SourceAddr(), *frm.DestinationAddr() = f1.src, f1.dst
		copy(frm.Options(), f1.options)
		copy(frm.Payload(), f1.payload)
		f2, ok := ipv4Decode(out)
		if !ok || f1 != f2 {
			t.Fatalf("roundtrip mismatch (valid=%v):\n%+v\n%+v", ok, f1, f2)
		}
	})
}

type ipv6Fields struct {
	version    uint8
	tos        ipv6.ToS
	flow       uint32
	payloadLen uint16
	next       lneto.IPProto
	hop        uint8
	src, dst   [16]byte
	payload    string
}

func ipv6Decode(b []byte) (ipv6Fields, bool) {
	frm, err := ipv6.NewFrame(b)
	if err != nil || !valid(frm.ValidateSize) {
		return ipv6Fields{}, false
	}
	var f ipv6Fields
	f.version, f.tos, f.flow = frm.VersionTrafficAndFlow()
	f.payloadLen, f.next, f.hop = frm.PayloadLength(), frm.NextHeader(), frm.HopLimit()
	f.src, f.dst = *frm.SourceAddr(), *frm.DestinationAddr()
	f.payload = string(frm.Payload())
	return f, true
}

func FuzzIPv6Roundtrip(f *testing.F) {
	f.Add(append([]byte{0x60, 0, 0, 0, 0, 4, 17, 64}, make([]byte, 36)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		f1, ok := ipv6Decode(slices.Clip(b))
		if !ok {
			return
		}
		out := make([]byte, len(b))
		frm, _ := ipv6.NewFrame(out)
		frm.SetVersionTrafficAndFlow(f1.version, f1.tos, f1.flow)
		frm.SetPayloadLength(f1.payloadLen)
		frm.SetNextHeader(f1.next)
		frm.SetHopLimit(f1.hop)
		*frm.SourceAddr(), *frm.DestinationAddr() = f1.src, f1.dst
		copy(frm.Payload(), f1.payload)
		f2, ok := ipv6Decode(out)
		if !ok || f1 != f2 {
			t.Fatalf("roundtrip mismatch (valid=%v):\n%+v\n%+v", ok, f1, f2)
		}
	})
}

type udpFields struct {
	src, dst, length, crc uint16
	payload               string
}

func udpDecode(b []byte) (udpFields, bool) {
	frm, err := udp.NewFrame(b)
	if err != nil || !valid(frm.ValidateSize) {
		return udpFields{}, false
	}
	return udpFields{frm.SourcePort(), frm.DestinationPort(), frm.Length(), frm.CRC(), string(frm.Payload())}, true
}

func FuzzUDPRoundtrip(f *testing.F) {
	f.Add([]byte{0, 53, 0, 53, 0, 12, 0, 0, 1, 2, 3, 4})
	f.Fuzz(func(t *testing.T, b []byte) {
		f1, ok := udpDecode(slices.Clip(b))
		if !ok {
			return
		}
		out := make([]byte, len(b))
		frm, _ := udp.NewFrame(out)
		frm.SetSourcePort(f1.src)
		frm.SetDestinationPort(f1.dst)
		frm.SetLength(f1.length)
		frm.SetCRC(f1.crc)
		copy(frm.Payload(), f1.payload)
		f2, ok := udpDecode(out)
		if !ok || f1 != f2 {
			t.Fatalf("roundtrip mismatch (valid=%v):\n%+v\n%+v", ok, f1, f2)
		}
	})
}

type tcpOption struct {
	kind tcp.OptionKind
	data string
}

type tcpFields struct {
	src, dst         uint16
	seq, ack         tcp.Value
	offset           uint8
	flags            tcp.Flags
	wnd, crc, urg    uint16
	options, payload string
}

func tcpDecode(b []byte) (tcpFields, bool) {
	frm, err := tcp.NewFrame(b)
	if err != nil || !valid(frm.ValidateExceptCRC) {
		return tcpFields{}, false
	}
	var f tcpFields
	f.src, f.dst, f.seq, f.ack = frm.SourcePort(), frm.DestinationPort(), frm.Seq(), frm.Ack()
	f.offset, f.flags = frm.OffsetAndFlags()
	f.wnd, f.crc, f.urg = frm.WindowSize(), frm.CRC(), frm.UrgentPtr()
	f.options, f.payload = string(frm.Options()), string(frm.Payload())
	_ = frm.String()
	return f, true
}

// tcpOptions decodes opts until the end-of-options list.
func tcpOptions(opts []byte) (list []tcpOption, err error) {
	var codec tcp.OptionCodec
	err = codec.ForEachOption(opts, func(kind tcp.OptionKind, data []byte) error {
		list = append(list, tcpOption{kind, string(data)})
		return nil
	})
	return list, err
}

// tcpEncodeOptions writes list into dst, NOPs as single bytes.
func tcpEncodeOptions(t *testing.T, dst []byte, list []tcpOption) {
	var codec tcp.OptionCodec
	for _, o := range list {
		if o.kind == tcp.OptNop {
			dst[0] = byte(tcp.OptNop)
			dst = dst[1:]
			continue
		}
		n, err := codec.PutOption(dst, o.kind, []byte(o.data)...)
		if err != nil {
			t.Fatalf("re-encoding decoded option %v: %v", o, err)
		}
		dst = dst[n:]
	}
}

func FuzzTCPRoundtrip(f *testing.F) {
	f.Add([]byte{0, 80, 0, 81, 0, 0, 0, 1, 0, 0, 0, 0, 0x60, 0x02, 0xff, 0xff, 0, 0, 0, 0, 2, 4, 5, 0xb4})
	f.Add([]byte{0, 80, 0, 81, 0, 0, 0, 1, 0, 0, 0, 2, 0x80, 0x18, 0x01, 0x00, 0, 0, 0, 0, 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 'h', 'i'})
	f.Fuzz(func(t *testing.T, b []byte) {
		f1, ok := tcpDecode(slices.Clip(b))
		if !ok {
			return
		}
		opts1, optErr := tcpOptions([]byte(f1.options))
		out := make([]byte, len(b))
		frm, _ := tcp.NewFrame(out)
		frm.SetSourcePort(f1.src)
		frm.SetDestinationPort(f1.dst)
		frm.SetSeq(f1.seq)
		frm.SetAck(f1.ack)
		frm.SetOffsetAndFlags(f1.offset, f1.flags)
		frm.SetWindowSize(f1.wnd)
		frm.SetCRC(f1.crc)
		frm.SetUrgentPtr(f1.urg)
		if optErr == nil {
			tcpEncodeOptions(t, frm.Options(), opts1)
		} else {
			copy(frm.Options(), f1.options)
		}
		copy(frm.Payload(), f1.payload)
		f2, ok := tcpDecode(out)
		if !ok {
			t.Fatalf("re-encoded frame does not validate:\n%+v", f1)
		}
		if optErr != nil {
			if f1 != f2 {
				t.Fatalf("roundtrip mismatch:\n%+v\n%+v", f1, f2)
			}
			return
		}
		opts2, err := tcpOptions([]byte(f2.options))
		f1.options, f2.options = "", ""
		if err != nil || f1 != f2 || !slices.Equal(opts1, opts2) {
			t.Fatalf("roundtrip mismatch (err=%v):\n%+v %v\n%+v %v", err, f1, opts1, f2, opts2)
		}
	})
}

type dhcpOption struct {
	num  dhcpv4.OptNum
	data string
}

type dhcpv4Fields struct {
	op                dhcpv4.Op
	htype, hlen, hops uint8
	xid               uint32
	secs              uint16
	flags             dhcpv4.Flags
	ciaddr, yiaddr    [4]byte
	siaddr, giaddr    [4]byte
	chaddr            [16]byte
	snameFile         string
	cookie            uint32
	options           string // Encoded options, only compared when decoding them failed.
	optionsList       []dhcpOption
	optionsErr        error
}

// snameFile is the BOOTP server host name and boot file name, between the
// client hardware address and the magic cookie. dhcpv4 has no accessors for it.
const snameStart, snameEnd = 44, 236

func dhcpv4Decode(b []byte) (dhcpv4Fields, bool) {
	frm, err := dhcpv4.NewFrame(b)
	if err != nil || !valid(frm.ValidateSize) {
		return dhcpv4Fields{}, false
	}
	var f dhcpv4Fields
	f.op = frm.Op()
	f.htype, f.hlen, f.hops = frm.Hardware()
	f.xid, f.secs, f.flags = frm.XID(), frm.Secs(), frm.Flags()
	f.ciaddr, f.yiaddr, f.siaddr, f.giaddr = *frm.CIAddr(), *frm.YIAddr(), *frm.SIAddr(), *frm.GIAddr()
	f.chaddr = *frm.CHAddr()
	f.snameFile = string(frm.RawData()[snameStart:snameEnd])
	f.cookie = frm.MagicCookie()
	f.options = string(frm.OptionsPayload())
	f.optionsErr = frm.ForEachOption(func(_ int, num dhcpv4.OptNum, data []byte) error {
		f.optionsList = append(f.optionsList, dhcpOption{num, string(data)})
		return nil
	})
	return f, true
}

func FuzzDHCPv4Roundtrip(f *testing.F) {
	seed := make([]byte, dhcpv4.OptionsOffset+4)
	copy(seed[dhcpv4.OptionsOffset-4:], []byte{0x63, 0x82, 0x53, 0x63})
	copy(seed[dhcpv4.OptionsOffset:], []byte{53, 1, 1, 255})
	f.Add(seed)
	f.Fuzz(func(t *testing.T, b []byte) {
		f1, ok := dhcpv4Decode(slices.Clip(b))
		if !ok {
			return
		}
		out := make([]byte, len(b))
		frm, _ := dhcpv4.NewFrame(out)
		frm.SetOp(f1.op)
		frm.SetHardware(f1.htype, f1.hlen, f1.hops)
		frm.SetXID(f1.xid)
		frm.SetSecs(f1.secs)
		frm.SetFlags(f1.flags)
		*frm.CIAddr(), *frm.YIAddr(), *frm.SIAddr(), *frm.GIAddr() = f1.ciaddr, f1.yiaddr, f1.siaddr, f1.giaddr
		*frm.CHAddr() = f1.chaddr
		copy(frm.RawData()[snameStart:snameEnd], f1.snameFile)
		frm.SetMagicCookie(f1.cookie)
		opts := frm.OptionsPayload()
		if f1.optionsErr != nil {
			copy(opts, f1.options)
		} else {
			// Pads are dropped and the list ends with an end option, so it fits.
			for _, o := range f1.optionsList {
				n, err := dhcpv4.EncodeOption(opts, o.num, []byte(o.data)...)
				if err != nil {
					t.Fatalf("re-encoding decoded option %v: %v", o, err)
				}
				opts = opts[n:]
			}
			if len(opts) > 0 {
				opts[0] = byte(dhcpv4.OptEnd)
			}
		}
		f2, ok := dhcpv4Decode(out)
		if !ok {
			t.Fatalf("re-encoded frame does not validate:\n%+v", f1)
		}
		if f1.optionsErr == nil {
			f1.options, f2.options = "", "" // Pads and trailing bytes differ.
		}
		if f1.optionsErr != f2.optionsErr || !slices.Equal(f1.optionsList, f2.optionsList) {
			t.Fatalf("options roundtrip mismatch:\n%v %v\n%v %v", f1.optionsErr, f1.optionsList, f2.optionsErr, f2.optionsList)
		}
		f1.optionsList, f2.optionsList = nil, nil
		if f1.optionsErr, f2.optionsErr = nil, nil; !dhcpv4Equal(f1, f2) {
			t.Fatalf("roundtrip mismatch:\n%+v\n%+v", f1, f2)
		}
	})
}

func dhcpv4Equal(a, b dhcpv4Fields) bool {
	return a.op == b.op && a.htype == b.htype && a.hlen == b.hlen && a.hops == b.hops &&
		a.xid == b.xid && a.secs == b.secs && a.flags == b.flags &&
		a.ciaddr == b.ciaddr && a.yiaddr == b.yiaddr && a.siaddr == b.siaddr && a.giaddr == b.giaddr &&
		a.chaddr == b.chaddr && a.snameFile == b.snameFile && a.cookie == b.cookie && a.options == b.options
}

type dhcpv6Option struct {
	code dhcpv6.OptCode
	data string
}

func dhcpv6Decode(b []byte) (msg dhcpv6.MsgType, txid uint32, list []dhcpv6Option, ok bool) {
	frm, err := dhcpv6.NewFrame(b)
	if err != nil || frm.ValidateSize() != nil {
		return 0, 0, nil, false
	}
	err = frm.ForEachOption(func(_ int, code dhcpv6.OptCode, data []byte) error {
		list = append(list, dhcpv6Option{code, string(data)})
		return nil
	})
	return frm.MsgType(), frm.TransactionID(), list, err == nil
}

func FuzzDHCPv6Roundtrip(f *testing.F) {
	f.Add([]byte{1, 0, 0, 1, 0, 1, 0, 2, 0xab, 0xcd})
	f.Fuzz(func(t *testing.T, b []byte) {
		msg, txid, list, ok := dhcpv6Decode(slices.Clip(b))
		if !ok {
			return
		}
		out := make([]byte, len(b))
		frm, _ := dhcpv6.NewFrame(out)
		frm.SetMsgType(msg)
		frm.SetTransactionID(txid)
		opts := frm.Options()
		for _, o := range list {
			n, err := dhcpv6.EncodeOption(opts, o.code, []byte(o.data)...)
			if err != nil {
				t.Fatalf("re-encoding decoded option %v: %v", o, err)
			}
			opts = opts[n:]
		}
		msg2, txid2, list2, ok := dhcpv6Decode(out)
		if !ok || msg != msg2 || txid != txid2 || !slices.Equal(list, list2) {
			t.Fatalf("roundtrip mismatch (valid=%v):\n%v %v %v\n%v %v %v", ok, msg, txid, list, msg2, txid2, list2)
		}
	})
}
