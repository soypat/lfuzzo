package regress

import (
	"encoding/binary"
	"testing"

	"github.com/soypat/lneto/dhcp/dhcpv4"
	"github.com/soypat/lneto/ipv4"
)

func regressDiscover(buf []byte, i int) []byte {
	clear(buf)
	buf[0], buf[1], buf[2] = 1, 1, 6
	binary.BigEndian.PutUint32(buf[4:], uint32(i)+1000) // xid
	buf[28], buf[29] = 0x02, 0xaa                       // chaddr: distinct MAC per client.
	binary.BigEndian.PutUint32(buf[30:], uint32(i))
	binary.BigEndian.PutUint32(buf[236:], dhcpv4.MagicCookie)
	buf[240], buf[241], buf[242], buf[243] = byte(dhcpv4.OptMessageType), 1, byte(dhcpv4.MsgDiscover), byte(dhcpv4.OptEnd)
	return buf[:244]
}

func newRegressServer(t *testing.T) *dhcpv4.Server {
	var sv dhcpv4.Server
	err := sv.Configure(dhcpv4.ServerConfig{ServerAddr: [4]byte{192, 168, 4, 1}, Subnet: ipv4.PrefixFrom([4]byte{192, 168, 4, 0}, 24)})
	if err != nil {
		t.Fatal(err)
	}
	return &sv
}

// Offers must never be network/broadcast or an address already leased.
func TestServerAddressWrapDuplicates(t *testing.T) {
	sv := newRegressServer(t)
	in := make([]byte, 548)
	out := make([]byte, 548)
	owner := map[[4]byte]int{}
	for i := range 300 {
		if err := sv.Demux(regressDiscover(in, i), 0); err != nil {
			continue // Pool exhausted is fine.
		}
		n, err := sv.Encapsulate(out, -1, 0)
		if err != nil || n == 0 {
			t.Fatalf("no offer for %d: %v", i, err)
		}
		yi := [4]byte(out[16:20])
		if yi[3] == 0 || yi[3] == 255 {
			t.Fatalf("client %d offered network/broadcast address %v", i, yi)
		}
		if prev, ok := owner[yi]; ok {
			t.Fatalf("client %d offered %v already held by client %d", i, yi, prev)
		}
		owner[yi] = i
	}
}

// Encapsulate with a small MTU buffer must error, not panic.
func TestServerEncapsulateShortBuffer(t *testing.T) {
	sv := newRegressServer(t)
	sv.Encapsulate(make([]byte, 228), -1, 0) // MTU 256 - IP(20) - UDP(8).
}

// Unhandled message types (INFORM is routine from Windows/macOS) must not allocate.
func TestServerDemuxErrorAllocs(t *testing.T) {
	sv := newRegressServer(t)
	pkt := regressDiscover(make([]byte, 548), 1)
	pkt[242] = byte(dhcpv4.MsgInform)
	if a := testing.AllocsPerRun(100, func() { sv.Demux(pkt, 0) }); a != 0 {
		t.Fatalf("allocs per INFORM: %.0f", a)
	}
}
