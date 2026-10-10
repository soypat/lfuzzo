package roundtrip

import (
	"bytes"
	"testing"

	"github.com/soypat/lneto/dns"
)

// FuzzMessageRoundtrip: Decode -> AppendTo must produce exactly Len() bytes and
// re-decode to the same message.
//
//	go test -run XXX -fuzz FuzzMessageRoundtrip -fuzztime 2m ./roundtrip/
func FuzzMessageRoundtrip(f *testing.F) {
	f.Add([]byte{0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1,
		0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4})
	f.Add([]byte{0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0,
		3, 'w', 'w', 'w', 0xc0, 12, 0, 5, 0, 1,
		0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 12})
	f.Fuzz(func(t *testing.T, data []byte) {
		var m dns.Message
		m.LimitResourceDecoding(4, 8, 4, 4)
		if _, incomplete, err := m.Decode(data); err != nil && !incomplete {
			return
		}
		enc, err := m.AppendTo(nil, 1, 0)
		if err != nil {
			return
		}
		if len(enc) != int(m.Len()) {
			t.Fatalf("Len()=%d but AppendTo wrote %d", m.Len(), len(enc))
		}
		var m2 dns.Message
		m2.LimitResourceDecoding(4, 8, 4, 4)
		if _, inc2, err := m2.Decode(enc); err != nil && !inc2 {
			t.Fatalf("re-decode of own encoding failed: %v\nenc=% x", err, enc)
		}
		t1, _ := m.AppendText(nil)
		t2, _ := m2.AppendText(nil)
		if !bytes.Equal(t1, t2) {
			t.Fatalf("roundtrip mismatch:\n%s\n%s", t1, t2)
		}
	})
}
