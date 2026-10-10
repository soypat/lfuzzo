package synth

import (
	"bytes"
	"runtime"
	"testing"

	"github.com/soypat/lfuzzo/check"
)

// Oracle fuzzers: catch bugs that do not panic.
//
//	go test -run XXX -fuzz 'FuzzOracle$'  -fuzztime 5m ./synth/
//	go test -run XXX -fuzz 'FuzzNoAlloc$' -fuzztime 5m ./synth/

// FuzzOracle runs the same packet stream twice. Each packet has 64 bytes of
// spare capacity filled with different garbage per run. Egress and ingress
// errors must match (reads past len(frame) are detected) and every egress
// frame must be well formed.
func FuzzOracle(f *testing.F) {
	addStreamSeeds(f)
	f.Fuzz(func(t *testing.T, mtuSel, icmpq uint8, stream []byte) {
		mtu := 256 + int(mtuSel)*5
		var outs [2][]byte
		var errs [2][]error
		for run := range 2 {
			s, ports := newFuzzStackCfg(t, uint16(mtu), int(icmpq%32)+1)
			for _, pkt := range splitStream(stream, ports) {
				big := make([]byte, len(pkt), len(pkt)+64)
				copy(big, pkt)
				tail := big[len(pkt):cap(big)]
				for i := range tail {
					tail[i] = byte(run * 0xff)
				}
				errs[run] = append(errs[run], s.IngressEthernet(big))
				check.Drain(t, s, mtu, &outs[run])
			}
		}
		if !bytes.Equal(outs[0], outs[1]) {
			t.Fatal("egress depends on bytes past len(frame): reads beyond slice length")
		}
		for i := range errs[0] {
			if errs[0][i] != errs[1][i] {
				t.Fatalf("ingress result depends on bytes past len: %v vs %v", errs[0][i], errs[1][i])
			}
		}
	})
}

// FuzzNoAlloc replays a packet stream until warm, then fails if steady state
// allocates. Heap use after init is fatal on microcontrollers.
func FuzzNoAlloc(f *testing.F) {
	addStreamSeeds(f)
	f.Fuzz(func(t *testing.T, mtuSel, icmpq uint8, stream []byte) {
		mtu := 256 + int(mtuSel)*5
		s, ports := newFuzzStackCfg(t, uint16(mtu), int(icmpq%32)+1)
		pkts := splitStream(stream, ports)
		buf := make([]byte, mtu+14)
		pass := func() {
			for _, p := range pkts {
				s.IngressEthernet(p)
				for range 3 {
					s.EgressEthernet(buf)
				}
			}
		}
		pass()
		pass()
		// Average over many passes to filter Go runtime background allocations (GC workers).
		const N = 50
		var m0, m1 runtime.MemStats
		runtime.ReadMemStats(&m0)
		for range N {
			pass()
		}
		runtime.ReadMemStats(&m1)
		if avg := float64(m1.Mallocs-m0.Mallocs) / N; avg >= 1 {
			t.Fatalf("steady state allocates %.1f objects per pass over %d packets", avg, len(pkts))
		}
	})
}
