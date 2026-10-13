package mutation

import (
	"net/netip"
	"testing"
	"time"

	"github.com/soypat/lfuzzo"
	"github.com/soypat/lfuzzo/internal/trace"
	"github.com/soypat/lneto"
	"github.com/soypat/lneto/ethernet"
	"github.com/soypat/lneto/http/httphi"
	"github.com/soypat/lneto/http/httpraw"
	"github.com/soypat/lneto/ipv4"
	"github.com/soypat/lneto/tcp"
	"github.com/soypat/lneto/x/xnet"
)

// dual.go contains fuzzers for dual stack configurations
// i.e: HTTP client and server interactions that can be modelled with lneto same stack.

func FuzzHTTPClientServer(f *testing.F) {
	f.Add(uint64(0), []byte{})                     // Clean run.
	f.Add(uint64(0x0f0f), []byte{0, 0, 0x2, 1, 0}) // SEQ+1 on the third segment.
	f.Add(uint64(0x2a00), []byte{0x10, 0, 0})      // WND nudge on the SYN.
	// Fuzzeresco Team Findings:
	{
		f.Add(uint64(10759), []byte("$0000\xf9\xff\xff00007000007\x00\x00\x01\x00"))       // Pato: "Listen to SYNFIN to desync"
		f.Add(uint64(10806), []byte("B\x01\x0000\xf9\xff\xff00007000007\x00\x00\x01\x00")) // Pato: "wtf is this"
		const long1 = "\x00\x00\x00800001000000$2000 0080000100000000000$20000000020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x03000000000200\x0020\x030000\xf710\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x00\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x030000000002+\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x00000000000\x03000\x03\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x0300000000020\x030d00\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x00200000000020\x030000\x0020\x030000\x0020\x030000\x0020\x00000000000\x03000\x03\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x0300000000020\x030d00\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x0020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x0300000000020\x030000\x0020\x030000\x002\x8f\x8a\x12\x98\xd6}\xbb\xfdɾ\x95\xacv\xb9\xbdѕ"
		f.Add(uint64(10281), []byte(long1)) // Pato: "slow open only"
	}
	f.Fuzz(func(t *testing.T, cfg uint64, script []byte) {
		mutTcp := lfuzzo.MutatorTCPBasic{
			RateACKNudge: 1,
			RateSEQNudge: 1,
			RateWNDNudge: 1,
			RateCtlSet:   1,
			RateCtlFlip:  1,
			RateACKFlip:  1,
		}
		testRandHTTPSetup(t, &mutTcp, cfg, script)
	})
}

// testRandHTTPSetup runs an HTTP exchange between two stacks. cfg selects MTUs and
// random seeds; script drives TCP segment mutations, see [lfuzzo.MutatorTCPBasic.Load].
func testRandHTTPSetup(t *testing.T, mtcp *lfuzzo.MutatorTCPBasic, cfg uint64, script []byte) {
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	mtu1 := 256 + int(uint8(cfg))*5
	mtu2 := 256 + int(uint8(cfg>>8))*5
	buf := make([]byte, max(mtu1, mtu2)+ethernet.MaxOverheadSize)
	configStack := func(s *xnet.StackAsync, id byte, mtu int, rng uint64) {
		err := s.Reset(xnet.StackConfig{
			HardwareAddress:     [6]byte{10, 0, 0, id},
			StaticAddress4:      [4]byte{10, 0, 0, id},
			RandSeed:            int64(rng),
			MTU:                 uint16(mtu),
			Hostname:            "fuzzdual",
			ICMPQueueLimit:      2,
			PassivePeers:        2,
			MaxActiveTCPPorts:   2,
			MaxActiveUDPPorts:   2,
			AcceptMulticast:     true,
			AcceptIPv4Broadcast: true,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	var sv, cl xnet.StackAsync
	configStack(&cl, 1, mtu1, cfg>>16|1) // Zero seed is invalid.
	configStack(&sv, 2, mtu2, cfg>>32|1)
	// Configure server.
	pool, err := sv.NewTCPPool(xnet.TCPPoolConfig{
		PoolSize:  2,
		QueueSize: 4,
		TxBufSize: 1024,
		RxBufSize: 1024,

		EstablishedTimeout: time.Second,
		ClosingTimeout:     time.Second,
		NewBackoff:         func() lneto.BackoffStrategy { return backoffNone },
	})
	if err != nil {
		t.Fatal(err)
	}
	const svPort = 80
	var listener tcp.Listener
	must(listener.Reset(svPort, pool))
	must(sv.RegisterListenerTCP(&listener))

	var clConn tcp.Conn
	must(clConn.Configure(tcp.ConnConfig{
		RxBuf:             make([]byte, 1024),
		TxBuf:             make([]byte, 1024),
		TxPacketQueueSize: 4,
		RWBackoff:         backoffNone,
	}))
	must(cl.DialTCP4(&clConn, 1337, sv.Addr4(), svPort))
	// Establish connection, three way handshake occurs here.
	w := wire{stacks: [2]*xnet.StackAsync{&cl, &sv}, buf: buf, mut: mtcp, script: script}
	const fromCl, fromSv = 0, 1
	mtuFail, mutated := w.quiesce(t, fromCl, maxRounds)
	if mtuFail {
		t.Fatal("should not happen?")
	}
	if clConn.State() != tcp.StateEstablished {
		if mutated {
			return // Normal failure to establish
		}
		t.Fatal("client unable to establish connection!")
	} else if listener.NumberOfReadyToAccept() == 0 {
		if mutated {
			return
		}
		t.Fatal("client established but listener has none ready to accept")
	}
	svConn, err := listener.TryAccept()
	must(err)
	if svConn.State() != tcp.StateEstablished {
		t.Fatal("expected established server connection")
	}
	svTCB := svConn.Conn().InternalHandler().ControlBlock()
	clTCB := clConn.InternalHandler().ControlBlock()

	if trace.Enabled {
		t.Log("handshake done: cl", clConn.State(), "sv", svConn.State(), "mutated", mutated)
	}
	// don't end test early due to desync, maybe we hit a panic case- keep going but ignore obvious failures as a result of this!
	desynced := clTCB.SendNext() != svTCB.RecvNext() || svTCB.SendNext() != clTCB.RecvNext()
	// Connection established, Begin HTTP phase.
	var hdr httpraw.HeaderV1
	hdr.SetMethod("GET")
	hdr.SetRequestTarget("/abc")
	hdr.SetProtocol("HTTP/1.1")
	req, err := hdr.AppendRequest(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Write to [tcp.Handler] is fail on insufficient buffer space, which is what we want. We don't want to block in fuzzer.
	_, err = clConn.InternalHandler().Write(req)
	must(err)
	// Send request over the network.
	mtuFail2, mutated2 := w.quiesce(t, fromCl, maxRounds)
	mutated = mutated || mutated2
	if trace.Enabled {
		t.Log("request sent: cl", clConn.State(), "sv", svConn.State(), "mutated", mutated2,
			"sv buffered", svConn.Conn().BufferedInput(), "of", len(req), "cl unsent", clConn.BufferedUnsent())
	}
	if mtuFail2 {
		t.Fatal("unexpected mtu fail")
	} else if svConn.State() != tcp.StateEstablished {
		return
	}
	if len(req) != svConn.Conn().BufferedInput() {
		if mutated || desynced {
			if clConn.State() != tcp.StateEstablished {
				return // Connection ended gracefully"
			}
		} else {
			t.Fatal("did not receive request fully")
		}
	}
	// Receive request in router.
	var mux httphi.MuxSlice
	mux.Handle("/", func(ex *httphi.Exchange) {
		ex.Respond(200, "", nil)
	})
	mux.Handle("/{id}", func(ex *httphi.Exchange) {
		id := ex.PathValue("id")
		ex.Respond(200, "", id)
	})
	var svExch httphi.Exchange
	svExch.Configure(httphi.ExchangeConfig{
		RawBuf: make([]byte, 1024),
		// Below the request size Handle fails with io.ErrNoProgress although
		// buffer growth is enabled: lneto httphi bug, kept out of this fuzzer.
		RequestBufferLim: 512,
		NumHeaderKVCap:   12,
		PathValuesBuf:    make([]httphi.PathValue, mux.MaxPathValues()),
	})
	must(svConn.SetReadDeadline(time.Now()))
	if !svExch.Acquire(svConn) {
		t.Fatal("exchange could not acquire server connection")
	}
	err = httphi.Handle(&svExch, &mux, nil) // This writes to svConn.
	if err != nil {
		if !mutated2 && !desynced {
			t.Fatal("did not expect failure:", err)
		}
		return // request malformed, dump.
	}
	// We expect a response contained in svConn by now.
	if svConn.Conn().BufferedUnsent() == 0 {
		t.Fatal("unexpected empty response")
	}
	mtuFail3, mutated3 := w.quiesce(t, fromSv, maxRounds)
	desynced = desynced || clTCB.SendNext() != svTCB.RecvNext() || svTCB.SendNext() != clTCB.RecvNext()
	mutated = mutated || mutated3
	if trace.Enabled {
		t.Log("response sent: cl", clConn.State(), "sv", svConn.State(), "mutated", mutated3,
			"cl buffered", clConn.BufferedInput(), "sv unsent", svConn.Conn().BufferedUnsent())
	}
	if mtuFail3 {
		t.Fatal("mtu fail on server HTTP response")
	}
	clState := clConn.State()
	n, err := clConn.InternalHandler().Read(buf)
	if n == 0 {
		if mutated || !clState.RxDataOpen() || desynced {
			return
		}
		t.Fatal("failed to read server's response", clState)
	}
	// done!
}

// maxRounds bounds unmutated exchanges per phase. Normal traffic settles in a few rounds,
// so exceeding it indicates an endless exchange such as an ACK storm.
const maxRounds = 64

// backoffNone never waits so a non-blocking call fails fast instead of stalling the fuzzer.
func backoffNone(uint) time.Duration { return 0 }

// wire carries segments between two stacks, mutating TCP segments per script and
// checking each stack's output against what it was delivered.
type wire struct {
	stacks [2]*xnet.StackAsync // stacks exchanging data.
	buf    []byte
	mut    *lfuzzo.MutatorTCPBasic
	script []byte
	// synRcvd is the SEQ of the last SYN each stack accepted, after mutation; valid if hasSynRcvd.
	synRcvd    [2]tcp.Value
	hasSynRcvd [2]bool
}

// quiesce exchanges segments, stacks[first] sending first each round, until neither stack
// has anything to send. It fails t if lim rounds pass without mutation.
func (w *wire) quiesce(t *testing.T, first, lim int) (mtuExcess, mutation bool) {
	// Rounds carrying a mutation do not count toward lim: each mutated segment
	// draws a reply, so a long script sustains traffic without a stack fault.
	for round := 0; round < lim; round++ {
		exchanged := false
		for i := range 2 {
			itx := (first + i) % 2
			irx := 1 - itx
			tx, rx := w.stacks[itx], w.stacks[irx]
			ntx, _ := tx.EgressEthernet(w.buf[:tx.MTU()+ethernet.MaxOverheadSize])
			if ntx == 0 {
				continue
			}
			exchanged = true
			if ntx > rx.MTU()+ethernet.MaxOverheadSize {
				mtuExcess = true
				ntx = rx.MTU() + ethernet.MaxOverheadSize
			}
			var tfrm tcp.Frame
			isTCP := false
			efrm, _ := ethernet.NewFrame(w.buf[:ntx])
			if efrm.EtherTypeOrSize() == ethernet.TypeIPv4 {
				ifrm, _ := ipv4.NewFrame(efrm.Payload())
				if ifrm.Protocol() == lneto.IPProtoTCP {
					isTCP = true
					tfrm, _ = tcp.NewFrame(ifrm.Payload())
					pre := tfrm.Segment(len(tfrm.Payload()))
					w.checkSent(t, itx, pre)
					w.script = w.mut.Load(w.script)
					if w.mut.MutateTCP(tfrm) {
						if trace.Enabled {
							t.Logf("MUT %s: %+v => %+v", netip.AddrFrom4(tx.Addr4()), pre, tfrm.Segment(len(tfrm.Payload())))
						}
						mutation = true
						round = -1 // Reset round. This prevents mutation triggering a vicious response cycle.
						var crc lneto.CRC791
						ifrm.CRCWriteTCPPseudo(&crc)
						tfrm.SetCRC(0)
						tfrm.SetCRC(crc.PayloadSum16(ifrm.Payload()))
					}
					if trace.Enabled {
						t.Logf("SEG %s->%s: %+v", netip.AddrFrom4(tx.Addr4()), netip.AddrFrom4(rx.Addr4()), tfrm.Segment(len(tfrm.Payload())))
					}
				}
			}
			var delivered tcp.Segment // Read before handing buf to rx.
			if isTCP {
				delivered = tfrm.Segment(len(tfrm.Payload()))
			}
			err := rx.IngressEthernet(w.buf[:ntx])
			if trace.Enabled && err != nil {
				t.Logf("    ingress %s: %v", netip.AddrFrom4(rx.Addr4()), err)
			}
			if isTCP && err == nil && delivered.Flags.HasAny(tcp.FlagSYN) {
				w.synRcvd[irx] = delivered.SEQ
				w.hasSynRcvd[irx] = true
			}
		}
		if !exchanged {
			return mtuExcess, mutation
		}
	}
	t.Error("stacks did not quiesce after", lim, "rounds without mutation")
	return mtuExcess, mutation
}

// checkSent fails t if stacks[itx] sent seg, before mutation, inconsistent with
// the segments it accepted. Mutations cannot excuse these: they are stack faults.
func (w *wire) checkSent(t *testing.T, itx int, seg tcp.Segment) {
	t.Helper()
	isSYN := seg.Flags.HasAny(tcp.FlagSYN)
	isACK := seg.Flags.HasAny(tcp.FlagACK)
	switch {
	case isSYN && isACK && w.hasSynRcvd[itx] && seg.ACK != w.synRcvd[itx]+1:
		t.Fatalf("stack %d SYN,ACK acknowledges %d, want accepted SYN SEQ+1=%d: %+v", itx, seg.ACK, w.synRcvd[itx]+1, seg)
	case isACK && !isSYN && !seg.Flags.HasAny(tcp.FlagRST) && !w.hasSynRcvd[itx]:
		t.Fatalf("stack %d sent ACK before accepting any SYN: %+v", itx, seg)
	}
}
