package mutation

import (
	"testing"
	"time"

	"github.com/soypat/lfuzzo"
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
	mtuFail, mutated := stacksQuiesceMutateTCP(t, &cl, &sv, maxRounds, buf, mtcp, &script)
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
	mtuFail2, mutated2 := stacksQuiesceMutateTCP(t, &cl, &sv, maxRounds, buf, mtcp, &script)
	if mtuFail2 {
		t.Fatal("unexpected mtu fail")
	}
	if len(req) != svConn.Conn().BufferedInput() {
		if mutated2 {
			// malfunction due to mutation.
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
	// Expired deadline: Read returns buffered data, then fails instead of
	// spinning when mutation lost part of the request.
	must(svConn.SetReadDeadline(time.Now()))
	if !svExch.Acquire(svConn) {
		t.Fatal("exchange could not acquire server connection")
	}
	err = httphi.Handle(&svExch, &mux, nil) // This writes to svConn.
	if err != nil {
		if !mutated2 {
			t.Fatal("did not expect failure:", err)
		}
		return // request malformed, dump.
	}
	// We expect a response contained in svConn by now.
	if svConn.Conn().BufferedUnsent() == 0 {
		t.Fatal("unexpected empty response")
	}
	mtuFail3, mutated3 := stacksQuiesceMutateTCP(t, &sv, &cl, maxRounds, buf, mtcp, &script)
	if mtuFail3 {
		t.Fatal("mtu fail on server HTTP response")
	}
	n, err := clConn.InternalHandler().Read(buf)
	if n == 0 {
		if mutated3 {
			return
		}
		t.Fatal("failed to read server's response")
	}
	// done!
}

// maxRounds bounds exchanges per phase. Normal traffic settles in a few rounds,
// so exceeding it indicates an endless exchange such as an ACK storm.
const maxRounds = 64

// backoffNone never waits so a non-blocking call fails fast instead of stalling the fuzzer.
func backoffNone(uint) time.Duration { return 0 }

func stacksQuiesceMutateTCP(t *testing.T, s1, s2 *xnet.StackAsync, lim int, buf []byte, mutTCP *lfuzzo.MutatorTCPBasic, script *[]byte) (mtuExcess, mutation bool) {
	for range lim {
		exchanged := false
		for _, s := range [2][2]*xnet.StackAsync{{s1, s2}, {s2, s1}} {
			tx, rx := s[0], s[1]
			ntx, _ := tx.EgressEthernet(buf[:tx.MTU()+ethernet.MaxOverheadSize])
			if ntx != 0 {
				exchanged = true
				if ntx > rx.MTU()+ethernet.MaxOverheadSize {
					mtuExcess = true
					ntx = rx.MTU() + ethernet.MaxOverheadSize
				}
				efrm, _ := ethernet.NewFrame(buf[:ntx])
				if efrm.EtherTypeOrSize() == ethernet.TypeIPv4 {
					ifrm, _ := ipv4.NewFrame(efrm.Payload())
					if ifrm.Protocol() == lneto.IPProtoTCP {
						tfrm, _ := tcp.NewFrame(ifrm.Payload())
						*script = mutTCP.Load(*script)
						if mutTCP.MutateTCP(tfrm) {
							mutation = true
							var crc lneto.CRC791
							ifrm.CRCWriteTCPPseudo(&crc)
							tfrm.SetCRC(0)
							tfrm.SetCRC(crc.PayloadSum16(ifrm.Payload()))
						}
					}
				}
				rx.IngressEthernet(buf[:ntx])
			}
		}
		if !exchanged {
			return mtuExcess, mutation
		}
	}
	t.Error("stacks did not quiesce after", lim)
	return mtuExcess, mutation
}
