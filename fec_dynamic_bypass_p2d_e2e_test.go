package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func waitDynamicCondition(t *testing.T, timeout time.Duration, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func dynamicLiveSession(h *perfHarness) *ClientSession {
	h.srv.mu.RLock()
	session := h.srv.activeClients[h.cli.clientID]
	h.srv.mu.RUnlock()
	return session
}

func dynamicSessionDecoder(h *perfHarness) *fecDecoder {
	session := dynamicLiveSession(h)
	if session == nil {
		return nil
	}
	session.sessionMu.RLock()
	dec := session.FecDec
	session.sessionMu.RUnlock()
	return dec
}

func dynamicServerConnCount(h *perfHarness) int {
	session := dynamicLiveSession(h)
	if session == nil {
		return 0
	}
	session.sessionMu.RLock()
	n := len(session.conns)
	session.sessionMu.RUnlock()
	return n
}

func closeOneDynamicServerConn(t *testing.T, h *perfHarness) {
	t.Helper()
	session := dynamicLiveSession(h)
	if session == nil {
		t.Fatal("dynamic fault session disappeared before path kill")
	}
	var target *connInfo
	session.sessionMu.RLock()
	for ci := range session.conns {
		if ci != nil && ci.tcpConn != nil {
			target = ci
			break
		}
	}
	session.sessionMu.RUnlock()
	if target == nil {
		t.Fatal("no physical server connection available to kill")
	}
	if err := target.tcpConn.Close(); err != nil {
		t.Fatalf("close physical connection: %v", err)
	}
}

func TestDynamicFECPhysicalPathKill2To1To2(t *testing.T) {
	// Use the real in-process client/server data plane: TCP + TLS + protocol-v3
	// handshake/control frames + AsyncPort + XOR FEC + reorder + VSwitch + mem TAP.
	// Inner AEAD is enabled so the same fault transition also exercises epoch keys
	// and FEC-domain authentication.
	h := startPerfHarness(t, 2, true, true)
	defer h.stop()

	waitDynamicCondition(t, 15*time.Second, "two authenticated physical connections", func() bool {
		return atomic.LoadInt32(&h.cli.liveConns) == 2 && dynamicServerConnCount(h) == 2
	})

	var deliveredMu sync.Mutex
	delivered := make([]uint32, 0, 192)
	h.srvTap.SetOnWrite(func(frame []byte) {
		if len(frame) < 38 {
			return
		}
		seq := binary.BigEndian.Uint32(frame[34:38])
		deliveredMu.Lock()
		delivered = append(delivered, seq)
		deliveredMu.Unlock()
	})
	defer h.srvTap.SetOnWrite(nil)

	payload := bytes.Repeat([]byte{0x5a}, 256)
	sendRange := func(first, last uint32) {
		for seq := first; seq <= last; seq++ {
			h.tapWriter(clientUplinkFrame(h.srv, h.cli, seq, payload))
			// Keep the test below local producer saturation so any missing frame is a
			// tunnel/fault-transition problem rather than p.ch backpressure.
			if seq&7 == 0 {
				time.Sleep(200 * time.Microsecond)
			}
		}
	}
	waitDelivered := func(want int) {
		waitDynamicCondition(t, 10*time.Second, fmt.Sprintf("%d delivered frames", want), func() bool {
			deliveredMu.Lock()
			n := len(delivered)
			deliveredMu.Unlock()
			return n >= want
		})
	}

	// Warm multipath FEC first so the later path loss is a genuine >=2 -> 1
	// transition, not startup single-path suppression.
	sendRange(1, 32)
	waitDelivered(32)
	if got := h.cli.txPort.ParitySent(); got == 0 {
		t.Fatal("multipath warmup generated no FEC parity")
	}

	// Hold replacement handshakes out while preserving the already-authenticated
	// surviving TCP stream. Existing session traffic does not consult srv.psk;
	// only new handshakes do. This creates a deterministic sustained 1-path window
	// without changing the configured client.conns topology.
	h.srv.mu.Lock()
	originalPSK := h.srv.psk
	h.srv.psk = originalPSK + "-p2d-reconnect-block"
	h.srv.mu.Unlock()
	pskRestored := false
	defer func() {
		if !pskRestored {
			h.srv.mu.Lock()
			h.srv.psk = originalPSK
			h.srv.mu.Unlock()
		}
	}()

	closeOneDynamicServerConn(t, h)
	waitDynamicCondition(t, 10*time.Second, "sustained single physical connection", func() bool {
		return atomic.LoadInt32(&h.cli.liveConns) == 1 && dynamicServerConnCount(h) == 1
	})

	parityBeforeSingle := h.cli.txPort.ParitySent()
	sendRange(33, 96)
	waitDelivered(96)

	dec := dynamicSessionDecoder(h)
	if dec == nil {
		t.Fatal("server FEC decoder unavailable during single-path interval")
	}
	waitDynamicCondition(t, 5*time.Second, "FEC SUSPEND window", func() bool {
		from, until := dec.fence.Window()
		return from != 0 && until == 0
	})
	from, until := dec.fence.Window()
	if until != 0 {
		t.Fatalf("single-path bypass window=%d..%d, want open-ended", from, until)
	}
	if got := h.cli.txPort.ParitySent(); got != parityBeforeSingle {
		t.Fatalf("single-path TX generated parity: before=%d after=%d", parityBeforeSingle, got)
	}
	for start := range decoderGroupStarts(dec) {
		if start >= from {
			t.Fatalf("RX retained decoder group %d inside dynamic bypass window starting at %d", start, from)
		}
	}

	// Re-enable replacement handshakes. The fixed client topology automatically
	// restores its second physical connection. The next governed data dispatch
	// must carry RESUME before the first complete resumed FEC group.
	h.srv.mu.Lock()
	h.srv.psk = originalPSK
	h.srv.mu.Unlock()
	pskRestored = true
	waitDynamicCondition(t, 20*time.Second, "restored two physical connections", func() bool {
		return atomic.LoadInt32(&h.cli.liveConns) == 2 && dynamicServerConnCount(h) == 2
	})

	sendRange(97, 160)
	waitDelivered(160)
	waitDynamicCondition(t, 5*time.Second, "FEC RESUME window", func() bool {
		resumeFrom, resumeUntil := dec.fence.Window()
		return resumeFrom == from && resumeUntil > resumeFrom
	})
	resumeFrom, resumeUntil := dec.fence.Window()
	if dec.fence.BypassData(resumeUntil) {
		t.Fatalf("first resumed boundary %d is still bypassed (window %d..%d)", resumeUntil, resumeFrom, resumeUntil)
	}
	if got := h.cli.txPort.ParitySent(); got <= parityBeforeSingle {
		t.Fatalf("multipath restore did not resume parity: single=%d restored=%d", parityBeforeSingle, got)
	}

	// No data is injected while the physical connection is actually being killed
	// or while the second connection is being re-authenticated. Therefore every
	// application frame submitted in the three stable phases must arrive exactly
	// once and in order; any hole/reorder here is a transition regression.
	deliveredMu.Lock()
	got := append([]uint32(nil), delivered...)
	deliveredMu.Unlock()
	if len(got) != 160 {
		t.Fatalf("delivered=%d want=160: %v", len(got), got)
	}
	for i, seq := range got {
		want := uint32(i + 1)
		if seq != want {
			t.Fatalf("delivered[%d]=%d want=%d; full=%v", i, seq, want, got)
		}
	}

	recovered, lost := dec.FECStats()
	if lost != 0 {
		t.Fatalf("dynamic physical-path transition reported FEC loss: recovered=%d lost=%d", recovered, lost)
	}
	t.Logf("P2d live fault passed: suspend=%d, resume=%d, parity %d -> %d, recovered=%d lost=%d",
		from, resumeUntil, parityBeforeSingle, h.cli.txPort.ParitySent(), recovered, lost)
}
