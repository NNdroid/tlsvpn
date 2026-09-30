package main

import (
	"bytes"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// p2dDelivered tracks application sequence numbers embedded in the Ethernet/IP
// payload. It deliberately observes the server TAP, after TLS framing, v3 control
// handling, FEC/reorder and VSwitch delivery have all completed.
type p2dDelivered struct {
	mu   sync.Mutex
	seen map[uint32]int
}

func newP2DDelivered() *p2dDelivered {
	return &p2dDelivered{seen: make(map[uint32]int)}
}

func (d *p2dDelivered) observe(frame []byte) {
	// buildEthFrameFor: 14B Ethernet + 20B IPv4 + first 4B app sequence.
	if len(frame) < 38 {
		return
	}
	seq := binary.BigEndian.Uint32(frame[34:38])
	d.mu.Lock()
	d.seen[seq]++
	d.mu.Unlock()
}

func (d *p2dDelivered) complete(start uint32, n int) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := 0; i < n; i++ {
		if d.seen[start+uint32(i)] != 1 {
			return false
		}
	}
	return true
}

func (d *p2dDelivered) assertExactlyOnce(t *testing.T, start uint32, n int) {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := 0; i < n; i++ {
		seq := start + uint32(i)
		if got := d.seen[seq]; got != 1 {
			t.Fatalf("application frame %d delivered %d times, want exactly once", seq, got)
		}
	}
}

func p2dWaitFor(t *testing.T, timeout time.Duration, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !fn() {
		t.Fatalf("timed out waiting for %s", what)
	}
}

func p2dBackendCount(p *AsyncPort) int {
	p.backendsMu.RLock()
	n := len(p.backends)
	p.backendsMu.RUnlock()
	return n
}

func p2dSession(h *perfHarness) *ClientSession {
	h.srv.mu.RLock()
	s := h.srv.activeClients[h.cli.clientID]
	h.srv.mu.RUnlock()
	return s
}

func p2dCloseOneClientConnection(t *testing.T, c *Client) int {
	t.Helper()
	c.connsMu.Lock()
	defer c.connsMu.Unlock()
	for idx, ci := range c.conns {
		if ci == nil {
			continue
		}
		if state, _ := ci.state.Load().(string); state != "up" {
			continue
		}
		v := ci.conn.Load()
		if v == nil {
			continue
		}
		h, ok := v.(connHolder)
		if !ok || h.c == nil {
			continue
		}
		h.CloseIfOpen()
		return idx
	}
	t.Fatal("no established client connection available to fail")
	return -1
}

func p2dInjectRange(h *perfHarness, start uint32, n int) {
	payload := bytes.Repeat([]byte{0xA5}, 128)
	for i := 0; i < n; i++ {
		frame := clientUplinkFrame(h.srv, h.cli, start+uint32(i), payload)
		h.tapWriter(frame)
	}
}

func p2dNoDecoderGroupsAtOrAfter(d *fecDecoder, boundary uint32) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for start := range d.groups {
		if start >= boundary {
			return false
		}
	}
	return true
}

// TestDynamicFECTLSMemTAPFailover2To1To2 is the P2d process-level fault test.
// It uses the real client reconnect supervisors, TCP/TLS handshakes, protocol-v3
// typed controls, AsyncPort scheduler/backends, session FEC decoder, reorder
// buffer, VSwitch and mem-TAP I/O. Only the kernel TAP/netlink layer is replaced
// by memTap so this remains runnable on unprivileged CI workers.
func TestDynamicFECTLSMemTAPFailover2To1To2(t *testing.T) {
	h := startPerfHarness(t, 2, true, false)
	defer h.stop()

	p2dWaitFor(t, perfHandshakeBudget, "two established client backends", func() bool {
		return atomic.LoadInt32(&h.cli.liveConns) == 2 && p2dBackendCount(h.cli.txPort) == 2
	})
	p2dWaitFor(t, perfHandshakeBudget, "server FEC session", func() bool {
		s := p2dSession(h)
		return s != nil && s.FecDec != nil && s.ActiveConns >= 2
	})

	sess := p2dSession(h)
	dec := sess.FecDec
	delivered := newP2DDelivered()
	h.srvTap.SetOnWrite(delivered.observe)

	// Establish genuine multipath data history before the failure. Without this,
	// starting with one path would correctly produce no dynamic SUSPEND.
	const preStart uint32 = 1_000
	const preFrames = 32
	p2dInjectRange(h, preStart, preFrames)
	p2dWaitFor(t, 5*time.Second, "pre-failure TAP delivery", func() bool {
		return delivered.complete(preStart, preFrames)
	})
	delivered.assertExactlyOnce(t, preStart, preFrames)

	failedIndex := p2dCloseOneClientConnection(t, h.cli)
	t.Logf("closed physical client connection index=%d", failedIndex)

	// liveConns is decremented just before the backend-unregister defer runs, so
	// require both signals before injecting the first single-path data batch.
	p2dWaitFor(t, 5*time.Second, "2->1 physical backend transition", func() bool {
		return atomic.LoadInt32(&h.cli.liveConns) == 1 && p2dBackendCount(h.cli.txPort) == 1
	})

	// The first post-failure batch creates SUSPEND. Then send >256 data frames so
	// the sparse P2c progress probe is exercised while all normal data must bypass
	// decoder group/map/XOR work. Initial reconnect backoff is >= 2/3 second, so
	// this local burst is queued while exactly one backend is registered.
	const singleStart uint32 = 10_000
	const singleFrames = 320
	p2dInjectRange(h, singleStart, 1)
	p2dWaitFor(t, 2*time.Second, "FEC_MODE SUSPEND at receiver", func() bool {
		return dec.fence.Generation() >= 1
	})
	from, until := dec.fence.Window()
	if from == 0 || until != 0 {
		t.Fatalf("SUSPEND window=%d..%d, want nonzero..open", from, until)
	}
	p2dInjectRange(h, singleStart+1, singleFrames-1)

	p2dWaitFor(t, 5*time.Second, "single-path TAP delivery", func() bool {
		return delivered.complete(singleStart, singleFrames)
	})
	delivered.assertExactlyOnce(t, singleStart, singleFrames)
	if !p2dNoDecoderGroupsAtOrAfter(dec, from) {
		t.Fatalf("single-path bypass created/retained decoder group at or after boundary %d", from)
	}
	if got := dec.fence.Generation(); got != 1 {
		t.Fatalf("unexpected FEC mode generation before resumed traffic: got=%d want=1", got)
	}

	// The reconnect supervisor restores the failed physical stream automatically.
	// Topology alone does not emit RESUME; the first governed data dispatch does.
	p2dWaitFor(t, perfHandshakeBudget, "automatic 1->2 reconnect", func() bool {
		return atomic.LoadInt32(&h.cli.liveConns) == 2 && p2dBackendCount(h.cli.txPort) == 2
	})

	const resumedStart uint32 = 20_000
	const resumedFrames = 64
	p2dInjectRange(h, resumedStart, resumedFrames)
	p2dWaitFor(t, 5*time.Second, "FEC_MODE RESUME at receiver", func() bool {
		return dec.fence.Generation() >= 2
	})
	from2, until2 := dec.fence.Window()
	if from2 != from || until2 == 0 || until2 <= from2 {
		t.Fatalf("RESUME window=%d..%d, want same from=%d and finite upper bound", from2, until2, from)
	}
	if dec.fence.BypassData(until2) {
		t.Fatalf("first resumed FEC group at seq=%d remains bypassed", until2)
	}

	p2dWaitFor(t, 5*time.Second, "post-reconnect TAP delivery", func() bool {
		return delivered.complete(resumedStart, resumedFrames)
	})
	delivered.assertExactlyOnce(t, resumedStart, resumedFrames)

	recovered, lost := dec.FECStats()
	if lost != 0 {
		t.Fatalf("receiver reported FEC loss across 2->1->2 transition: recovered=%d lost=%d", recovered, lost)
	}
	t.Logf("dynamic FEC e2e complete: suspend=%d resume=%d recovered=%d lost=%d", from2, until2, recovered, lost)
}
