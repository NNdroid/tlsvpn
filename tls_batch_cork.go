package main

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Sub-MSS carry is intentionally disabled on sub-millisecond transport RTTs.
// Holding even a very short partial segment on those links disturbs the ACK
// clock more than it helps. On WAN-like RTTs, keep the window to a small
// fraction of RTT so the next real TLSVPN batch can fill the tail without
// adding synthetic padding.
const (
	tlsBatchCorkRTTThreshold = time.Millisecond
	tlsBatchCorkMaxDelay     = 150 * time.Microsecond
)

func tlsBatchCorkPolicyForRTT(rtt time.Duration) (time.Duration, bool) {
	if rtt <= 0 {
		// TCP_INFO should normally have an RTT after connect/accept. If it is
		// unavailable, keep the feature enabled with the conservative cap.
		return tlsBatchCorkMaxDelay, true
	}
	if rtt < tlsBatchCorkRTTThreshold {
		return 0, false
	}
	d := rtt / 8
	if d > tlsBatchCorkMaxDelay {
		d = tlsBatchCorkMaxDelay
	}
	return d, true
}

// tlsBatchCork controls TCP_CORK once per TLSVPN batch instead of wrapping the
// TLS transport's Write method. This keeps crypto/tls and uTLS on their normal
// socket hot path while still allowing adjacent batches to share a final TCP
// segment.
type tlsBatchCork struct {
	mu sync.Mutex

	setCork    func(bool) error
	carryState *atomic.Bool
	delay      time.Duration
	mss        int

	// noop is immutable after construction. RTT-gated/L2-only connections can
	// return before touching the mutex, leaving the existing data-plane hot path
	// effectively identical to main.
	noop bool

	enabled    bool
	corked     bool
	closed     bool
	progress   int
	deadline   time.Time
	timer      *time.Timer
	timerArmed bool
}

func newTLSBatchCork(conn net.Conn) *tlsBatchCork {
	c := &tlsBatchCork{delay: tlsBatchCorkMaxDelay, mss: fallbackTCPMSS, noop: true}
	tcp := underlyingTCPConn(conn)
	if tcp == nil {
		return c
	}
	if mss, err := getTCPMSS(tcp); err == nil && mss >= 256 {
		c.mss = mss
	}
	delay, enabled := tlsBatchCorkPolicyForRTT(ciphertextTransportRTT(tcp))
	if !enabled {
		return c
	}
	c.delay = delay
	c.setCork = func(on bool) error { return setTCPCork(tcp, on) }
	c.enabled = true
	c.noop = false
	return c
}

func newTLSBatchCorkForTest(mss int, delay time.Duration, setter func(bool) error) *tlsBatchCork {
	if mss < 256 {
		mss = fallbackTCPMSS
	}
	if delay <= 0 {
		delay = tlsBatchCorkMaxDelay
	}
	return &tlsBatchCork{setCork: setter, delay: delay, mss: mss, enabled: setter != nil, noop: setter == nil}
}

// BindCarryState exposes only a lock-free boolean to the multipath scheduler.
// The pointer is bound before the writer goroutine starts; scheduler reads never
// take the cork mutex.
func (c *tlsBatchCork) BindCarryState(state *atomic.Bool) {
	if c == nil || state == nil {
		return
	}
	c.mu.Lock()
	c.carryState = state
	state.Store(c.corked)
	c.mu.Unlock()
}

func (c *tlsBatchCork) publishCarryLocked(v bool) {
	if c.carryState != nil {
		c.carryState.Store(v)
	}
}

// BeforeWrite must be called exactly once for a data-plane TLSVPN batch, before
// tlsConn.Write. It does not see individual TLS records. progress is measured
// conservatively in TLSVPN plaintext bytes: once at least one MSS of new data
// has arrived, the previous partial TCP segment must have had enough real bytes
// available to be completed, so a fresh short deadline may begin.
func (c *tlsBatchCork) BeforeWrite(n int) {
	if c == nil || n <= 0 || c.noop {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled || c.closed {
		return
	}

	if !c.corked {
		if err := c.setCork(true); err != nil {
			// TCP_CORK is an optional optimization. Failure must never take the
			// tunnel down; permanently fall back to the normal socket path.
			c.enabled = false
			c.publishCarryLocked(false)
			return
		}
		c.corked = true
		c.publishCarryLocked(true)
		c.progress = 0
		c.deadline = time.Now().Add(c.delay)
	}

	c.progress += n
	if c.progress >= c.mss {
		c.progress %= c.mss
		c.deadline = time.Now().Add(c.delay)
	} else if c.deadline.IsZero() {
		c.deadline = time.Now().Add(c.delay)
	}
	c.ensureTimerLocked()
}

func (c *tlsBatchCork) ensureTimerLocked() {
	if !c.enabled || !c.corked || c.closed || c.timerArmed {
		return
	}
	remaining := time.Until(c.deadline)
	if remaining < 0 {
		remaining = 0
	}
	if c.timer == nil {
		c.timer = time.AfterFunc(remaining, c.flushTimer)
	} else {
		c.timer.Reset(remaining)
	}
	c.timerArmed = true
}

func (c *tlsBatchCork) flushTimer() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.timerArmed || !c.enabled || !c.corked || c.closed {
		return
	}
	if remaining := time.Until(c.deadline); remaining > 0 {
		c.timer.Reset(remaining)
		return
	}
	c.timerArmed = false
	c.deadline = time.Time{}
	c.progress = 0
	if err := c.setCork(false); err != nil {
		c.enabled = false
		c.publishCarryLocked(false)
		return
	}
	c.corked = false
	c.publishCarryLocked(false)
}

func (c *tlsBatchCork) Close() {
	if c == nil || c.noop {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	if c.timer != nil && c.timerArmed {
		c.timer.Stop()
	}
	c.timerArmed = false
	if c.enabled && c.corked {
		_ = c.setCork(false)
	}
	c.corked = false
	c.publishCarryLocked(false)
	c.deadline = time.Time{}
	c.progress = 0
}
