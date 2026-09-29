package main

import (
	"net"
	"sync"
	"time"
)

// tlsBatchCorkDelay is deliberately short: it only gives the next TLSVPN batch
// a chance to fill the current TCP tail. Sparse traffic is uncorked promptly.
const tlsBatchCorkDelay = 300 * time.Microsecond

// tlsBatchCork controls TCP_CORK once per TLSVPN batch instead of wrapping the
// TLS transport's Write method. This keeps crypto/tls and uTLS on their normal
// socket hot path while still allowing adjacent batches to share a final TCP
// segment.
type tlsBatchCork struct {
	mu sync.Mutex

	setCork func(bool) error
	delay   time.Duration
	mss     int

	enabled      bool
	corked       bool
	closed       bool
	progress     int
	deadline     time.Time
	timer        *time.Timer
	timerArmed   bool
}

func newTLSBatchCork(conn net.Conn) *tlsBatchCork {
	c := &tlsBatchCork{delay: tlsBatchCorkDelay, mss: fallbackTCPMSS}
	tcp := underlyingTCPConn(conn)
	if tcp == nil {
		return c
	}
	if mss, err := getTCPMSS(tcp); err == nil && mss >= 256 {
		c.mss = mss
	}
	c.setCork = func(on bool) error { return setTCPCork(tcp, on) }
	c.enabled = true
	return c
}

func newTLSBatchCorkForTest(mss int, delay time.Duration, setter func(bool) error) *tlsBatchCork {
	if mss < 256 {
		mss = fallbackTCPMSS
	}
	if delay <= 0 {
		delay = tlsBatchCorkDelay
	}
	return &tlsBatchCork{setCork: setter, delay: delay, mss: mss, enabled: setter != nil}
}

// BeforeWrite must be called exactly once for a data-plane TLSVPN batch, before
// tlsConn.Write. It does not see individual TLS records. progress is measured
// conservatively in TLSVPN plaintext bytes: once at least one MSS of new data
// has arrived, the previous partial TCP segment must have had enough real bytes
// available to be completed, so a fresh short deadline may begin.
func (c *tlsBatchCork) BeforeWrite(n int) {
	if c == nil || n <= 0 {
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
			return
		}
		c.corked = true
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
		return
	}
	c.corked = false
}

func (c *tlsBatchCork) Close() {
	if c == nil {
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
	c.deadline = time.Time{}
	c.progress = 0
}
