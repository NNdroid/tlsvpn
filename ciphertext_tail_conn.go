package main

import (
	"io"
	"net"
	"sync"
	"time"
)

// ciphertextTailCarryDelay bounds the latency added to a final partial TCP
// payload. Sustained traffic normally fills the carry from the next TLS record
// before this timer fires; sparse traffic is flushed unchanged at the deadline.
const ciphertextTailCarryDelay = 300 * time.Microsecond

// ciphertextTailConn sits below TLS and above the real socket. It is disabled
// during TLS/TLSVPN handshakes, then enabled for the data plane. Once enabled it
// writes complete TCP-MSS-sized ciphertext prefixes immediately and carries only
// the final real-data tail (< MSS) into the next TLS write. No padding is added.
//
// Returning len(p) while a copied tail remains buffered is intentional: this is
// a small bounded transport buffer, similar to bufio.Writer, with an automatic
// deadline flush. Delayed write failures close the underlying connection and are
// surfaced on the next Write/Flush.
type ciphertextTailConn struct {
	net.Conn

	mu           sync.Mutex
	enabled      bool
	mss          int
	tail         []byte
	timer        *time.Timer
	timerArmed   bool
	tailDeadline time.Time
	delay        time.Duration
	asyncErr     error
	closed       bool
}

func newCiphertextTailConn(conn net.Conn) *ciphertextTailConn {
	return newCiphertextTailConnWithDelay(conn, ciphertextTailCarryDelay)
}

func newCiphertextTailConnWithDelay(conn net.Conn, delay time.Duration) *ciphertextTailConn {
	if delay <= 0 {
		delay = ciphertextTailCarryDelay
	}
	return &ciphertextTailConn{Conn: conn, delay: delay}
}

func (c *ciphertextTailConn) Unwrap() net.Conn { return c.Conn }

// ciphertextCarryMSS returns the MSS of the TCP socket that actually carries
// these TLS ciphertext bytes. Under SOCKS5 this deliberately means the local
// client-to-proxy TCP hop.
func ciphertextCarryMSS(conn net.Conn) int {
	tcp := underlyingTCPConn(conn)
	if tcp != nil {
		if mss, err := getTCPMSS(tcp); err == nil && mss >= 256 {
			return mss
		}
	}
	return fallbackTCPMSS
}

func (c *ciphertextTailConn) Enable(mss int) {
	if mss < 256 {
		mss = fallbackTCPMSS
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.mss = mss
	c.enabled = true
	if cap(c.tail) < mss {
		c.tail = make([]byte, 0, mss)
	} else {
		c.tail = c.tail[:0]
	}
}

func (c *ciphertextTailConn) pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.tail)
}

func (c *ciphertextTailConn) stopTimerLocked() {
	if c.timer != nil && c.timerArmed {
		c.timer.Stop()
	}
	c.timerArmed = false
	c.tailDeadline = time.Time{}
}

func (c *ciphertextTailConn) armTimerLocked() {
	if len(c.tail) == 0 || c.closed || !c.enabled {
		c.stopTimerLocked()
		return
	}
	if c.timerArmed {
		// Do not slide the deadline forward: the oldest carried byte keeps a
		// hard latency bound even if small TLS writes keep arriving.
		return
	}
	c.tailDeadline = time.Now().Add(c.delay)
	if c.timer == nil {
		c.timer = time.AfterFunc(c.delay, c.flushFromTimer)
	} else {
		c.timer.Reset(c.delay)
	}
	c.timerArmed = true
}

func writeAllConn(conn net.Conn, p []byte) error {
	for len(p) > 0 {
		n, err := conn.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (c *ciphertextTailConn) failLocked(err error) error {
	if err == nil {
		return nil
	}
	if c.asyncErr == nil {
		c.asyncErr = err
	}
	c.stopTimerLocked()
	_ = c.Conn.Close()
	return err
}

func (c *ciphertextTailConn) flushTailLocked() error {
	if len(c.tail) == 0 {
		return nil
	}
	if err := writeAllConn(c.Conn, c.tail); err != nil {
		return c.failLocked(err)
	}
	c.tail = c.tail[:0]
	return nil
}

func (c *ciphertextTailConn) flushFromTimer() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.timerArmed || c.closed || !c.enabled || c.asyncErr != nil {
		return
	}
	// A Stop/Reset can race with a callback that has already started and is
	// waiting for c.mu. If a newer tail now owns a later deadline, the stale
	// callback must not flush it early; simply re-arm for the remaining time.
	if !c.tailDeadline.IsZero() {
		if remaining := time.Until(c.tailDeadline); remaining > 0 {
			c.timer.Reset(remaining)
			return
		}
	}
	c.timerArmed = false
	c.tailDeadline = time.Time{}
	_ = c.flushTailLocked()
}

// Flush immediately writes the current real-data tail without adding cover
// bytes. It is mainly used by Close and tests; ordinary data traffic relies on
// the bounded timer.
func (c *ciphertextTailConn) Flush() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.asyncErr != nil {
		return c.asyncErr
	}
	c.stopTimerLocked()
	return c.flushTailLocked()
}

func (c *ciphertextTailConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, net.ErrClosed
	}
	if c.asyncErr != nil {
		return 0, c.asyncErr
	}
	if !c.enabled {
		return c.Conn.Write(p)
	}
	if c.mss < 256 {
		c.mss = fallbackTCPMSS
	}

	accepted := len(p)
	c.stopTimerLocked()

	// First complete a previously carried partial MSS using the beginning of
	// this TLS ciphertext write.
	if len(c.tail) > 0 {
		need := c.mss - len(c.tail)
		if len(p) < need {
			c.tail = append(c.tail, p...)
			c.armTimerLocked()
			return accepted, nil
		}
		c.tail = append(c.tail, p[:need]...)
		if err := c.flushTailLocked(); err != nil {
			return 0, err
		}
		p = p[need:]
	}

	// Preserve the TLS library's existing write cadence: full MSS multiples are
	// passed straight through without copying into an application-sized buffer.
	full := len(p) / c.mss * c.mss
	if full > 0 {
		if err := writeAllConn(c.Conn, p[:full]); err != nil {
			return 0, c.failLocked(err)
		}
		p = p[full:]
	}

	// Copy at most MSS-1 bytes because the TLS caller may reuse p immediately
	// after Write returns.
	if len(p) > 0 {
		c.tail = append(c.tail[:0], p...)
		c.armTimerLocked()
	}
	return accepted, nil
}

func (c *ciphertextTailConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	c.closed = true
	c.stopTimerLocked()
	var flushErr error
	if c.asyncErr == nil {
		flushErr = c.flushTailLocked()
	} else {
		flushErr = c.asyncErr
	}
	closeErr := c.Conn.Close()
	c.mu.Unlock()
	if flushErr != nil {
		return flushErr
	}
	return closeErr
}
