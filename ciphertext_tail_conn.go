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
// during TLS/TLSVPN handshakes, then enabled for the data plane.
//
// Linux fast path: TCP_CORK keeps only the final partial TCP payload in the
// kernel while complete MSS segments continue to leave immediately. The next
// ordinary TLS socket Write therefore fills that partial segment with zero
// userspace copying or writev reshaping. A short idle deadline temporarily
// uncorks to flush a sparse tail, then corks again for the next burst.
//
// Fallback path: if the real TCP socket is unavailable (or TCP_CORK is not
// supported), retain at most MSS-1 ciphertext bytes in userspace and combine
// them with the next TLS write. No synthetic padding is added in either path.
type ciphertextTailConn struct {
	net.Conn

	writeConn net.Conn
	tcpConn   *net.TCPConn

	mu         sync.Mutex
	enabled    bool
	kernelCork bool
	mss        int

	// kernelPending is the logical number of bytes in the current partial MSS
	// while TCP_CORK owns the actual bytes. tail is used only by the fallback.
	kernelPending int
	tail          []byte
	scratch       []byte

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
	tcp := underlyingTCPConn(conn)
	writeConn := conn
	if tcp != nil {
		writeConn = tcp
	}
	return &ciphertextTailConn{Conn: conn, writeConn: writeConn, tcpConn: tcp, delay: delay}
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
	c.kernelPending = 0
	c.tail = c.tail[:0]
	// Prefer kernel carry whenever the platform exposes TCP_CORK. This keeps
	// the TLS hot path identical to main: one ordinary socket Write per TLS
	// ciphertext write, with no userspace MSS splitting.
	if c.tcpConn != nil && setTCPCork(c.tcpConn, true) == nil {
		c.kernelCork = true
		return
	}
	c.kernelCork = false
	if cap(c.tail) < mss {
		c.tail = make([]byte, 0, mss)
	}
}

func (c *ciphertextTailConn) pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.kernelCork {
		return c.kernelPending
	}
	return len(c.tail)
}

func (c *ciphertextTailConn) hasPendingLocked() bool {
	if c.kernelCork {
		return c.kernelPending != 0
	}
	return len(c.tail) != 0
}

// cancelTimerLocked is reserved for explicit flush/close/error paths. The hot
// Write path deliberately does not Stop/Reset the runtime timer on every TLS
// record.
func (c *ciphertextTailConn) cancelTimerLocked() {
	if c.timer != nil && c.timerArmed {
		c.timer.Stop()
	}
	c.timerArmed = false
	c.tailDeadline = time.Time{}
}

func (c *ciphertextTailConn) ensureTimerLocked() {
	if !c.hasPendingLocked() || c.closed || !c.enabled {
		return
	}
	if c.tailDeadline.IsZero() {
		c.tailDeadline = time.Now().Add(c.delay)
	}
	if c.timerArmed {
		return
	}
	remaining := time.Until(c.tailDeadline)
	if remaining < 0 {
		remaining = 0
	}
	if c.timer == nil {
		c.timer = time.AfterFunc(remaining, c.flushFromTimer)
	} else {
		c.timer.Reset(remaining)
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

// writeJoinedPrefixLocked is only the non-TCP/non-CORK fallback. Real Linux TCP
// data traffic never enters this path.
func (c *ciphertextTailConn) writeJoinedPrefixLocked(oldTail, newPrefix []byte) error {
	want := len(oldTail) + len(newPrefix)
	if want == 0 {
		return nil
	}
	if len(oldTail) == 0 {
		return writeAllConn(c.writeConn, newPrefix)
	}
	if _, ok := c.writeConn.(*net.TCPConn); ok {
		bufs := net.Buffers{oldTail, newPrefix}
		n, err := bufs.WriteTo(c.writeConn)
		if err != nil {
			return err
		}
		if n != int64(want) {
			return io.ErrShortWrite
		}
		return nil
	}
	c.scratch = append(c.scratch[:0], oldTail...)
	c.scratch = append(c.scratch, newPrefix...)
	return writeAllConn(c.writeConn, c.scratch)
}

func (c *ciphertextTailConn) failLocked(err error) error {
	if err == nil {
		return nil
	}
	if c.asyncErr == nil {
		c.asyncErr = err
	}
	c.cancelTimerLocked()
	_ = c.Conn.Close()
	return err
}

func (c *ciphertextTailConn) flushKernelTailLocked(recork bool) error {
	if !c.kernelCork || c.kernelPending == 0 {
		return nil
	}
	// Clearing TCP_CORK releases the current partial segment. For an ordinary
	// Flush we immediately cork again so the next burst retains its own tail.
	if err := setTCPCork(c.tcpConn, false); err != nil {
		return c.failLocked(err)
	}
	c.kernelPending = 0
	c.tailDeadline = time.Time{}
	if recork && !c.closed {
		if err := setTCPCork(c.tcpConn, true); err != nil {
			return c.failLocked(err)
		}
	} else {
		c.kernelCork = false
	}
	return nil
}

func (c *ciphertextTailConn) flushFallbackTailLocked() error {
	if len(c.tail) == 0 {
		return nil
	}
	if err := writeAllConn(c.writeConn, c.tail); err != nil {
		return c.failLocked(err)
	}
	c.tail = c.tail[:0]
	c.tailDeadline = time.Time{}
	return nil
}

func (c *ciphertextTailConn) flushTailLocked(recork bool) error {
	if c.kernelCork {
		return c.flushKernelTailLocked(recork)
	}
	return c.flushFallbackTailLocked()
}

func (c *ciphertextTailConn) flushFromTimer() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.timerArmed || c.closed || !c.enabled || c.asyncErr != nil {
		return
	}
	if !c.hasPendingLocked() {
		c.timerArmed = false
		c.tailDeadline = time.Time{}
		return
	}
	if !c.tailDeadline.IsZero() {
		if remaining := time.Until(c.tailDeadline); remaining > 0 {
			c.timer.Reset(remaining)
			return
		}
	}
	c.timerArmed = false
	c.tailDeadline = time.Time{}
	_ = c.flushTailLocked(true)
}

// Flush immediately releases the current real-data tail without adding cover
// bytes. In the Linux fast path this is an uncork/recork; no data is copied.
func (c *ciphertextTailConn) Flush() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.asyncErr != nil {
		return c.asyncErr
	}
	c.cancelTimerLocked()
	return c.flushTailLocked(true)
}

func (c *ciphertextTailConn) writeKernelCorkLocked(p []byte) (int, error) {
	oldPending := c.kernelPending
	n, err := c.Conn.Write(p)
	if n > 0 {
		total := oldPending + n
		newPending := total % c.mss
		crossedBoundary := total >= c.mss
		c.kernelPending = newPending
		if newPending == 0 {
			c.tailDeadline = time.Time{}
		} else {
			// A fresh partial segment starts either from an empty state or after
			// this write completed at least one full MSS. Only then may its idle
			// deadline advance; merely appending to the same partial tail keeps
			// the original oldest-byte deadline.
			if oldPending == 0 || crossedBoundary {
				c.tailDeadline = time.Now().Add(c.delay)
			}
			c.ensureTimerLocked()
		}
	}
	if err != nil {
		return n, err
	}
	return n, nil
}

func (c *ciphertextTailConn) writeFallbackLocked(p []byte) (int, error) {
	accepted := len(p)
	oldTailLen := len(c.tail)
	total := oldTailLen + len(p)
	sendLen := total / c.mss * c.mss

	if sendLen == 0 {
		if oldTailLen == 0 {
			c.tailDeadline = time.Now().Add(c.delay)
		}
		c.tail = append(c.tail, p...)
		c.ensureTimerLocked()
		return accepted, nil
	}

	fromP := sendLen - oldTailLen
	if fromP < 0 || fromP > len(p) {
		return 0, c.failLocked(io.ErrShortWrite)
	}
	if err := c.writeJoinedPrefixLocked(c.tail, p[:fromP]); err != nil {
		return 0, c.failLocked(err)
	}
	c.tail = c.tail[:0]
	p = p[fromP:]
	if len(p) > 0 {
		c.tail = append(c.tail, p...)
		c.tailDeadline = time.Now().Add(c.delay)
		c.ensureTimerLocked()
	} else {
		c.tailDeadline = time.Time{}
	}
	return accepted, nil
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
	if c.kernelCork {
		return c.writeKernelCorkLocked(p)
	}
	return c.writeFallbackLocked(p)
}

func (c *ciphertextTailConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return net.ErrClosed
	}
	c.closed = true
	c.cancelTimerLocked()
	var flushErr error
	if c.asyncErr == nil {
		flushErr = c.flushTailLocked(false)
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
