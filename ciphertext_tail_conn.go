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

	// writeConn is the real local TCP socket whenever it can be unwrapped. Using
	// it directly lets net.Buffers use the standard library's writev fast path
	// when a previous tail and bytes from the next TLS write must be emitted as
	// one continuous MSS-aligned prefix.
	writeConn net.Conn

	mu           sync.Mutex
	enabled      bool
	mss          int
	tail         []byte
	scratch      []byte // fallback only when the transport cannot be unwrapped
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
	writeConn := conn
	if tcp := underlyingTCPConn(conn); tcp != nil {
		writeConn = tcp
	}
	return &ciphertextTailConn{Conn: conn, writeConn: writeConn, delay: delay}
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

// cancelTimerLocked is reserved for explicit flush/close/error paths. The hot
// Write path deliberately does not Stop/Reset the runtime timer on every TLS
// record; doing so was measurable at multi-gigabit rates.
func (c *ciphertextTailConn) cancelTimerLocked() {
	if c.timer != nil && c.timerArmed {
		c.timer.Stop()
	}
	c.timerArmed = false
	c.tailDeadline = time.Time{}
}

// ensureTimerLocked arms a timer only when none is already active. If a newer
// carried tail replaces an older one while the old timer is still pending, the
// callback observes tailDeadline and re-arms itself for the remaining time.
func (c *ciphertextTailConn) ensureTimerLocked() {
	if len(c.tail) == 0 || c.closed || !c.enabled {
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

// writeJoinedPrefixLocked emits [oldTail][newPrefix] without turning the old
// tail into its own socket write. On a real TCP socket net.Buffers.WriteTo uses
// Go's writev fast path, so the pair normally costs one syscall. The scratch
// fallback preserves the same single-Write semantics for unusual wrapped
// transports that cannot expose their TCP socket.
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

func (c *ciphertextTailConn) flushTailLocked() error {
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

func (c *ciphertextTailConn) flushFromTimer() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.timerArmed || c.closed || !c.enabled || c.asyncErr != nil {
		return
	}
	if len(c.tail) == 0 {
		c.timerArmed = false
		c.tailDeadline = time.Time{}
		return
	}
	// A newer tail may have replaced the one for which this callback was first
	// armed. Do not flush that newer tail early; wait until its own deadline.
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
	c.cancelTimerLocked()
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
	oldTailLen := len(c.tail)
	total := oldTailLen + len(p)
	sendLen := total / c.mss * c.mss

	if sendLen == 0 {
		// No full MSS is available yet. These bytes extend the existing tail;
		// retain the original oldest-byte deadline rather than sliding it.
		if oldTailLen == 0 {
			c.tailDeadline = time.Now().Add(c.delay)
		}
		c.tail = append(c.tail, p...)
		c.ensureTimerLocked()
		return accepted, nil
	}

	// sendLen is a prefix of the logical concatenation [tail][p]. Because tail
	// is always < MSS, at least one byte from p participates whenever sendLen>0.
	fromP := sendLen - oldTailLen
	if fromP < 0 || fromP > len(p) {
		return 0, c.failLocked(io.ErrShortWrite)
	}
	if err := c.writeJoinedPrefixLocked(c.tail, p[:fromP]); err != nil {
		return 0, c.failLocked(err)
	}
	c.tail = c.tail[:0]
	p = p[fromP:]

	// p now contains strictly less than one MSS. It is a new carried tail, so
	// give it a fresh bounded deadline. An already-active older timer is left
	// alone; its callback will re-arm for this newer deadline if necessary.
	if len(p) > 0 {
		c.tail = append(c.tail, p...)
		c.tailDeadline = time.Now().Add(c.delay)
		c.ensureTimerLocked()
	} else {
		c.tailDeadline = time.Time{}
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
	c.cancelTimerLocked()
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
