package main

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type captureNetConn struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	writes []int
	closed bool
}

func (c *captureNetConn) Read([]byte) (int, error) { return 0, errors.New("read not supported") }
func (c *captureNetConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	c.writes = append(c.writes, len(p))
	return c.buf.Write(p)
}
func (c *captureNetConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}
func (c *captureNetConn) LocalAddr() net.Addr              { return dummyNetAddr("local") }
func (c *captureNetConn) RemoteAddr() net.Addr             { return dummyNetAddr("remote") }
func (c *captureNetConn) SetDeadline(time.Time) error      { return nil }
func (c *captureNetConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureNetConn) SetWriteDeadline(time.Time) error { return nil }
func (c *captureNetConn) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Len()
}
func (c *captureNetConn) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.buf.Bytes()...)
}

func (c *captureNetConn) WriteSizes() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.writes...)
}

type dummyNetAddr string

func (a dummyNetAddr) Network() string { return string(a) }
func (a dummyNetAddr) String() string  { return string(a) }

func TestCiphertextTailConnPassesHandshakeWritesThrough(t *testing.T) {
	under := &captureNetConn{}
	c := newCiphertextTailConnWithDelay(under, time.Second)
	payload := bytes.Repeat([]byte{0x11}, 137)
	n, err := c.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("Write=%d,%v want %d,nil", n, err, len(payload))
	}
	if got := under.Len(); got != len(payload) {
		t.Fatalf("disabled wrapper buffered handshake: underlying=%d want %d", got, len(payload))
	}
	if got := c.pending(); got != 0 {
		t.Fatalf("disabled wrapper pending=%d want 0", got)
	}
}

func TestCiphertextTailConnCarriesOnlySubMSSBytes(t *testing.T) {
	under := &captureNetConn{}
	c := newCiphertextTailConnWithDelay(under, time.Second)
	c.Enable(1440)

	first := bytes.Repeat([]byte{0x21}, 1510)
	n, err := c.Write(first)
	if err != nil || n != len(first) {
		t.Fatalf("first Write=%d,%v", n, err)
	}
	if got := under.Len(); got != 1440 {
		t.Fatalf("first underlying=%d want 1440", got)
	}
	if got := c.pending(); got != 70 {
		t.Fatalf("first pending=%d want 70", got)
	}

	second := bytes.Repeat([]byte{0x32}, 1370)
	n, err = c.Write(second)
	if err != nil || n != len(second) {
		t.Fatalf("second Write=%d,%v", n, err)
	}
	if got := under.Len(); got != 2880 {
		t.Fatalf("second underlying=%d want 2880", got)
	}
	if got := c.pending(); got != 0 {
		t.Fatalf("second pending=%d want 0", got)
	}
	if got := under.WriteSizes(); len(got) != 2 || got[0] != 1440 || got[1] != 1440 {
		t.Fatalf("underlying writes=%v want [1440 1440]", got)
	}

	want := append(append([]byte(nil), first...), second...)
	if got := under.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("ciphertext byte stream changed: got=%d want=%d bytes", len(got), len(want))
	}
}

func TestCiphertextTailConnDeadlineFlushesSparseTail(t *testing.T) {
	under := &captureNetConn{}
	c := newCiphertextTailConnWithDelay(under, 2*time.Millisecond)
	c.Enable(1440)
	payload := bytes.Repeat([]byte{0x44}, 100)
	if n, err := c.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write=%d,%v", n, err)
	}
	if got := under.Len(); got != 0 {
		t.Fatalf("tail flushed too early: %d", got)
	}
	deadline := time.Now().Add(200 * time.Millisecond)
	for under.Len() != len(payload) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := under.Len(); got != len(payload) {
		t.Fatalf("timer flush=%d want %d", got, len(payload))
	}
	if got := c.pending(); got != 0 {
		t.Fatalf("pending after timer=%d want 0", got)
	}
}

func TestCiphertextTailConnFlushPreservesSparseBytes(t *testing.T) {
	under := &captureNetConn{}
	c := newCiphertextTailConnWithDelay(under, time.Second)
	c.Enable(1440)
	payload := bytes.Repeat([]byte{0x55}, 731)
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := c.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := under.Bytes(); !bytes.Equal(got, payload) {
		t.Fatalf("Flush changed bytes: got=%d want=%d", len(got), len(payload))
	}
}
