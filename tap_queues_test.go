package main

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testTapQueue struct {
	r      *io.PipeReader
	w      *io.PipeWriter
	closed atomic.Int32
}

func newTestTapQueue() *testTapQueue                { r, w := io.Pipe(); return &testTapQueue{r: r, w: w} }
func (q *testTapQueue) Read(b []byte) (int, error)  { return q.r.Read(b) }
func (q *testTapQueue) Write(b []byte) (int, error) { return q.w.Write(b) }
func (q *testTapQueue) Close() error                { q.closed.Add(1); _ = q.w.Close(); return q.r.Close() }

func TestTapQueuesConcurrentSequenceAndShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := NewAsyncPort(ctx, "mq-test")
	defer p.Close()
	backend := make(chan *VPNFrameBatch, 128)
	p.RegisterOwnedBackend(backend, nil)
	mq := &tapQueues{}
	for i := 0; i < 4; i++ {
		mq.queues = append(mq.queues, newTestTapQueue())
	}
	stop := runTapReaders(mq, func(r io.Reader) {
		for {
			b := getFrameAtLeast(2)[:2]
			n, err := r.Read(b)
			if err != nil {
				putFrame(b)
				return
			}
			_ = p.WriteOwnedFrame(b[:n])
		}
	})
	defer stop()
	var producers sync.WaitGroup
	for lane, q := range mq.queues {
		producers.Add(1)
		go func(lane int, q io.ReadWriteCloser) {
			defer producers.Done()
			for i := 0; i < 64; i++ {
				if _, err := q.Write([]byte{byte(lane), byte(i)}); err != nil {
					return
				}
			}
		}(lane, q)
	}
	last := [4]int{-1, -1, -1, -1}
	seq := uint32(0)
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for seq < 256 {
		select {
		case batch := <-backend:
			for _, f := range batch.Frames {
				seq++
				if f.Seq != seq {
					t.Fatalf("sequence gap: %d != %d", f.Seq, seq)
				}
				lane := int(f.Data[0])
				index := int(f.Data[1])
				if index != last[lane]+1 {
					t.Fatalf("lane %d reordered: %d after %d", lane, index, last[lane])
				}
				last[lane] = index
			}
			putOwnedVPNFrameBatch(batch)
		case <-timer.C:
			t.Fatal("multi-queue data stalled")
		}
	}
	producers.Wait()
	done := make(chan struct{})
	go func() { stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock all readers")
	}
	_ = mq.Close()
	for _, q := range mq.queues {
		if q.(*testTapQueue).closed.Load() != 1 {
			t.Fatal("fd closed more than once")
		}
	}
}

func TestTapQueueConfigAndRestart(t *testing.T) {
	c := &Config{Mode: "client", Addr: "127.0.0.1:1234", PSK: "test-secret"}
	c.applyDefaults()
	if c.TapQueues != 1 {
		t.Fatal("single queue must remain default")
	}
	for _, n := range []int{-1, 17} {
		c.TapQueues = n
		if c.Validate() == nil {
			t.Fatalf("accepted %d", n)
		}
	}
	c.TapQueues = 4
	c.Tap = "mem"
	if c.Validate() == nil {
		t.Fatal("memory TAP cannot prove multi-queue")
	}
	c.Tap = "tap0"
	base := *c
	base.TapQueues = 1
	client := &Client{}
	client.bootCfg.Store(&base)
	server := &Server{bootCfg: &base}
	if len(client.NeedsRestart(c)) == 0 || len(server.NeedsRestart(c)) == 0 {
		t.Fatal("queue changes require restart")
	}
}
