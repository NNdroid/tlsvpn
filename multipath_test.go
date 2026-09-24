package main

import (
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestReorderGapDeadlineStartsWhenFutureFrameArrives(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		delivered := make(chan byte, 4)
		rb := NewReorderBuffer(func(frame []byte) { delivered <- frame[0] })
		defer rb.Close()

		rb.Insert(1, []byte{1})
		synctest.Wait()
		if got := <-delivered; got != 1 {
			t.Fatalf("first frame = %d, want 1", got)
		}

		// Long idle time is not a gap and must not age the future deadline.
		time.Sleep(time.Second)
		rb.Insert(3, []byte{3})
		synctest.Wait()
		select {
		case got := <-delivered:
			t.Fatalf("future frame %d was delivered before the gap deadline", got)
		default:
		}

		time.Sleep(reorderSkipDelay)
		synctest.Wait()
		if got := <-delivered; got != 3 {
			t.Fatalf("frame after skipped gap = %d, want 3", got)
		}
		stats := rb.Stats()
		if stats.GapEvents != 1 || stats.TimeoutFlushes != 1 || stats.SkippedFrames != 1 {
			t.Fatalf("unexpected reorder stats: %+v", stats)
		}
	})
}

func TestPickBackendKeepsStickyPathUntilMateriallyBetterOrBackpressured(t *testing.T) {
	rttA, rttB := uint32(250_000), uint32(240_000)
	a := &Backend{ch: make(chan []VPNFrame, 32), rttCache: &rttA}
	b := &Backend{ch: make(chan []VPNFrame, 32), rttCache: &rttB}
	p := &AsyncPort{}

	if got := p.pickBackend([]*Backend{a, b}); got != b {
		t.Fatal("initial selection did not choose the lower-RTT backend")
	}
	atomic.StoreUint32(&rttA, 240_000)
	atomic.StoreUint32(&rttB, 255_000)
	if got := p.pickBackend([]*Backend{a, b}); got != b {
		t.Fatal("small RTT jitter switched the sticky backend")
	}

	for len(b.ch) < cap(b.ch)-2 {
		b.ch <- nil
	}
	if got := p.pickBackend([]*Backend{a, b}); got != a {
		t.Fatal("backpressured backend was not replaced")
	}
}

func TestParityQueueDropIsObservable(t *testing.T) {
	rtt := uint32(1)
	b := &Backend{ch: make(chan []VPNFrame, 1), rttCache: &rtt}
	b.ch <- nil
	if dropped := sendFrameTo(b, VPNFrame{Data: []byte{1}}); dropped != 1 {
		t.Fatalf("sendFrameTo drop count = %d, want 1", dropped)
	}
}
