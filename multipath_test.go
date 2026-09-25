package main

import (
	"bytes"
	"context"
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

func TestSendBatchTransfersPayloadOwnershipWithoutCopy(t *testing.T) {
	rtt := uint32(1)
	b := &Backend{ch: make(chan []VPNFrame, 1), rttCache: &rtt}

	payload := getFrameAtLeast(1400)[:1400]
	payload[0] = 0x5a
	ptr := &payload[0]
	batch := []VPNFrame{{Seq: 7, Data: payload}}

	if dropped := sendBatchTo(b, batch); dropped != 0 {
		t.Fatalf("sendBatchTo dropped=%d, want 0", dropped)
	}
	if batch[0].Data != nil {
		t.Fatal("caller retained payload after ownership transfer")
	}

	out := <-b.ch
	if len(out) != 1 || out[0].Seq != 7 || len(out[0].Data) != 1400 {
		t.Fatalf("unexpected transferred batch: %+v", out)
	}
	if &out[0].Data[0] != ptr {
		t.Fatal("payload was copied instead of ownership-transferred")
	}
	if out[0].Data[0] != 0x5a {
		t.Fatal("transferred payload content changed")
	}

	freeFrames(out)
	putVPNFrameBatch(out)
}

func TestSendBatchFallsBackWhenPreferredBackendIsFull(t *testing.T) {
	rttA, rttB := uint32(1), uint32(2)
	preferred := &Backend{ch: make(chan []VPNFrame, 1), rttCache: &rttA}
	alternate := &Backend{ch: make(chan []VPNFrame, 1), rttCache: &rttB}
	preferred.ch <- nil // force preferred full

	payload := getFrameAtLeast(512)[:512]
	payload[0] = 0x7b
	batch := []VPNFrame{{Seq: 9, Data: payload}}

	if dropped := sendBatchToAny([]*Backend{preferred, alternate}, preferred, batch); dropped != 0 {
		t.Fatalf("fallback send dropped=%d, want 0", dropped)
	}
	select {
	case out := <-alternate.ch:
		if len(out) != 1 || out[0].Seq != 9 || out[0].Data[0] != 0x7b {
			t.Fatalf("unexpected fallback batch: %+v", out)
		}
		freeFrames(out)
		putVPNFrameBatch(out)
	default:
		t.Fatal("alternate backend did not receive fallback batch")
	}
}

func TestAsyncPortBackpressureDoesNotConsumeSequenceBeforeBackendSlot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := NewAsyncPort(ctx, "pre-seq-backpressure")
	rtt := uint32(1)
	ch := make(chan []VPNFrame, 1)
	// 先占满唯一 backend slot。旧实现会先分配 seq，再最多等 5ms 后把这帧
	// 丢掉；新实现应一直把它保留在 seq 分配之前。
	ch <- nil
	p.RegisterBackend(ch, &rtt)
	defer p.UnregisterBackend(ch)

	if err := p.WriteFrame(bytes.Repeat([]byte{0x5a}, 1400)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond) // 明确超过旧 sendBatchToAny 的 5ms 丢弃窗口
	<-ch                             // 释放 backend slot

	select {
	case batch := <-ch:
		if len(batch) != 1 || batch[0].Seq != 1 {
			t.Fatalf("unexpected batch after backpressure release: %+v", batch)
		}
		freeFrames(batch)
		putVPNFrameBatch(batch)
	case <-time.After(time.Second):
		t.Fatal("frame was dropped while waiting for backend capacity")
	}
}

func TestFECParityIsSentOnceAcrossMultipleBackends(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := NewAsyncPort(ctx, "fec-single-parity")
	p.AttachFEC(2, nil)

	rtts := []uint32{1000, 2000, 3000}
	chans := make([]chan []VPNFrame, 3)
	for i := range chans {
		chans[i] = make(chan []VPNFrame, 8)
		p.RegisterBackend(chans[i], &rtts[i])
		defer p.UnregisterBackend(chans[i])
	}

	if err := p.WriteFrame(bytes.Repeat([]byte{0x11}, 1400)); err != nil {
		t.Fatal(err)
	}
	if err := p.WriteFrame(bytes.Repeat([]byte{0x22}, 1400)); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Second)
	dataFrames, parityFrames := 0, 0
	for time.Now().Before(deadline) && (dataFrames < 2 || parityFrames < 1) {
		for _, ch := range chans {
			for {
				select {
				case batch := <-ch:
					for _, vf := range batch {
						if vf.Seq == 0 {
							parityFrames++
						} else {
							dataFrames++
						}
					}
					freeFrames(batch)
					putVPNFrameBatch(batch)
				default:
					goto nextBackend
				}
			}
		nextBackend:
		}
		if dataFrames < 2 || parityFrames < 1 {
			time.Sleep(time.Millisecond)
		}
	}
	if dataFrames != 2 {
		t.Fatalf("data frames=%d, want 2", dataFrames)
	}
	if parityFrames != 1 {
		t.Fatalf("parity copies=%d, want exactly 1 across all backends", parityFrames)
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
