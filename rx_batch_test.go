package main

import (
	"sync"
	"testing"
	"time"
)

func pooledTestFrame(v byte) []byte {
	b := getFrameAtLeast(64)[:64]
	b[0] = v
	return b
}

func TestRXSessionWorkerBatchesAcrossProducers(t *testing.T) {
	var mu sync.Mutex
	got := make([]byte, 0, 4)
	done := make(chan struct{})
	rb := NewReorderBuffer(func(frame []byte) {
		mu.Lock()
		got = append(got, frame[0])
		if len(got) == 4 {
			select {
			case <-done:
			default:
				close(done)
			}
		}
		mu.Unlock()
	})
	w := newRXSessionWorker(rb)
	defer func() { w.Close(); rb.Close() }()

	p1 := w.NewProducer(nil, func(err error) { t.Errorf("unexpected RX error: %v", err) })
	p2 := w.NewProducer(nil, func(err error) { t.Errorf("unexpected RX error: %v", err) })
	p1.Push(1, pooledTestFrame(1))
	p1.Push(3, pooledTestFrame(3))
	p1.Flush()
	p2.Push(2, pooledTestFrame(2))
	p2.Push(4, pooledTestFrame(4))
	p2.Flush()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ordered RX delivery")
	}
	mu.Lock()
	defer mu.Unlock()
	for i, want := range []byte{1, 2, 3, 4} {
		if got[i] != want {
			t.Fatalf("ordered byte[%d]=%d want=%d (all=%v)", i, got[i], want, got)
		}
	}
}

func TestRXSessionWorkerEpochDropsStaleProducer(t *testing.T) {
	got := make(chan byte, 2)
	rb := NewReorderBuffer(func(frame []byte) { got <- frame[0] })
	w := newRXSessionWorker(rb)
	defer func() { w.Close(); rb.Close() }()

	stale := w.NewProducer(nil, nil)
	stale.Push(1, pooledTestFrame(9))
	w.AdvanceEpoch()
	stale.Flush()

	fresh := w.NewProducer(nil, nil)
	fresh.Push(1, pooledTestFrame(1))
	fresh.Flush()
	select {
	case v := <-got:
		if v != 1 {
			t.Fatalf("stale epoch delivered byte=%d", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fresh epoch frame not delivered")
	}
}

func BenchmarkFECDecoderDataSerial16(b *testing.B) {
	d := NewFECDecoder(4, nil, nil)
	frame := make([]byte, 256)
	seq := uint32(1)
	b.ReportAllocs()
	b.SetBytes(16 * int64(len(frame)))
	for n := 0; n < b.N; n++ {
		for i := 0; i < 16; i++ {
			d.OnData(seq, frame)
			seq++
		}
	}
}

func BenchmarkFECDecoderDataBatch16(b *testing.B) {
	d := NewFECDecoder(4, nil, nil)
	frame := make([]byte, 256)
	var batch [16]VPNFrame
	seq := uint32(1)
	b.ReportAllocs()
	b.SetBytes(16 * int64(len(frame)))
	for n := 0; n < b.N; n++ {
		for i := range batch {
			batch[i] = VPNFrame{Seq: seq, Data: frame}
			seq++
		}
		d.OnDataBatch(batch[:])
	}
}
