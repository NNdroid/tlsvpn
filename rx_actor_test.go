package main

import (
	"sync"
	"testing"
	"time"
)

func TestRXActorOwnsGapTimeout(t *testing.T) {
	got := make(chan byte, 4)
	rb := NewActorReorderBuffer(func(frame []byte) { got <- frame[0] })
	w := newRXSessionWorker(rb)
	defer func() { w.Close(); rb.Close() }()
	p := w.NewProducer(nil, func(err error) { t.Errorf("unexpected RX error: %v", err) })
	p.Push(1, pooledTestFrame(1))
	p.Push(3, pooledTestFrame(3))
	p.Flush()
	for _, want := range []byte{1, 3} {
		select {
		case v := <-got:
			if v != want {
				t.Fatalf("got byte=%d want=%d", v, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for byte=%d", want)
		}
	}
	stats := rb.Stats()
	if stats.TimeoutFlushes != 1 || stats.SkippedFrames != 1 {
		t.Fatalf("actor timeout stats=%+v, want one flush skipping one frame", stats)
	}
}

func TestRXActorEpochResetCancelsOldGap(t *testing.T) {
	got := make(chan byte, 8)
	rb := NewActorReorderBuffer(func(frame []byte) { got <- frame[0] })
	w := newRXSessionWorker(rb)
	defer func() { w.Close(); rb.Close() }()
	stale := w.NewProducer(nil, nil)
	stale.Push(1, pooledTestFrame(1))
	stale.Push(3, pooledTestFrame(3))
	stale.Flush()
	select {
	case v := <-got:
		if v != 1 {
			t.Fatalf("pre-reset byte=%d want=1", v)
		}
	case <-time.After(time.Second):
		t.Fatal("pre-reset seq=1 not delivered")
	}
	w.AdvanceEpochAndReset(nil)
	fresh := w.NewProducer(nil, nil)
	fresh.Push(1, pooledTestFrame(7))
	fresh.Push(2, pooledTestFrame(8))
	fresh.Flush()
	for _, want := range []byte{7, 8} {
		select {
		case v := <-got:
			if v != want {
				t.Fatalf("post-reset byte=%d want=%d", v, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("post-reset byte=%d not delivered", want)
		}
	}
	time.Sleep(2 * reorderSkipDelay)
	select {
	case v := <-got:
		t.Fatalf("stale pre-reset frame leaked after actor reset: %d", v)
	default:
	}
}

func TestRXActorFECRecoveryStaysOnOwner(t *testing.T) {
	var mu sync.Mutex
	got := make([]byte, 0, 4)
	done := make(chan struct{})
	rb := NewActorReorderBuffer(func(frame []byte) {
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
	parts := [][]byte{pooledTestFrame(1), pooledTestFrame(2), pooledTestFrame(3), pooledTestFrame(4)}
	parity := encodeGroup(4, nil, 1, parts)
	putFrame(parts[1])
	fec := NewFECDecoder(4, nil, rb.InsertActor)
	fec.SetReorderProgress(rb.ExpectedSeqActor)
	p := w.NewProducer(fec, func(err error) { t.Errorf("unexpected FEC control error: %v", err) })
	p.Push(1, parts[0])
	p.Push(3, parts[2])
	p.Push(4, parts[3])
	p.Push(0, parity)
	p.Flush()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for actor-owned FEC recovery")
	}
	mu.Lock()
	defer mu.Unlock()
	want := []byte{1, 2, 3, 4}
	if len(got) != len(want) {
		t.Fatalf("delivered=%v want=%v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("delivered[%d]=%d want=%d (all=%v)", i, got[i], want[i], got)
		}
	}
	recovered, _ := fec.FECStats()
	if recovered != 1 {
		t.Fatalf("recovered=%d want=1", recovered)
	}
}

func BenchmarkFECDecoderDataActor16(b *testing.B) {
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
		for i := range batch {
			_, rec, _ := d.OnDataActor(batch[i].Seq, batch[i].Data)
			if rec != nil {
				putFrame(rec)
			}
		}
	}
}
