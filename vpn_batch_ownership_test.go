package main

import (
	"context"
	"testing"
	"time"
)

var vpnBatchBenchSink uint64

func TestOwnedVPNFrameBatchTransferPreservesIdentityAndBytes(t *testing.T) {
	rtt := uint32(1)
	ch := make(chan *VPNFrameBatch, 1)
	b := &Backend{ownedCh: ch, rttCache: &rtt}
	batch := getOwnedVPNFrameBatch()
	payload := getFrameAtLeast(1400)[:1400]
	ptr := &payload[0]
	appendOwnedVPNFrame(batch, VPNFrame{Seq: 7, Data: payload})
	wantBatch := batch

	if !tryQueueOwnedBatch(b, batch) {
		freeOwnedVPNFrameBatch(batch)
		t.Fatal("owned batch queue unexpectedly full")
	}
	got := <-ch
	if got != wantBatch {
		t.Fatal("production owned channel copied/replaced the batch object")
	}
	if got.Bytes != 1400 || len(got.Frames) != 1 || got.Frames[0].Seq != 7 {
		t.Fatalf("unexpected owned batch: bytes=%d frames=%d", got.Bytes, len(got.Frames))
	}
	if &got.Frames[0].Data[0] != ptr {
		t.Fatal("payload backing buffer changed across ownership transfer")
	}
	freeOwnedVPNFrameBatch(got)
}

func TestAsyncPortOwnedBackendCarriesAuthoritativeBytes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := NewAsyncPort(ctx, "owned-batch-bytes")
	rtt := uint32(1)
	ch := make(chan *VPNFrameBatch, 4)
	p.RegisterOwnedBackend(ch, &rtt)
	defer p.UnregisterOwnedBackend(ch)

	payload := getFrameAtLeast(1379)[:1379]
	if err := p.WriteOwnedFrame(payload); err != nil {
		t.Fatal(err)
	}
	select {
	case batch := <-ch:
		if batch.Bytes != 1379 {
			t.Fatalf("batch.Bytes=%d, want 1379", batch.Bytes)
		}
		if vpnFrameBatchBytes(batch.Frames) != batch.Bytes {
			t.Fatal("authoritative batch byte count diverged from frame contents")
		}
		freeOwnedVPNFrameBatch(batch)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for owned batch")
	}
}

func BenchmarkVPNFrameBatchAccounting(b *testing.B) {
	frames := make([]VPNFrame, 64)
	payload := make([]byte, 1400)
	var total uint64
	for i := range frames {
		frames[i] = VPNFrame{Seq: uint32(i + 1), Data: payload}
		total += uint64(len(payload))
	}
	batch := &VPNFrameBatch{Frames: frames, Bytes: total}

	b.Run("Scan64", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			vpnBatchBenchSink = vpnFrameBatchBytes(frames)
		}
	})
	b.Run("Metadata", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			vpnBatchBenchSink = batch.Bytes
		}
	})
}

func TestAdaptiveSchedulerOwnedBackendQueues(t *testing.T) {
	p := &AsyncPort{}
	fastRTT := uint32(800)
	slowRTT := uint32(900)
	fast := &Backend{ownedCh: make(chan *VPNFrameBatch, 32), rttCache: &fastRTT}
	slow := &Backend{ownedCh: make(chan *VPNFrameBatch, 32), rttCache: &slowRTT}
	fast.rateBytesPerSec.Store(25_000_000)
	slow.rateBytesPerSec.Store(25_000_000)

	got := p.pickAdaptiveBackend([]*Backend{fast, slow}, 0, 12*1024)
	if got != fast {
		t.Fatalf("owned backend scheduler picked %p, want fast %p", got, fast)
	}
	if !fast.active.Load() || p.activePaths.Load() != 1 {
		t.Fatalf("owned backend was not admitted to active set: active=%v paths=%d", fast.active.Load(), p.activePaths.Load())
	}
}
