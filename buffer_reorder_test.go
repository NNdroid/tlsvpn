package main

import "testing"

func TestReorderDrainUsesFixedChunks(t *testing.T) {
	const frames = 1024

	rb := &ReorderBuffer{
		expectedSeq: 1,
		ring:        make([][]byte, ReorderWindowSize),
		seqSlots:    make([]uint32, ReorderWindowSize),
		windowMask:  ReorderWindowSize - 1,
		buffered:    frames,
	}

	for seq := uint32(1); seq <= frames; seq++ {
		idx := seq & rb.windowMask
		frame := getFrameAtLeast(64)[:64]
		frame[0] = byte(seq)
		rb.ring[idx] = frame
		rb.seqSlots[idx] = seq
	}

	rb.drainLocked()
	head := rb.takePendingLocked()
	if head == nil {
		t.Fatal("drain produced no output")
	}

	total, chunks := 0, 0
	for b := head; b != nil; b = b.next {
		chunks++
		if b.n <= 0 || b.n > reorderBatchHotCap {
			t.Fatalf("chunk %d has invalid length %d", chunks, b.n)
		}
		total += b.n
	}
	if total != frames {
		t.Fatalf("drained %d frames, want %d", total, frames)
	}
	wantChunks := (frames + reorderBatchHotCap - 1) / reorderBatchHotCap
	if chunks != wantChunks {
		t.Fatalf("chunks=%d, want %d", chunks, wantChunks)
	}
	if rb.buffered != 0 || rb.expectedSeq != frames+1 {
		t.Fatalf("post-drain state buffered=%d expected=%d", rb.buffered, rb.expectedSeq)
	}

	rb.freeBatch(head)
}

func BenchmarkReorderChunkDrain1024(b *testing.B) {
	rb := &ReorderBuffer{
		ring:       make([][]byte, ReorderWindowSize),
		seqSlots:   make([]uint32, ReorderWindowSize),
		windowMask: ReorderWindowSize - 1,
	}
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rb.expectedSeq = 1
		rb.buffered = 1024
		for seq := uint32(1); seq <= 1024; seq++ {
			idx := seq & rb.windowMask
			frame := getFrameAtLeast(64)[:64]
			rb.ring[idx] = frame
			rb.seqSlots[idx] = seq
		}
		rb.drainLocked()
		batch := rb.takePendingLocked()
		rb.freeBatch(batch)
	}
}
