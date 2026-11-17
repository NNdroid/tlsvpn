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

// TestReorderResetShrinksGrownWindow 一次大偏斜把窗口扩到 8192 后，Reset 必须
// 把 ring/seqSlots 缩回初始 2048——扩容后的描述符（满档 65536 约 0.8MB）不应
// 常驻到会话结束。缩回只在 Reset（会话重置，单写者）时发生，热路径不缩容。
func TestReorderResetShrinksGrownWindow(t *testing.T) {
	rb := NewReorderBuffer(nil)
	defer rb.Close()
	rb.Insert(1, getFrameAtLeast(32)[:32])
	rb.Insert(1+5000, getFrameAtLeast(32)[:32])
	if len(rb.ring) <= ReorderWindowSize {
		t.Fatalf("前置条件失败：偏斜未触发扩容 ring=%d", len(rb.ring))
	}
	rb.Reset()
	if len(rb.ring) != ReorderWindowSize || len(rb.seqSlots) != ReorderWindowSize ||
		rb.windowMask != ReorderWindowSize-1 {
		t.Fatalf("Reset 后窗口未缩回: ring=%d seqSlots=%d mask=%d",
			len(rb.ring), len(rb.seqSlots), rb.windowMask)
	}
	// 缩回后缓冲区仍可正常工作。
	rb.Insert(1, getFrameAtLeast(32)[:32])
	if rb.ExpectedSeqSnapshot() != 2 {
		t.Fatalf("Reset 后 Insert 不可用: expectedSeq=%d", rb.ExpectedSeqSnapshot())
	}
}

// TestReorderResetActorShrinksGrownWindow 同上走 actor 路径：ResetActor 在
// epoch barrier 内由唯一写者调用，扩容窗口同样必须缩回初始 2048。
func TestReorderResetActorShrinksGrownWindow(t *testing.T) {
	rb := NewActorReorderBuffer(nil)
	defer rb.Close()
	rb.InsertActor(1, getFrameAtLeast(32)[:32])
	rb.InsertActor(1+5000, getFrameAtLeast(32)[:32])
	if len(rb.ring) <= ReorderWindowSize {
		t.Fatalf("前置条件失败：偏斜未触发扩容 ring=%d", len(rb.ring))
	}
	rb.ResetActor()
	if len(rb.ring) != ReorderWindowSize || len(rb.seqSlots) != ReorderWindowSize ||
		rb.windowMask != ReorderWindowSize-1 {
		t.Fatalf("ResetActor 后窗口未缩回: ring=%d seqSlots=%d mask=%d",
			len(rb.ring), len(rb.seqSlots), rb.windowMask)
	}
}
