package main

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestStreamAlignedTLSPlaintextTarget(t *testing.T) {
	if got := streamAlignedTLSPlaintextTarget(2000, 1440); got != 2848 {
		t.Fatalf("2000B batch target=%d want 2848", got)
	}
	if got := streamAlignedTLSPlaintextTarget(10000, 1440); got != 10048 {
		t.Fatalf("10000B batch target=%d want 10048", got)
	}
}

func TestStreamPaddingBudget(t *testing.T) {
	if got := streamPaddingBudget(1500); got != 150 {
		t.Fatalf("1500B budget=%d want 150", got)
	}
	if got := streamPaddingBudget(10000); got != streamPadAbsoluteLimit {
		t.Fatalf("10000B budget=%d want %d", got, streamPadAbsoluteLimit)
	}
}

func TestStreamTailPaddingSkipsWastefulSingleMTUBatch(t *testing.T) {
	old := setPadMode(padModeBucket)
	defer setPadMode(old)
	frames := getVPNFrameBatch(1)
	frames[0] = VPNFrame{Seq: 1, Data: cloneFrame(make([]byte, 1500))}
	buf, _, last := appendOwnedFrameBatchStream(nil, frames, nil)
	before := len(buf)
	buf, pad := padStreamBatchTail(buf, last, paddingRecordLimitForMSS(1440))
	if pad != 0 {
		t.Fatalf("wasteful single-frame tail padding=%d, want 0", pad)
	}
	if len(buf) != before {
		t.Fatalf("single-frame batch length changed: before=%d after=%d", before, len(buf))
	}
	if got := binary.BigEndian.Uint16(buf[last+4 : last+6]); got != 0 {
		t.Fatalf("single-frame pad header=%d want 0", got)
	}
}

func TestStreamTailPaddingAppliesWhenCheap(t *testing.T) {
	old := setPadMode(padModeBucket)
	defer setPadMode(old)
	frames := getVPNFrameBatch(2)
	frames[0] = VPNFrame{Seq: 1, Data: cloneFrame(make([]byte, 4990))}
	frames[1] = VPNFrame{Seq: 2, Data: cloneFrame(make([]byte, 4990))}
	buf, _, last := appendOwnedFrameBatchStream(nil, frames, nil)
	if firstPad := binary.BigEndian.Uint16(buf[4:6]); firstPad != 0 {
		t.Fatalf("first frame unexpectedly padded: %d", firstPad)
	}
	before := len(buf)
	buf, pad := padStreamBatchTail(buf, last, paddingRecordLimitForMSS(1440))
	if pad <= 0 || pad > streamPaddingBudget(before) {
		t.Fatalf("cheap tail padding=%d budget=%d", pad, streamPaddingBudget(before))
	}
	if got := binary.BigEndian.Uint16(buf[last+4 : last+6]); int(got) != pad {
		t.Fatalf("last frame pad header=%d want %d", got, pad)
	}
	if (len(buf)+tlsRecordOverheadReserve)%1440 != 0 {
		t.Fatalf("batch is not MSS aligned: plaintext=%d", len(buf))
	}
}

func TestStreamCoalesceDelay(t *testing.T) {
	tests := []struct {
		bytes int
		want  time.Duration
	}{
		{0, 0},
		{1500, 500 * time.Microsecond},
		{3000, 350 * time.Microsecond},
		{6000, 150 * time.Microsecond},
		{9000, 0},
	}
	for _, tt := range tests {
		if got := streamCoalesceDelay(tt.bytes); got != tt.want {
			t.Fatalf("streamCoalesceDelay(%d)=%s want %s", tt.bytes, got, tt.want)
		}
	}
}
