package main

import (
	"encoding/binary"
	"testing"
)

func TestStreamAlignedTLSPlaintextTarget(t *testing.T) {
	if got := streamAlignedTLSPlaintextTarget(2000, 1440); got != 2848 {
		t.Fatalf("2000B batch target=%d want 2848", got)
	}
	if got := streamAlignedTLSPlaintextTarget(10000, 1440); got != 10048 {
		t.Fatalf("10000B batch target=%d want 10048", got)
	}
}

func TestStreamTailPaddingOnlyTouchesLastFrame(t *testing.T) {
	old := setPadMode(padModeBucket)
	defer setPadMode(old)
	frames := getVPNFrameBatch(2)
	frames[0] = VPNFrame{Seq: 1, Data: cloneFrame(make([]byte, 700))}
	frames[1] = VPNFrame{Seq: 2, Data: cloneFrame(make([]byte, 700))}
	buf, _, last := appendOwnedFrameBatchStream(nil, frames, nil)
	firstPad := binary.BigEndian.Uint16(buf[4:6])
	if firstPad != 0 {
		t.Fatalf("first frame unexpectedly padded: %d", firstPad)
	}
	before := len(buf)
	buf, pad := padStreamBatchTail(buf, last, paddingRecordLimitForMSS(1440))
	if pad <= 0 || len(buf) <= before {
		t.Fatalf("tail padding not added: pad=%d before=%d after=%d", pad, before, len(buf))
	}
	if got := binary.BigEndian.Uint16(buf[last+4 : last+6]); int(got) != pad {
		t.Fatalf("last frame pad header=%d want %d", got, pad)
	}
	if (len(buf)+tlsRecordOverheadReserve)%1440 != 0 {
		t.Fatalf("batch is not MSS aligned: plaintext=%d", len(buf))
	}
}
