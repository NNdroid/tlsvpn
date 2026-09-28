package main

import "testing"

// These tests lock the carry-tail invariant: transport boundaries are allowed
// to cross logical VPN frames, while a lone MTU-sized frame is never expanded
// with a large cover gap just to manufacture an MSS multiple.
func TestPersistentStreamChunkMaySplitVPNFrame(t *testing.T) {
	old := setPadMode(padModeBucket)
	defer setPadMode(old)

	p := newTunnelStreamPacker(paddingRecordLimitForMSS(1440))
	frames := getVPNFrameBatch(2)
	for i := range frames {
		frames[i] = VPNFrame{Seq: uint32(i + 1), Data: cloneFrame(make([]byte, 1500))}
	}
	p.appendOwnedFrames(frames, nil)

	target := p.alignedPrefixSize()
	if want := 2*1440 - tlsRecordOverheadReserve; target != want {
		t.Fatalf("downward MSS target=%d want=%d", target, want)
	}
	if got := (target + tlsRecordOverheadReserve) % 1440; got != 0 {
		t.Fatalf("aligned prefix remainder=%d", got)
	}
	// Each frame is 1510B. A 2848B prefix contains all of frame 1 and 1338B
	// of frame 2, proving the transport boundary cuts through a logical frame.
	completed := p.consume(target)
	if completed != 1 {
		t.Fatalf("aligned prefix should finish exactly one frame: completed=%d", completed)
	}
	if p.available() != 2*1510-target {
		t.Fatalf("unexpected carry tail: got=%d want=%d", p.available(), 2*1510-target)
	}
}

func TestSparseMTUFrameDoesNotPayLargeCoverGap(t *testing.T) {
	old := setPadMode(padModeBucket)
	defer setPadMode(old)

	p := newTunnelStreamPacker(paddingRecordLimitForMSS(1440))
	frames := getVPNFrameBatch(1)
	frames[0] = VPNFrame{Seq: 1, Data: cloneFrame(make([]byte, 1500))}
	p.appendOwnedFrames(frames, nil)

	before := p.available()
	if got := p.appendIdleCover(); got != 0 {
		t.Fatalf("single MTU frame should not spend a large MSS gap on cover: cover=%d", got)
	}
	if p.available() != before {
		t.Fatalf("stream changed despite rejected cover: before=%d after=%d", before, p.available())
	}
	if budget := streamPaddingBudget(before); budget > streamPadAbsoluteLimit || budget != before*streamPadRatioPercent/100 {
		t.Fatalf("unexpected sparse padding budget: useful=%d budget=%d", before, budget)
	}
}
