package main

import "testing"

func TestPersistentStreamChunkMaySplitVPNFrame(t *testing.T) {
	old := setPadMode(padModeBucket)
	defer setPadMode(old)

	p := newTunnelStreamPacker(paddingRecordLimitForMSS(1440))
	frames := getVPNFrameBatch(12)
	for i := range frames {
		frames[i] = VPNFrame{Seq: uint32(i + 1), Data: cloneFrame(make([]byte, 1500))}
	}
	p.appendOwnedFrames(frames, nil)

	target := p.fullChunkSize()
	if got := (target + tlsRecordOverheadReserve) % 1440; got != 0 {
		t.Fatalf("full chunk is not MSS aligned: target=%d remainder=%d", target, got)
	}
	if p.available() <= target {
		t.Fatalf("test needs residual stream after first chunk: available=%d target=%d", p.available(), target)
	}

	// Each unencrypted frame is 1510 bytes. 10 frames end at 15100 bytes,
	// while an MSS-aligned target of 15808 lands 708 bytes inside frame 11.
	completed := p.consume(target)
	if completed != 10 {
		t.Fatalf("MSS chunk should end inside frame 11: completed=%d want=10", completed)
	}
	if p.available() == 0 {
		t.Fatal("split frame remainder was unexpectedly discarded")
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
