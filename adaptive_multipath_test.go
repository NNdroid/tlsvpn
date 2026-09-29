package main

import (
	"testing"
	"time"
)

func testAdaptiveBackend(rtt uint32) *Backend {
	r := rtt
	return &Backend{ch: make(chan []VPNFrame, 32), rttCache: &r}
}

func TestAdaptiveActivePathTarget(t *testing.T) {
	cases := []struct {
		pressure       uint64
		eligible, want int
	}{
		{0, 4, 1},
		{adaptiveActive2Pressure - 1, 4, 1},
		{adaptiveActive2Pressure, 4, 2},
		{adaptiveActive3Pressure, 4, 3},
		{adaptiveActive4Pressure, 4, 4},
		{adaptiveActive4Pressure, 2, 2},
	}
	for _, tc := range cases {
		if got := adaptiveActivePathTarget(tc.pressure, 0, tc.eligible); got != tc.want {
			t.Fatalf("pressure=%d eligible=%d got=%d want=%d", tc.pressure, tc.eligible, got, tc.want)
		}
	}
}

func TestAdaptiveSchedulerPrefersEarlierCompletionOverRawRTT(t *testing.T) {
	p := &AsyncPort{}
	fastRTT := testAdaptiveBackend(20_000)
	empty := testAdaptiveBackend(22_000)
	fastRTT.queuedBytes.Store(512 * 1024)
	fastRTT.rateBytesPerSec.Store(20_000_000)
	empty.rateBytesPerSec.Store(20_000_000)
	got := p.pickAdaptiveBackend([]*Backend{fastRTT, empty}, adaptiveActive2Pressure, 12*1024)
	if got != empty {
		t.Fatalf("queued lower-RTT path won: got=%p want=%p", got, empty)
	}
}

func TestAdaptiveSchedulerSinglePathStaysStickyBelowExpansionThreshold(t *testing.T) {
	p := &AsyncPort{}
	a := testAdaptiveBackend(20_000)
	b := testAdaptiveBackend(20_000)
	backends := []*Backend{a, b}

	first := p.pickAdaptiveBackend(backends, adaptiveActive2Pressure-1, 8*1024)
	if first == nil {
		t.Fatal("first adaptive choice is nil")
	}
	// Simulate one small batch still queued on the selected path. Its ETA becomes
	// slightly worse than the idle peer, but pressure still says one path is
	// enough; this must not turn low-rate traffic into per-batch round robin.
	first.queuedBytes.Store(8 * 1024)
	second := p.pickAdaptiveBackend(backends, adaptiveActive2Pressure-1, 8*1024)
	if second != first {
		t.Fatalf("single-path active set thrashed: first=%p second=%p", first, second)
	}
	if got := p.activePaths.Load(); got != 1 {
		t.Fatalf("activePaths=%d want 1", got)
	}
	if !first.active.Load() {
		t.Fatal("sticky path was not marked active")
	}
	other := a
	if other == first {
		other = b
	}
	if other.active.Load() {
		t.Fatal("standby path was marked active below expansion threshold")
	}
}

func TestAdaptiveSchedulerExcludesMateriallySlowerRTT(t *testing.T) {
	p := &AsyncPort{}
	a := testAdaptiveBackend(20_000)
	b := testAdaptiveBackend(21_000)
	slow := testAdaptiveBackend(60_000)
	for _, path := range []*Backend{a, b, slow} {
		path.rateBytesPerSec.Store(100_000_000)
	}
	_ = p.pickAdaptiveBackend([]*Backend{a, b, slow}, adaptiveActive4Pressure, 12*1024)
	if !a.active.Load() || !b.active.Load() {
		t.Fatalf("near-RTT paths not active: a=%v b=%v", a.active.Load(), b.active.Load())
	}
	if slow.active.Load() {
		t.Fatal("materially slower warmed path entered active set")
	}
	if got := p.activePaths.Load(); got != 2 {
		t.Fatalf("activePaths=%d want 2 eligible paths", got)
	}
}

func TestAdaptiveSchedulerCarryIsOnlyTieBreaker(t *testing.T) {
	p := &AsyncPort{}
	a := testAdaptiveBackend(20_000)
	b := testAdaptiveBackend(20_000)
	a.rateBytesPerSec.Store(100_000_000)
	b.rateBytesPerSec.Store(100_000_000)
	b.carryPending.Store(true)
	got := p.pickAdaptiveBackend([]*Backend{a, b}, adaptiveActive2Pressure, 4*1024)
	if got != b {
		t.Fatalf("carry pending did not win near tie: got=%p want=%p", got, b)
	}

	p.preferred.Store(nil)
	far := testAdaptiveBackend(40_000)
	far.rateBytesPerSec.Store(100_000_000)
	far.carryPending.Store(true)
	got = p.pickAdaptiveBackend([]*Backend{a, far}, adaptiveActive2Pressure, 4*1024)
	if got == far {
		t.Fatal("carry bonus overrode a materially better RTT")
	}
}

func TestAdaptiveQueueAccountingFollowsOwnership(t *testing.T) {
	rtt := uint32(10_000)
	b := &Backend{ch: make(chan []VPNFrame, 1), rttCache: &rtt}
	payload := getFrameAtLeast(1400)[:1400]
	batch := []VPNFrame{{Seq: 1, Data: payload}}
	if dropped := sendBatchTo(b, batch); dropped != 0 {
		t.Fatalf("send dropped=%d", dropped)
	}
	if got := b.queuedBytes.Load(); got != 1400 {
		t.Fatalf("queuedBytes=%d want 1400", got)
	}
	out := <-b.ch
	b.completeQueuedBytes(vpnFrameBatchBytes(out))
	if got := b.queuedBytes.Load(); got != 0 {
		t.Fatalf("queuedBytes after completion=%d want 0", got)
	}
	freeFrames(out)
	putVPNFrameBatch(out)
}

func TestSchedulerSnapshotExposesState(t *testing.T) {
	b := testAdaptiveBackend(10_000)
	b.queuedBytes.Store(4096)
	b.rateBytesPerSec.Store(125_000_000)
	b.etaUsec.Store(1234)
	b.active.Store(true)
	b.carryPending.Store(true)
	s := schedulerSnapshot(b)
	if s.QueuedBytes != 4096 || s.RateMbps != 1000 || s.ETAUs != 1234 || !s.Active || !s.CarryPending {
		t.Fatalf("unexpected snapshot: %+v", s)
	}
}

func TestAdaptiveActivePathTargetByDemandRate(t *testing.T) {
	cases := []struct {
		rate uint64
		want int
	}{
		{0, 1},
		{adaptiveActive2RateBytesPerSec - 1, 1},
		{adaptiveActive2RateBytesPerSec, 2},
		{adaptiveActive3RateBytesPerSec, 3},
		{adaptiveActive4RateBytesPerSec, 4},
	}
	for _, tc := range cases {
		if got := adaptiveActivePathTarget(0, tc.rate, 4); got != tc.want {
			t.Fatalf("rate=%d got=%d want=%d", tc.rate, got, tc.want)
		}
	}
}

func TestAdaptiveSchedulerVirtualFinishStripesShallowQueues(t *testing.T) {
	p := &AsyncPort{}
	backends := []*Backend{
		testAdaptiveBackend(20_000),
		testAdaptiveBackend(20_000),
		testAdaptiveBackend(20_000),
		testAdaptiveBackend(20_000),
	}
	for _, b := range backends {
		b.rateBytesPerSec.Store(100_000_000)
	}
	p.inputRateBytesPerSec.Store(adaptiveActive4RateBytesPerSec)
	seen := map[*Backend]int{}
	for i := 0; i < 8; i++ {
		seen[p.pickAdaptiveBackend(backends, 0, 12*1024)]++
		// Deliberately exceed one batch's estimated service time. A wall-clock
		// finish timestamp would expire here and collapse back to one path; logical
		// WFQ debt must survive and continue striping.
		time.Sleep(1 * time.Millisecond)
	}
	if len(seen) < 4 {
		t.Fatalf("logical service debt did not stripe all active paths: distinct=%d counts=%v", len(seen), seen)
	}
	for _, b := range backends {
		if !b.active.Load() {
			t.Fatal("high demand did not keep every eligible path active")
		}
	}
}

func TestAdaptiveSchedulerWriterRateCannotMonopolizePath(t *testing.T) {
	p := &AsyncPort{}
	a := testAdaptiveBackend(20_000)
	b := testAdaptiveBackend(20_000)
	// Deliberately publish a wildly different userspace writer-drain rate. This
	// telemetry must not become a positive-feedback scheduling weight.
	a.rateBytesPerSec.Store(400_000_000)
	b.rateBytesPerSec.Store(40_000_000)
	p.inputRateBytesPerSec.Store(adaptiveActive2RateBytesPerSec)
	counts := map[*Backend]int{}
	for i := 0; i < 60; i++ {
		counts[p.pickAdaptiveBackend([]*Backend{a, b}, 0, 12*1024)]++
	}
	if counts[a] == 0 || counts[b] == 0 {
		t.Fatalf("eligible path starved: counts=%v", counts)
	}
	diff := counts[a] - counts[b]
	if diff < 0 {
		diff = -diff
	}
	if diff > 2 {
		t.Fatalf("writer-rate telemetry skewed byte-fair WFQ: counts=%v", counts)
	}
}

func TestAdaptiveSchedulerUnknownPathGetsFairStart(t *testing.T) {
	p := &AsyncPort{}
	hot := testAdaptiveBackend(20_000)
	cold := testAdaptiveBackend(20_000)
	hot.rateBytesPerSec.Store(250_000_000)
	p.inputRateBytesPerSec.Store(adaptiveActive2RateBytesPerSec)
	counts := map[*Backend]int{}
	for i := 0; i < 12; i++ {
		counts[p.pickAdaptiveBackend([]*Backend{hot, cold}, 0, 12*1024)]++
	}
	if counts[cold] == 0 {
		t.Fatalf("unknown active path never received fair-start traffic: counts=%v", counts)
	}
	if counts[hot] > counts[cold]*3 || counts[cold] > counts[hot]*3 {
		t.Fatalf("fair-start distribution is badly skewed before cold path measurement: counts=%v", counts)
	}
}

func TestAdaptiveSchedulerColdMeasuredRTTWarmsBeforeExclusion(t *testing.T) {
	p := &AsyncPort{}
	hot := testAdaptiveBackend(20_000)
	coldSlow := testAdaptiveBackend(80_000)
	warmedSlow := testAdaptiveBackend(80_000)
	hot.rateBytesPerSec.Store(100_000_000)
	warmedSlow.rateBytesPerSec.Store(100_000_000)
	p.inputRateBytesPerSec.Store(adaptiveActive3RateBytesPerSec)

	counts := map[*Backend]int{}
	for i := 0; i < 12; i++ {
		counts[p.pickAdaptiveBackend([]*Backend{hot, coldSlow, warmedSlow}, 0, 12*1024)]++
	}
	if counts[coldSlow] == 0 {
		t.Fatalf("cold path with early high RTT was starved before delivery warm-up: counts=%v", counts)
	}
	if counts[warmedSlow] != 0 {
		t.Fatalf("already-warmed slow path bypassed near-MinRTT exclusion: counts=%v", counts)
	}
	if got := p.activePaths.Load(); got != 2 {
		t.Fatalf("activePaths=%d want hot+cold fair-start paths", got)
	}

	// Once the cold path has a real delivery-rate sample, its measured 80ms RTT
	// becomes authoritative and it must leave the active set immediately.
	coldSlow.rateBytesPerSec.Store(100_000_000)
	before := counts[coldSlow]
	for i := 0; i < 8; i++ {
		counts[p.pickAdaptiveBackend([]*Backend{hot, coldSlow, warmedSlow}, 0, 12*1024)]++
	}
	if counts[coldSlow] != before {
		t.Fatalf("warmed slow path kept receiving traffic after RTT exclusion: before=%d after=%d", before, counts[coldSlow])
	}
	if coldSlow.active.Load() {
		t.Fatal("warmed slow path retained stale active membership")
	}
	if got := p.activePaths.Load(); got != 1 {
		t.Fatalf("activePaths=%d want only near-MinRTT hot path after warm-up", got)
	}
}
