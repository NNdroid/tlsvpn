package main

import (
	"testing"
	"time"
)

func testAdaptiveBackend(rtt uint32) *Backend {
	r := rtt
	// 生产里 SRTT 与 tcpi_min_rtt 来自同一次 TCP_INFO 采样，故合成后端也一并
	// 填充 minRttCache；否则 adaptiveBackendMinRTT 一律返回 unknown，资格包络
	// 与 baseQualityUS 会落到哨兵分支而不是被测路径。
	m := rtt
	return &Backend{ch: make(chan []VPNFrame, 32), rttCache: &r, minRttCache: &m}
}

func TestAdaptiveActivePathTarget(t *testing.T) {
	// adaptiveActivePathTarget 返回未按候选数收口的目标（收口在调用方先放宽
	// 包络之后）：本表验证压力阈值的映射；旧用例 {adaptiveActive4Pressure,
	// eligible=2 → 2} 的收口语义已移入 pickAdaptiveBackend，由
	// TestAdaptiveSchedulerExcludesMateriallySlowerRTT（activePaths=2）覆盖。
	cases := []struct {
		pressure uint64
		want     int
	}{
		{0, 1},
		{adaptiveActive2Pressure - 1, 1},
		{adaptiveActive2Pressure, 2},
		{adaptiveActive3Pressure, 3},
		{adaptiveActive4Pressure, 4},
	}
	for _, tc := range cases {
		if got := adaptiveActivePathTarget(tc.pressure, 0, nil); got != tc.want {
			t.Fatalf("pressure=%d got=%d want=%d", tc.pressure, got, tc.want)
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
	// 跨路径探针的单向估计也要随快照上报，WebUI"去/回"列读的就是这两个字段。
	b.fwdOneWayUS.Store(1234)
	b.retOneWayUS.Store(5678)
	s := schedulerSnapshot(b)
	if s.QueuedBytes != 4096 || s.RateMbps != 1000 || s.ETAUs != 1234 || !s.Active || !s.CarryPending {
		t.Fatalf("unexpected snapshot: %+v", s)
	}
	if s.FwdOneWayUS != 1234 || s.RetOneWayUS != 5678 {
		t.Fatalf("one-way snapshot: fwd=%d ret=%d want 1234/5678", s.FwdOneWayUS, s.RetOneWayUS)
	}
	// fixture testAdaptiveBackend(10000) 设 minRttCache=10000µs（非哨兵），
	// 快照应原样上报该内核 min_rtt 地板。
	if s.MinRttUS != 10000 {
		t.Fatalf("min_rtt snapshot: got=%d want=10000", s.MinRttUS)
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
		if got := adaptiveActivePathTarget(0, tc.rate, nil); got != tc.want {
			t.Fatalf("rate=%d got=%d want=%d", tc.rate, got, tc.want)
		}
	}
}

// TestAdaptiveActivePathTargetCapacityDriven 容量驱动扩张：需求超过「已实测容量
// 路径的合计容量」的 80% 时，目标抬到已测路径数 + 1（未测路径凭防饿地板参与
// 承载并修正测量）；需求回落到容量水位内则回到阈值式结果。修正历史阈值把
// 单路径容量假设（40/100/180MB/s）写死、与实测容量脱节的问题。
func TestAdaptiveActivePathTargetCapacityDriven(t *testing.T) {
	const n = 3
	backends := make([]*Backend, n)
	obs := make([]envelopeObs, n)
	for i := range backends {
		backends[i] = testAdaptiveBackend(20_000)
		obs[i] = envelopeObs{alive: true}
	}
	// 两条路径实测容量合计 60MB/s，第三条未测得。容量合计直接喂 obs——
	// adaptiveActivePathTarget 只读观测快照，不重读原子。
	backends[0].deliverRateBytesPerSec.Store(30_000_000)
	backends[1].deliverRateBytesPerSec.Store(30_000_000)
	obs[0].deliverRate = 30_000_000
	obs[1].deliverRate = 30_000_000
	// 需求 70MB/s > 0.8×60MB/s=48MB/s：阈值式（<100MB/s → ≤2）不动，容量驱动
	// 抬到已测数+1 = 3（未测的第三条凭防饿地板参与）。
	if got := adaptiveActivePathTarget(0, 70_000_000, obs); got != 3 {
		t.Fatalf("capacity-driven target = %d, want 3", got)
	}
	// 需求 30MB/s 在容量水位内且低于需求阈值：want=1。
	if got := adaptiveActivePathTarget(0, 30_000_000, obs); got != 1 {
		t.Fatalf("within-capacity target = %d, want 1", got)
	}
	// 无实测容量：回退需求阈值（40MB/s → 2）。
	if got := adaptiveActivePathTarget(0, adaptiveActive2RateBytesPerSec, nil); got != 2 {
		t.Fatalf("threshold fallback target = %d, want 2", got)
	}
	// 未通过健康闸的路径容量不参与合计（防饿地板语义只对可服务路径成立）：
	// 剩 1 条实测 30MB/s，需求 70MB/s > 0.8×30MB/s=24MB/s → 已测数+1 = 2。
	obs[1] = envelopeObs{}
	if got := adaptiveActivePathTarget(0, 70_000_000, obs); got != 2 {
		t.Fatalf("dead-path capacity must not count: got=%d want 2 (1 measured + 1)", got)
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
