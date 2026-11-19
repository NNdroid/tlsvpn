package main

import "testing"

func TestAdaptiveSchedulerFairStartsUnknownRTTPaths(t *testing.T) {
	p := &AsyncPort{}
	measured := testAdaptiveBackend(800)
	unknownA := testAdaptiveBackend(adaptiveUnknownRTTUS)
	unknownB := testAdaptiveBackend(adaptiveUnknownRTTUS)
	unknownC := testAdaptiveBackend(adaptiveUnknownRTTUS)
	backends := []*Backend{measured, unknownA, unknownB, unknownC}

	// Reproduce the real server-download startup state: one socket has obtained
	// a low TCP_INFO RTT while the other physical connections still contain the
	// legacy 50 ms bootstrap estimate. Under sustained bulk demand those unknown
	// paths must receive fair-start traffic instead of being excluded forever by
	// the near-MinRTT envelope.
	p.inputRateBytesPerSec.Store(adaptiveActive4RateBytesPerSec)
	counts := map[*Backend]int{}
	for i := 0; i < 40; i++ {
		counts[p.pickAdaptiveBackend(backends, 0, 12*1024)]++
	}
	if got := p.activePaths.Load(); got != 4 {
		t.Fatalf("activePaths=%d want 4", got)
	}
	for i, b := range backends {
		if counts[b] == 0 {
			t.Fatalf("path %d starved before RTT warm-up: counts=%v", i, counts)
		}
		if !b.active.Load() {
			t.Fatalf("path %d not active during RTT fair-start", i)
		}
	}
}

func TestAdaptiveSchedulerMeasuredSlowRTTStillExcluded(t *testing.T) {
	p := &AsyncPort{}
	fastA := testAdaptiveBackend(800)
	fastB := testAdaptiveBackend(900)
	unknown := testAdaptiveBackend(adaptiveUnknownRTTUS)
	slow := testAdaptiveBackend(80_000)
	// A measured path needs both RTT and a writer sample. Keep unknown cold.
	for _, b := range []*Backend{fastA, fastB, slow} {
		b.rateBytesPerSec.Store(100_000_000)
	}
	backends := []*Backend{fastA, fastB, unknown, slow}

	p.inputRateBytesPerSec.Store(adaptiveActive4RateBytesPerSec)
	counts := map[*Backend]int{}
	for i := 0; i < 30; i++ {
		counts[p.pickAdaptiveBackend(backends, 0, 12*1024)]++
	}
	if counts[unknown] == 0 {
		t.Fatalf("unknown RTT path did not receive fair-start traffic: counts=%v", counts)
	}
	if counts[slow] != 0 || slow.active.Load() {
		t.Fatalf("measured slow path entered near-MinRTT active set: counts=%v active=%v", counts, slow.active.Load())
	}
	if got := p.activePaths.Load(); got != 3 {
		t.Fatalf("activePaths=%d want 3 eligible paths", got)
	}
}

// TestAdaptiveSchedulerMinRTTElapsedEnvelope 资格包络按 tcpi_min_rtt 而非 SRTT
// 计算：瞬时拥塞把某条路径的 SRTT 抬到 60ms、但它的 min_rtt 仍是 900µs 时，该
// 路径必须留在候选集里——SRTT 只用于 ETA 遥测，不能搅动成员稳定性。
func TestAdaptiveSchedulerMinRTTElapsedEnvelope(t *testing.T) {
	p := &AsyncPort{}
	fastA := testAdaptiveBackend(800)
	fastB := testAdaptiveBackend(900)
	// 拥塞中的慢路径：SRTT 很高，但 min_rtt（无拥塞地板）仍与快路径同档。
	congested := testAdaptiveBackend(60_000)
	congested.minRttCache = new(uint32)
	*congested.minRttCache = 900
	for _, b := range []*Backend{fastA, fastB, congested} {
		b.rateBytesPerSec.Store(100_000_000)
	}
	backends := []*Backend{fastA, fastB, congested}

	p.inputRateBytesPerSec.Store(adaptiveActive4RateBytesPerSec)
	counts := map[*Backend]int{}
	for i := 0; i < 30; i++ {
		counts[p.pickAdaptiveBackend(backends, 0, 12*1024)]++
	}
	if counts[congested] == 0 {
		t.Fatalf("min_rtt-eligible congested path was excluded by the SRTT envelope: counts=%v", counts)
	}
	if got := p.activePaths.Load(); got != 3 {
		t.Fatalf("activePaths=%d want 3", got)
	}
	if !congested.active.Load() {
		t.Fatal("min_rtt-eligible congested path not marked active")
	}
}

// TestAdaptiveSchedulerMinRTTRanksBelowSRTT 候选排序同样吃 min_rtt：min_rtt 更优的
// 路径在两条都进候选集的前提下应被优先选中，即使它当前的 SRTT 略高（拥塞会
// 恢复，地板不会）。
//
// 资格包络按需放宽（demand starvation 逐级放宽）落地后，高需求会把远包络路径
// 拉进活跃集做吞吐聚合，此时字节公平 WFQ 按容量权重分摊、排名只决定成员与
// 平局裁决——"min_rtt 主导"改在单路径模式（active=1，rank0 即所选）下钉死：
// 若排名退化成 SRTT，noisy（SRTT 900µs）将反超 floor（SRTT 5000µs）并被选中，
// 测试同样失败。noisy 的 min_rtt 取 5000µs 使其落在基础包络内（两条同候选），
// 保证比较式真的发生。
func TestAdaptiveSchedulerMinRTTRanksBelowSRTT(t *testing.T) {
	p := &AsyncPort{}
	// floor 路径：min_rtt 700µs 但当下 SRTT 5000µs。
	floor := testAdaptiveBackend(5000)
	floor.minRttCache = new(uint32)
	*floor.minRttCache = 700
	// noisy 路径：min_rtt 5000µs（基础包络内）但当下 SRTT 900µs（刚恢复完拥塞）。
	noisy := testAdaptiveBackend(900)
	noisy.minRttCache = new(uint32)
	*noisy.minRttCache = 5000
	for _, b := range []*Backend{floor, noisy} {
		b.rateBytesPerSec.Store(100_000_000)
	}
	backends := []*Backend{floor, noisy}

	// 低需求：单路径模式，rank0 即所选。排名若吃 SRTT，noisy 会接管。
	counts := map[*Backend]int{}
	for i := 0; i < 30; i++ {
		counts[p.pickAdaptiveBackend(backends, 0, 12*1024)]++
	}
	if counts[floor] == 0 {
		t.Fatalf("lower min_rtt path never picked: counts=%v", counts)
	}
	if counts[floor] <= counts[noisy] {
		t.Fatalf("lower min_rtt should dominate ranking: floor=%d noisy=%d", counts[floor], counts[noisy])
	}
}
