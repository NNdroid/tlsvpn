package main

// 选路算法第二轮修复的回归测试。覆盖五个缺陷：
//
//  1. 冷/热路径排名尺度混排——未测路径的乐观回退键（min_rtt/2 等）系统性低于
//     已测探针值，冷路径抢跑 rank0（measured 分类排序 + sticky 守卫）。
//  2. 内核 min_rtt 是 min-ever——对持续劣化永久钝感（noteRTTSample 的
//     decayed-min 有效地板，包络与 min_rtt_* 排名改吃该值）。
//  3. 探针超时无健康信号——黑洞路径保持陈旧低地板持续赢得排名（streak 罚时）。
//  4. 资格包络固定宽度——高需求下高时延高容量路径永远无法参与聚合（逐级放宽）。
//  5. 容量估计只有饱和窗一个来源——永不饱和路径退出 25MB/s 保守地板（BDP 下界）。

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestAdaptiveSwitchMeasuredBeatsOptimisticColdFallback 冷路径凭低 min_rtt 的
// 乐观回退键不得压过已测更慢路径。修复前：冷路径回退键 = min_rtt/2（纯内核
// 地板），已测路径排名键 = 探针单向值（含协议开销 + halfRef≥1ms 抬底），前者
// 恒低于后者——8ms 冷路径（回退 4ms）恒排进 20ms 已测路径之前，拓扑变化时
// 活跃路径必然向未测路径游移一个探针收敛周期。修复后：measured 分类排序，
// 已测恒先于未测；冷路径探针收敛后凭真实值参与竞争。
func TestAdaptiveSwitchMeasuredBeatsOptimisticColdFallback(t *testing.T) {
	p := &AsyncPort{}
	warm := oneWayBackend(20_000, 20_000, 20_000, 30_000_000) // 已测：fwd 20ms
	// 冷路径：rate=0（fair-start），但 min_rtt 已采样到 8ms → 回退键 4ms，
	// 纯数值排序会压过 warm 的 20ms。
	cold := testAdaptiveBackend(8_000)
	cold.rateBytesPerSec.Store(0)
	backends := []*Backend{warm, cold}

	// latency_strict：每批取 rank[0]，无粘滞，行为差异最直接。
	p.routingAlgo.Store(routingAlgoCode(string(RoutingAlgoLatencyStrict)))
	for i := 0; i < 4; i++ {
		if got := p.pickAdaptiveBackend(backends, adaptiveActive2Pressure-1, 8*1024); got != warm {
			t.Fatalf("optimistic cold fallback stole rank0 (iter %d): got=%p want=%p", i, got, warm)
		}
	}

	// 冷路径探针收敛并测出真实 15ms（确实更快）：应立即正常参与竞争并接管。
	cold.fwdRankUS.Store(oneWayRankEncode(15_000))
	cold.retRankUS.Store(oneWayRankEncode(15_000))
	var mode atomic.Int32
	mode.Store(oneWayModeFwd)
	cold.oneWayModePtr = &mode
	if got := p.pickAdaptiveBackend(backends, adaptiveActive2Pressure-1, 8*1024); got != cold {
		t.Fatalf("converged cold path not allowed to compete: got=%p want=%p", got, cold)
	}
}

// TestAdaptiveSwitchStickyDoesNotHoldUnmeasuredPath 粘滞守卫：current 为未测
// 路径（回退键恰落在 rank0 + slack 带内）时不得粘滞保留——回退键乐观，放行会
// 把活跃路径单向锁死在未测路径上直到其探针收敛。
func TestAdaptiveSwitchStickyDoesNotHoldUnmeasuredPath(t *testing.T) {
	p := &AsyncPort{}
	a := oneWayBackend(20_000, 20_000, 20_000, 30_000_000) // 已测 rank0：20ms
	b := oneWayBackend(22_000, 22_000, 22_000, 30_000_000) // 已测次优：22ms
	cold := testAdaptiveBackend(42_000)                    // 未测冷路径：回退键 21ms
	cold.rateBytesPerSec.Store(0)
	backends := []*Backend{a, b, cold}

	// 21ms 落在 20ms + slack(20ms/16=1.25ms)=21.25ms 带内：修复前粘滞保留
	// current（cold），活跃路径锁死在未测路径上。
	p.preferred.Store(cold)
	if got := p.pickAdaptiveBackend(backends, adaptiveActive2Pressure-1, 8*1024); got != a {
		t.Fatalf("sticky held unmeasured path over measured best: got=%p want=%p", got, a)
	}
}

// TestNoteRTTSampleDecayedFloor 内核 RTT 有效化：decayed-min 地板在两个样本后
// 发布；瞬时拥塞（单窗高 SRTT）不抬地板（成员稳定性）；恢复时快降自愈；持续
// 高 SRTT 让地板慢升（0.5ms/s）最终跟上。
func TestNoteRTTSampleDecayedFloor(t *testing.T) {
	b := &Backend{}
	b.noteRTTSample(20_000)
	if v := b.effRttUS.Load(); v != 0 {
		t.Fatalf("single sample must not publish effective RTT, got %d", v)
	}
	b.noteRTTSample(20_000)
	if v := b.effRttUS.Load(); v != 20_000 {
		t.Fatalf("floor after two samples = %d, want 20000", v)
	}
	// 瞬时拥塞：SRTT 40ms 一窗，地板不动（慢升 0.5ms/s，单窗抬升可忽略）。
	b.noteRTTSample(40_000)
	if v := b.effRttUS.Load(); v > 21_000 {
		t.Fatalf("transient congestion lifted the floor: %d (want ≤21000)", v)
	}
	// 恢复：SRTT 低于地板 → 快降立即自愈。
	b.noteRTTSample(9_000)
	if v := b.effRttUS.Load(); v != 9_000 {
		t.Fatalf("fast drop on recovery = %d, want 9000", v)
	}
	// 持续劣化：地板慢升 0.5ms/s × 40s = 20ms → 20+20=40ms，与当前 SRTT 持平
	// （恢复时同式快降自愈）。此处用人工回拨 last 时刻模拟 40s 的持续拥塞。
	b.rttEffFloorNS = 20_000_000 // 20ms
	b.rttEffLast = b.rttEffLast.Add(-40 * time.Second)
	b.noteRTTSample(40_000)
	if v := b.effRttUS.Load(); v != 40_000 {
		t.Fatalf("sustained congestion floor rise = %d, want 40000", v)
	}
}

// TestAdaptiveBackendEffectiveRTTFallback 有效地板未建立时回退 min_rtt/SRTT 链；
// 建立后优先。
func TestAdaptiveBackendEffectiveRTTFallback(t *testing.T) {
	b := testAdaptiveBackend(30_000)
	if v, unknown := adaptiveBackendEffectiveRTT(b); unknown || v != 30_000 {
		t.Fatalf("fallback to min_rtt: got %d unknown=%v, want 30000 known", v, unknown)
	}
	b.noteRTTSample(25_000)
	b.noteRTTSample(25_000)
	if v, unknown := adaptiveBackendEffectiveRTT(b); unknown || v != 25_000 {
		t.Fatalf("established floor must win: got %d unknown=%v, want 25000", v, unknown)
	}
}

// TestAdaptiveEnvelopeWidensUnderDemandPressure 资格包络按需放宽：高需求把活跃
// 目标抬到 4、基包络只有 2 条候选时，逐级放宽（×2→×4→×8）把远包络的高时延
// 健康路径拉进活跃集；低需求（目标 2）不放宽，包络语义不变。
func TestAdaptiveEnvelopeWidensUnderDemandPressure(t *testing.T) {
	build := func() (*AsyncPort, []*Backend) {
		p := &AsyncPort{}
		fastA := oneWayBackend(20_000, 20_000, 20_000, 100_000_000)
		fastB := oneWayBackend(21_000, 21_000, 21_000, 100_000_000)
		slow := oneWayBackend(60_000, 60_000, 60_000, 100_000_000)
		return p, []*Backend{fastA, fastB, slow}
	}

	// 高需求：目标 4 > 候选 2 → 放宽后 slow（60ms = 20ms + 8×5ms slack 顶格）
	// 进活跃集。
	p, backends := build()
	p.inputRateBytesPerSec.Store(adaptiveActive4RateBytesPerSec)
	counts := map[*Backend]int{}
	for i := 0; i < 12; i++ {
		counts[p.pickAdaptiveBackend(backends, 0, 12*1024)]++
	}
	if counts[backends[2]] == 0 {
		t.Fatalf("far path never admitted under demand starvation: counts=%v", counts)
	}
	if got := p.activePaths.Load(); got != 3 {
		t.Fatalf("activePaths=%d want 3 (only 3 healthy paths exist)", got)
	}

	// 低需求：目标 2 = 基包络候选数 → 不放宽，slow 仍被排除（乱序界不变）。
	p2, backends2 := build()
	p2.inputRateBytesPerSec.Store(adaptiveActive2RateBytesPerSec)
	counts2 := map[*Backend]int{}
	for i := 0; i < 12; i++ {
		counts2[p2.pickAdaptiveBackend(backends2, 0, 12*1024)]++
	}
	if counts2[backends2[2]] != 0 {
		t.Fatalf("far path admitted without demand justification: counts=%v", counts2)
	}
	if got := p2.activePaths.Load(); got != 2 {
		t.Fatalf("activePaths=%d want 2", got)
	}
}

// TestProbeTimeoutStreakPenaltyRanking 探针连续超时罚时：同档双路径中，超时
// 路径的排名键被抬升（rank_key_us 可见），strict 模式改选干净路径；罚时封顶；
// sched_health_penalty_us=0 可整体禁用。
func TestProbeTimeoutStreakPenaltyRanking(t *testing.T) {
	p := &AsyncPort{}
	p.routingAlgo.Store(routingAlgoCode(string(RoutingAlgoLatencyStrict)))
	p.SetSchedHealthPenaltyUs(schedHealthPenaltyDefaultUS)
	clean := oneWayBackend(20_000, 20_000, 20_000, 30_000_000)
	lossy := oneWayBackend(20_000, 20_000, 20_000, 30_000_000)
	lossy.probeTimeoutStreak.Store(3) // 3×2ms = 6ms 罚时
	backends := []*Backend{clean, lossy}

	if got := p.pickAdaptiveBackend(backends, adaptiveActive2Pressure-1, 8*1024); got != clean {
		t.Fatalf("probe-timeout path outranked clean peer: got=%p want=%p", got, clean)
	}
	if got := lossy.rankKeyUS.Load(); got != 20_000+3*probeTimeoutPenaltyUS {
		t.Fatalf("rank key penalty = %d, want %d", got, 20_000+3*probeTimeoutPenaltyUS)
	}
	// 封顶：streak 100 → 罚时 10ms（不是 200ms）。rankKeyUS 在每次选路时发布，
	// 改完 streak 需再跑一轮才反映。
	lossy.probeTimeoutStreak.Store(100)
	p.pickAdaptiveBackend(backends, adaptiveActive2Pressure-1, 8*1024)
	if got := lossy.rankKeyUS.Load(); got != 20_000+schedHealthPenaltyMaxUS {
		t.Fatalf("penalty cap = %d, want %d", got, 20_000+schedHealthPenaltyMaxUS)
	}
	// 配置禁用（sched_health_penalty_us=0）：罚时不再生效，超时路径凭地板参与
	// 排名（与干净路径同档，稳定序保序即可）。
	p.SetSchedHealthPenaltyUs(0)
	lossy.probeTimeoutStreak.Store(3)
	if got := p.pickAdaptiveBackend(backends, adaptiveActive2Pressure-1, 8*1024); got != clean {
		t.Fatalf("disabled penalty still deprioritized lossy path: got=%p", got)
	}
	if got := lossy.rankKeyUS.Load(); got != 20_000 {
		t.Fatalf("penalty disabled but rank key lifted: %d, want 20000", got)
	}
}

// TestRetransRankPenalty 重传段罚时进入 adaptive 主排名：丢包路径劣于同档干净
// 路径（此前主排名对丢包完全钝感，仅兜底 backendScore 覆盖）。
func TestRetransRankPenalty(t *testing.T) {
	p := &AsyncPort{}
	p.routingAlgo.Store(routingAlgoCode(string(RoutingAlgoLatencyStrict)))
	p.SetSchedHealthPenaltyUs(schedHealthPenaltyDefaultUS)
	clean := oneWayBackend(20_000, 20_000, 20_000, 30_000_000)
	lossy := oneWayBackend(20_000, 20_000, 20_000, 30_000_000)
	lossy.retransDelta.Store(4) // 4×2ms = 8ms 罚时
	if got := p.pickAdaptiveBackend([]*Backend{clean, lossy}, adaptiveActive2Pressure-1, 8*1024); got != clean {
		t.Fatalf("lossy path outranked clean peer: got=%p want=%p", got, clean)
	}
	if got := lossy.rankKeyUS.Load(); got != 20_000+4*retransRankPenaltyUS {
		t.Fatalf("rank key penalty = %d, want %d", got, 20_000+4*retransRankPenaltyUS)
	}
}

// TestAdaptiveCapacityStarvedMembershipPrefersCapacity 容量饥饿下的成员选择：
// 延迟序 top-k 会把"低容量低延迟"路径全数送进活跃集、把高容量路径挤在席位之外
// ——聚合吞吐被封顶在低容量组合上（WFQ 权重只能分配已入选者，救不了没进场的）。
// capacityStarved 触发时成员改按实测容量降序选取；需求回落到容量水位内则回到
// 延迟序（交互优先）。
func TestAdaptiveCapacityStarvedMembershipPrefersCapacity(t *testing.T) {
	build := func() (*AsyncPort, map[*Backend]int, []*Backend) {
		p := &AsyncPort{}
		fast1 := testAdaptiveBackend(10_000) // 低容量低延迟 ×3
		fast2 := testAdaptiveBackend(10_200)
		fast3 := testAdaptiveBackend(10_400)
		big1 := testAdaptiveBackend(14_000) // 高容量高延迟 ×2（仍在基础包络内：maxRTT=15ms）
		big2 := testAdaptiveBackend(14_200)
		for _, b := range []*Backend{fast1, fast2, fast3, big1, big2} {
			b.rateBytesPerSec.Store(100_000_000)
		}
		fast1.deliverRateBytesPerSec.Store(20_000_000)
		fast2.deliverRateBytesPerSec.Store(20_000_000)
		fast3.deliverRateBytesPerSec.Store(20_000_000)
		big1.deliverRateBytesPerSec.Store(200_000_000)
		big2.deliverRateBytesPerSec.Store(200_000_000)
		return p, map[*Backend]int{}, []*Backend{fast1, fast2, fast3, big1, big2}
	}

	// 容量饥饿：实测合计 460MB/s，需求 400MB/s > 0.8×460=368MB/s → 成员按容量
	// 降序：big1/big2（200MB/s）+ 两条 fast（20MB/s，并列稳定序），fast3 掉出；
	// WFQ 分摊大头在 big 上。
	p, counts, backends := build()
	p.inputRateBytesPerSec.Store(400_000_000)
	for i := 0; i < 24; i++ {
		counts[p.pickAdaptiveBackend(backends, 0, 12*1024)]++
	}
	if counts[backends[3]] == 0 || counts[backends[4]] == 0 {
		t.Fatalf("high-capacity paths excluded from active set under starvation: counts=%v", counts)
	}
	if counts[backends[2]] != 0 {
		t.Fatalf("lowest-capacity path kept a seat it does not justify: counts=%v", counts)
	}
	if counts[backends[3]]+counts[backends[4]] <= counts[backends[0]]+counts[backends[1]] {
		t.Fatalf("capacity-proportional membership broken: counts=%v", counts)
	}
	if got := p.activePaths.Load(); got != 4 {
		t.Fatalf("activePaths=%d want 4", got)
	}

	// 需求回落（100MB/s < 368MB/s 水位，恰达 100MB/s 阈值 → demandWant=3）：
	// 非饥饿保持延迟序成员，高容量高延迟路径掉出活跃集。
	p2, counts2, backends2 := build()
	p2.inputRateBytesPerSec.Store(100_000_000)
	for i := 0; i < 12; i++ {
		counts2[p2.pickAdaptiveBackend(backends2, 0, 12*1024)]++
	}
	if counts2[backends2[3]] != 0 || counts2[backends2[4]] != 0 {
		t.Fatalf("far paths admitted without capacity starvation: counts=%v", counts2)
	}
	if got := p2.activePaths.Load(); got != 3 {
		t.Fatalf("activePaths=%d want 3 (latency-ordered top-3)", got)
	}
}

// TestNoteCapacitySampleBDPFloor 非饱和窗的 BDP 容量下界：cwnd×mss/srtt 结算到
// bdpRate，不污染饱和门控的 deliverRate 字段；空窗无测量。
func TestNoteCapacitySampleBDPFloor(t *testing.T) {
	const win = int64(200_000_000)
	b := &Backend{}
	// 非饱和窗（写阻塞 20ms < 半窗）+ TCP_INFO 有效：
	// BDP = 200×1400B / 20ms = 14MB/s。
	b.writeBusyNS = 20_000_000
	b.writeWindowBytes = 1_000_000
	b.noteCapacitySample(win, 200, 1400, 20_000)
	if got := b.bdpRateBytesPerSec.Load(); got != 14_000_000 {
		t.Fatalf("bdp floor = %d B/s, want 14MB/s", got)
	}
	if got := b.deliverRateBytesPerSec.Load(); got != 0 {
		t.Fatalf("unsaturated window must not touch deliverRate, got %d", got)
	}
	// 空窗：无流量即无测量。
	empty := &Backend{}
	empty.noteCapacitySample(win, 200, 1400, 20_000)
	if got := empty.bdpRateBytesPerSec.Load(); got != 0 {
		t.Fatalf("empty window must not sample, got %d", got)
	}
}
