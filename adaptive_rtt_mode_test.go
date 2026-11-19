package main

// 双向吞吐区间（rttMode）的回归测试：TCP ACK 自钟控把吞吐钉在 cwnd/(F+B)——
// 需求进入多路径区间后，fwd 系排名键升级往返（fwd+ret 之和）、fwd 门叠加回程
// 拥塞副门（探针回程抬升 = 对端发送排队深度 = 本端 ACK 排队深度）。交互区间
// 保持纯 fwd（慢回程不损交互时延，原设计意图成立）。

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestBackendRetUSAndRoundTrip(t *testing.T) {
	var mode atomic.Int32
	mode.Store(oneWayModeFwd)
	b := testAdaptiveBackend(10_000)
	b.oneWayModePtr = &mode
	if _, ok := b.backendRetUS(); ok {
		t.Fatal("unpublished ret must be unconverged")
	}
	b.retRankUS.Store(oneWayRankEncode(25_000))
	if v, ok := b.backendRetUS(); !ok || v != 25_000 {
		t.Fatalf("ret = %d ok=%v, want 25000/true", v, ok)
	}
	if _, ok := b.backendRoundTripUS(); ok {
		t.Fatal("round trip requires both directions converged")
	}
	b.fwdRankUS.Store(oneWayRankEncode(10_000))
	if v, ok := b.backendRoundTripUS(); !ok || v != 35_000 {
		t.Fatalf("round trip = %d ok=%v, want 35000/true", v, ok)
	}
	// roundtrip 兼容模式（0）不消费探针（与 backendOneWayUS 同契约）。
	var zero atomic.Int32
	b.oneWayModePtr = &zero
	if _, ok := b.backendRetUS(); ok {
		t.Fatal("roundtrip compat mode must not consume probes")
	}
	if _, ok := b.backendRoundTripUS(); ok {
		t.Fatal("roundtrip compat mode must not consume probes")
	}
}

// TestRetCongestPublishedByRecompute 回程拥塞抬升 = 回程有效值 − 回程地板：
// recent-typical 抬升回程有效值时，抬升量必须发布到 Backend.retCongestUS；
// typical 缺席（单样本）时抬升为 0（无拥塞证据不制造伪信号）。
func TestRetCongestPublishedByRecompute(t *testing.T) {
	// 探针尺度（µs）：ref 对称 fwd=ret=3000（halfRef=3000）；连接1 fwd=3000、
	// 回程地板 1000。recent[(ref,1)] 为原始探针 RTT，与 decay 同锚分解：
	// 典型值（相对量）= 8000−3000 = 5000µs（n≥2，dev=0 → 容差 200µs）
	// → 回程有效值 = max(1000, 5000−200) = 4800 → 抬升 = 3800。
	dec := map[[2]uint32]uint64{
		{0, 0}: 6000 * 1000,
		{1, 0}: 6000 * 1000,
		{0, 1}: 4000 * 1000,
	}
	minRtt := uint32(2000)
	b0 := &Backend{minRttCache: &minRtt}
	b1 := &Backend{minRttCache: &minRtt}
	s := &rttProbeScheduler{
		decay:     dec,
		lastDecay: make(map[[2]uint32]time.Time),
		recent:    map[[2]uint32]uint64{{0, 1}: 8000 * 1000},
		recentN:   map[[2]uint32]int{{0, 1}: 2},
		recentDev: map[[2]uint32]uint64{{0, 1}: 0},
		refConn:   0,
		active:    []int{0, 1},
		ctx:       context.Background(),
	}
	s.resolveConn = func(i int) *Backend {
		switch i {
		case 0:
			return b0
		case 1:
			return b1
		}
		return nil
	}
	s.recomputeAll()

	if got := b1.retCongestUS.Load(); got != 3800 {
		t.Fatalf("ret congest lift = %d, want 3800 (effective 4800 − floor 1000)", got)
	}
	// ref 自身：typical 缺席 → 有效值 = 地板 → 抬升 0。
	if got := b0.retCongestUS.Load(); got != 0 {
		t.Fatalf("ref lift = %d, want 0 (no typical)", got)
	}
}

// TestSchedRttModeGateExcludesCongestedReturn 双向吞吐区间的回程拥塞门：去程
// 最快但回程被对端下行踩死（排队深度超窗）的路径在 bulk 区间被排除——放宽
// 只换乱序界，换不回容量（回程窗不随放宽变化）；交互区间回程门关闭，纯 fwd
// 排名照旧选它。
func TestSchedRttModeGateExcludesCongestedReturn(t *testing.T) {
	// A：去程最快（10ms）但回程被对端下行踩死（ret 40ms，排队深度 30ms）。
	a := oneWayBackend(10_000, 10_000, 40_000, 30_000_000)
	a.retCongestUS.Store(30_000)
	// B：对称干净（14ms/14ms）。
	b := oneWayBackend(14_000, 14_000, 14_000, 30_000_000)
	backends := []*Backend{a, b}

	// 交互区间（demand=0）：回程门关闭，fwd 排名 A 最快 → 选中 A。
	p := schedEnvelopeFwdPort(t, 20, a, b)
	if got := p.pickAdaptiveBackend(backends, adaptiveActive2Pressure-1, 8*1024); got != a {
		t.Fatalf("interactive mode must keep forward ranking: got=%p want=a", got)
	}

	// 双向吞吐区间（demand=40MB/s）：A 的回程排队 30ms > 窗口 20ms → 排除；
	// 包络放宽不改回程窗 → B 当选。
	p2 := schedEnvelopeFwdPort(t, 20, a, b)
	p2.inputRateBytesPerSec.Store(adaptiveActive2RateBytesPerSec)
	if got := p2.pickAdaptiveBackend(backends, adaptiveActive2Pressure-1, 8*1024); got != b {
		t.Fatalf("bulk mode must exclude ACK-throttled path: got=%p want=b", got)
	}
	if a.active.Load() {
		t.Fatal("congested-return path must not stay active in bulk mode")
	}
	if snap := schedulerSnapshot(a); snap.ExcludeReason != "ret_congested" || snap.Eligible {
		t.Fatalf("exclude reason = %q eligible=%v, want ret_congested/false", snap.ExcludeReason, snap.Eligible)
	}
}

// TestSchedRttModeRankPrefersRoundTrip 双向吞吐区间的排名升级：两条回程都干净
// （抬升 0 → 回程门放行）的路径，交互按去程选 A（10ms < 14ms），bulk 按往返选
// B（28ms < 40ms，cwnd/(F+B) 决定交付力）。
func TestSchedRttModeRankPrefersRoundTrip(t *testing.T) {
	// A：去程最快但往返较慢（fwd 10ms / ret 30ms，远而干净——抬升 0）。
	a := oneWayBackend(10_000, 10_000, 30_000, 30_000_000)
	// B：对称（14ms/14ms）。
	b := oneWayBackend(14_000, 14_000, 14_000, 30_000_000)
	backends := []*Backend{a, b}

	p := schedEnvelopeFwdPort(t, 20, a, b)
	p.routingAlgo.Store(routingAlgoCode(string(RoutingAlgoLatencyStrict)))
	if got := p.pickAdaptiveBackend(backends, adaptiveActive2Pressure-1, 8*1024); got != a {
		t.Fatalf("interactive mode ranks by forward: got=%p want=a", got)
	}

	p2 := schedEnvelopeFwdPort(t, 20, a, b)
	p2.routingAlgo.Store(routingAlgoCode(string(RoutingAlgoLatencyStrict)))
	p2.inputRateBytesPerSec.Store(adaptiveActive2RateBytesPerSec)
	if got := p2.pickAdaptiveBackend(backends, adaptiveActive2Pressure-1, 8*1024); got != b {
		t.Fatalf("bulk mode ranks by round trip: got=%p want=b", got)
	}
}

// TestSchedRttModeFallbackNoHalving 无探针路径的回退键：交互区间折半（历史行为
// min_rtt/2，单向语义），双向吞吐区间不折半（键的语义是往返，kernel RTT 全值
// 与已收敛探针往返同尺度可比）。measured 分类之下这只影响组内排序与 fair-start
// 喂量，不引入跨尺度混排。latency_strict 剥离 auto 的服务时间项，键即回退值。
func TestSchedRttModeFallbackNoHalving(t *testing.T) {
	warm1 := testAdaptiveBackend(10_000)
	warm2 := testAdaptiveBackend(12_000)
	for _, b := range []*Backend{warm1, warm2} {
		b.rateBytesPerSec.Store(50_000_000)
	}
	backends := []*Backend{warm1, warm2}

	p := &AsyncPort{}
	p.routingAlgo.Store(routingAlgoCode(string(RoutingAlgoLatencyStrict)))
	p.pickAdaptiveBackend(backends, 0, 8*1024)
	if got := warm1.rankKeyUS.Load(); got != 5_000 {
		t.Fatalf("interactive fallback key = %d, want 5000 (halved)", got)
	}

	p2 := &AsyncPort{}
	p2.routingAlgo.Store(routingAlgoCode(string(RoutingAlgoLatencyStrict)))
	p2.inputRateBytesPerSec.Store(adaptiveActive2RateBytesPerSec)
	p2.pickAdaptiveBackend(backends, 0, 8*1024)
	if got := warm1.rankKeyUS.Load(); got != 10_000 {
		t.Fatalf("bulk fallback key = %d, want 10000 (full kernel RTT)", got)
	}
	if got := warm2.rankKeyUS.Load(); got != 12_000 {
		t.Fatalf("bulk fallback key = %d, want 12000", got)
	}
	if snap := schedulerSnapshot(warm1); !snap.RttMode {
		t.Fatal("bulk mode bit must be published for candidates")
	}
}
