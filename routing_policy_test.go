package main

import "testing"

func TestRoutingPolicyForCode(t *testing.T) {
	// 未知码必须回退 auto（默认策略），保证配置热更/损坏不突变行为。
	if p := routingPolicyForCode(99); p.rank != rankOneWayPlusService || !p.sticky || !p.wfq {
		t.Fatalf("unknown code should fall back to auto, got %+v", p)
	}
	cases := []struct {
		algo   string
		rank   rankKey
		sticky bool
		wfq    bool
	}{
		{string(RoutingAlgoAuto), rankOneWayPlusService, true, true},
		{string(RoutingAlgoLatencyStrict), rankOneWay, false, false},
		{string(RoutingAlgoLatencySticky), rankOneWay, true, false},
		{string(RoutingAlgoMinRTTStrict), rankMinRTTHalf, false, false},
		{string(RoutingAlgoMinRTTAdaptive), rankMinRTTHalf, true, true},
		{string(RoutingAlgoRoundTripStrict), rankSRTTHalf, false, false},
	}
	for _, tc := range cases {
		p := routingPolicyFor(tc.algo)
		if p.rank != tc.rank || p.sticky != tc.sticky || p.wfq != tc.wfq {
			t.Fatalf("%s: got rank=%v sticky=%v wfq=%v, want rank=%v sticky=%v wfq=%v",
				tc.algo, p.rank, p.sticky, p.wfq, tc.rank, tc.sticky, tc.wfq)
		}
	}
}

func TestRoutingAlgoValidation(t *testing.T) {
	for _, v := range []string{"auto", "latency_strict", "latency_sticky", "min_rtt_strict", "min_rtt_adaptive", "roundtrip_strict"} {
		if !ValidRoutingAlgo(v) {
			t.Fatalf("ValidRoutingAlgo(%q)=false, want true", v)
		}
	}
	for _, bad := range []string{"", "min_rtt", "fastest", "AUTO", "latency"} {
		if ValidRoutingAlgo(bad) {
			t.Fatalf("ValidRoutingAlgo(%q)=true, want false", bad)
		}
	}
}

func TestRoutingAlgoListCoversAll(t *testing.T) {
	seen := map[string]bool{}
	for _, a := range routingAlgoList() {
		seen[string(a)] = true
	}
	for _, v := range []string{"auto", "latency_strict", "latency_sticky", "min_rtt_strict", "min_rtt_adaptive", "roundtrip_strict"} {
		if !seen[v] {
			t.Fatalf("routingAlgoList missing %q", v)
		}
	}
}

func TestCandidateRankUS(t *testing.T) {
	// serviceTime(8KiB, 25M) = 8192*1e6/25e6 = 327µs
	const svc = 327
	if got := candidateRankUS(routingPolicyFor(string(RoutingAlgoAuto)), 1000, 2000, 3000, 8*1024, 25_000_000); got != 1000+svc {
		t.Fatalf("auto rank = %d, want %d", got, 1000+svc)
	}
	if got := candidateRankUS(routingPolicyFor(string(RoutingAlgoLatencyStrict)), 1000, 2000, 3000, 8*1024, 25_000_000); got != 1000 {
		t.Fatalf("latency_strict rank = %d, want 1000", got)
	}
	if got := candidateRankUS(routingPolicyFor(string(RoutingAlgoMinRTTStrict)), 1000, 2000, 3000, 8*1024, 25_000_000); got != 1000 {
		t.Fatalf("min_rtt_strict rank = %d, want 1000", got)
	}
	if got := candidateRankUS(routingPolicyFor(string(RoutingAlgoRoundTripStrict)), 1000, 2000, 3000, 8*1024, 25_000_000); got != 1500 {
		t.Fatalf("roundtrip_strict rank = %d, want 1500", got)
	}
}

// TestAdaptiveLatencyStrictPicksLowestForward 严格去程：fwd 更低但 min_rtt 更高者接管，
// 证明严格模式按去程稳定地板排名而非混合键（min_rtt/服务时间）。
func TestAdaptiveLatencyStrictPicksLowestForward(t *testing.T) {
	p := &AsyncPort{}
	p.SetRoutingAlgo(string(RoutingAlgoLatencyStrict))
	lowFwd := oneWayBackend(180_000, 60_000, 80_000, 30_000_000)  // fwd 60ms, floor 180ms
	highFwd := oneWayBackend(150_000, 90_000, 70_000, 30_000_000) // fwd 90ms, floor 150ms
	if got := p.pickAdaptiveBackend([]*Backend{highFwd, lowFwd}, adaptiveActive2Pressure-1, 8*1024); got != lowFwd {
		t.Fatalf("latency_strict picked %p, want lowest-forward %p", got, lowFwd)
	}
	if !lowFwd.active.Load() || highFwd.active.Load() {
		t.Fatalf("latency_strict active flags wrong: lowFwd=%v highFwd=%v", lowFwd.active.Load(), highFwd.active.Load())
	}
}

// TestAdaptiveMinRTTStrictPicksLowestFloor 严格无拥塞地板：min_rtt 更低但 fwd 更差者接管。
func TestAdaptiveMinRTTStrictPicksLowestFloor(t *testing.T) {
	p := &AsyncPort{}
	p.SetRoutingAlgo(string(RoutingAlgoMinRTTStrict))
	lowFloor := oneWayBackend(150_000, 90_000, 70_000, 30_000_000)  // floor 150ms, fwd 90ms
	highFloor := oneWayBackend(180_000, 60_000, 80_000, 30_000_000) // floor 180ms, fwd 60ms
	if got := p.pickAdaptiveBackend([]*Backend{highFloor, lowFloor}, adaptiveActive2Pressure-1, 8*1024); got != lowFloor {
		t.Fatalf("min_rtt_strict picked %p, want lowest-floor %p", got, lowFloor)
	}
}

// TestAdaptiveRoundTripStrictPicksLowestRTT 严格当前往返：SRTT 更低但 fwd 更差者接管。
func TestAdaptiveRoundTripStrictPicksLowestRTT(t *testing.T) {
	p := &AsyncPort{}
	p.SetRoutingAlgo(string(RoutingAlgoRoundTripStrict))
	lowRTT := oneWayBackend(150_000, 90_000, 70_000, 30_000_000)  // srtt 150ms, fwd 90ms
	highRTT := oneWayBackend(180_000, 60_000, 80_000, 30_000_000) // srtt 180ms, fwd 60ms
	if got := p.pickAdaptiveBackend([]*Backend{highRTT, lowRTT}, adaptiveActive2Pressure-1, 8*1024); got != lowRTT {
		t.Fatalf("roundtrip_strict picked %p, want lowest-RTT %p", got, lowRTT)
	}
}

// TestAdaptiveLatencyStrictIgnoresSticky 严格模式关键差异：即使候选只差 3ms（在 auto
// 的 5ms 粘滞带内）也必须切换——严格模式不受粘滞滞回约束。
func TestAdaptiveLatencyStrictIgnoresSticky(t *testing.T) {
	p := &AsyncPort{}
	p.SetRoutingAlgo(string(RoutingAlgoLatencyStrict))
	active := oneWayBackend(168_000, 82_000, 80_000, 30_000_000)
	slightlyBetter := oneWayBackend(166_000, 79_000, 90_000, 20_000_000) // fwd 3ms better < 5ms slack
	p.preferred.Store(active)
	if got := p.pickAdaptiveBackend([]*Backend{active, slightlyBetter}, adaptiveActive2Pressure-1, 8*1024); got != slightlyBetter {
		t.Fatalf("latency_strict must switch even within sticky slack: got=%p want=%p", got, slightlyBetter)
	}
}

// TestAdaptiveLatencyStickyKeepsWithinSlack 粘滞去程：候选只差 3ms（< 5ms slack）时保持当前。
func TestAdaptiveLatencyStickyKeepsWithinSlack(t *testing.T) {
	p := &AsyncPort{}
	p.SetRoutingAlgo(string(RoutingAlgoLatencySticky))
	active := oneWayBackend(168_000, 82_000, 80_000, 30_000_000)
	slightlyBetter := oneWayBackend(166_000, 79_000, 90_000, 20_000_000)
	p.preferred.Store(active)
	if got := p.pickAdaptiveBackend([]*Backend{active, slightlyBetter}, adaptiveActive2Pressure-1, 8*1024); got != active {
		t.Fatalf("latency_sticky within slack must not switch: got=%p want=%p", got, active)
	}
}

// TestConfigRoutingAlgoValidation 配置校验：合法值通过，非法值拒绝。
func TestConfigRoutingAlgoValidation(t *testing.T) {
	base := &Config{Mode: "client", PSK: "k", Addr: "1.2.3.4:4000", Client: ClientConfig{Conns: 2}}
	base.applyDefaults()
	for _, v := range []string{"auto", "latency_strict", "latency_sticky", "min_rtt_strict", "min_rtt_adaptive", "roundtrip_strict"} {
		c := *base
		c.RoutingAlgo = v
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate(routing_algo=%s) err=%v", v, err)
		}
	}
	c := *base
	c.RoutingAlgo = "bogus"
	if err := c.Validate(); err == nil {
		t.Fatal("Validate(bogus routing_algo) should fail")
	}
	// applyDefaults 把空值归一化为 auto
	if base.RoutingAlgo != string(RoutingAlgoAuto) {
		t.Fatalf("applyDefaults should normalize empty routing_algo to auto, got %q", base.RoutingAlgo)
	}
}
