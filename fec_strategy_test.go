package main

import (
	"context"
	"testing"
)

func TestFecStrategyCodeMapping(t *testing.T) {
	if fecStrategyCode("near") != 1 {
		t.Fatal("fecStrategyCode(near) should be 1")
	}
	if fecStrategyCode("auto") != 0 {
		t.Fatal("fecStrategyCode(auto) should be 0")
	}
	if fecStrategyCode("bogus") != 0 {
		t.Fatal("fecStrategyCode(bogus) should fall back to 0 (auto)")
	}
	if fecStrategyForCode(1) != FecStrategyNear {
		t.Fatal("fecStrategyForCode(1) should be near")
	}
	if fecStrategyForCode(0) != FecStrategyAuto || fecStrategyForCode(99) != FecStrategyAuto {
		t.Fatal("fecStrategyForCode unknown should fall back to auto")
	}
}

func TestValidFecStrategy(t *testing.T) {
	for _, v := range []string{"auto", "near"} {
		if !ValidFecStrategy(v) {
			t.Fatalf("ValidFecStrategy(%q)=false, want true", v)
		}
	}
	for _, bad := range []string{"", "active", "NEAR", "spread"} {
		if ValidFecStrategy(bad) {
			t.Fatalf("ValidFecStrategy(%q)=true, want false", bad)
		}
	}
}

func TestFecStrategyListCoversAll(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range fecStrategyList() {
		seen[string(s)] = true
	}
	for _, v := range []string{"auto", "near"} {
		if !seen[v] {
			t.Fatalf("fecStrategyList missing %q", v)
		}
	}
}

func TestSetFecNearWindowMsClamp(t *testing.T) {
	p := &AsyncPort{}
	p.SetFecNearWindowMs(200)
	if got := p.fecNearWindowUS.Load(); got != 100_000 {
		t.Fatalf("window 200 clamped: got %d want 100000", got)
	}
	p.SetFecNearWindowMs(0)
	if got := p.fecNearWindowUS.Load(); got != 1_000 {
		t.Fatalf("window 0 clamped: got %d want 1000", got)
	}
	p.SetFecNearWindowMs(7)
	if got := p.fecNearWindowUS.Load(); got != 7_000 {
		t.Fatalf("window 7: got %d want 7000", got)
	}
}

func TestNewAsyncPortFecNearWindowDefault(t *testing.T) {
	p := NewAsyncPort(context.Background(), "test-fec-default")
	defer p.cancel()
	if got := p.fecNearWindowUS.Load(); got != uint64(fecNearWindowDefaultMs)*1000 {
		t.Fatalf("NewAsyncPort near window default: got %d want %d", got, uint64(fecNearWindowDefaultMs)*1000)
	}
}

func TestParityNearEligible(t *testing.T) {
	p := &AsyncPort{}
	p.SetFecNearWindowMs(10)
	// 数据路径 fwd=80ms；near=85ms（+5ms，窗口内）；far=120ms（+40ms，窗口外）
	dataBest := oneWayBackend(160_000, 80_000, 80_000, 30_000_000)
	near := oneWayBackend(160_000, 85_000, 80_000, 30_000_000)
	far := oneWayBackend(160_000, 120_000, 80_000, 30_000_000)
	if !p.parityNearEligible(near, dataBest) {
		t.Fatal("85ms should be within 10ms window of 80ms")
	}
	if p.parityNearEligible(far, dataBest) {
		t.Fatal("120ms should be outside 10ms window of 80ms")
	}
}

func TestPickParityBackendNearStrategy(t *testing.T) {
	p := &AsyncPort{}
	p.SetFecStrategy("near")
	p.SetFecNearWindowMs(10)
	dataBest := oneWayBackend(160_000, 80_000, 80_000, 30_000_000)
	far := oneWayBackend(160_000, 120_000, 80_000, 30_000_000)
	// 唯一候选 far 在窗口外：near 策略必须回退到数据路径，而非把 parity 泄到慢链路。
	if got := p.pickParityBackend([]*Backend{dataBest, far}, dataBest); got != dataBest {
		t.Fatalf("near strategy must not pick out-of-window far backend: got=%p want=%p", got, dataBest)
	}
	// 窗口内候选 near 存在：应优先选它（避开数据路径）。
	near := oneWayBackend(160_000, 85_000, 80_000, 30_000_000)
	if got := p.pickParityBackend([]*Backend{dataBest, far, near}, dataBest); got != near {
		t.Fatalf("near strategy should pick in-window backend: got=%p want=%p", got, near)
	}
}

func TestPickParityBackendAutoStrategy(t *testing.T) {
	p := &AsyncPort{}
	p.SetFecStrategy("auto")
	dataBest := oneWayBackend(160_000, 80_000, 80_000, 30_000_000)
	far := oneWayBackend(160_000, 120_000, 80_000, 30_000_000)
	// auto：所有健康后端都可用，far 即使远超窗口也照常承载 parity（当前行为）。
	if got := p.pickParityBackend([]*Backend{dataBest, far}, dataBest); got != far {
		t.Fatalf("auto strategy should spread to far backend: got=%p want=%p", got, far)
	}
}

func TestConfigFecStrategyValidation(t *testing.T) {
	base := &Config{Mode: "client", PSK: "test-only-high-entropy-secret", Addr: "1.2.3.4:4000", Client: ClientConfig{Conns: 2}}
	base.applyDefaults()
	if base.FecStrategy != string(FecStrategyAuto) {
		t.Fatalf("applyDefaults should normalize empty fec_strategy to auto, got %q", base.FecStrategy)
	}
	if base.FecNearWindowMs != fecNearWindowDefaultMs {
		t.Fatalf("applyDefaults should default fec_near_window_ms to %d, got %d", fecNearWindowDefaultMs, base.FecNearWindowMs)
	}
	for _, v := range []string{"auto", "near"} {
		c := *base
		c.FecStrategy = v
		if err := c.Validate(); err != nil {
			t.Fatalf("Validate(fec_strategy=%s) err=%v", v, err)
		}
	}
	c := *base
	c.FecStrategy = "bogus"
	if err := c.Validate(); err == nil {
		t.Fatal("Validate(bogus fec_strategy) should fail")
	}
	c = *base
	c.FecNearWindowMs = 200
	if err := c.Validate(); err == nil {
		t.Fatal("Validate(fec_near_window_ms=200) should fail")
	}
	c = *base
	c.FecNearWindowMs = 0
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(fec_near_window_ms=0→default) should pass, got %v", err)
	}
}
