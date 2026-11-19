package main

import (
	"encoding/json"
	"testing"
)

// TestConfigSchedHealthPenaltyDefaults 验证未配置时回落默认 2000µs，且指针语义
// 能区分"未配置"与"显式 0"（0=禁用健康罚时是合法配置）。
func TestConfigSchedHealthPenaltyDefaults(t *testing.T) {
	cfg := &Config{Mode: "server", PSK: "x", Addr: "0.0.0.0:4000"}
	cfg.applyDefaults()
	if cfg.SchedHealthPenaltyUs == nil {
		t.Fatal("applyDefaults left SchedHealthPenaltyUs nil")
	}
	if *cfg.SchedHealthPenaltyUs != schedHealthPenaltyDefaultUS {
		t.Fatalf("default = %d, want %d", *cfg.SchedHealthPenaltyUs, schedHealthPenaltyDefaultUS)
	}

	// 显式 0（禁用）不得被 applyDefaults 覆盖。
	cfg2 := &Config{Mode: "server", PSK: "x", Addr: "0.0.0.0:4000"}
	zero := 0
	cfg2.SchedHealthPenaltyUs = &zero
	cfg2.applyDefaults()
	if cfg2.SchedHealthPenaltyUs == nil || *cfg2.SchedHealthPenaltyUs != 0 {
		t.Fatalf("explicit 0 overwritten: %v", cfg2.SchedHealthPenaltyUs)
	}
}

// TestConfigSchedHealthPenaltyValidate 验证取值范围校验。
func TestConfigSchedHealthPenaltyValidate(t *testing.T) {
	base := func(v int) *Config {
		c := &Config{Mode: "server", PSK: "test-only-high-entropy-secret", Addr: "0.0.0.0:4000"}
		c.SchedHealthPenaltyUs = &v
		c.applyDefaults()
		return c
	}
	if err := base(schedHealthPenaltyDefaultUS).Validate(); err != nil {
		t.Fatalf("valid value rejected: %v", err)
	}
	if err := base(0).Validate(); err != nil {
		t.Fatalf("explicit 0 rejected: %v", err)
	}
	if err := base(-1).Validate(); err == nil {
		t.Fatal("negative value accepted")
	}
	if err := base(schedHealthPenaltyMaxConfigUS).Validate(); err != nil {
		t.Fatalf("config ceiling rejected: %v", err)
	}
	if err := base(schedHealthPenaltyMaxConfigUS + 1).Validate(); err == nil {
		t.Fatal("over-large value accepted")
	}
}

// TestConfigSchedHealthPenaltyJSON 验证 JSON 键名与往返。
func TestConfigSchedHealthPenaltyJSON(t *testing.T) {
	const raw = `{"mode":"server","psk":"x","addr":"0.0.0.0:4000","sched_health_penalty_us":500}`
	var cfg Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.SchedHealthPenaltyUs == nil || *cfg.SchedHealthPenaltyUs != 500 {
		t.Fatalf("sched_health_penalty_us not parsed: %v", cfg.SchedHealthPenaltyUs)
	}

	// 省略时字段为 nil（omitempty 对称）。
	var cfg2 Config
	if err := json.Unmarshal([]byte(`{"mode":"server","psk":"x","addr":"0.0.0.0:4000"}`), &cfg2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg2.SchedHealthPenaltyUs != nil {
		t.Fatalf("omitted field not nil: %v", *cfg2.SchedHealthPenaltyUs)
	}
}

// TestAsyncPortSchedHealthPenaltyHotApply 验证热更钳制：负值按 0（禁用）处理，
// 与配置校验层双保险。
func TestAsyncPortSchedHealthPenaltyHotApply(t *testing.T) {
	p := NewAsyncPort(t.Context(), "test")
	defer p.cancel()
	if got := p.SchedHealthPenaltyUs(); got != schedHealthPenaltyDefaultUS {
		t.Fatalf("NewAsyncPort default = %d, want %d", got, schedHealthPenaltyDefaultUS)
	}
	p.SetSchedHealthPenaltyUs(500)
	if got := p.SchedHealthPenaltyUs(); got != 500 {
		t.Fatalf("hot apply = %d, want 500", got)
	}
	p.SetSchedHealthPenaltyUs(-3)
	if got := p.SchedHealthPenaltyUs(); got != 0 {
		t.Fatalf("negative must clamp to 0 (disabled), got %d", got)
	}
}
