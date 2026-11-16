package main

import (
	"encoding/json"
	"testing"
)

// TestConfigProbeMinHalfRTTDefaults 验证未配置时回落默认 1000µs，且指针语义
// 能区分"未配置"与"显式 0"。
func TestConfigProbeMinHalfRTTDefaults(t *testing.T) {
	cfg := &Config{Mode: "server", PSK: "x", Addr: "0.0.0.0:4000"}
	cfg.applyDefaults()
	if cfg.ProbeMinHalfRTTUs == nil {
		t.Fatal("applyDefaults left ProbeMinHalfRTTUs nil")
	}
	if *cfg.ProbeMinHalfRTTUs != defaultProbeMinHalfRTTUs {
		t.Fatalf("default = %d, want %d", *cfg.ProbeMinHalfRTTUs, defaultProbeMinHalfRTTUs)
	}

	// 显式 0 是合法值（禁用下界），不得被 applyDefaults 覆盖。
	cfg2 := &Config{Mode: "server", PSK: "x", Addr: "0.0.0.0:4000"}
	zero := 0
	cfg2.ProbeMinHalfRTTUs = &zero
	cfg2.applyDefaults()
	if cfg2.ProbeMinHalfRTTUs == nil || *cfg2.ProbeMinHalfRTTUs != 0 {
		t.Fatalf("explicit 0 overwritten: %v", cfg2.ProbeMinHalfRTTUs)
	}
}

// TestConfigProbeMinHalfRTTValidate 验证取值范围校验。
func TestConfigProbeMinHalfRTTValidate(t *testing.T) {
	base := func(v int) *Config {
		c := &Config{Mode: "server", PSK: "test-only-high-entropy-secret", Addr: "0.0.0.0:4000"}
		c.ProbeMinHalfRTTUs = &v
		c.applyDefaults() // 填齐 priority_control 等必填项，聚焦校验 probe_min_half_rtt_us
		if v != *c.ProbeMinHalfRTTUs {
			c.ProbeMinHalfRTTUs = &v
		}
		return c
	}
	if err := base(1000).Validate(); err != nil {
		t.Fatalf("valid value rejected: %v", err)
	}
	if err := base(0).Validate(); err != nil {
		t.Fatalf("explicit 0 rejected: %v", err)
	}
	if err := base(-1).Validate(); err == nil {
		t.Fatal("negative value accepted")
	}
	if err := base(3_600_001).Validate(); err == nil {
		t.Fatal("over-large value accepted")
	}
}

// TestConfigProbeMinHalfRTTJSON 验证 JSON 键名与往返。
func TestConfigProbeMinHalfRTTJSON(t *testing.T) {
	const raw = `{"mode":"server","psk":"x","addr":"0.0.0.0:4000","probe_min_half_rtt_us":2500}`
	var cfg Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.ProbeMinHalfRTTUs == nil || *cfg.ProbeMinHalfRTTUs != 2500 {
		t.Fatalf("probe_min_half_rtt_us not parsed: %v", cfg.ProbeMinHalfRTTUs)
	}

	// 省略时字段为 nil（omitempty 对称）。
	var cfg2 Config
	if err := json.Unmarshal([]byte(`{"mode":"server","psk":"x","addr":"0.0.0.0:4000"}`), &cfg2); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg2.ProbeMinHalfRTTUs != nil {
		t.Fatalf("omitted field not nil: %v", *cfg2.ProbeMinHalfRTTUs)
	}
}
