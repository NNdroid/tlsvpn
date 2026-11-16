package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestConfigSchedulerFieldsAtTopLevel 验证迁移后三字段在 Config 顶层：
// 顶层默认值填充、顶层校验、以及旧位置（client 块）被 DisallowUnknownFields 拒绝。
func TestConfigSchedulerFieldsAtTopLevel(t *testing.T) {
	// 1. 顶层默认值填充（对 client 和 server 都生效）。
	for _, mode := range []string{"client", "server"} {
		c := &Config{Mode: mode, PSK: "test-only-high-entropy-secret", Addr: "1.2.3.4:4000"}
		if mode == "client" {
			c.Client = ClientConfig{Conns: 2}
		}
		c.applyDefaults()
		if c.RoutingAlgo != string(RoutingAlgoAuto) {
			t.Fatalf("[%s] top-level routing_algo default: got %q want auto", mode, c.RoutingAlgo)
		}
		if c.FecStrategy != string(FecStrategyAuto) {
			t.Fatalf("[%s] top-level fec_strategy default: got %q want auto", mode, c.FecStrategy)
		}
		if c.FecNearWindowMs != fecNearWindowDefaultMs {
			t.Fatalf("[%s] top-level fec_near_window_ms default: got %d want %d", mode, c.FecNearWindowMs, fecNearWindowDefaultMs)
		}
	}

	// 2. 顶层校验生效：非法 routing_algo / fec_strategy / 越界窗口被拒。
	bad := &Config{Mode: "client", PSK: "test-only-high-entropy-secret", Addr: "1.2.3.4:4000", Client: ClientConfig{Conns: 2}, RoutingAlgo: "bogus"}
	bad.applyDefaults()
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "routing_algo") {
		t.Fatalf("Validate(bogus routing_algo) should fail with routing_algo, got %v", err)
	}
	bad2 := &Config{Mode: "client", PSK: "test-only-high-entropy-secret", Addr: "1.2.3.4:4000", Client: ClientConfig{Conns: 2}, FecStrategy: "bogus"}
	bad2.applyDefaults()
	if err := bad2.Validate(); err == nil || !strings.Contains(err.Error(), "fec_strategy") {
		t.Fatalf("Validate(bogus fec_strategy) should fail with fec_strategy, got %v", err)
	}
	bad3 := &Config{Mode: "client", PSK: "test-only-high-entropy-secret", Addr: "1.2.3.4:4000", Client: ClientConfig{Conns: 2}, FecNearWindowMs: 500}
	bad3.applyDefaults()
	if err := bad3.Validate(); err == nil || !strings.Contains(err.Error(), "fec_near_window_ms") {
		t.Fatalf("Validate(fec_near_window_ms=500) should fail, got %v", err)
	}

	// 3. 服务端顶层字段合法值通过（routing_algo=latency_strict + fec_strategy=near）。
	srv := &Config{Mode: "server", PSK: "test-only-high-entropy-secret", Addr: "1.2.3.4:4000", RoutingAlgo: "latency_strict", FecStrategy: "near", FecNearWindowMs: 10}
	srv.applyDefaults()
	if err := srv.Validate(); err != nil {
		t.Fatalf("server cfg with top-level scheduler fields should validate, got %v", err)
	}
}

// TestConfigSchedulerFieldsOldPositionRejected 验证旧位置（client 块内三字段）
// 被 DisallowUnknownFields 拒绝：用户选择"直接删旧位置"，旧配置会报 unknown field。
func TestConfigSchedulerFieldsOldPositionRejected(t *testing.T) {
	// 旧格式：三字段在 client 块内。删除 ClientConfig tag 后应被拒绝。
	oldJSON := `{
		"mode": "client", "psk": "k", "addr": "1.2.3.4:4000",
		"client": {"conns": 2, "routing_algo": "auto", "fec_strategy": "auto", "fec_near_window_ms": 10}
	}`
	var cfg Config
	dec := json.NewDecoder(bytes.NewReader([]byte(oldJSON)))
	dec.DisallowUnknownFields()
	err := dec.Decode(&cfg)
	if err == nil {
		t.Fatal("old-position client.routing_algo should be rejected by DisallowUnknownFields after migration")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}
