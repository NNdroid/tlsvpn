package main

import (
	"encoding/json"
	"testing"
)

// 调度设置保存：面板回传的是 GET /api/config 脱敏后的完整结构（web.auth 被置空，
// 凭据用空值表示“保留现有”），叠加用户改动的调度字段。mergeAndValidateConfig 必须
// 回填脱敏凭据（auth/psk），并接受合法调度字段值。这覆盖了“服务端通过 WebUI 保存
// 调度设置”的核心路径——任何回填或字段校验回归都会在这里暴露。
func TestSchedSaveFullGetRoundtrip(t *testing.T) {
	old := &Config{Mode: "server", SourcePath: "cfg.json",
		PSK: "0123456789abcdef0123456789abcdef",
		Web: WebConfig{Addr: "127.0.0.1:8080", Bind: "all", Auth: "admin:realpassword",
			MCP: MCPConfig{OAuth: MCPOAuthJWTConfig{}}}}
	// 完整 GET 结构（脱敏后 web.auth 为空）+ 用户改调度字段（fwd 门 / near 策略）
	posted := map[string]any{
		"mode": "server", "psk": "", "addr": ":4000", "log_level": "info",
		"encrypt": true, "enc_algo": "gcm256", "pad_mode": "bucket",
		"routing_algo": "latency_sticky", "sched_envelope": "fwd", "sched_envelope_ms": 50,
		"fec_strategy": "near", "fec_near_window_ms": 5,
		"tap": "tap0",
		"web": map[string]any{"addr": "127.0.0.1:8080", "bind": "all", "auth": "",
			"mcp": map[string]any{"oauth": map[string]any{}}},
		"server": map[string]any{"v4_cidr": "10.0.0.0/24", "v6_cidr": "fd00::/64"},
	}
	raw, err := json.Marshal(posted)
	if err != nil {
		t.Fatalf("marshal posted config: %v", err)
	}
	cfg, _, err := mergeAndValidateConfig(old, raw, true, &Server{}, nil)
	if err != nil {
		t.Fatalf("完整 GET 回传保存失败: %v", err)
	}
	// 脱敏凭据必须回填，而不是被清空
	if cfg.Web.Auth != "admin:realpassword" {
		t.Errorf("web.auth 未回填: got %q want %q", cfg.Web.Auth, "admin:realpassword")
	}
	if cfg.PSK != old.PSK {
		t.Errorf("psk 未回填: got %q", cfg.PSK)
	}
	// 用户改的调度字段必须原样保留
	if cfg.RoutingAlgo != "latency_sticky" {
		t.Errorf("routing_algo: got %q want latency_sticky", cfg.RoutingAlgo)
	}
	if cfg.SchedEnvelope != "fwd" || cfg.SchedEnvelopeMs != 50 {
		t.Errorf("sched_envelope: got %s/%d want fwd/50", cfg.SchedEnvelope, cfg.SchedEnvelopeMs)
	}
	if cfg.FecStrategy != "near" || cfg.FecNearWindowMs != 5 {
		t.Errorf("fec_strategy: got %s/%d want near/5", cfg.FecStrategy, cfg.FecNearWindowMs)
	}
}
