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

// TestMergeConfigPinsMode 回归：注释承诺"面板不能改写 mode"，但实现此前只固定
// 了 SourcePath——提交 mode:"client" 会把相反角色持久化进配置文件，下次重启
// 进程身份静默互换。
func TestMergeConfigPinsMode(t *testing.T) {
	old := &Config{Mode: "server", SourcePath: "cfg.json",
		PSK:  "0123456789abcdef0123456789abcdef",
		Addr: ":4000", Tap: "tap0",
		Web: WebConfig{Addr: "127.0.0.1:8080", Bind: "all", Auth: "admin:realpassword",
			MCP: MCPConfig{OAuth: MCPOAuthJWTConfig{}}}}
	old.applyDefaults()
	posted := map[string]any{
		"mode": "client", "psk": "", "addr": ":4000", "tap": "tap0",
		"web":    map[string]any{"addr": "127.0.0.1:8080", "bind": "all", "auth": ""},
		"server": map[string]any{"v4_cidr": "10.0.0.0/24", "v6_cidr": "fd00::/64"},
	}
	raw, err := json.Marshal(posted)
	if err != nil {
		t.Fatalf("marshal posted config: %v", err)
	}
	cfg, _, err := mergeAndValidateConfig(old, raw, false, &Server{}, nil)
	if err != nil {
		t.Fatalf("merge failed: %v", err)
	}
	if cfg.Mode != old.Mode {
		t.Fatalf("mode was rewritten via panel save: got %q want %q", cfg.Mode, old.Mode)
	}
}

// TestMergeConfigMCPredentialRoundtrip 回归：GET /api/config 脱敏 web.mcp.credential
// 后，面板回传空值必须回填现有验证器；切换认证模式则必须重新提供凭据（fail-closed），
// 不能把旧验证器静默套到新模式上。
func TestMergeConfigMCPredentialRoundtrip(t *testing.T) {
	old := &Config{Mode: "server", SourcePath: "cfg.json",
		PSK:  "0123456789abcdef0123456789abcdef",
		Addr: ":4000", Tap: "tap0",
		Web: WebConfig{Addr: "127.0.0.1:8080", Bind: "all", Auth: "admin:realpassword",
			MCP: MCPConfig{AuthMode: "bearer", Credential: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
				OAuth: MCPOAuthJWTConfig{}}}}
	old.applyDefaults()

	// 1) 模式不变 + 空凭据 → 回填
	sameMode := map[string]any{
		"mode": "server", "psk": "", "addr": ":4000", "tap": "tap0",
		"web": map[string]any{"addr": "127.0.0.1:8080", "bind": "all", "auth": "",
			"mcp": map[string]any{"auth_mode": "bearer", "credential": ""}},
	}
	raw, _ := json.Marshal(sameMode)
	cfg, _, err := mergeAndValidateConfig(old, raw, false, &Server{}, nil)
	if err != nil {
		t.Fatalf("same-mode save with redacted credential failed: %v", err)
	}
	if cfg.Web.MCP.Credential != "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("mcp credential not preserved: %q", cfg.Web.MCP.Credential)
	}

	// 2) 模式切换 + 空凭据 → 拒绝（fail-closed），不静默沿用旧验证器
	switchMode := map[string]any{
		"mode": "server", "psk": "", "addr": ":4000", "tap": "tap0",
		"web": map[string]any{"addr": "127.0.0.1:8080", "bind": "all", "auth": "",
			"mcp": map[string]any{"auth_mode": "api_key", "api_key_header": "X-API-Key", "credential": ""}},
	}
	raw2, _ := json.Marshal(switchMode)
	if _, _, err := mergeAndValidateConfig(old, raw2, false, &Server{}, nil); err == nil {
		t.Fatal("mode switch with empty credential must fail validation")
	}
}
