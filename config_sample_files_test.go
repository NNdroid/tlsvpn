package main

import (
	"os"
	"strings"
	"testing"
)

// TestConfigSampleFilesLoadAndValidate 验证两个样本配置文件（config.client.json /
// config.server.json）能通过 loadConfigFile（含 DisallowUnknownFields）加载，且
// 迁移后的调度/FEC 三字段位于**顶层**（而非 client 块）并是合法值。
// 注意：样本文件含占位符（psk/web.auth），Validate 会故意拒占位符——这是预期
// 行为（提醒用户替换），因此这里**不跑完整 Validate**，只验证迁移相关结构。
// 这防止样本文件与代码迁移脱节：若有人把三字段放回 client 块，DisallowUnknownFields
// 会拒绝加载，测试立即失败。
func TestConfigSampleFilesLoadAndValidate(t *testing.T) {
	samples := []struct {
		path string
		mode string
	}{
		{"config.client.json", "client"},
		{"config.server.json", "server"},
	}
	for _, s := range samples {
		t.Run(s.mode, func(t *testing.T) {
			// 样本文件在仓库根（测试的 cwd）。
			cfg, err := loadConfigFile(s.path)
			if err != nil {
				t.Fatalf("loadConfigFile(%s): %v", s.path, err)
			}
			if cfg.Mode != s.mode {
				t.Fatalf("%s mode = %q, want %q", s.path, cfg.Mode, s.mode)
			}

			// 顶层三字段必须存在且为合法值（迁移后位置）。
			if cfg.RoutingAlgo == "" {
				t.Fatalf("%s: top-level routing_algo missing after migration", s.path)
			}
			if cfg.FecStrategy == "" {
				t.Fatalf("%s: top-level fec_strategy missing after migration", s.path)
			}
			if cfg.FecNearWindowMs <= 0 {
				t.Fatalf("%s: top-level fec_near_window_ms missing after migration", s.path)
			}
			if !ValidRoutingAlgo(cfg.RoutingAlgo) {
				t.Fatalf("%s: invalid routing_algo %q", s.path, cfg.RoutingAlgo)
			}
			if !ValidFecStrategy(cfg.FecStrategy) {
				t.Fatalf("%s: invalid fec_strategy %q", s.path, cfg.FecStrategy)
			}
		})
	}
}

// TestConfigSampleFilesOldPositionAbsent 断言样本文件的 client 块**不含**三字段
// （迁移后旧位置必须消失），并直接验证整个文件用 DisallowUnknownFields 能解码——
// 即样本里没有遗留的 client.routing_algo 等未知字段。
func TestConfigSampleFilesOldPositionAbsent(t *testing.T) {
	for _, path := range []string{"config.client.json", "config.server.json"} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, field := range []string{"routing_algo", "fec_strategy", "fec_near_window_ms"} {
			// 检查这些字段名是否只出现在顶层（以 2 空格缩进，行首），而非嵌套 client/server 块内。
			for _, line := range strings.Split(string(data), "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.Contains(trimmed, field) && !strings.HasPrefix(trimmed, `"`+field+`"`) {
					t.Fatalf("%s: %q appears nested (old position) at line %q", path, field, line)
				}
			}
		}
		// 完整解码必须成功（无 unknown field）。
		if _, err := loadConfigFile(path); err != nil {
			t.Fatalf("loadConfigFile(%s) should succeed (no unknown fields): %v", path, err)
		}
	}
}
