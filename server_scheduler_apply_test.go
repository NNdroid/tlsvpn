package main

import (
	"testing"
	"time"
)

// TestServerApplySchedulerFields 验证服务端接线：ApplyConfig 改顶层调度/FEC 策略
// 字段后，tapPort 与所有活跃 session 的 per-session port 的 atomic 都被设置，
// 且下行 ping 不中断。这是本次迁移（字段移到 Config 顶层 + 服务端接线）的核心验证。
func TestServerApplySchedulerFields(t *testing.T) {
	h := startPerfHarness(t, 2, true, true)
	defer h.stop()
	time.Sleep(500 * time.Millisecond)

	// 构造 server 侧 cfg 副本，改顶层调度字段。
	srvCfg := *h.srv.cfg.Load()
	srvCfg.RoutingAlgo = "latency_strict"
	srvCfg.FecStrategy = "near"
	srvCfg.FecNearWindowMs = 25
	srvCfg.applyDefaults()
	if err := srvCfg.Validate(); err != nil {
		t.Fatalf("server cfg invalid: %v", err)
	}

	h.srv.ApplyConfig(&srvCfg)

	// tapPort 必须被设置。
	if h.srv.tapPort == nil {
		t.Fatal("server tapPort is nil")
	}
	if got := h.srv.tapPort.routingAlgo.Load(); got != routingAlgoCode("latency_strict") {
		t.Fatalf("tapPort.routingAlgo = %d, want %d", got, routingAlgoCode("latency_strict"))
	}
	if got := h.srv.tapPort.fecStrategy.Load(); got != fecStrategyCode("near") {
		t.Fatalf("tapPort.fecStrategy = %d, want %d", got, fecStrategyCode("near"))
	}
	if got := h.srv.tapPort.fecNearWindowUS.Load(); got != 25_000 {
		t.Fatalf("tapPort.fecNearWindowUS = %d, want 25000", got)
	}

	// 所有活跃 session 的 per-session port 也必须被设置。
	h.srv.mu.RLock()
	checked := 0
	for _, session := range h.srv.activeClients {
		if session.Port == nil {
			continue
		}
		checked++
		if got := session.Port.routingAlgo.Load(); got != routingAlgoCode("latency_strict") {
			t.Fatalf("session.Port.routingAlgo = %d, want %d", got, routingAlgoCode("latency_strict"))
		}
		if got := session.Port.fecStrategy.Load(); got != fecStrategyCode("near") {
			t.Fatalf("session.Port.fecStrategy = %d, want %d", got, fecStrategyCode("near"))
		}
	}
	h.srv.mu.RUnlock()
	if checked == 0 {
		t.Fatal("no active client sessions found to verify per-session port")
	}

	// 下行 ping 仍通（ApplyConfig 服务端调度字段热更不中断数据面）。
	ping := applyConfigPingHarness(t, h)
	if base := ping("after-server-apply", 20); base < 19 {
		t.Fatalf("downlink ping degraded after server ApplyConfig scheduler hot-reload: %d/20", base)
	}
}

// TestServerApplySchedulerFieldsIsolate 隔离哪个调度字段导致下行丢包。
// 分别只改 routing_algo / fec_strategy / 原样（对照），各起独立 harness。
func TestServerApplySchedulerFieldsIsolate(t *testing.T) {
	cases := []struct {
		name        string
		mutate      func(cfg *Config)
		samePointer bool
	}{
		{"control-noop", func(cfg *Config) {}, false},
		{"control-same-pointer", func(cfg *Config) {}, true}, // 同指针：不拷贝、不改
		{"routing-latency-strict", func(cfg *Config) { cfg.RoutingAlgo = "latency_strict" }, false},
		{"fec-near", func(cfg *Config) { cfg.FecStrategy = "near" }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := startPerfHarness(t, 2, true, true)
			defer h.stop()
			time.Sleep(500 * time.Millisecond)

			// 基线：ApplyConfig 之前 ping 必须通。
			ping := applyConfigPingHarness(t, h)
			if base := ping("baseline", 20); base < 19 {
				t.Fatalf("baseline ping before ApplyConfig degraded: %d/20", base)
			}

			var applyCfg *Config
			if tc.samePointer {
				applyCfg = h.srv.cfg.Load()
			} else {
				applyCfg = new(Config)
				*applyCfg = *h.srv.cfg.Load()
				tc.mutate(applyCfg)
				applyCfg.applyDefaults()
				if err := applyCfg.Validate(); err != nil {
					t.Fatalf("server cfg invalid: %v", err)
				}
			}
			// 注意：Server.ApplyConfig 的 brutalChanged 依赖 s.brutalUp/Down 与
			// cfg.BrutalUp/Down 同步；newServerForTest 必须从 cfg 初始化该三元组
			// （与 startServer 一致），否则零值(0/0) 与 cfg 默认(100/500) 被误判为
			// "已变更"，每次保存配置都误触发全量 reconnect（见 e2e_perf_test.go）。
			h.srv.ApplyConfig(applyCfg)

			post := ping("after-apply", 20)
			t.Logf("%s: post-apply ping %d/20", tc.name, post)
			if post < 19 {
				t.Fatalf("%s caused downlink ping degradation: %d/20", tc.name, post)
			}
		})
	}
}
