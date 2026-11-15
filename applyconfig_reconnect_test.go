package main

import (
	"context"
	"testing"
)

// TestApplyConfigHotReloadNoReconnect 验证修复①：仅热更调度字段（routing_algo/
// fec_strategy/fec_near_window_ms/pad_mode）时不触发 ForceReconnect（forceGen 不变），
// 因为这些字段是纯原子热更、无需重建连接；改握手消费字段（psk/encrypt/fec）才重连。
func TestApplyConfigHotReloadNoReconnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{
		txPort:     NewAsyncPort(ctx, "test-apply"),
		wake:       make(chan struct{}, 1),
		connsCount: 2,
	}
	// 模拟启动：bootCfg / live / cfgSnap 均已 store。
	boot := &Config{
		Mode: "client", PSK: "boot-psk", Addr: "1.2.3.4:4000",
		RoutingAlgo: "auto", FecStrategy: "auto", FecNearWindowMs: 10,
		Client: ClientConfig{Conns: 2, FEC: true, FecGroup: 4},
	}
	boot.applyDefaults()
	c.bootCfg.Store(boot)
	c.live.Store(liveFromCfg(boot))
	c.cfgSnap.Store(boot)

	baseGen := func() uint64 { return c.forceGen }

	// ---- 仅改调度字段：不应重连 ----
	schedCfg := *boot
	schedCfg.FecStrategy = "near"
	schedCfg.FecNearWindowMs = 25
	c.ApplyConfig(&schedCfg)
	if g := baseGen(); g != 0 {
		t.Fatalf("scheduler-only hot reload must NOT reconnect: forceGen=%d want 0", g)
	}

	// ---- 改握手消费字段（psk）：应重连 ----
	handCfg := *boot
	handCfg.PSK = "new-psk"
	c.ApplyConfig(&handCfg)
	if g := baseGen(); g == 0 {
		t.Fatal("handshake-consumed field change (psk) MUST reconnect: forceGen still 0")
	}
}
