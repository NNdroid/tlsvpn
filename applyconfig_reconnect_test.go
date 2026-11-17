package main

import (
	"context"
	"sync/atomic"
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

// TestApplyConfigRejectsEmptyTargetAddrs 回归：全分隔符 addr（如 ",,,"）经
// parseServerAddresses 得到空表，热更若照单全收，重连监督器里
// targetAddrs[connIndex%len(...)] 会除零 panic——被 goSafe recover 后 Run 返回、
// 进程以退出码 0 静默退出。ApplyConfig 必须拒绝并保留旧 live。
func TestApplyConfigRejectsEmptyTargetAddrs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{
		txPort:     NewAsyncPort(ctx, "test-apply-empty"),
		wake:       make(chan struct{}, 1),
		connsCount: 1,
	}
	boot := &Config{Mode: "client", PSK: "boot-psk", Addr: "1.2.3.4:4000",
		Client: ClientConfig{Conns: 1}}
	boot.applyDefaults()
	c.bootCfg.Store(boot)
	c.live.Store(liveFromCfg(boot))
	c.cfgSnap.Store(boot)

	bad := *boot
	bad.Addr = " , ,, "
	c.ApplyConfig(&bad)
	lv := c.live.Load()
	if len(lv.targetAddrs) == 0 || lv.targetAddrs[0] != "1.2.3.4:4000" {
		t.Fatalf("ApplyConfig accepted empty target list: live targetAddrs=%v", lv.targetAddrs)
	}
	if g := atomic.LoadUint64(&c.forceGen); g != 0 {
		t.Fatalf("rejected hot-apply must not reconnect: forceGen=%d", g)
	}

	// Validate 必须在入口就拒绝全空目标列表
	vcfg := *boot
	vcfg.Addr = ",,,"
	if err := vcfg.Validate(); err == nil {
		t.Fatal("Validate accepted client addr that parses to zero target addresses")
	}
}
