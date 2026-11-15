package main

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// startServerWithSchedulerHarness 起一对进程内 server+client，server cfg 显式带
// 调度/FEC 策略三元组（非默认值），用于验证服务端各接线点是否正确应用这些字段。
// 与 startPerfHarnessWithAlgo 的唯一区别是 srvCfg 的 RoutingAlgo/FecStrategy/
// FecNearWindowMs 由参数指定（而非恒 auto）。
func startServerWithSchedulerHarness(t *testing.T, routingAlgo, fecStrategy string, fecNearWindowMs int) *perfHarness {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h := &perfHarness{cancel: cancel, srvDone: make(chan struct{}), cliDone: make(chan struct{})}

	// ---- server：显式调度字段 ----
	srvAddr := fmt.Sprintf("127.0.0.1:%d", nextPerfPort())
	h.srvAddr = srvAddr
	srvCfg := &Config{
		Mode: "server", PSK: "perf-psk", Tap: "mem", Addr: srvAddr,
		Mac: "02:00:00:00:00:01", Encrypt: true, EncAlgo: "",
		Server:        ServerConfig{V4CIDR: "10.0.0.0/24", V6CIDR: "fd00::/64"},
		RoutingAlgo:   routingAlgo,
		FecStrategy:   fecStrategy,
		FecNearWindowMs: fecNearWindowMs,
	}
	srvCfg.applyDefaults()
	if err := srvCfg.Validate(); err != nil {
		cancel()
		t.Fatalf("server cfg: %v", err)
	}
	srv, err := newServerForTest(ctx, srvCfg)
	if err != nil {
		cancel()
		t.Fatalf("server init: %v", err)
	}
	h.srv = srv
	h.srvTap = srv.tap.(*memTap)
	go func() {
		defer close(h.srvDone)
		tlsConfig := getServerTLSConfig(srvCfg.Server.Cert, srvCfg.Server.Key)
		l, err := net.Listen("tcp", srvCfg.Addr)
		if err != nil {
			t.Errorf("server listen: %v", err)
			return
		}
		serveListener(ctx, srv, l.(*net.TCPListener), tlsConfig)
	}()

	// ---- client ----
	cliCfg := &Config{
		Mode: "client", PSK: "perf-psk", Tap: "mem", Addr: srvAddr,
		Mac: "02:00:00:00:00:02", Encrypt: true, EncAlgo: "",
		Client: ClientConfig{Conns: 2, FEC: true, FecGroup: 4, Insecure: true},
	}
	cliCfg.applyDefaults()
	if err := cliCfg.Validate(); err != nil {
		cancel()
		t.Fatalf("client cfg: %v", err)
	}
	cli := NewClient(ctx, cliCfg)
	h.cli = cli
	h.cliTap = cli.tap.(*memTap)
	h.tapWriter = func(frame []byte) {
		cli.txPort.WriteFrame(frame)
	}
	go func() {
		cli.Run(ctx)
		close(h.cliDone)
	}()

	// 等握手完成。
	deadline := time.Now().Add(perfHandshakeBudget)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&h.cli.liveConns) > 0 {
			time.Sleep(300 * time.Millisecond)
			return h
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	t.Fatalf("tunnel did not come up in %s", perfHandshakeBudget)
	return nil
}

// waitServerSession 等待服务端出现至少一个活跃 session，返回它。
func waitServerSession(t *testing.T, srv *Server, timeout time.Duration) *ClientSession {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		srv.mu.RLock()
		for _, session := range srv.activeClients {
			if session.Port != nil {
				srv.mu.RUnlock()
				return session
			}
		}
		srv.mu.RUnlock()
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no active server session within %s", timeout)
	return nil
}

// TestServerInitAppliesSchedulerFieldsToTapPort 验证服务端构造（newServerForTest，
// 与生产 startServer 等价）时 tapPort 的三字段从 cfg 初始化。NewAsyncPort 只默认
// auto，若构造时未接线则 tapPort 恒 auto，服务端下行永远不应用用户策略。
func TestServerInitAppliesSchedulerFieldsToTapPort(t *testing.T) {
	h := startServerWithSchedulerHarness(t, "latency_strict", "near", 25)
	defer h.stop()

	if h.srv.tapPort == nil {
		t.Fatal("server tapPort is nil")
	}
	if got := h.srv.tapPort.routingAlgo.Load(); got != routingAlgoCode("latency_strict") {
		t.Fatalf("tapPort.routingAlgo after init = %d, want %d", got, routingAlgoCode("latency_strict"))
	}
	if got := h.srv.tapPort.fecStrategy.Load(); got != fecStrategyCode("near") {
		t.Fatalf("tapPort.fecStrategy after init = %d, want %d", got, fecStrategyCode("near"))
	}
	if got := h.srv.tapPort.fecNearWindowUS.Load(); got != 25_000 {
		t.Fatalf("tapPort.fecNearWindowUS after init = %d, want 25000", got)
	}
}

// TestServerNewSessionPortInheritsSchedulerFields 验证**新 session 创建时**（而非
// ApplyConfig 热更时）per-session port 从 s.cfg.Load() 继承服务端调度字段：server
// cfg 设非默认调度字段，client 连接建立新 session 后，session.Port 的三 atomic
// 必须等于 cfg 值（而不是 NewAsyncPort 的 auto 默认）。这是 server.go 新 session
// port 创建处（SetOneWayMode 旁）接线点的直接验证。
func TestServerNewSessionPortInheritsSchedulerFields(t *testing.T) {
	h := startServerWithSchedulerHarness(t, "latency_strict", "near", 25)
	defer h.stop()

	session := waitServerSession(t, h.srv, perfHandshakeBudget)
	if got := session.Port.routingAlgo.Load(); got != routingAlgoCode("latency_strict") {
		t.Fatalf("new session.Port.routingAlgo = %d, want %d", got, routingAlgoCode("latency_strict"))
	}
	if got := session.Port.fecStrategy.Load(); got != fecStrategyCode("near") {
		t.Fatalf("new session.Port.fecStrategy = %d, want %d", got, fecStrategyCode("near"))
	}
	if got := session.Port.fecNearWindowUS.Load(); got != 25_000 {
		t.Fatalf("new session.Port.fecNearWindowUS = %d, want 25000", got)
	}
}

// TestServerApplyConfigThenNewSessionInherits 验证 ApplyConfig 改服务端调度字段后，
// s.cfg.Store 更新，**之后新建**的 session（client ForceReconnect 触发）继承**新值**
// 而非旧值。这证明 per-session port 创建读的是 s.cfg.Load()（最新生效配置）而不是
// 启动时快照。
func TestServerApplyConfigThenNewSessionInherits(t *testing.T) {
	h := startServerWithSchedulerHarness(t, "auto", "auto", 10)
	defer h.stop()

	// 基线：初始 session 继承 auto（启动 cfg）。
	s0 := waitServerSession(t, h.srv, perfHandshakeBudget)
	if got := s0.Port.routingAlgo.Load(); got != routingAlgoCode("auto") {
		t.Fatalf("initial session routingAlgo = %d, want auto", got)
	}

	// ApplyConfig 改调度字段（热更生效 + s.cfg.Store）。
	srvCfg := *h.srv.cfg.Load()
	srvCfg.RoutingAlgo = "latency_strict"
	srvCfg.FecStrategy = "near"
	srvCfg.FecNearWindowMs = 25
	srvCfg.applyDefaults()
	if err := srvCfg.Validate(); err != nil {
		t.Fatalf("server cfg invalid: %v", err)
	}
	h.srv.ApplyConfig(&srvCfg)

	// 强制 client 重连：server 端销毁旧 session 并新建，新 session 必须继承新值。
	h.cli.ForceReconnect()
	time.Sleep(500 * time.Millisecond)

	s1 := waitServerSession(t, h.srv, perfHandshakeBudget)
	if got := s1.Port.routingAlgo.Load(); got != routingAlgoCode("latency_strict") {
		t.Fatalf("new session after ApplyConfig routingAlgo = %d, want latency_strict", got)
	}
	if got := s1.Port.fecStrategy.Load(); got != fecStrategyCode("near") {
		t.Fatalf("new session after ApplyConfig fecStrategy = %d, want near", got)
	}
	if got := s1.Port.fecNearWindowUS.Load(); got != 25_000 {
		t.Fatalf("new session after ApplyConfig fecNearWindowUS = %d, want 25000", got)
	}
}

// TestServerApplyConfigDoesNotReconnectOnSameBrutal 回归：Server.ApplyConfig 在
// brutal 三元组未变时必须不关闭既有 client 连接（brutalChanged=false → 不收集
// reconnect）。这防止"保存服务端配置就断线"回归（见 e2e_perf_test.go newServerForTest
// brutal 初始化修复）。验证方式：ApplyConfig 前后 liveConns 都不为 0 且 ping 通。
func TestServerApplyConfigDoesNotReconnectOnSameBrutal(t *testing.T) {
	h := startPerfHarness(t, 2, true, true)
	defer h.stop()
	time.Sleep(500 * time.Millisecond)

	ping := applyConfigPingHarness(t, h)
	if base := ping("baseline", 20); base < 19 {
		t.Fatalf("baseline degraded: %d/20", base)
	}

	// 同指针、不改任何字段：等价于保存一份未改动的服务端配置。
	h.srv.ApplyConfig(h.srv.cfg.Load())

	if got := atomic.LoadInt32(&h.cli.liveConns); got == 0 {
		t.Fatal("ApplyConfig with unchanged brutal triple must NOT drop client connections")
	}
	if post := ping("after-apply", 20); post < 19 {
		t.Fatalf("ApplyConfig with unchanged brutal triple degraded downlink: %d/20", post)
	}
}
