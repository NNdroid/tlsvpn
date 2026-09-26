package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// restartCase 服务端重启后自动恢复的配置组合。默认配置已证明可恢复，
// 因此这里只扫可能触发"客户端不重启就恢复不了"的开关。
type restartCase struct {
	name string
	// 客户端侧
	fecMode  bool
	fecGroup int
	conns    int
	encrypt  bool
	reqV4    string
}

// TestClientRecoversAfterServerRestart 复现并回归"服务端重启后客户端无法自动恢复"：
// 客户端进程保持存活，仅服务端整体重建（监听器、TCP 连接、会话表、IP 池、
// MAC 学习表全部清空），随后在同一端口重新起服务端，断言双向隧道流量恢复。
//
// 双向各测一次：
//   - 上行：client TAP → txPort → TLS → 服务端 VSwitch → 服务端 TAP（SetOnWrite 观测）
//   - 下行：服务端 TAP 侧注帧 → VSwitch → client 端口 → TLS → client 重排缓冲 → client TAP
func TestClientRecoversAfterServerRestart(t *testing.T) {
	cases := []restartCase{
		{name: "默认(GCM,1连接,无FEC)", encrypt: true},
		{name: "GCM+FEC-XOR K=4", encrypt: true, fecMode: true, fecGroup: 4},
		{name: "GCM+FEC-XOR K=2(下限)", encrypt: true, fecMode: true, fecGroup: fecMinGroup},
		{name: "GCM+3条物理连接", encrypt: true, conns: 3},
		{name: "GCM+3连接+FEC", encrypt: true, conns: 3, fecMode: true, fecGroup: 4},
		{name: "GCM+客户端指定IP", encrypt: true, reqV4: "10.0.0.9"},
		{name: "加密关闭", encrypt: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			runRestartCase(t, tc)
		})
	}
}

func runRestartCase(t *testing.T, tc restartCase) {
	port := nextPerfPort()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	const psk = "restart-psk"

	// ---- 客户端（长生命周期，跨服务端重启，模拟用户"不重启客户端"）----
	cliCtx, cliCancel := context.WithCancel(context.Background())
	defer cliCancel()
	cliCfg := &Config{
		Mode: "client", PSK: psk, Tap: "mem", Addr: addr,
		Encrypt: tc.encrypt,
		Client:  ClientConfig{Conns: tc.conns, FEC: tc.fecMode, FecGroup: tc.fecGroup, Insecure: true, ReqV4: tc.reqV4},
	}
	cliCfg.applyDefaults()
	if err := cliCfg.Validate(); err != nil {
		t.Fatalf("client cfg: %v", err)
	}
	cli := NewClient(cliCtx, cliCfg)
	cliTap := cli.tap.(*memTap)
	go cli.Run(cliCtx)

	// ---- 服务端模板：每次调用都是全新的进程内 Server（状态全空）----
	startServer := func(ctx context.Context) *Server {
		srvCfg := &Config{
			Mode: "server", PSK: psk, Tap: "mem", Addr: addr,
			Encrypt: tc.encrypt,
			Server:  ServerConfig{V4CIDR: "10.0.0.0/24", V6CIDR: "fd00::/64"},
		}
		srvCfg.applyDefaults()
		if err := srvCfg.Validate(); err != nil {
			t.Fatalf("server cfg: %v", err)
		}
		srv, err := newServerForTest(ctx, srvCfg)
		if err != nil {
			t.Fatalf("server init: %v", err)
		}
		// 端口复用重试：上一轮服务端可能尚未完成 listener.Close()
		var l net.Listener
		var err2 error
		for i := 0; i < 100; i++ {
			l, err2 = net.Listen("tcp", addr)
			if err2 == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if l == nil {
			t.Fatalf("重新绑定监听 %s 失败: %v", addr, err2)
		}
		go serveListener(ctx, srv, l.(*net.TCPListener),
			getServerTLSConfig(srvCfg.Server.Cert, srvCfg.Server.Key))
		return srv
	}

	// killServer 模拟服务端进程被杀：撤下监听器 + 关闭全部已建立 TCP 连接
	killServer := func(srv *Server) {
		srv.mu.Lock()
		for _, sess := range srv.activeClients {
			sess.sessionMu.Lock()
			for ci := range sess.conns {
				if ci.tcpConn != nil {
					ci.tcpConn.Close()
				}
			}
			sess.sessionMu.Unlock()
		}
		srv.mu.Unlock()
	}

	waitLive := func(t *testing.T, n int, d time.Duration) {
		t.Helper()
		deadline := time.Now().Add(d)
		for time.Now().Before(deadline) {
			if atomic.LoadInt32(&cli.liveConns) >= int32(n) {
				time.Sleep(300 * time.Millisecond) // 等交换机学习/重排缓冲稳定
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("等待 %d 条活跃连接超时（当前 %d，重连尝试 %d 次）",
			n, atomic.LoadInt32(&cli.liveConns), cli.ReconnectAttempts())
	}

	// forwardOK 上行：持续注入（真实用户是连续发包，不是一次性注入后就判定），
	// 统计有多少交付到服务端 TAP。观察窗口内收到任意帧即视为连通。
	forwardOK := func(t *testing.T, srv *Server, tag string) bool {
		t.Helper()
		var got atomic.Int64
		srv.tap.(*memTap).SetOnWrite(func([]byte) { got.Add(1) })
		payload := make([]byte, 64)
		binary.BigEndian.PutUint32(payload, 0xC0FFEE)
		deadline := time.Now().Add(5 * time.Second)
		for i := uint32(1); time.Now().Before(deadline) && got.Load() == 0; i++ {
			cli.txPort.WriteFrame(clientUplinkFrame(srv, cli, i, payload))
			time.Sleep(10 * time.Millisecond)
		}
		n := got.Load()
		t.Logf("%s 上行 交付到服务端 TAP: %d 帧", tag, n)
		return n > 0
	}

	// returnOK 下行：从服务端 TAP 侧持续注帧，统计有多少交付到客户端 TAP
	returnOK := func(t *testing.T, srv *Server, tag string) bool {
		t.Helper()
		var got atomic.Int64
		cliTap.SetOnWrite(func([]byte) { got.Add(1) })
		payload := make([]byte, 64)
		binary.BigEndian.PutUint32(payload, 0xBEEF)
		deadline := time.Now().Add(5 * time.Second)
		for i := uint32(1000); time.Now().Before(deadline) && got.Load() == 0; i++ {
			f := clientUplinkFrame(srv, cli, i, payload)
			rev := append([]byte(nil), f...)
			copy(rev[0:6], f[6:12]) // swap dst/src
			copy(rev[6:12], f[0:6])
			srv.vswitch.ProcessFrame(tapPortID, rev)
			time.Sleep(10 * time.Millisecond)
		}
		n := got.Load()
		t.Logf("%s 下行 交付到客户端 TAP: %d 帧", tag, n)
		return n > 0
	}

	// ---- 第 1 轮 ----
	ctxA, cancelA := context.WithCancel(context.Background())
	srvA := startServer(ctxA)
	defer cancelA()

	waitLive(t, tc.conns, 15*time.Second)
	fwd1, ret1 := forwardOK(t, srvA, "第1轮"), returnOK(t, srvA, "第1轮")
	if !fwd1 || !ret1 {
		cancelA()
		t.Fatalf("第1轮（服务端重启前）隧道本身不通（上行=%v 下行=%v），测试前提不成立", fwd1, ret1)
	}

	// ---- 杀掉服务端 A ----
	killServer(srvA)
	cancelA()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&cli.liveConns) > 0 {
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("服务端 A 已销毁；客户端存活连接数=%d 重连尝试=%d",
		atomic.LoadInt32(&cli.liveConns), cli.ReconnectAttempts())

	// ---- 第 2 轮：同一端口重新起服务端 ----
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	srvB := startServer(ctxB)

	waitLive(t, tc.conns, 30*time.Second)
	fwd2, ret2 := forwardOK(t, srvB, "第2轮"), returnOK(t, srvB, "第2轮")
	if !fwd2 {
		t.Error("第2轮（服务端重启后）上行不通：客户端无法自动恢复")
	}
	if !ret2 {
		t.Error("第2轮（服务端重启后）下行不通：客户端无法自动恢复")
	}
}
