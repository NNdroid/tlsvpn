package main

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

// TestE2EPeerActiveFlag 回归：0x07 active-paths 控制帧让两端互相看到对方调度器
// 选中了哪条连接——客户端 conns 的 peer_active 表示"服务端下行调度正活跃在本
// 连接"，服务端 server_conns 的 peer_active 表示"客户端上行调度正活跃在本连接"。
// 广播周期 500ms、快照窗口 2s，两条连接握手完成后 8s 内两端标志必须点亮。
func TestE2EPeerActiveFlag(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	port := nextPerfPort()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	const psk = "test-only-high-entropy-secret"

	srvCfg := &Config{Mode: "server", PSK: psk, Tap: "mem", Addr: addr, Encrypt: true,
		Server: ServerConfig{V4CIDR: "10.0.0.0/24", V6CIDR: "fd00::/64"}}
	srvCfg.applyDefaults()
	if err := srvCfg.Validate(); err != nil {
		t.Fatalf("server cfg: %v", err)
	}
	srv, err := newServerForTest(ctx, srvCfg)
	if err != nil {
		t.Fatalf("server init: %v", err)
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go serveListener(ctx, srv, l.(*net.TCPListener),
		getServerTLSConfig(srvCfg.Server.Cert, srvCfg.Server.Key))

	cliCfg := &Config{Mode: "client", PSK: psk, Tap: "mem", Addr: addr, Encrypt: true,
		Client: ClientConfig{Conns: 2, Insecure: true, CertSHA256: e2eServerCertFingerprint()}}
	cliCfg.applyDefaults()
	if err := cliCfg.Validate(); err != nil {
		t.Fatalf("client cfg: %v", err)
	}
	cli := NewClient(ctx, cliCfg)
	go cli.Run(ctx)

	// 注入双向流量激活调度器：空闲隧道没有数据批，b.active 不会被刷新，
	// 0x07 位图为空是对端无决策的诚实状态。上行帧走 client txPort dispatch
	// （点亮 client active），下行帧经 server vswitch（点亮 server active）。
	payload := make([]byte, 64)
	tapPortID := "TAP_LOCAL"
	seq := uint32(1)
	deadline := time.Now().Add(10 * time.Second)
	var cliOK, srvOK bool
	for time.Now().Before(deadline) {
		for k := 0; k < 2; k++ {
			f := clientUplinkFrame(srv, cli, seq, payload)
			cli.txPort.WriteFrame(f)
			rev := append([]byte(nil), f...)
			copy(rev[0:6], f[6:12])
			copy(rev[6:12], f[0:6])
			srv.vswitch.ProcessFrame(tapPortID, rev)
			seq++
		}
		conns := cli.snapshotConns()
		up := 0
		cliOK = true
		for _, c := range conns {
			if c.State != "up" {
				continue
			}
			up++
			if !c.Scheduler.PeerActive {
				cliOK = false
			}
		}
		if up < 2 {
			cliOK = false // 两条连接都起来才有意义
		}
		srvOK = false
		serverUps := 0
		for _, sc := range srv.snapshotServerConns() {
			serverUps++
			if sc.Scheduler.PeerActive {
				srvOK = true
			}
		}
		if serverUps < 2 {
			srvOK = false
		}
		if cliOK && srvOK {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("peer_active flags not set within 10s: client=%v server=%v (client conns=%d, server conns=%d)",
		cliOK, srvOK, len(cli.snapshotConns()), len(srv.snapshotServerConns()))
}
