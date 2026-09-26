package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"sync/atomic"
	"testing"
	"time"
)

// clientRestartCase 客户端进程重启（服务端不动）后能否自动恢复的配置组合。
//
// 与 e2e_reconnect_test.go 是镜像场景：那边是服务端重建、客户端长命，这边是
// 客户端重建、服务端长命。服务端状态（会话表、IP 池、MAC→IP 粘性绑定、
// 会话侧重排缓冲、交换机学习表）全部保留，这正是两个方向不对称的地方。
type clientRestartCase struct {
	name    string
	encrypt bool
	// macShift 模拟客户端 MAC 在重启后发生变化。
	// 真实场景：mac 配置留空时 clientID = uuid(MAC+PSK)，而 Linux 上
	// water.New 创建的 TAP 设备由内核分配随机 MAC，因此客户端每次重启
	// clientID 都会变——服务端会看到"来了个新客户端"而不是"老客户端回来了"。
	macShift bool
	// conns 每轮客户端建立的物理连接数；0 按 1 处理。
	conns int
}

// TestClientRecoversAfterClientRestart 是回归守卫：杀掉客户端进程、服务端不动，
// 重建一个全新客户端进程后隧道必须双向自动恢复。
//
// 覆盖的三个缺陷：
//   - 会话复活分支不复位服务端上行重排缓冲（server.go）：新进程 txSeq 从 1 起，
//     旧缓冲把每帧都当旧包丢弃 → 上行断、下行正常。
//   - 固定启用的 session token 在冷启动时必须从 state 恢复，否则新进程会被
//     按"冒充在线会话"永久拒绝（令牌跨进程持久化）。
//   - Linux 上 water 每次创建 TAP 给随机 MAC → clientID 漂移 → 每次重启换新 IP
//     （客户端_state 落盘修复：MAC 跨进程持久化）。
func TestClientRecoversAfterClientRestart(t *testing.T) {
	cases := []clientRestartCase{
		{name: "GCM-MAC不变-固定SessionToken", encrypt: true},
		{name: "GCM-MAC变化-固定SessionToken(模拟Linux随机MAC)", encrypt: true, macShift: true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) { runClientRestartCase(t, tc) })
	}
}

func runClientRestartCase(t *testing.T, tc clientRestartCase) {
	t.Helper()
	h := newClientRestartHarness(t, tc)
	defer h.stop()

	// ---- 第 1 轮 ----
	const mac1 = "02:00:00:00:00:02"
	cli1, cliTap1, cancel1 := h.startClient(mac1)
	if !h.waitLive(cli1, 15*time.Second) {
		t.Fatalf("第1轮：客户端连不上，测试前提不成立")
	}
	h.snapshot("第1轮")
	if f, r := h.forwardOK(cli1, "第1轮"), h.returnOK(cli1, cliTap1, "第1轮"); !f || !r {
		t.Fatalf("第1轮（客户端重启前）隧道本身不通（上行=%v 下行=%v），测试前提不成立", f, r)
	}

	// ---- 杀掉客户端 ----
	cancel1()
	h.waitDead(cli1, 10*time.Second)
	h.snapshot("客户端已停止")
	waterBefore := h.upstreamSeqWaterMark(cli1.clientID)
	if waterBefore < 101 {
		t.Fatalf("测试前提不成立：第1轮注了 100 帧后服务端上行水位仅 %d", waterBefore)
	}

	// ---- 第 2 轮：全新客户端进程，服务端未动 ----
	mac2 := mac1
	if tc.macShift {
		mac2 = "02:00:00:00:00:99"
	}
	cli2, cliTap2, _ := h.startClient(mac2)
	if !h.waitLive(cli2, 20*time.Second) {
		// 不在此中断：先看清服务端把这次握手处理成什么，再判定。
		h.snapshot("第2轮（握手未成功）")
		if sess := h.findSession(cli1.clientID); sess != nil {
			t.Logf("新进程令牌缓存=%q；落盘状态=%+v", cli2.sessionToken, cli2.state)
		}
		t.Fatal("第2轮：新客户端进程永远建立不了连接（服务端拒绝重连，客户端无限重试）")
	}
	h.snapshot("第2轮")

	// 机制断言：新进程 txSeq 从 1 起，它那条会话的上行重排缓冲必须已在起点。
	// MAC 不变走会话复活分支（服务端复位缓冲）；MAC 变化则 clientID 变了、
	// 服务端建全新会话（缓冲天然为空）。两条路径都不成立时，新进程的每一帧
	// 都会被判成旧包丢弃。
	if waterAfter := h.upstreamSeqWaterMark(cli2.clientID); waterAfter >= waterBefore/2 {
		t.Errorf("第2轮：新进程会话的上行重排缓冲未回到起点（旧会话重启前 %d → 现在 %d）",
			waterBefore, waterAfter)
	}
	if !h.forwardOK(cli2, "第2轮") {
		t.Error("第2轮（客户端重启后）上行不通：客户端无法自动恢复")
	}
	if !h.returnOK(cli2, cliTap2, "第2轮") {
		t.Error("第2轮（客户端重启后）下行不通：客户端无法自动恢复")
	}
}

// clientRestartHarness 服务端全程不重启、客户端可反复重建的测试夹具。
type clientRestartHarness struct {
	t    *testing.T
	tc   clientRestartCase
	srv  *Server
	addr string
	psk  string
	// cfgPath 模拟真实客户端的配置文件路径：客户端身份状态落在 <cfgPath>.state，
	// 两轮进程共用同一份，这正是"同一台机器重启"的前提。
	cfgPath   string
	cancelSrv context.CancelFunc
	clientCbs []context.CancelFunc
}

func newClientRestartHarness(t *testing.T, tc clientRestartCase) *clientRestartHarness {
	t.Helper()
	port := nextPerfPort()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	const psk = "cli-restart-psk"

	srvCtx, srvCancel := context.WithCancel(context.Background())
	srvCfg := &Config{
		Mode: "server", PSK: psk, Tap: "mem", Addr: addr,
		Encrypt: tc.encrypt,
		Server:  ServerConfig{V4CIDR: "10.0.0.0/24", V6CIDR: "fd00::/64"},
	}
	srvCfg.applyDefaults()
	if err := srvCfg.Validate(); err != nil {
		t.Fatalf("server cfg: %v", err)
	}
	srv, err := newServerForTest(srvCtx, srvCfg)
	if err != nil {
		t.Fatalf("server init: %v", err)
	}
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	go serveListener(srvCtx, srv, l.(*net.TCPListener),
		getServerTLSConfig(srvCfg.Server.Cert, srvCfg.Server.Key))

	return &clientRestartHarness{
		t: t, tc: tc, srv: srv, addr: addr, psk: psk,
		cfgPath: t.TempDir() + "/config.json", cancelSrv: srvCancel,
	}
}

// ---- 夹具方法 ----

// stop 关掉所有还没退出的客户端并拆掉服务端
func (h *clientRestartHarness) stop() {
	for _, cb := range h.clientCbs {
		cb()
	}
	h.cancelSrv()
}

// snapshot 打印服务端会话视图：判断"复活"还是"新建"，并读出会话侧上行重排
// 缓冲的期望序号——客户端上行帧的 seq 必须 >= expectedSeq 才会被接收。
func (h *clientRestartHarness) snapshot(tag string) {
	h.srv.mu.Lock()
	defer h.srv.mu.Unlock()
	type row struct {
		id, v4, mac string
		live        int
		nextSeq     uint32
	}
	rows := make([]row, 0, len(h.srv.activeClients))
	for id, s := range h.srv.activeClients {
		s.sessionMu.Lock()
		r := row{id: id, v4: s.IPv4, mac: s.MAC, live: s.ActiveConns}
		if rb := s.RxReorder; rb != nil {
			rb.mu.Lock()
			r.nextSeq = rb.expectedSeq
			rb.mu.Unlock()
		}
		rows = append(rows, r)
		s.sessionMu.Unlock()
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].id < rows[j].id })
	h.t.Logf("%s 服务端会话 %d 个: %v", tag, len(rows), rows)
}

// startClient 起一个全新的客户端进程（全新进程状态：会话令牌缓存为空、
// txSeq 从 1 起、重排缓冲全新）。返回的 cancel 即"杀掉该进程"。
func (h *clientRestartHarness) startClient(mac string) (*Client, *memTap, context.CancelFunc) {
	cliCtx, cliCancel := context.WithCancel(context.Background())
	conns := h.tc.conns
	if conns < 1 {
		conns = 1
	}
	c := &Config{
		Mode: "client", PSK: h.psk, Tap: "mem", Addr: h.addr, Mac: mac,
		Encrypt:    h.tc.encrypt,
		Client:     ClientConfig{Conns: conns, Insecure: true},
		SourcePath: h.cfgPath,
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		h.t.Fatalf("client cfg: %v", err)
	}
	cli := NewClient(cliCtx, c)
	h.t.Logf("客户端进程启动 clientID=%s mac=%s", cli.clientID, cli.macAddr)
	go cli.Run(cliCtx)
	h.clientCbs = append(h.clientCbs, cliCancel)
	return cli, cli.tap.(*memTap), cliCancel
}

// waitLive 等客户端进程建立起配置数量的活跃物理连接；返回 false 表示始终连不上。
func (h *clientRestartHarness) waitLive(cli *Client, d time.Duration) bool {
	want := int32(1)
	if h.tc.conns > 1 {
		want = int32(h.tc.conns)
	}
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&cli.liveConns) >= want {
			time.Sleep(300 * time.Millisecond) // 等交换机学习/重排缓冲稳定
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	h.t.Logf("等待客户端建立 %d 条连接超时（实际 %d 条，重连尝试 %d 次）",
		want, atomic.LoadInt32(&cli.liveConns), cli.ReconnectAttempts())
	return false
}

// waitDead 等客户端进程的所有物理连接断开
func (h *clientRestartHarness) waitDead(cli *Client, d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) && atomic.LoadInt32(&cli.liveConns) > 0 {
		time.Sleep(100 * time.Millisecond)
	}
}

// uplinkFrame 以当前客户端的真实身份构上行帧（源 MAC/IP 取自该进程的 TAP
// 身份与其被分配的地址）。vswitch 对会话 MAC 做钉扎校验，换 MAC 重连的
// 进程必须以新身份构帧——沿用旧身份的帧会被当作 MAC 欺骗丢弃，这正是
// 产品要防的行为，夹具不能依赖旧行为。
func (h *clientRestartHarness) uplinkFrame(cli *Client, seq uint32, payload []byte) []byte {
	return clientUplinkFrame(h.srv, cli, seq, payload)
}

// forwardOK 上行：持续注帧（真实用户是连续发包，不是一次性注入后判定），
// 统计交付到服务端 TAP 的帧数。
func (h *clientRestartHarness) forwardOK(cli *Client, tag string) bool {
	var got atomic.Int64
	h.srv.tap.(*memTap).SetOnWrite(func([]byte) { got.Add(1) })
	payload := make([]byte, 64)
	binary.BigEndian.PutUint32(payload, 0xC0FFEE)
	go func() {
		for i := 0; i < 100; i++ {
			cli.txPort.WriteFrame(h.uplinkFrame(cli, uint32(i+1), payload))
			time.Sleep(10 * time.Millisecond)
		}
	}()
	time.Sleep(2 * time.Second)
	h.t.Logf("%s 上行 交付到服务端 TAP: %d 帧", tag, got.Load())
	return got.Load() > 0
}

// returnOK 下行：从服务端 TAP 侧持续注帧（目的地为该客户端的身份），
// 统计交付到客户端 TAP 的帧数
func (h *clientRestartHarness) returnOK(cli *Client, cliTap *memTap, tag string) bool {
	var got atomic.Int64
	cliTap.SetOnWrite(func([]byte) { got.Add(1) })
	payload := make([]byte, 64)
	binary.BigEndian.PutUint32(payload, 0xBEEF)
	go func() {
		for i := 0; i < 100; i++ {
			f := h.uplinkFrame(cli, uint32(i+1000), payload)
			rev := append([]byte(nil), f...)
			copy(rev[0:6], f[6:12]) // swap dst/src
			copy(rev[6:12], f[0:6])
			h.srv.vswitch.ProcessFrame(tapPortID, rev)
			time.Sleep(10 * time.Millisecond)
		}
	}()
	time.Sleep(2 * time.Second)
	h.t.Logf("%s 下行 交付到客户端 TAP: %d 帧", tag, got.Load())
	return got.Load() > 0
}

// findSession 按 clientID 取会话（测试用）
func (h *clientRestartHarness) findSession(clientID string) *ClientSession {
	h.srv.mu.Lock()
	defer h.srv.mu.Unlock()
	return h.srv.activeClients[clientID]
}

// TestRevivalBufferResetNeedsAllConnsDead 保护会话复活分支的复位守卫：
// 只有上一代物理连接全部断开（ActiveConns==0）才复位服务端上行重排缓冲。
// Conns>1 时后续物理连接的到达不得触发复位——客户端各物理连接共享同一个
// txPort，上行序号跨连接连续，中途复位会丢掉在途帧。
func TestRevivalBufferResetNeedsAllConnsDead(t *testing.T) {
	h := newClientRestartHarness(t, clientRestartCase{name: "守卫", conns: 2})
	defer h.stop()

	const mac = "02:00:00:00:00:02"
	cli1, cliTap1, cancel1 := h.startClient(mac)
	if !h.waitLive(cli1, 15*time.Second) {
		t.Fatal("第1轮连不上")
	}
	if f, r := h.forwardOK(cli1, "第1轮"), h.returnOK(cli1, cliTap1, "第1轮"); !f || !r {
		t.Fatalf("第1轮隧道本身不通（上行=%v 下行=%v），测试前提不成立", f, r)
	}
	waterBefore := h.upstreamSeqWaterMark(cli1.clientID)
	if waterBefore < 101 {
		t.Fatalf("测试前提不成立：第1轮注了 100 帧后水位仅 %d", waterBefore)
	}

	cancel1()
	h.waitDead(cli1, 10*time.Second)

	cli2, cliTap2, _ := h.startClient(mac)
	if !h.waitLive(cli2, 20*time.Second) {
		h.snapshot("第2轮（握手未成功）")
		t.Fatal("第2轮：新客户端进程建立不了连接")
	}
	// 两条物理连接都已建立：此时水位必须已回落（复位发生在第一条连接握手时，
	// 第二条连接的到达只是 ActiveConns 0→1→2，不得再次复位）。
	if waterAfter := h.upstreamSeqWaterMark(cli2.clientID); waterAfter >= waterBefore/2 {
		t.Errorf("会话复活未复位上行重排缓冲（重启前 %d → 现在 %d）", waterBefore, waterAfter)
	}
	if !h.forwardOK(cli2, "第2轮") {
		t.Error("第2轮上行不通：客户端无法自动恢复")
	}
	if !h.returnOK(cli2, cliTap2, "第2轮") {
		t.Error("第2轮下行不通：客户端无法自动恢复")
	}
}

// upstreamSeqWaterMark 读出指定 clientID 会话的上行重排缓冲期望序号。
// 必须按会话取而不是取全局最大值：120 秒僵尸保留期内上一代客户端的旧会话
// 仍留在表里且水位不变，取 max 会把旧会话的水位误当成新进程会话的水位。
func (h *clientRestartHarness) upstreamSeqWaterMark(clientID string) uint32 {
	h.srv.mu.Lock()
	defer h.srv.mu.Unlock()
	s := h.srv.activeClients[clientID]
	if s == nil {
		return 0
	}
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	if rb := s.RxReorder; rb != nil {
		rb.mu.Lock()
		defer rb.mu.Unlock()
		return rb.expectedSeq
	}
	return 0
}
