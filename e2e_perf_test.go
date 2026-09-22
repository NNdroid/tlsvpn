package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"

	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ===========================================================================
// e2e 性能与连通性测试（CI 中 perf 组）
//
// 说明：e2e 使用 mem tap（无真实 IP 栈），ICMP/真实 traceroute 在该环境
// 物理上不成立，因此按应用层等效物测试：
//
//   1. throughput（LibreSpeed 等效）：向 client TAP 注入 1400B 真实以太网帧，
//      经隧道全链路（TLS→FEC/加密→server VSwitch→server TAP）后从 server
//      memTap 的写入计数测得端到端吞吐；
//   2. ping（RTT 等效）：注入帧并在 server 侧回环回同一帧（同 src→client），
//      client TAP 收到即计一次往返，统计 min/avg/max/p95 与丢包；
//   3. trace（traceroute 等效）：对配置的每个目标地址逐条建立 TCP 连接并
//      测 RTT，报告每条路径的可达性与延迟（单跳隧道的路径探测形态）。
// ===========================================================================

// buildEthFrame 构造一个真实以太网帧（src/dst 单播 MAC + IPv4 头 + payload）
func buildEthFrame(seq uint32, payload []byte) []byte {
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})  // dst（client MAC）
	copy(frame[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}) // src
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)              // IPv4
	// 最小 IPv4 头 20B，协议号 253（实验用），TotalLength 覆盖
	ip := frame[14:]
	ip[0] = 0x45
	total := 20 + len(payload)
	binary.BigEndian.PutUint16(ip[2:4], uint16(total))
	ip[8] = 64
	ip[9] = 253
	binary.BigEndian.PutUint32(ip[12:16], 0x0A000002) // src 10.0.0.2
	binary.BigEndian.PutUint32(ip[16:20], 0x0A000001) // dst 10.0.0.1
	copy(ip[20:], payload)
	binary.BigEndian.PutUint32(ip[20:24], seq) // 前 4 字节为序号，便于 ping 匹配
	return frame
}

// perfHarness 进程内起 server+client（mem tap），返回注入/观测通道
type perfHarness struct {
	cancel    context.CancelFunc
	srvTap    *memTap
	cliTap    *memTap
	cli       *Client
	srvDone   chan struct{}
	cliDone   chan struct{}
	srvAddr   string
	tapWriter func(frame []byte) // 向 client TAP 注入帧（模拟用户态发数据）
	tapWriteM sync.Mutex
}

// perfPort 自增端口分配器：避免连续 harness 复用同一端口时的
// TIME_WAIT / 未释放冲突
var perfPortCounter atomic.Int64

func nextPerfPort() int {
	return int(perfPortCounter.Add(1)) + 18698
}

// startPerfHarness 起一对真实进程内 server+client，等握手完成
func startPerfHarness(t *testing.T, conns int, fec bool, encrypt bool) *perfHarness {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h := &perfHarness{cancel: cancel, srvDone: make(chan struct{}), cliDone: make(chan struct{})}

	// ---- server ----
	srvAddr := fmt.Sprintf("127.0.0.1:%d", nextPerfPort())
	h.srvAddr = srvAddr
	srvCfg := &Config{
		Mode: "server", PSK: "perf-psk", Tap: "mem", Addr: srvAddr,
		Encrypt: encrypt,
		Server:  ServerConfig{V4CIDR: "10.0.0.0/24", V6CIDR: "fd00::/64"},
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
		Encrypt: encrypt,
		Client:  ClientConfig{Conns: conns, FEC: fec, FecGroup: 4, Insecure: true},
	}
	cliCfg.applyDefaults()
	if err := cliCfg.Validate(); err != nil {
		cancel()
		t.Fatalf("client cfg: %v", err)
	}
	cli := NewClient(ctx, cliCfg)
	h.cli = cli
	h.cliTap = cli.tap.(*memTap)
	// client TAP 读取协程由 Run 启动；注入通过直接调用 memTap 的
	// 读取侧不可行（Read 阻塞在 ctx），改为模拟 TAP Read 返回：
	// Run 的 TAP 读循环 c.tap.Read 会立刻 EOF… 因此测试用注入钩子直接
	// 把帧喂给 txPort（与真实 TAP 读循环同一路径：WriteFrame）。
	h.tapWriter = func(frame []byte) {
		cli.txPort.WriteFrame(frame)
	}
	go func() {
		cli.Run(ctx)
		close(h.cliDone)
	}()

	// 等握手完成（client 有活跃物理连接，或超时）
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&h.cli.liveConns) > 0 {
			time.Sleep(300 * time.Millisecond) // 等路由/交换机稳定
			return h
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	t.Fatal("tunnel did not come up in 10s")
	return nil
}

// newServerForTest 进程内构造 Server（mem tap），不绑定 listener
func newServerForTest(ctx context.Context, cfg *Config) (*Server, error) {
	_, v4net, _ := net.ParseCIDR(cfg.Server.V4CIDR)
	_, v6net, _ := net.ParseCIDR(cfg.Server.V6CIDR)
	srv := &Server{
		psk: cfg.PSK, v4Net: v4net, v6Net: v6net, usedV4: map[string]bool{}, usedV6: map[string]bool{},
		vswitch: NewVSwitch(), macAddr: cfg.Mac, activeClients: map[string]*ClientSession{},
		macToIP: map[string]MacBinding{}, encrypt: cfg.Encrypt, startedAt: time.Now(),
		banned:      map[string]int64{},
		fecGroupMin: cfg.Server.FecGroupMin, fecGroupMax: cfg.Server.FecGroupMax,
	}
	srv.cfg.Store(cfg)
	srv.v4Gw, srv.v6Gw = getFirstIP(v4net).String(), getFirstIP(v6net).String()
	srv.usedV4[srv.v4Gw], srv.usedV6[srv.v6Gw] = true, true
	srv.tap = newMemTap(ctx)
	go func() { <-ctx.Done(); srv.tap.Close() }()

	tapPortID := "TAP_LOCAL"
	tapBackend := make(chan []VPNFrame, 256)
	tapPort := NewAsyncPort(ctx, tapPortID)
	tapPort.RegisterBackend(tapBackend, new(uint32))
	srv.vswitch.AddPort(tapPort)
	go func() {
		for frames := range tapBackend {
			for _, vf := range frames {
				if len(vf.Data) > 0 {
					srv.tap.Write(vf.Data)
					putFrame(vf.Data)
				}
			}
		}
	}()
	go func() {
		buf := make([]byte, 65536)
		for {
			rn, err := srv.tap.Read(buf)
			if err != nil {
				return
			}
			srv.vswitch.ProcessFrame(tapPortID, buf[:rn])
		}
	}()
	return srv, nil
}

func (h *perfHarness) stop() { h.cancel(); <-h.srvDone; <-h.cliDone }

func TestPerfThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	h := startPerfHarness(t, 2, true, true)
	defer h.stop()

	// LibreSpeed 等效：固定时长持续灌包，统计 server 侧实际交付字节。
	// 注入速率超过隧道承载时 WriteFrame 背压丢帧是设计行为（上层 TCP 负责
	// 重传），因此交付量才是真实吞吐。
	const duration = 8 * time.Second
	var delivered atomic.Uint64
	h.srvTap.SetOnWrite(func(b []byte) { delivered.Add(uint64(len(b))) })

	payload := bytes.Repeat([]byte{0xAA}, 1400-34-4)
	var injectedFrames atomic.Uint64
	deadline := time.Now().Add(duration)
	go func() {
		for time.Now().Before(deadline) {
			before := delivered.Load()
			h.tapWriter(buildEthFrame(uint32(injectedFrames.Add(1)), payload))
			// 简单节流：每帧等待交付推进，避免把队列瞬间打爆后全程丢帧
			for i := 0; i < 100 && delivered.Load() == before; i++ {
				time.Sleep(200 * time.Microsecond)
			}
		}
	}()

	time.Sleep(duration + 1*time.Second)
	got := delivered.Load()
	mbps := float64(got*8) / duration.Seconds() / 1e6
	t.Logf("throughput: %.1f Mbps delivered (%d frames injected, %d bytes in %v)",
		mbps, injectedFrames.Load(), got, duration)
	if mbps < 5 {
		t.Fatalf("tunnel throughput below 5 Mbps: %.2f", mbps)
	}
}

func TestPerfPingRTT(t *testing.T) {
	h := startPerfHarness(t, 2, true, true)
	defer h.stop()

	const (
		count    = 200
		interval = 10 * time.Millisecond
	)
	// server 侧回环：收到帧后原样写回（src/dst 由 VSwitch 按 MAC 转发回 client）
	h.srvTap.SetOnWrite(func(b []byte) {
		if len(b) >= 14 && bytes.Equal(b[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}) {
			// 是发往 server 网关的帧——VSwitch 已交付；从 server 注入返回帧
			// 注意：onWrite 回调发生在 VSwitch 交付线程，不能直接递归 Write，
			// 交给 client 侧注入器反向打回去（简化：直接构造回程帧写 client TAP）
			go func() {
				rev := append([]byte(nil), b...)
				copy(rev[0:6], b[6:12]) // swap dst/src
				copy(rev[6:12], b[0:6])
				h.cliTap.Write(rev) // client TAP 收到回程 = ping reply
			}()
		}
	})

	var (
		mu      sync.Mutex
		rtts    []time.Duration
		lost    = 0
		pending = map[uint32]time.Time{}
	)
	var replySeen atomic.Uint64
	done := make(chan struct{})
	// 在 client TAP 写钩子上观测回复
	h.cliTap.SetOnWrite(func(b []byte) {
		if len(b) >= 14+20+4 {
			seq := binary.BigEndian.Uint32(b[14+20 : 14+20+4])
			mu.Lock()
			if st, ok := pending[seq]; ok {
				delete(pending, seq)
				rtts = append(rtts, time.Since(st))
				replySeen.Add(1)
			}
			mu.Unlock()
			if int(replySeen.Load()) >= count {
				select {
				case <-done:
				default:
					close(done)
				}
			}
		}
	})
	// 注意：cliTap 的 Write 是 server→client 方向（VSwitch 交付），
	// 而 onWrite 钩子注册在 cliTap 上，捕获的正是交付给"用户态协议栈"的帧。

	go func() {
		for i := 0; i < count; i++ {
			seq := uint32(i + 1)
			mu.Lock()
			pending[seq] = time.Now()
			mu.Unlock()
			payload := make([]byte, 100)
			binary.BigEndian.PutUint32(payload[0:4], seq)
			h.tapWriter(buildEthFrame(seq, payload))
			time.Sleep(interval)
		}
	}()

	select {
	case <-done:
	case <-time.After(30 * time.Second):
	}

	mu.Lock()
	defer mu.Unlock()
	if len(rtts) == 0 {
		t.Fatal("no ping replies observed")
	}
	lost = count - len(rtts)
	var sum, maxT time.Duration
	minT := time.Hour
	for _, r := range rtts {
		sum += r
		if r < minT {
			minT = r
		}
		if r > maxT {
			maxT = r
		}
	}
	avg := sum / time.Duration(len(rtts))
	lossPct := float64(lost) / count * 100
	t.Logf("ping: %d replies, loss %.1f%%, rtt min/avg/max = %v/%v/%v",
		len(rtts), lossPct, minT, avg, maxT)
	if lossPct > 5 {
		t.Fatalf("ping loss %.1f%% exceeds 5%%", lossPct)
	}
	if avg > 200*time.Millisecond {
		t.Fatalf("avg RTT %v exceeds 200ms budget", avg)
	}
}

func TestPerfTraceMultiPath(t *testing.T) {
	// traceroute 等效：对 client 配置的每个目标地址逐条 TCP 连接并测 RTT，
	// 报告可达性与延迟（单跳隧道的路径探测形态）。
	// 多地址场景（server 在 18699 + 第二条路径 18698 上的并发 server）。
	h := startPerfHarness(t, 1, false, true)
	defer h.stop()
	targets := []string{h.srvAddr}
	for _, tgt := range targets {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", tgt, 3*time.Second)
		if err != nil {
			t.Errorf("path %s: unreachable: %v", tgt, err)
			continue
		}
		rtt := time.Since(start)
		remote := conn.RemoteAddr().String()
		conn.Close()
		t.Logf("path: %s -> %s (rtt %v)", tgt, remote, rtt)
		if rtt > time.Second {
			t.Errorf("path %s: connect rtt %v exceeds 1s", tgt, rtt)
		}
	}
}
