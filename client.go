package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	mathrand "math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	utls "github.com/refraction-networking/utls"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

// ======================= 异步聚合端口 (支持 MinRTT) =======================
type Backend struct {
	ch       chan []VPNFrame
	rttCache *uint32
}

type AsyncPort struct {
	id         string
	ch         chan []byte
	ctx        context.Context
	cancel     context.CancelFunc
	backendsMu sync.RWMutex
	backends   []*Backend
	fecMode    bool
	encoder    *fecEncoder
	txSeq      uint32
	dropped    uint64 // 各环节丢弃帧计数（面板/metrics）
}

// Dropped 累计丢弃帧数（队列满、后端投递失败、无后端）
func (p *AsyncPort) Dropped() uint64 { return atomic.LoadUint64(&p.dropped) }

// ParitySent 已生成的 FEC 校验帧数（未启用 FEC 时为 0）
func (p *AsyncPort) ParitySent() uint64 {
	if p.encoder == nil {
		return 0
	}
	return p.encoder.ParitySent()
}

func (p *AsyncPort) dropN(n int) {
	if n > 0 {
		atomic.AddUint64(&p.dropped, uint64(n))
	}
}

func NewAsyncPort(ctx context.Context, id string, fecMode bool) *AsyncPort {
	pCtx, pCancel := context.WithCancel(ctx)
	p := &AsyncPort{id: id, ch: make(chan []byte, 4096), ctx: pCtx, cancel: pCancel, fecMode: fecMode}
	go p.run()
	return p
}

// AttachFEC 在端口上启用 XOR 奇偶校验 FEC：每 K 个数据帧广播 1 个校验帧
// （开销约 1/K，可恢复组内单帧丢失）。须在数据流开始前调用一次。
// ic 为本端发送方向的内层加密器（-encrypt 关闭时为 nil，校验帧明文）。
func (p *AsyncPort) AttachFEC(k int, ic *innerCipher) {
	p.encoder = newFECEncoder(k, ic)
}

func (p *AsyncPort) ID() string { return p.id }
func (p *AsyncPort) RegisterBackend(ch chan []VPNFrame, rttCache *uint32) {
	p.backendsMu.Lock()
	defer p.backendsMu.Unlock()
	p.backends = append(p.backends, &Backend{ch: ch, rttCache: rttCache})
}
func (p *AsyncPort) UnregisterBackend(ch chan []VPNFrame) {
	p.backendsMu.Lock()
	defer p.backendsMu.Unlock()
	for i, b := range p.backends {
		if b.ch == ch {
			p.backends = append(p.backends[:i], p.backends[i+1:]...)
			break
		}
	}
}
func (p *AsyncPort) WriteFrame(frame []byte) error {
	select {
	case <-p.ctx.Done():
		return fmt.Errorf("port closed")
	default:
	}
	var buf []byte
	if frame != nil {
		buf = getFrame()[:len(frame)]
		copy(buf, frame)
	}
	select {
	case p.ch <- buf:
	default:
		log.Debugf("[AsyncPort %s] BACKPRESSURE! Queue full, dropping frame.", p.id)
		p.dropN(1)
		if buf != nil {
			putFrame(buf)
		}
	}
	return nil
}

func (p *AsyncPort) run() {
	const MaxBatchBytes = 64 * 1024
	batch := make([]VPNFrame, 0, 128)
	var batchBytes int

	for {
		select {
		case <-p.ctx.Done():
			return
		case frame := <-p.ch:
			seq := atomic.AddUint32(&p.txSeq, 1)
			if seq == 0 {
				// 防止 uint32 溢出为 0。因为 0 被保留作为控制/心跳帧
				seq = atomic.AddUint32(&p.txSeq, 1)
			}
			batch = append(batch, VPNFrame{Seq: seq, Data: frame})
			batchBytes += len(frame)

			queueLen := len(p.ch)
			for i := 0; i < queueLen && batchBytes < MaxBatchBytes; i++ {
				f := <-p.ch
				s := atomic.AddUint32(&p.txSeq, 1)
				batch = append(batch, VPNFrame{Seq: s, Data: f})
				batchBytes += len(f)
			}

			p.dispatchBatch(batch)

			batch = batch[:0]
			batchBytes = 0
		}
	}
}

// dispatchBatch 把一批帧分发给后端，并接管 batch 内全部缓冲的所有权：
//   - XOR FEC：数据帧 MinRTT 单路发送，校验帧向所有连接广播；
//   - 传统 FEC（fecMode）：全部帧向所有连接复制；
//   - 普通模式：MinRTT 单路发送。
//
// 每个后端收到的帧均经过深拷贝、彼此独立，由发送协程发送后归还内存池。
func (p *AsyncPort) dispatchBatch(batch []VPNFrame) {
	p.backendsMu.RLock()
	backends := p.backends
	p.backendsMu.RUnlock()
	if len(backends) == 0 {
		p.dropN(len(batch))
		freeFrames(batch)
		return
	}

	if p.encoder != nil {
		var parities [][]byte
		for _, vf := range batch {
			if par := p.encoder.add(vf); par != nil {
				parities = append(parities, par)
			}
		}
		best := p.pickBackend(backends)
		p.dropN(sendBatchTo(best, batch))
		for _, par := range parities {
			pf := VPNFrame{Seq: 0, Data: par}
			for _, b := range backends {
				sendFrameTo(b, pf)
			}
			putFrame(par)
		}
		freeFrames(batch)
		return
	}

	if p.fecMode {
		// 传统模式：同一帧复制到所有连接（旧版实现互通用）
		for _, b := range backends {
			p.dropN(sendBatchTo(b, batch))
		}
		freeFrames(batch)
		return
	}

	p.dropN(sendBatchTo(p.pickBackend(backends), batch))
	freeFrames(batch)
}

// pickBackend MinRTT 选路：延迟 + 积压惩罚评分，全部拥塞时回落到首个后端
func (p *AsyncPort) pickBackend(backends []*Backend) *Backend {
	var bestBackend *Backend
	var minScore uint32 = math.MaxUint32
	for _, b := range backends {
		qLen := len(b.ch)
		if qLen >= cap(b.ch)-2 {
			continue
		}
		rtt := atomic.LoadUint32(b.rttCache)
		// 积压超过 10 个包才开始惩罚
		penalty := uint32(0)
		if qLen > 10 {
			penalty = uint32((qLen - 10) * 1000)
		}
		score := rtt + penalty
		if score < minScore {
			minScore = score
			bestBackend = b
		}
	}
	if bestBackend == nil {
		bestBackend = backends[0]
	}
	return bestBackend
}

// sendBatchTo 深拷贝整批帧后投递给单个后端；队列满时丢弃并释放副本。
// 返回实际丢弃的帧数（用于丢帧统计）。
func sendBatchTo(b *Backend, batch []VPNFrame) int {
	copies := make([]VPNFrame, len(batch))
	for i := range batch {
		copies[i] = VPNFrame{Seq: batch[i].Seq, Data: cloneFrame(batch[i].Data)}
	}
	select {
	case b.ch <- copies:
		return 0
	default:
		freeFrames(copies)
		return len(copies)
	}
}

// sendFrameTo 深拷贝单帧后投递给单个后端；队列满时丢弃并释放副本
func sendFrameTo(b *Backend, vf VPNFrame) {
	cp := VPNFrame{Seq: vf.Seq, Data: cloneFrame(vf.Data)}
	select {
	case b.ch <- []VPNFrame{cp}:
	default:
		if cp.Data != nil {
			putFrame(cp.Data)
		}
	}
}

// FECRecovered FEC 解码恢复帧数（客户端会话级，面板/metrics 用）
func (c *Client) FECRecovered() uint64 {
	if c.fecDec == nil {
		return 0
	}
	rec, _ := c.fecDec.FECStats()
	return rec
}

// FECLost FEC 无法恢复的确认丢失帧数
func (c *Client) FECLost() uint64 {
	if c.fecDec == nil {
		return 0
	}
	_, lost := c.fecDec.FECStats()
	return lost
}

// FECStats 恢复/丢失计数（面板用）
func (c *Client) FECStats() (uint64, uint64) {
	if c.fecDec == nil {
		return 0, 0
	}
	return c.fecDec.FECStats()
}

// ReconnectAttempts 累计重连尝试次数
func (c *Client) ReconnectAttempts() uint64 { return atomic.LoadUint64(&c.reconnects) }

// ForceReconnect 触发所有物理连接断开并由重连循环重建（面板控制用）
func (c *Client) ForceReconnect() { c.forceOnce.Do(func() { close(c.forceReconnect) }) }
func (p *AsyncPort) Close()       { p.cancel() }

// ======================= 客户端实现 =======================

// parseServerAddresses 解析逗号分隔的服务器地址字符串，并清理空格
func parseServerAddresses(addrStr string) []string {
	var addrs []string
	rawList := strings.Split(addrStr, ",")

	for _, raw := range rawList {
		cleanAddr := strings.TrimSpace(raw)
		if cleanAddr != "" {
			addrs = append(addrs, cleanAddr)
		}
	}

	// 如果由于某种原因解析后为空，提供一个安全的降级处理
	if len(addrs) == 0 {
		return []string{}
	}
	return addrs
}

type Client struct {
	clientID        string
	serverSessionID string     // 记录服务端的会话ID
	gwV4            string     // 记录网关以便退出时清理
	gwV6            string     // 记录网关以便退出时清理
	sessionMu       sync.Mutex // 保护状态防止并发写
	psk             string
	targetAddrs     []string
	tapName         string
	reqV4           string
	reqV6           string
	sni             string
	insecure        bool
	certHash        string
	fwmark          int
	brutal          bool
	brutalUp        uint64
	brutalDown      uint64
	tap             io.ReadWriteCloser
	macAddr         string
	connsCount      int
	fecMode         bool
	fecGroupReq     int    // 用户指定的 XOR 分组大小（0=默认）
	fecNegotiated   int    // 0=未协商, >0=XOR 分组大小, -1=服务端不支持（回退传统复制）
	fecStatus       string // 面板展示用
	fecAlgo         int    // fecDec 绑定的加密算法（会话重建判据）
	fecSaltKey      string // fecDec 绑定的盐（会话重建判据）
	txPort          *AsyncPort
	rxReorder       *ReorderBuffer
	fecDec          *fecDecoder
	dedup           *DeDuplicator
	TxBytes         uint64
	RxBytes         uint64
	TxPackets       uint64
	RxPackets       uint64
	encrypt         bool
	icLegacy        *innerCipher  // 对端不支持协商时的回退加密器
	icTx            *innerCipher  // 当前会话发送方向（GCM）
	icRx            *innerCipher  // 当前会话接收方向（GCM）
	encAlgo         int           // 当前会话协商结果（0=legacy，2=GCM）
	assignedV4      string        // 服务端分配的 IPv4（面板展示）
	assignedV6      string        // 服务端分配的 IPv6（面板展示）
	liveConns       int32         // 当前已建立的物理连接数（面板展示）
	reconnects      uint64        // 累计重连尝试次数（面板展示）
	forceReconnect  chan struct{} // 关闭即触发所有物理连接重连（面板控制用）
	forceOnce       sync.Once
	connsMu         sync.Mutex
	conns           map[int]*clientConnInfo // 每物理连接明细（connIndex → 状态）
	startedAt       time.Time
}

// clientConnInfo 单条物理连接的运行明细（面板展示 + 强制重连句柄）
type clientConnInfo struct {
	target    string
	remote    atomic.Value // string：对端地址（握手后可得）
	state     atomic.Value // string：connecting / up / retrying
	lastError atomic.Value // string：最近一次失败原因
	rttCache  *uint32      // 微秒（200ms 刷新）
	conn      atomic.Value // net.Conn：强制重连时关闭
	txBytes   uint64
	rxBytes   uint64
	retries   uint64
	linkedAt  int64 // 最近一次握手成功时间（unix 秒，0=未连接过）
}

// startClient 以 JSON 配置启动客户端（cfg 已经过 applyDefaults + Validate）
func startClient(ctx context.Context, cfg *Config) {
	cl := cfg.Client
	log.Infof("Starting TCP TLS client process...")
	var iface io.ReadWriteCloser
	if cfg.Tap == "mem" {
		iface = newMemTap(ctx)
		log.Infof("Using in-memory TAP backend (no real device)")
	} else {
		t, err := water.New(newTapConfig(cfg.Tap))
		if err != nil {
			log.Fatalf("Client TAP creation error: %v", err)
		}
		iface = t
		if err := setTapMac(cfg.Tap, cfg.Mac); err != nil {
			log.Warnf("Client failed to set tap MAC: %v", err)
		}
	}
	go func() { <-ctx.Done(); iface.Close() }()

	actualMac := cfg.Mac
	if actualMac == "" && cfg.Tap != "mem" {
		if link, err := netlink.LinkByName(cfg.Tap); err == nil {
			actualMac = link.Attrs().HardwareAddr.String()
		}
	}

	ns := uuid.NewMD5(uuid.NameSpaceURL, []byte("my_vpn_tunnel"))
	clientID := uuid.NewSHA1(ns, []byte(actualMac+cfg.PSK)).String()
	log.Infof("Assigned UUID v5 ClientID: %s", clientID)

	c := &Client{
		clientID: clientID, psk: cfg.PSK, targetAddrs: parseServerAddresses(cfg.Addr), tapName: cfg.Tap, reqV4: cl.ReqV4, reqV6: cl.ReqV6,
		sni: cl.SNI, insecure: cl.Insecure, certHash: cl.CertSHA256, fwmark: cl.Fwmark, brutal: cfg.Brutal, brutalUp: cfg.BrutalUp, brutalDown: cfg.BrutalDown,
		tap: iface, macAddr: actualMac, connsCount: cl.Conns, fecMode: cl.FEC, encrypt: cfg.Encrypt,
		txPort:    NewAsyncPort(ctx, "client_tx_port", cl.FEC),
		dedup:     NewDeDuplicator(), // 初始化客户端去重器
		startedAt: time.Now(),
	}
	if len(c.targetAddrs) == 0 {
		log.Fatalf("Client addr 解析结果为空，请检查配置文件中的 addr 字段")
	}
	c.fecStatus = "off"

	// 程序彻底退出时才清理系统路由表
	defer func() {
		c.sessionMu.Lock()
		cleanPolicyRouting(c.tapName, c.fwmark, c.gwV4, c.gwV6)
		c.sessionMu.Unlock()
	}()

	// 初始化重排缓冲区：当包按序理顺后，统一写入 c.tap
	c.rxReorder = NewReorderBuffer(func(orderedFrame []byte) {
		c.tap.Write(orderedFrame)
	})
	if cfg.Encrypt {
		c.icLegacy = newLegacyInnerCipher(cfg.PSK)
	}

	// Web 面板（可选，web.addr 未指定时不启动）
	if cfg.Web.Addr != "" {
		go startWebServer(cfg.Web.Addr, nil, c, cfg.Web.Auth, cfg.Web.Cert, cfg.Web.Key)
	}

	// XOR 分组大小（Validate 保证在 [2,64]）
	if cl.FEC {
		c.fecGroupReq = cl.FecGroup
	}

	// 连接明细注册表初始化
	c.conns = make(map[int]*clientConnInfo)
	for i := 0; i < c.connsCount; i++ {
		c.conns[i] = &clientConnInfo{target: c.targetAddrs[i%len(c.targetAddrs)], rttCache: new(uint32)}
		c.conns[i].state.Store("connecting")
	}

	go func() {
		buf := make([]byte, 65536)
		for {
			rn, err := iface.Read(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				time.Sleep(1 * time.Second)
				continue
			}
			// WriteFrame 内部会拷贝进独立的池缓冲，这里直接复用本地缓冲，
			// 不再额外取池（旧实现取池后从未归还，造成每帧 32KB 泄漏）
			c.txPort.WriteFrame(buf[:rn])
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < c.connsCount; i++ {
		wg.Add(1)
		go func(connIndex int) {
			defer wg.Done()
			ci := c.conns[connIndex]
			attempt := 0
			for {
				select {
				case <-ctx.Done():
					return
				case <-c.forceReconnect:
					// 面板触发强制重连：立即重拨（backoff 归零）
					attempt = 0
				default:
				}
				atomic.AddUint64(&c.reconnects, 1)
				atomic.AddUint64(&ci.retries, 1)
				linked, err := c.dialAndServe(ctx, connIndex)
				if linked >= reconnectBackoffReset {
					attempt = 0 // 长连接断开后以短间隔立即重试
				}
				delay := reconnectBackoffDelay(attempt)
				if err != nil {
					ci.lastError.Store(err.Error())
					ci.state.Store("retrying")
					log.Warnf("[Conn %d] Tunnel down: %v. Reconnecting in %s...", connIndex, err, delay)
				} else {
					log.Infof("[Conn %d] Tunnel closed, reconnecting in %s...", connIndex, delay)
				}
				attempt++
				select {
				case <-ctx.Done():
					return
				case <-c.forceReconnect:
					attempt = 0 // 跳过等待立即重连
				case <-time.After(delay):
				}
			}
		}(i)
	}
	wg.Wait()
}

// 重连退避参数：1s 起指数增长，封顶 30s；持续在线 reconnectBackoffReset
// 以上视为稳定连接，断开后重置退避
const (
	reconnectBackoffBase  = 1 * time.Second
	reconnectBackoffMax   = 30 * time.Second
	reconnectBackoffReset = 30 * time.Second
)

// reconnectBackoffDelay 第 attempt 次重试前的等待时长（含 25% 随机抖动）
func reconnectBackoffDelay(attempt int) time.Duration {
	d := reconnectBackoffBase << uint(min(attempt, 5))
	if d > reconnectBackoffMax || d <= 0 {
		d = reconnectBackoffMax
	}
	jitter := time.Duration(mathrand.Int64N(int64(d) / 4))
	return d - d/8 + jitter/2
}

// connSnapshot 面板用连接明细快照
type connSnapshot struct {
	Index     int    `json:"index"`
	Target    string `json:"target"`
	Remote    string `json:"remote"`
	State     string `json:"state"`
	LastError string `json:"last_error,omitempty"`
	RttMs     uint32 `json:"rtt_ms"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxBytes   uint64 `json:"rx_bytes"`
	Retries   uint64 `json:"retries"`
	AgeSec    uint64 `json:"age_sec"`
}

// snapshotConns 汇总所有物理连接明细
func (c *Client) snapshotConns() []connSnapshot {
	c.connsMu.Lock()
	defer c.connsMu.Unlock()
	out := make([]connSnapshot, 0, len(c.conns))
	now := time.Now().Unix()
	for i := 0; i < c.connsCount; i++ {
		ci, ok := c.conns[i]
		if !ok {
			continue
		}
		snap := connSnapshot{
			Index:   i,
			Target:  ci.target,
			RttMs:   atomic.LoadUint32(ci.rttCache) / 1000,
			TxBytes: atomic.LoadUint64(&ci.txBytes),
			RxBytes: atomic.LoadUint64(&ci.rxBytes),
			Retries: atomic.LoadUint64(&ci.retries),
		}
		if v, okv := ci.remote.Load().(string); okv {
			snap.Remote = v
		}
		if v, okv := ci.state.Load().(string); okv {
			snap.State = v
		}
		if v, okv := ci.lastError.Load().(string); okv {
			snap.LastError = v
		}
		if la := atomic.LoadInt64(&ci.linkedAt); la > 0 {
			snap.AgeSec = uint64(now - la)
		}
		out = append(out, snap)
	}
	return out
}

// negotiateUTLS 负责配置 uTLS、选择指纹并执行 TLS 握手
func (c *Client) negotiateUTLS(ctx context.Context, rawConn net.Conn) (*utls.UConn, error) {
	utlsConf := &utls.Config{
		ServerName:         c.sni,
		InsecureSkipVerify: c.insecure,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	// 自定义证书哈希校验
	if c.certHash != "" {
		utlsConf.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return verifyCertHash(rawCerts, c.certHash)
		}
	}

	// 映射 ClientHello 指纹
	var utlsID string = "chrome"
	var clientHelloID utls.ClientHelloID
	switch strings.ToLower(utlsID) {
	case "firefox":
		clientHelloID = utls.HelloFirefox_Auto
	case "ios":
		clientHelloID = utls.HelloIOS_Auto
	case "random":
		clientHelloID = utls.HelloRandomized
	default:
		clientHelloID = utls.HelloChrome_Auto // 默认 Chrome
	}

	// 构建 uTLS 连接并握手
	utlsConn := utls.UClient(rawConn, utlsConf, clientHelloID)
	if err := utlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("uTLS handshake failed: %v", err)
	}

	return utlsConn, nil
}

// dialAndServe 建立一条物理连接并服务到断开。返回该连接的在线时长
// （用于重连退避归零判断；从未在线则为 0）与最终错误。
func (c *Client) dialAndServe(parentCtx context.Context, connIndex int) (linked time.Duration, err error) {
	runCtx, runCancel := context.WithCancel(parentCtx)
	defer runCancel()

	ci := c.conns[connIndex]
	linkedAt := time.Time{}
	defer func() {
		if !linkedAt.IsZero() {
			linked = time.Since(linkedAt)
		}
	}()

	target := c.targetAddrs[connIndex%len(c.targetAddrs)]
	if isSocks5Enabled() {
		log.Infof("[Conn %d] Initiating connection to %s via SOCKS5 %s ...", connIndex, target, globalSocks5Addr)
	} else {
		log.Infof("[Conn %d] Initiating connection...", connIndex)
	}
	// 统一走全局拨号器：启用 -socks5 时所有 socket 均经由代理，否则全部直连
	rawConn, err := dialContext(runCtx, "tcp", target)
	if err != nil {
		return 0, err
	}
	ci.remote.Store(rawConn.RemoteAddr().String())
	ci.conn.Store(rawConn)

	// 通用 socket 调优：作用于本地 socket，与是否经过代理无关，两种模式下都应生效。
	// （KeepAlive 已由 newBaseDialer 统一设置，此处补充 NoDelay 与收发缓冲区）
	if sock := underlyingTCPConn(rawConn); sock != nil {
		sock.SetNoDelay(true)
		sock.SetReadBuffer(4 * 1024 * 1024)
		sock.SetWriteBuffer(4 * 1024 * 1024)
	}

	// tcpConn 仅用于端到端语义的内核调优（Brutal/RTT）；代理模式下为 nil 并自动跳过
	tcpConn := asTCPConn(rawConn)

	// 1. 防御整除为 0 的陷阱
	clientTxRate := c.brutalUp / uint64(c.connsCount)
	if clientTxRate == 0 && c.brutalUp > 0 {
		clientTxRate = 1
	}

	clientRxRate := c.brutalDown / uint64(c.connsCount)
	if clientRxRate == 0 && c.brutalDown > 0 {
		clientRxRate = 1
	}

	// 初始以客户端期望的速率申请接管
	if c.brutal && clientTxRate > 0 {
		applyTCPBrutal(tcpConn, clientTxRate)
	}

	rawConn.SetDeadline(time.Now().Add(10 * time.Second)) // tls握手超时
	tlsConn, err := c.negotiateUTLS(runCtx, rawConn)
	rawConn.SetDeadline(time.Time{})
	if err != nil {
		rawConn.Close()
		return 0, err
	}
	defer tlsConn.Close()

	scanner := NewFrameScanner(tlsConn)
	// -fec-group 透传：仅当显式指定（>0）时使用，否则 fec 开启时用默认 4
	fecGroupReq := 0
	if c.fecMode {
		fecGroupReq = clampFecGroup(c.fecGroupReq)
	}
	req := HandshakeReq{
		ClientID: c.clientID,
		PSK:      hashPSK(c.psk),
		MAC:      c.macAddr,
		IPv4:     c.reqV4,
		IPv6:     c.reqV6,
		Padding:  generatePadding(100, 500),
		FEC:      c.fecMode,
		FecGroup: fecGroupReq,
		BrutalTx: clientTxRate,
		BrutalRx: clientRxRate,
		Encrypt:  c.encrypt,
		EncAlgo:  clientEncAlgoSupport,
	}
	log.Debugf("[Conn %d] => 发送握手请求 (HandshakeReq): %+v", connIndex, req)
	reqData, _ := json.Marshal(req)
	writeStreamFrame(tlsConn, reqData)

	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respData, _, err := scanner.ReadFrame()
	tlsConn.SetReadDeadline(time.Time{})
	if err != nil {
		return 0, err
	}

	var resp HandshakeResp
	if err := json.Unmarshal(respData, &resp); err != nil || !resp.Success {
		return 0, fmt.Errorf("handshake rejected")
	}
	log.Debugf("[Conn %d] <= 收到握手响应 (HandshakeResp): %+v", connIndex, resp)

	if resp.Encrypt != c.encrypt {
		return 0, fmt.Errorf("server encryption mismatch")
	}

	// 内层加密协商：双方均声明 GCM 支持时启用（会话盐由服务端生成、
	// 通过响应下发，服务端重启即换盐）；否则回退 legacy CTR。
	encAlgo := encAlgoLegacyCTR
	var icTx, icRx *innerCipher
	if c.encrypt {
		if resp.EncAlgo >= encAlgoGCM {
			saltTx, err1 := hex.DecodeString(resp.EncSalt)  // c2s
			saltRx, err2 := hex.DecodeString(resp.EncSalt2) // s2c
			if err1 == nil && err2 == nil && len(saltTx) == encSaltSize && len(saltRx) == encSaltSize {
				var errTx, errRx error
				icTx, errTx = newGCMInnerCipher(c.psk, saltTx)
				icRx, errRx = newGCMInnerCipher(c.psk, saltRx)
				if errTx == nil && errRx == nil {
					encAlgo = encAlgoGCM
				} else {
					log.Warnf("[Conn %d] GCM cipher init failed, falling back to legacy CTR: %v/%v", connIndex, errTx, errRx)
				}
			} else {
				log.Warnf("[Conn %d] Server sent invalid enc salts, falling back to legacy CTR", connIndex)
			}
		} else if c.encrypt {
			log.Infof("[Conn %d] Server lacks GCM support, using legacy CTR inner encryption", connIndex)
		}
		if icTx == nil {
			icTx, icRx = c.icLegacy, c.icLegacy
		}
	}

	// 会话级协商：首个连接的握手决定本端解码与端口编码模式，后续连接沿用。
	// 服务端响应带 fec_group>0 表示支持 XOR 校验；否则回退传统复制模式
	// （旧服务端会把校验帧当作未知控制帧丢弃，编码器就不必挂载）。
	c.sessionMu.Lock()
	if c.fecMode && c.fecNegotiated == 0 {
		if resp.FecGroup >= fecMinGroup {
			c.fecNegotiated = resp.FecGroup
			c.fecStatus = fmt.Sprintf("xor K=%d", resp.FecGroup)
			log.Infof("[Conn %d] XOR FEC negotiated: K=%d (overhead 1/%d)", connIndex, resp.FecGroup, resp.FecGroup)
		} else {
			c.fecNegotiated = -1
			c.fecStatus = "dup"
			log.Infof("[Conn %d] Server lacks XOR FEC support, falling back to legacy duplication mode", connIndex)
		}
	}
	useXorFec := false
	fecRebuild := false
	if c.fecMode && c.fecNegotiated > 0 {
		useXorFec = true
		// FEC 编解码器绑定当前会话的加密器与盐：会话/盐变化即重建
		if c.fecDec == nil || c.fecAlgo != encAlgo || c.fecSaltKey != resp.EncSalt {
			if c.fecDec != nil {
				c.fecDec.Reset()
			}
			fecRebuild = true
			c.fecAlgo = encAlgo
			c.fecSaltKey = resp.EncSalt
		}
		if fecRebuild {
			// XOR FEC 解码器：恢复出的帧按原 seq 注入重排缓冲，保证输出有序
			c.fecDec = NewFECDecoder(c.fecNegotiated, icRx, c.rxReorder.Insert)
			c.txPort.AttachFEC(c.fecNegotiated, icTx)
		}
	}
	if c.encAlgo != encAlgo {
		c.encAlgo = encAlgo
		c.icTx = icTx
		c.icRx = icRx
	}
	isNewSession := false
	if c.serverSessionID != resp.SessionID {
		isNewSession = true
		c.serverSessionID = resp.SessionID
	}
	c.gwV4 = resp.GwV4
	c.gwV6 = resp.GwV6
	// 面板展示：分配的隧道地址
	c.assignedV4 = strings.Split(resp.IPv4, "/")[0]
	c.assignedV6 = strings.Split(resp.IPv6, "/")[0]
	c.sessionMu.Unlock()

	if isNewSession {
		log.Infof("[Conn %d] 🔄 检测到服务端重置了会话，正在清理本地旧的接收缓冲池...", connIndex)
		c.rxReorder.Reset()
		c.dedup.Reset()
	}

	c.setupInterface(resp.IPv4, resp.IPv6)
	setupPolicyRouting(c.tapName, c.fwmark, resp.GwV4, resp.GwV6)

	rttCache := new(uint32)
	atomic.StoreUint32(rttCache, 50000)
	go startRTTPoller(runCtx, tcpConn, rttCache)

	// 连接明细：握手成功，进入 up 态
	ci.rttCache = rttCache
	ci.conn.Store(tlsConn)
	ci.linkedAt = time.Now().Unix()
	ci.state.Store("up")
	ci.lastError.Store("")

	errChan := make(chan error, 2)
	connTxChan := make(chan []VPNFrame, 32)
	c.txPort.RegisterBackend(connTxChan, rttCache)
	defer c.txPort.UnregisterBackend(connTxChan)

	// 面板展示：活跃连接计数
	atomic.AddInt32(&c.liveConns, 1)
	defer atomic.AddInt32(&c.liveConns, -1)

	go func() {
		sendBuffer := make([]byte, 0, 64*1024+4096)
		keepAliveTicker := time.NewTicker(4 * time.Second)
		defer keepAliveTicker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case frames := <-connTxChan:
				sendBuffer = sendBuffer[:0]
				for _, vf := range frames {
					sendBuffer = appendPaddedFrame(sendBuffer, vf, icTx)
				}
				// 副本所有权归本协程：发送后无条件归还（深拷贝分发保证独立）
				freeFrames(frames)
				tlsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				_, err := tlsConn.Write(sendBuffer)
				tlsConn.SetWriteDeadline(time.Time{})
				if err != nil {
					errChan <- err
					return
				}
				atomic.AddUint64(&c.TxBytes, uint64(len(sendBuffer)))
				atomic.AddUint64(&c.TxPackets, uint64(len(frames)))
				atomic.AddUint64(&ci.txBytes, uint64(len(sendBuffer)))
			case <-keepAliveTicker.C:
				sendBuffer = sendBuffer[:0]
				sendBuffer = appendPaddedFrame(sendBuffer, VPNFrame{Seq: 0, Data: nil}, nil)
				if _, err := tlsConn.Write(sendBuffer); err != nil {
					errChan <- err
					return
				}
			}
		}
	}()

	go func() {
		for {
			tlsConn.SetReadDeadline(time.Now().Add(30 * time.Second))
			frame, seq, err := scanner.ReadFrame()
			if err != nil {
				errChan <- err
				return
			}

			if err == nil && frame != nil {
				atomic.AddUint64(&c.RxBytes, uint64(len(frame)))
				atomic.AddUint64(&c.RxPackets, 1)
				atomic.AddUint64(&ci.rxBytes, uint64(len(frame)))
				if seq != 0 && icRx != nil {
					plain, derr := icRx.openInPlace(frame, seq, uint32(len(frame)))
					if derr != nil {
						// GCM 校验失败：篡改或异源注入的帧，直接丢弃
						log.Debugf("[Conn %d] dropped tampered/foreign frame (seq=%d): %v", connIndex, seq, derr)
						putFrame(frame)
						continue
					}
					frame = plain
				}
				if seq == 0 && useXorFec && c.isParityFrame(frame) {
					// XOR 校验帧：交给 FEC 解码器，恢复出的帧由其回调写 TAP
					c.fecDec.OnParity(frame)
					putFrame(frame)
					continue
				}
				if useXorFec {
					c.fecDec.OnData(seq, frame)
				}
				// 丢入重排缓冲区，后续的 Write 和 putFrame 由缓冲区内部接管
				c.rxReorder.Insert(seq, frame)
			}
		}
	}()

	select {
	case err := <-errChan:
		return 0, err
	case <-runCtx.Done():
		return 0, nil
	}
}

// isParityFrame 识别 XOR 校验帧：线路帧 seq=0（不加密），负载首字节为魔数
// 0xFE；普通控制/心跳帧负载为空，握手帧以 '{' 开头，均不会误判。
func (c *Client) isParityFrame(frame []byte) bool {
	return len(frame) >= 7 && frame[0] == fecMagic
}

func (c *Client) setupInterface(v4cidr, v6cidr string) error {
	link, err := netlink.LinkByName(c.tapName)
	if err != nil {
		return err
	}
	if v4cidr != "/" && v4cidr != "" {
		if addrV4, err := netlink.ParseAddr(v4cidr); err == nil {
			netlink.AddrReplace(link, addrV4)
		}
	}
	if v6cidr != "/" && v6cidr != "" {
		if addrV6, err := netlink.ParseAddr(v6cidr); err == nil {
			netlink.AddrReplace(link, addrV6)
		}
	}
	return netlink.LinkSetUp(link)
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
func duplicateIP(ip net.IP) net.IP         { dup := make(net.IP, len(ip)); copy(dup, ip); return dup }
func maskSize(m net.IPMask) int            { ones, _ := m.Size(); return ones }
func getFirstIP(network *net.IPNet) net.IP { ip := duplicateIP(network.IP); incrementIP(ip); return ip }
