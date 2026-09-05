package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

// ======================= VSwitch =======================
type Port interface {
	ID() string
	WriteFrame(frame []byte) error
}
type macEntry struct {
	portID    string
	updatedAt time.Time
}

const ShardCount = 16

type VSwitchShard struct {
	mu       sync.RWMutex
	macTable map[string]*macEntry
}
type VSwitch struct {
	portsMu sync.RWMutex
	ports   map[string]Port
	shards  [ShardCount]*VSwitchShard
}

func NewVSwitch() *VSwitch {
	vs := &VSwitch{ports: make(map[string]Port)}
	for i := 0; i < ShardCount; i++ {
		vs.shards[i] = &VSwitchShard{macTable: make(map[string]*macEntry)}
	}
	go vs.purgeExpiredMACs()
	return vs
}

// 快速字符串 Hash
func getShardIdx(mac string) int {
	var hash uint32 = 2166136261
	for i := 0; i < len(mac); i++ {
		hash *= 16777619
		hash ^= uint32(mac[i])
	}
	return int(hash % ShardCount)
}
func (vs *VSwitch) purgeExpiredMACs() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		for i := 0; i < ShardCount; i++ {
			shard := vs.shards[i]
			shard.mu.Lock()
			for mac, entry := range shard.macTable {
				if time.Since(entry.updatedAt) > 30*time.Minute {
					delete(shard.macTable, mac)
				}
			}
			shard.mu.Unlock()
		}
	}
}
func (vs *VSwitch) AddPort(p Port) {
	vs.portsMu.Lock()
	vs.ports[p.ID()] = p
	vs.portsMu.Unlock()
	log.Debugf("[VSwitch] Port UP: %s", p.ID())
}

func (vs *VSwitch) RemovePort(portID string) {
	vs.portsMu.Lock()
	delete(vs.ports, portID)
	vs.portsMu.Unlock()

	// 清理分片表里的 MAC
	for i := 0; i < ShardCount; i++ {
		shard := vs.shards[i]
		shard.mu.Lock()
		for mac, entry := range shard.macTable {
			if entry.portID == portID {
				delete(shard.macTable, mac)
			}
		}
		shard.mu.Unlock()
	}
	log.Debugf("[VSwitch] Port DOWN: %s", portID)
}
func (vs *VSwitch) ProcessFrame(srcPortID string, frame []byte) {
	if len(frame) < 14 {
		return
	}
	dstMAC, srcMAC := frame[0:6], frame[6:12]
	strDstMAC, strSrcMAC := string(dstMAC), string(srcMAC)

	// 计算属于哪一个锁分片
	srcShard := vs.shards[getShardIdx(strSrcMAC)]

	srcShard.mu.RLock()
	entry, exists := srcShard.macTable[strSrcMAC]
	needUpdate := !exists || entry.portID != srcPortID || time.Since(entry.updatedAt) > 5*time.Second
	srcShard.mu.RUnlock()

	if needUpdate {
		srcShard.mu.Lock()
		srcShard.macTable[strSrcMAC] = &macEntry{portID: srcPortID, updatedAt: time.Now()}
		log.Debugf("[VSwitch] Learned NEW MAC %s on port %s", fmtMAC(srcMAC), srcPortID)
		srcShard.mu.Unlock()
	}

	var targetPortID string
	if (dstMAC[0] & 1) != 1 { // 单播包
		dstShard := vs.shards[getShardIdx(strDstMAC)]
		dstShard.mu.RLock()
		if dEntry, dExists := dstShard.macTable[strDstMAC]; dExists {
			targetPortID = dEntry.portID
		}
		dstShard.mu.RUnlock()
	}

	if targetPortID != "" && targetPortID != srcPortID {
		vs.sendToPort(targetPortID, frame)
	} else if targetPortID == "" {
		vs.flood(srcPortID, frame)
	}
}
func (vs *VSwitch) sendToPort(targetPortID string, frame []byte) {
	vs.portsMu.RLock()
	port, exists := vs.ports[targetPortID]
	vs.portsMu.RUnlock()
	if exists {
		port.WriteFrame(frame)
	}
}
func (vs *VSwitch) flood(excludePortID string, frame []byte) {
	vs.portsMu.RLock()
	var targets []Port
	for id, port := range vs.ports {
		if id != excludePortID {
			targets = append(targets, port)
		}
	}
	vs.portsMu.RUnlock()
	for _, port := range targets {
		port.WriteFrame(frame)
	}
}

// ======================= 服务端 =======================
type ClientSession struct {
	SessionID   string
	Port        *AsyncPort
	IPv4        string
	IPv6        string
	MAC         string
	Dedup       *DeDuplicator
	RxReorder   *ReorderBuffer
	FecDec      *fecDecoder       // XOR 奇偶校验解码器（req.FecGroup >= 2 时启用）
	FecEncK     int               // 下行 XOR 分组大小（0 表示未启用）
	FecMode     string            // 面板展示：xor:K / dup / off
	EncAlgo     int               // 内层加密算法（0=legacy，2=GCM）
	SaltA       [encSaltSize]byte // c2s 方向盐（客户端加密/服务端解密）
	SaltB       [encSaltSize]byte // s2c 方向盐（服务端加密/客户端解密）
	icTx        *innerCipher      // s2c 加密器
	icRx        *innerCipher      // c2s 解密器
	CreatedAt   time.Time
	ActiveConns int
	TxBytes     uint64
	RxBytes     uint64
	TxPackets   uint64
	RxPackets   uint64
	// 会话保活与生命周期控制
	sessionMu    sync.Mutex
	destroyTimer *time.Timer
	// 该会话的物理连接注册表：Web 面板踢出时逐个关闭，并输出连接明细
	connsMu sync.Mutex
	conns   map[*connInfo]struct{}
}

// connInfo 单条物理连接的运行明细（面板展示 + kick 关闭句柄）
type connInfo struct {
	remote    string
	tcpConn   *net.TCPConn
	rttCache  *uint32 // 微秒（200ms 刷新）
	txBytes   uint64
	rxBytes   uint64
	txPackets uint64
	rxPackets uint64
	linkedAt  int64 // 建立时间（unix 秒）
	brutalTx  uint64
	brutalRx  uint64
}

type Server struct {
	psk        string
	v4Net      *net.IPNet
	v6Net      *net.IPNet
	v4Gw       string
	v6Gw       string
	usedV4     map[string]bool
	usedV6     map[string]bool
	mu         sync.RWMutex
	tap        io.ReadWriteCloser
	vswitch    *VSwitch
	brutal     bool
	brutalUp   uint64
	brutalDown uint64

	macAddr       string
	activeClients map[string]*ClientSession
	macToIP       map[string]MacBinding

	encrypt   bool
	icLegacy  *innerCipher
	startedAt time.Time

	banned   map[string]int64 // clientID → 封禁到期 unix 毫秒（0=永久）；被 ban 连接直接进焦油坑
	bannedMu sync.Mutex
}

// Ban 封禁客户端。ttl<=0 表示永久；会话若在线则立即断开。
func (s *Server) Ban(clientID string, ttl time.Duration) bool {
	if clientID == "" {
		return false
	}
	s.bannedMu.Lock()
	if ttl <= 0 {
		s.banned[clientID] = 0
	} else {
		s.banned[clientID] = time.Now().Add(ttl).UnixMilli()
	}
	s.bannedMu.Unlock()
	// 已在线则立刻踢下线
	s.mu.RLock()
	session, ok := s.activeClients[clientID]
	s.mu.RUnlock()
	if ok {
		s.kickSession(session)
	}
	log.Infof("[Server] Client %s banned (ttl=%s)", clientID, ttl)
	return true
}

// Unban 解除封禁
func (s *Server) Unban(clientID string) {
	s.bannedMu.Lock()
	delete(s.banned, clientID)
	s.bannedMu.Unlock()
}

// IsBanned 查询 clientID 当前是否被封禁（自动清理过期项）
func (s *Server) IsBanned(clientID string) bool {
	if clientID == "" {
		return false
	}
	s.bannedMu.Lock()
	defer s.bannedMu.Unlock()
	exp, ok := s.banned[clientID]
	if !ok {
		return false
	}
	if exp > 0 && time.Now().UnixMilli() >= exp {
		delete(s.banned, clientID)
		return false
	}
	return true
}

// BanList 返回当前封禁列表快照（clientID → 剩余秒，0=永久）
func (s *Server) BanList() map[string]int64 {
	s.bannedMu.Lock()
	defer s.bannedMu.Unlock()
	out := make(map[string]int64, len(s.banned))
	nowMs := time.Now().UnixMilli()
	for id, exp := range s.banned {
		if exp == 0 {
			out[id] = 0
		} else if exp > nowMs {
			out[id] = (exp - nowMs) / 1000
		} else {
			delete(s.banned, id)
		}
	}
	return out
}

// kickSession 断开一个会话的所有物理连接并停止下行（Web 面板 kick 用）
func (s *Server) kickSession(session *ClientSession) {
	session.Port.Close()
	session.sessionMu.Lock()
	conns := make([]*connInfo, 0, len(session.conns))
	for ci := range session.conns {
		conns = append(conns, ci)
	}
	session.sessionMu.Unlock()
	for _, ci := range conns {
		ci.tcpConn.Close()
	}
}

// IPPoolStatus 地址池使用情况（面板展示）。v6 空间巨大不计算容量。
func (s *Server) IPPoolStatus() (v4Used, v4Total, v6Used int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v4Used, v4Total = len(s.usedV4), ipNetHostCount(s.v4Net)
	v6Used = len(s.usedV6)
	return
}

// ipNetHostCount 估算 IPv4 网段可用主机数（扣网络号/广播，超大网段封顶）
func ipNetHostCount(n *net.IPNet) int {
	ones, bits := n.Mask.Size()
	hostBits := bits - ones
	if hostBits >= 16 {
		return 1 << 16
	}
	cnt := 1 << uint(hostBits)
	if cnt > 2 {
		cnt -= 2
	}
	return cnt
}

// MACEntry 面板展示的 MAC 表条目
type MACEntry struct {
	MAC    string `json:"mac"`
	Port   string `json:"port"`
	AgeSec uint64 `json:"age_sec"`
}

// MACSnapshot 交换机学习到的 MAC→端口 快照（面板展示）
func (s *Server) MACSnapshot() []MACEntry {
	out := []MACEntry{}
	for i := 0; i < ShardCount; i++ {
		shard := s.vswitch.shards[i]
		shard.mu.RLock()
		for mac, entry := range shard.macTable {
			out = append(out, MACEntry{MAC: mac, Port: entry.portID, AgeSec: uint64(time.Since(entry.updatedAt) / time.Second)})
		}
		shard.mu.RUnlock()
	}
	return out
}

// startServer 以 JSON 配置启动服务端（cfg 已经过 applyDefaults + Validate）
func startServer(ctx context.Context, cfg *Config) {
	log.Infof("Starting TCP TLS server process...")
	_, v4net, _ := net.ParseCIDR(cfg.Server.V4CIDR)
	_, v6net, _ := net.ParseCIDR(cfg.Server.V6CIDR)

	srv := &Server{
		psk: cfg.PSK, v4Net: v4net, v6Net: v6net, usedV4: make(map[string]bool), usedV6: make(map[string]bool),
		vswitch: NewVSwitch(), brutal: cfg.Brutal, brutalUp: cfg.BrutalUp, brutalDown: cfg.BrutalDown,
		macAddr: cfg.Mac, activeClients: make(map[string]*ClientSession), macToIP: make(map[string]MacBinding),
		encrypt: cfg.Encrypt, startedAt: time.Now(),
		banned: make(map[string]int64),
	}
	srv.v4Gw, srv.v6Gw = getFirstIP(v4net).String(), getFirstIP(v6net).String()
	srv.usedV4[srv.v4Gw], srv.usedV6[srv.v6Gw] = true, true
	if cfg.Encrypt {
		srv.icLegacy = newLegacyInnerCipher(cfg.PSK)
	}

	var tap io.ReadWriteCloser
	if cfg.Tap == "mem" {
		// In-memory TAP backend for CI/e2e where no real TAP device can be
		// created (GitHub hosted runners lack CAP_NET_ADMIN). The tunnel
		// (TCP TLS, handshake, FEC, encryption) is exercised exactly the same.
		tap = newMemTap(ctx)
		log.Infof("Using in-memory TAP backend (no real device)")
	} else {
		t, err := water.New(newTapConfig(cfg.Tap))
		if err != nil {
			log.Fatalf("Server TAP error: %v", err)
		}
		tap = t
		if err := setTapMac(cfg.Tap, cfg.Mac); err != nil {
			log.Warnf("Server failed to set tap MAC: %v", err)
		}
		if link, err := netlink.LinkByName(cfg.Tap); err == nil {
			v4Addr, _ := netlink.ParseAddr(fmt.Sprintf("%s/%d", srv.v4Gw, maskSize(v4net.Mask)))
			v6Addr, _ := netlink.ParseAddr(fmt.Sprintf("%s/%d", srv.v6Gw, maskSize(v6net.Mask)))
			netlink.AddrReplace(link, v4Addr)
			netlink.AddrReplace(link, v6Addr)
			netlink.LinkSetUp(link)
		}
	}
	srv.tap = tap

	go func() { <-ctx.Done(); srv.tap.Close() }()

	if cfg.Web.Addr != "" {
		go startWebServer(cfg.Web.Addr, srv, nil, cfg.Web.Auth, cfg.Web.Cert, cfg.Web.Key)
	}

	tapPortID := "TAP_LOCAL"
	tapBackend := make(chan []VPNFrame, 32)
	tapPort := NewAsyncPort(ctx, tapPortID, false)
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
			// ProcessFrame 内部会拷贝进独立的池缓冲，直接复用本地缓冲
			srv.vswitch.ProcessFrame(tapPortID, buf[:rn])
		}
	}()

	tlsConfig := getServerTLSConfig(cfg.Server.Cert, cfg.Server.Key)
	tcpAddr, err := net.ResolveTCPAddr("tcp", cfg.Addr)
	if err != nil {
		log.Fatalf("ResolveTCPAddr error: %v", err)
	}
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		log.Fatalf("TCP Listen error: %v", err)
	}
	log.Infof("VPN Server listening on %s (TCP TLS, ALPN: h2)", cfg.Addr)

	go func() { <-ctx.Done(); listener.Close() }()

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			continue
		}

		conn.SetKeepAlive(true)
		conn.SetKeepAlivePeriod(15 * time.Second)
		conn.SetNoDelay(true)
		conn.SetReadBuffer(4 * 1024 * 1024)
		conn.SetWriteBuffer(4 * 1024 * 1024)

		go func(c *net.TCPConn) {
			peekBuf := make([]byte, 1)
			c.SetReadDeadline(time.Now().Add(3 * time.Second))
			n, err := c.Read(peekBuf)
			c.SetReadDeadline(time.Time{})
			if err != nil || n == 0 {
				c.Close()
				return
			}

			prefixConn := &PrefixConn{Conn: c, prefix: peekBuf[:n]}
			if peekBuf[0] != 0x16 {
				serveFallbackHTTP(prefixConn, "http/1.1")
				return
			}

			tlsConn := tls.Server(prefixConn, tlsConfig)
			tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
			err = tlsConn.Handshake()
			tlsConn.SetDeadline(time.Time{})
			if err != nil {
				tlsConn.Close()
				return
			}

			alpn := tlsConn.ConnectionState().NegotiatedProtocol
			peekBuf2 := make([]byte, 1)
			tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n2, err2 := tlsConn.Read(peekBuf2)
			tlsConn.SetReadDeadline(time.Time{})
			if err2 != nil || n2 == 0 {
				tlsConn.Close()
				return
			}

			prefixConn2 := &PrefixConn{Conn: tlsConn, prefix: peekBuf2[:n2]}
			if peekBuf2[0] >= 0x20 {
				serveFallbackHTTP(prefixConn2, alpn)
				return
			}

			srv.handleConnection(ctx, prefixConn2, c)
		}(conn)
	}
}

func (s *Server) handleConnection(parentCtx context.Context, conn net.Conn, tcpConn *net.TCPConn) {
	connCtx, cancel := context.WithCancel(parentCtx)
	defer cancel()
	defer conn.Close()

	scanner := NewFrameScanner(conn)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reqData, _, err := scanner.ReadFrame()
	conn.SetReadDeadline(time.Time{})

	if err != nil {
		camouflageProbe(conn)
		return
	}

	var req HandshakeReq
	if err := json.Unmarshal(reqData, &req); err != nil {
		log.Warnf("握手数据解析失败. 开启伪装焦油坑.")
		putFrame(reqData)
		camouflageProbe(conn)
		return
	}
	putFrame(reqData)
	log.Debugf("<= 收到客户端握手请求 (HandshakeReq): %+v", req)

	if req.PSK != hashPSK(s.psk) {
		log.Warnf("PSK 验证失败 (Hash不匹配).")
		camouflageProbe(conn)
		return
	}
	if req.Encrypt != s.encrypt {
		log.Warnf("加密配置不匹配 (Client: %v, Server: %v)", req.Encrypt, s.encrypt)
		camouflageProbe(conn)
		return
	}
	clientID := req.ClientID
	if clientID == "" {
		log.Warnf("拒绝连接: 缺少 ClientID")
		return
	}
	// 封禁检查：命中直接进焦油坑（与 PSK 错误同等对待，不泄露 ban 状态）
	if s.IsBanned(clientID) {
		log.Warnf("[%s] 已封禁，拒绝接入", clientID)
		camouflageProbe(conn)
		return
	}
	mac := req.MAC

	s.mu.Lock()
	if bind, exists := s.macToIP[mac]; exists && mac != "" {
		req.IPv4, req.IPv6 = bind.IPv4, bind.IPv6
	}

	session, exists := s.activeClients[clientID]
	if exists {
		if req.MAC != session.MAC {
			log.Warnf("[%s] 拒绝连接: MAC 不匹配", clientID)
			s.mu.Unlock()
			camouflageProbe(conn)
			return
		}
		// 检测到老会话，立刻取消销毁倒计时，无缝复活！
		session.sessionMu.Lock()
		if session.destroyTimer != nil {
			session.destroyTimer.Stop()
			session.destroyTimer = nil
			log.Infof("[%s] ⚡ 会话在销毁倒计时内成功复活！(无缝接续)", clientID)
		}
		session.ActiveConns++
		session.sessionMu.Unlock()

		log.Infof("[%s] 🔗 已有会话增加新物理连接 (当前连接数: %d)", clientID, session.ActiveConns)
	} else {
		v4ip, v6ip := s.assignIPsLocked(req.IPv4, req.IPv6)
		// FEC 模式协商：req.FecGroup>=2 表示客户端请求 XOR 奇偶校验模式
		// （服务端对下行也用同参数编码）；否则维持传统逐帧复制模式。
		fecEncK := 0
		if req.FEC && int(req.FecGroup) >= fecMinGroup {
			fecEncK = clampFecGroup(int(req.FecGroup))
		}
		// 内层加密协商：双方均声明 GCM 支持时启用。会话盐每次建会话随机
		// 生成（c2s/s2c 各一个），服务端重启或会话重建即换盐，密钥流不再
		// 跨会话重用；旧客户端 enc_algo=0 → 维持 legacy CTR。
		saltA, saltB := newRandomSalt(), newRandomSalt()
		encAlgo := encAlgoLegacyCTR
		if s.encrypt && int(req.EncAlgo) >= encAlgoGCM {
			encAlgo = encAlgoGCM
		}
		// 各方向加密器：legacy 模式各方向共用回退实例；加密关闭时为 nil
		var icTx, icRx *innerCipher
		if s.encrypt {
			if encAlgo == encAlgoGCM {
				icTx, _ = newGCMInnerCipher(s.psk, saltB[:]) // s2c
				icRx, _ = newGCMInnerCipher(s.psk, saltA[:]) // c2s
			} else {
				icTx, icRx = s.icLegacy, s.icLegacy
			}
		}
		fecMode := "off"
		if fecEncK > 0 {
			fecMode = fmt.Sprintf("xor K=%d", fecEncK)
		} else if req.FEC {
			fecMode = "dup"
		}

		port := NewAsyncPort(parentCtx, clientID, req.FEC && fecEncK == 0)
		if fecEncK > 0 {
			port.AttachFEC(fecEncK, icTx)
		}
		session = &ClientSession{
			SessionID: uuid.New().String(), Port: port, IPv4: v4ip, IPv6: v6ip, MAC: req.MAC,
			Dedup: NewDeDuplicator(), ActiveConns: 1, FecEncK: fecEncK, FecMode: fecMode,
			EncAlgo: encAlgo, SaltA: saltA, SaltB: saltB, CreatedAt: time.Now(),
			conns: make(map[*connInfo]struct{}),
		}
		session.icTx = icTx
		session.icRx = icRx
		// 初始化服务端重排缓冲区，理顺后交由交换机转发
		session.RxReorder = NewReorderBuffer(func(orderedFrame []byte) {
			s.vswitch.ProcessFrame(clientID, orderedFrame)
		})
		if fecEncK > 0 {
			session.FecDec = NewFECDecoder(fecEncK, icRx, session.RxReorder.Insert)
		}
		s.activeClients[clientID] = session
		if mac != "" {
			s.macToIP[mac] = MacBinding{IPv4: v4ip, IPv6: v6ip}
		}
		s.vswitch.AddPort(port)
		log.Infof("[%s] 新逻辑 Client 上线 (FEC=%s EncAlgo=%d), Assigned IPs: %s, %s", clientID, fecMode, encAlgo, v4ip, v6ip)
	}

	v4ip, v6ip, port := session.IPv4, session.IPv6, session.Port
	sessionID := session.SessionID // 提取出来准备发给客户端
	encAlgo := session.EncAlgo
	icTx, icRx := session.icTx, session.icRx
	ci := &connInfo{
		remote:   tcpConn.RemoteAddr().String(),
		tcpConn:  tcpConn,
		linkedAt: time.Now().Unix(),
	}
	// 注册本物理连接到会话，供 Web 面板踢出/展示明细
	session.sessionMu.Lock()
	session.conns[ci] = struct{}{}
	session.sessionMu.Unlock()
	s.mu.Unlock()

	serverTxRate, clientTxRate := s.brutalUp, s.brutalDown
	if req.BrutalRx > 0 && (s.brutalUp == 0 || req.BrutalRx < s.brutalUp) {
		serverTxRate = req.BrutalRx
	}
	if req.BrutalTx > 0 && (s.brutalDown == 0 || req.BrutalTx < s.brutalDown) {
		clientTxRate = req.BrutalTx
	}
	ci.brutalTx, ci.brutalRx = serverTxRate, clientTxRate

	if s.brutal && serverTxRate > 0 {
		applyTCPBrutal(tcpConn, serverTxRate)
	}

	v4cidr := fmt.Sprintf("%s/%d", v4ip, maskSize(s.v4Net.Mask))
	v6cidr := fmt.Sprintf("%s/%d", v6ip, maskSize(s.v6Net.Mask))
	// 响应带协商结果：FEC XOR 分组大小 + 内层加密算法与两个方向的会话盐。
	// 旧客户端忽略未知字段，互操作不受影响。
	encSalt, encSalt2 := "", ""
	if encAlgo == encAlgoGCM {
		encSalt = hex.EncodeToString(session.SaltA[:])  // c2s
		encSalt2 = hex.EncodeToString(session.SaltB[:]) // s2c
	}
	s.sendResp(conn, true, "OK", clientID, sessionID, v4cidr, v6cidr, serverTxRate, clientTxRate, req.FEC, uint32(session.FecEncK), encAlgo, encSalt, encSalt2, req.Encrypt)

	rttCache := new(uint32)
	atomic.StoreUint32(rttCache, 50000)
	ci.rttCache = rttCache
	go startRTTPoller(connCtx, tcpConn, rttCache)

	connTxChan := make(chan []VPNFrame, 32)
	port.RegisterBackend(connTxChan, rttCache)

	defer func() {
		port.UnregisterBackend(connTxChan)
		// 从会话连接注册表移除本连接
		session.sessionMu.Lock()
		delete(session.conns, ci)
		session.sessionMu.Unlock()
		s.mu.Lock()
		session.sessionMu.Lock()
		session.ActiveConns--
		if session.ActiveConns <= 0 {
			// 不要立刻删除！给它 120 秒的“僵尸续命期”
			log.Infof("[%s] ⚠️ 客户端所有物理连接已断开，会话进入 120 秒保留期...", clientID)

			session.destroyTimer = time.AfterFunc(120*time.Second, func() {
				s.mu.Lock()
				session.sessionMu.Lock()

				// 120 秒后再次检查，如果还是没连上，才彻底销毁
				if session.ActiveConns <= 0 {
					delete(s.usedV4, session.IPv4)
					delete(s.usedV6, session.IPv6)
					delete(s.activeClients, clientID)
					s.macToIPCleanLocked(session.MAC, session.IPv4)
					s.vswitch.RemovePort(clientID)
					session.Port.Close()
					log.Infof("[%s] 💀 会话超时彻底销毁，释放 IP 及内存资源", clientID)
				}

				session.sessionMu.Unlock()
				s.mu.Unlock()
			})
		}
		session.sessionMu.Unlock()
		s.mu.Unlock()
	}()

	go func() {
		sendBuffer := make([]byte, 0, 64*1024+4096)
		keepAliveTicker := time.NewTicker(4 * time.Second)
		defer keepAliveTicker.Stop()
		for {
			select {
			case <-connCtx.Done():
				return
			case frames := <-connTxChan:
				sendBuffer = sendBuffer[:0]
				for _, vf := range frames {
					sendBuffer = appendPaddedFrame(sendBuffer, vf, icTx)
				}
				// 副本所有权归本协程：发送后无条件归还（深拷贝分发保证独立）
				freeFrames(frames)
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				_, werr := conn.Write(sendBuffer)
				conn.SetWriteDeadline(time.Time{})
				if werr != nil {
					log.Debugf("[%s] 下行写入失败，关闭连接: %v", clientID, werr)
					conn.Close()
					return
				}
				atomic.AddUint64(&session.TxBytes, uint64(len(sendBuffer)))
				atomic.AddUint64(&session.TxPackets, uint64(len(frames)))
				atomic.AddUint64(&ci.txBytes, uint64(len(sendBuffer)))
				atomic.AddUint64(&ci.txPackets, uint64(len(frames)))
			case <-keepAliveTicker.C:
				sendBuffer = sendBuffer[:0]
				sendBuffer = appendPaddedFrame(sendBuffer, VPNFrame{Seq: 0, Data: nil}, nil)
				if _, err := conn.Write(sendBuffer); err != nil {
					conn.Close()
					return
				}
			}
		}
	}()

	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		frame, seq, err := scanner.ReadFrame()
		if err != nil {
			log.Debugf("[%s] 链接断开: %v", clientID, err)
			return
		}

		if err == nil && frame != nil {
			atomic.AddUint64(&session.RxBytes, uint64(len(frame)))
			atomic.AddUint64(&session.RxPackets, 1)
			atomic.AddUint64(&ci.rxBytes, uint64(len(frame)))
			atomic.AddUint64(&ci.rxPackets, 1)
			if seq != 0 && icRx != nil {
				plain, derr := icRx.openInPlace(frame, seq, uint32(len(frame)))
				if derr != nil {
					// GCM 校验失败：篡改或异源注入的帧，直接丢弃
					log.Debugf("[%s] dropped tampered/foreign frame (seq=%d): %v", clientID, seq, derr)
					putFrame(frame)
					continue
				}
				frame = plain
			}
			if seq == 0 && session.FecDec != nil && len(frame) >= 7 && frame[0] == fecMagic {
				// XOR 校验帧：交给会话级 FEC 解码器
				session.FecDec.OnParity(frame)
				putFrame(frame)
				continue
			}
			if session.FecDec != nil {
				session.FecDec.OnData(seq, frame)
			}
			// 交给重排缓冲区
			session.RxReorder.Insert(seq, frame)
		}
	}
}

// macToIPCleanLocked 会话销毁时回收其 MAC 绑定，防止表无限增长。
// 调用方须持有 s.mu。
func (s *Server) macToIPCleanLocked(mac, ip string) {
	if mac == "" {
		return
	}
	if bind, ok := s.macToIP[mac]; ok && bind.IPv4 == ip {
		// 仅当绑定仍指向本会话地址时清除（期间 MAC 可能已重新绑定）
		delete(s.macToIP, mac)
	}
}

func (s *Server) assignIPsLocked(reqV4, reqV6 string) (string, string) {
	alloc := func(req string, netw *net.IPNet, used map[string]bool) string {
		req = strings.Split(req, "/")[0]
		parsed := net.ParseIP(req)
		if parsed != nil && netw.Contains(parsed) && !used[parsed.String()] {
			used[parsed.String()] = true
			return parsed.String()
		}
		ip := duplicateIP(netw.IP)
		for netw.Contains(ip) {
			ipStr := ip.String()
			if !used[ipStr] && ip[len(ip)-1] != 0 && ip[len(ip)-1] != 255 {
				used[ipStr] = true
				return ipStr
			}
			incrementIP(ip)
		}
		return ""
	}
	return alloc(reqV4, s.v4Net, s.usedV4), alloc(reqV6, s.v6Net, s.usedV6)
}

func (s *Server) sendResp(w io.Writer, ok bool, msg, clientID, sessionID, v4cidr, v6cidr string, srvTx, srvRx uint64, fec bool, fecGroup uint32, encAlgo int, encSalt, encSalt2 string, encrypt bool) {
	resp := HandshakeResp{
		Success: ok, Message: msg, ClientID: clientID, SessionID: sessionID, IPv4: v4cidr, IPv6: v6cidr,
		GwV4: s.v4Gw, GwV6: s.v6Gw, Padding: generatePadding(100, 500), BrutalTx: srvTx, BrutalRx: srvRx,
		FEC: fec, FecGroup: int(fecGroup), Encrypt: encrypt, EncAlgo: encAlgo, EncSalt: encSalt, EncSalt2: encSalt2,
	}
	log.Debugf("[%s] => 发送握手响应 (HandshakeResp): %+v", clientID, resp)
	d, _ := json.Marshal(resp)
	writeStreamFrame(w, d)
}

// ======================= in-memory TAP =======================
// memTap is a no-op TAP backend used when -tap mem is requested (CI/e2e on
// runners that cannot create a real TAP device). Writes are dropped (there is
// no real subnet behind it); reads block until the context is cancelled so the
// stack goroutines terminate cleanly. The actual tunnel (TCP TLS, handshake,
// FEC, encryption) runs identically to the real-TAP path.
type memTap struct {
	ctx context.Context
}

func newMemTap(ctx context.Context) *memTap { return &memTap{ctx: ctx} }

func (m *memTap) Read(p []byte) (int, error) {
	<-m.ctx.Done()
	return 0, io.EOF
}

func (m *memTap) Write(p []byte) (int, error) {
	return len(p), nil
}

func (m *memTap) Close() error { return nil }
