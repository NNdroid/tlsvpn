package main

import (
	"context"
	"crypto/cipher"
	"crypto/tls"
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
	ActiveConns int
	TxBytes     uint64
	RxBytes     uint64
	TxPackets   uint64
	RxPackets   uint64
	// 会话保活与生命周期控制
	sessionMu    sync.Mutex
	destroyTimer *time.Timer
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

	encrypt     bool
	cipherBlock cipher.Block
	baseIV      []byte
}

func startServer(ctx context.Context, psk, tapName, macAddr, addr, v4cidr, v6cidr, certFile, keyFile string, brutal bool, brutalUp, brutalDown uint64, webAddr string, encrypt bool) {
	log.Infof("Starting TCP TLS server process...")
	_, v4net, _ := net.ParseCIDR(v4cidr)
	_, v6net, _ := net.ParseCIDR(v6cidr)

	srv := &Server{
		psk: psk, v4Net: v4net, v6Net: v6net, usedV4: make(map[string]bool), usedV6: make(map[string]bool),
		vswitch: NewVSwitch(), brutal: brutal, brutalUp: brutalUp, brutalDown: brutalDown,
		macAddr: macAddr, activeClients: make(map[string]*ClientSession), macToIP: make(map[string]MacBinding),
		encrypt: encrypt,
	}
	srv.v4Gw, srv.v6Gw = getFirstIP(v4net).String(), getFirstIP(v6net).String()
	srv.usedV4[srv.v4Gw], srv.usedV6[srv.v6Gw] = true, true
	if encrypt {
		srv.cipherBlock, srv.baseIV = getCipherContext(psk)
	}

	var tap io.ReadWriteCloser
	if tapName == "mem" {
		// In-memory TAP backend for CI/e2e where no real TAP device can be
		// created (GitHub hosted runners lack CAP_NET_ADMIN). The tunnel
		// (TCP TLS, handshake, FEC, encryption) is exercised exactly the same.
		tap = newMemTap(ctx)
		log.Infof("Using in-memory TAP backend (no real device)")
	} else {
		config := water.Config{DeviceType: water.TAP}
		config.Name = tapName
		t, err := water.New(config)
		if err != nil {
			log.Fatalf("Server TAP error: %v", err)
		}
		tap = t
		if err := setTapMac(tapName, macAddr); err != nil {
			log.Warnf("Server failed to set tap MAC: %v", err)
		}
		if link, err := netlink.LinkByName(tapName); err == nil {
			v4Addr, _ := netlink.ParseAddr(fmt.Sprintf("%s/%d", srv.v4Gw, maskSize(v4net.Mask)))
			v6Addr, _ := netlink.ParseAddr(fmt.Sprintf("%s/%d", srv.v6Gw, maskSize(v6net.Mask)))
			netlink.AddrReplace(link, v4Addr)
			netlink.AddrReplace(link, v6Addr)
			netlink.LinkSetUp(link)
		}
	}
	srv.tap = tap

	go func() { <-ctx.Done(); srv.tap.Close() }()

	if webAddr != "" {
		go startWebServer(webAddr, srv, nil)
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
			frame := getFrame()[:rn]
			copy(frame, buf[:rn])
			srv.vswitch.ProcessFrame(tapPortID, frame)
			putFrame(frame)
		}
	}()

	tlsConfig := getServerTLSConfig(certFile, keyFile)
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		log.Fatalf("ResolveTCPAddr error: %v", err)
	}
	listener, err := net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		log.Fatalf("TCP Listen error: %v", err)
	}
	log.Infof("VPN Server listening on %s (TCP TLS, ALPN: h2)", addr)

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
		port := NewAsyncPort(parentCtx, clientID, req.FEC)
		session = &ClientSession{SessionID: uuid.New().String(), Port: port, IPv4: v4ip, IPv6: v6ip, MAC: req.MAC, Dedup: NewDeDuplicator(), ActiveConns: 1}
		// 初始化服务端重排缓冲区，理顺后交由交换机转发
		session.RxReorder = NewReorderBuffer(func(orderedFrame []byte) {
			s.vswitch.ProcessFrame(clientID, orderedFrame)
		})
		s.activeClients[clientID] = session
		if mac != "" {
			s.macToIP[mac] = MacBinding{IPv4: v4ip, IPv6: v6ip}
		}
		s.vswitch.AddPort(port)
		log.Infof("[%s] 新逻辑 Client 上线 (FEC=%v), Assigned IPs: %s, %s", clientID, req.FEC, v4ip, v6ip)
	}

	v4ip, v6ip, port := session.IPv4, session.IPv6, session.Port
	sessionID := session.SessionID // 提取出来准备发给客户端
	s.mu.Unlock()

	serverTxRate, clientTxRate := s.brutalUp, s.brutalDown
	if req.BrutalRx > 0 && (s.brutalUp == 0 || req.BrutalRx < s.brutalUp) {
		serverTxRate = req.BrutalRx
	}
	if req.BrutalTx > 0 && (s.brutalDown == 0 || req.BrutalTx < s.brutalDown) {
		clientTxRate = req.BrutalTx
	}

	if s.brutal && serverTxRate > 0 {
		applyTCPBrutal(tcpConn, serverTxRate)
	}

	v4cidr := fmt.Sprintf("%s/%d", v4ip, maskSize(s.v4Net.Mask))
	v6cidr := fmt.Sprintf("%s/%d", v6ip, maskSize(s.v6Net.Mask))
	s.sendResp(conn, true, "OK", clientID, sessionID, v4cidr, v6cidr, serverTxRate, clientTxRate, req.FEC, req.Encrypt)

	rttCache := new(uint32)
	atomic.StoreUint32(rttCache, 50000)
	go startRTTPoller(connCtx, tcpConn, rttCache)

	connTxChan := make(chan []VPNFrame, 32)
	port.RegisterBackend(connTxChan, rttCache)

	defer func() {
		port.UnregisterBackend(connTxChan)
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
					sendBuffer = appendPaddedFrame(sendBuffer, vf, s.cipherBlock, s.baseIV)
					if !req.FEC && vf.Data != nil {
						putFrame(vf.Data)
					} // 非FEC模式立即回收
				}
				conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				conn.Write(sendBuffer)
				conn.SetWriteDeadline(time.Time{})
				atomic.AddUint64(&session.TxBytes, uint64(len(sendBuffer)))
				atomic.AddUint64(&session.TxPackets, uint64(len(frames)))
			case <-keepAliveTicker.C:
				sendBuffer = sendBuffer[:0]
				sendBuffer = appendPaddedFrame(sendBuffer, VPNFrame{Seq: 0, Data: nil}, nil, nil)
				conn.Write(sendBuffer)
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
			if seq != 0 && s.cipherBlock != nil {
				xorCryptInPlace(frame, seq, s.cipherBlock, s.baseIV)
			}
			// 交给重排缓冲区
			session.RxReorder.Insert(seq, frame)
		}
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

func (s *Server) sendResp(w io.Writer, ok bool, msg, clientID, sessionID, v4cidr, v6cidr string, srvTx, srvRx uint64, fec bool, encrypt bool) {
	resp := HandshakeResp{
		Success: ok, Message: msg, ClientID: clientID, SessionID: sessionID, IPv4: v4cidr, IPv6: v6cidr,
		GwV4: s.v4Gw, GwV6: s.v6Gw, Padding: generatePadding(100, 500), BrutalTx: srvTx, BrutalRx: srvRx, FEC: fec, Encrypt: encrypt,
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
