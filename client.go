package main

import (
	"context"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
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
	txSeq      uint32
}

func NewAsyncPort(ctx context.Context, id string, fecMode bool) *AsyncPort {
	pCtx, pCancel := context.WithCancel(ctx)
	p := &AsyncPort{id: id, ch: make(chan []byte, 4096), ctx: pCtx, cancel: pCancel, fecMode: fecMode}
	go p.run()
	return p
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

			p.backendsMu.RLock()
			backends := p.backends
			p.backendsMu.RUnlock()

			if len(backends) > 0 {
				if p.fecMode {
					// FEC: 将带有相同 Seq 的 VPNFrame 分发给所有连接
					for _, b := range backends {
						batchCopy := make([]VPNFrame, len(batch))
						copy(batchCopy, batch)
						select {
						case b.ch <- batchCopy:
						default:
						}
					}
				} else {
					// MinRTT: 选路
					var bestBackend *Backend
					var minScore uint32 = math.MaxUint32
					for _, b := range backends {
						qLen := len(b.ch)
						if qLen >= cap(b.ch)-2 {
							continue
						}
						rtt := atomic.LoadUint32(b.rttCache)
						// 降低单包的惩罚权重，或者引入缓冲阈值
						// 假设 qLen 小于 10 时，不增加延迟惩罚
						penalty := uint32(0)
						if qLen > 10 {
							penalty = uint32((qLen - 10) * 1000) // 积压超过10个包才开始惩罚
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

					batchCopy := make([]VPNFrame, len(batch))
					copy(batchCopy, batch)
					select {
					case bestBackend.ch <- batchCopy:
					default:
					}
				}
			} else {
				// 丢弃内存
				for _, vf := range batch {
					if vf.Data != nil && !p.fecMode {
						putFrame(vf.Data)
					}
				}
			}

			batch = batch[:0]
			batchBytes = 0
		}
	}
}
func (p *AsyncPort) Close() { p.cancel() }

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
	txPort          *AsyncPort
	rxReorder       *ReorderBuffer
	dedup           *DeDuplicator
	TxBytes         uint64
	RxBytes         uint64
	TxPackets       uint64
	RxPackets       uint64
	encrypt         bool
	cipherBlock     cipher.Block
	baseIV          []byte
}

func startClient(ctx context.Context, psk, tapName, macAddr, addr, reqV4, reqV6, sni string, insecure bool, certHash string, fwmark int, brutal bool, brutalUp, brutalDown uint64, connsCount int, fec, encrypt bool) {
	log.Infof("Starting TCP TLS client process...")
	var iface io.ReadWriteCloser
	if tapName == "mem" {
		iface = newMemTap(ctx)
		log.Infof("Using in-memory TAP backend (no real device)")
	} else {
		config := water.Config{DeviceType: water.TAP}
		config.Name = tapName
		t, err := water.New(config)
		if err != nil {
			log.Fatalf("Client TAP creation error: %v", err)
		}
		iface = t
		if err := setTapMac(tapName, macAddr); err != nil {
			log.Warnf("Client failed to set tap MAC: %v", err)
		}
	}
	go func() { <-ctx.Done(); iface.Close() }()

	actualMac := macAddr
	if actualMac == "" && tapName != "mem" {
		if link, err := netlink.LinkByName(tapName); err == nil {
			actualMac = link.Attrs().HardwareAddr.String()
		}
	}

	ns := uuid.NewMD5(uuid.NameSpaceURL, []byte("my_vpn_tunnel"))
	clientID := uuid.NewSHA1(ns, []byte(actualMac+psk)).String()
	log.Infof("Assigned UUID v5 ClientID: %s", clientID)

	c := &Client{
		clientID: clientID, psk: psk, targetAddrs: parseServerAddresses(addr), tapName: tapName, reqV4: reqV4, reqV6: reqV6,
		sni: sni, insecure: insecure, certHash: certHash, fwmark: fwmark, brutal: brutal, brutalUp: brutalUp, brutalDown: brutalDown,
		tap: iface, macAddr: actualMac, connsCount: connsCount, fecMode: fec, encrypt: encrypt,
		txPort: NewAsyncPort(ctx, "client_tx_port", fec),
		dedup:  NewDeDuplicator(), // 初始化客户端去重器
	}

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
	if encrypt {
		c.cipherBlock, c.baseIV = getCipherContext(psk)
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
			frame := getFrame()[:rn]
			copy(frame, buf[:rn])
			c.txPort.WriteFrame(frame)
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < c.connsCount; i++ {
		wg.Add(1)
		go func(connIndex int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					err := c.dialAndServe(ctx, connIndex)
					log.Warnf("[Conn %d] Tunnel down: %v. Reconnecting in 3s...", connIndex, err)
					select {
					case <-ctx.Done():
						return
					case <-time.After(3 * time.Second):
					}
				}
			}
		}(i)
	}
	wg.Wait()
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
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificates provided")
			}
			hashStr := hex.EncodeToString(sha256.New().Sum(rawCerts[0]))
			if hashStr != c.certHash {
				return fmt.Errorf("cert SHA-256 mismatch: expected %s", c.certHash)
			}
			return nil
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

func (c *Client) dialAndServe(parentCtx context.Context, connIndex int) error {
	runCtx, runCancel := context.WithCancel(parentCtx)
	defer runCancel()

	tlsConf := &tls.Config{ServerName: c.sni, InsecureSkipVerify: c.insecure, NextProtos: []string{"h2", "http/1.1"}}
	if c.certHash != "" {
		tlsConf.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificates provided")
			}
			hashStr := hex.EncodeToString(sha256.New().Sum(rawCerts[0]))
			if hashStr != c.certHash {
				return fmt.Errorf("cert SHA-256 mismatch")
			}
			return nil
		}
	}

	target := c.targetAddrs[connIndex%len(c.targetAddrs)]
	if isSocks5Enabled() {
		log.Infof("[Conn %d] Initiating connection to %s via SOCKS5 %s ...", connIndex, target, globalSocks5Addr)
	} else {
		log.Infof("[Conn %d] Initiating connection...", connIndex)
	}
	// 统一走全局拨号器：启用 -socks5 时所有 socket 均经由代理，否则全部直连
	rawConn, err := dialContext(runCtx, "tcp", target)
	if err != nil {
		return err
	}

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
		return err
	}
	defer tlsConn.Close()

	scanner := NewFrameScanner(tlsConn)
	req := HandshakeReq{
		ClientID: c.clientID,
		PSK:      hashPSK(c.psk),
		MAC:      c.macAddr,
		IPv4:     c.reqV4,
		IPv6:     c.reqV6,
		Padding:  generatePadding(100, 500),
		FEC:      c.fecMode,
		BrutalTx: clientTxRate,
		BrutalRx: clientRxRate,
		Encrypt:  c.encrypt,
	}
	log.Debugf("[Conn %d] => 发送握手请求 (HandshakeReq): %+v", connIndex, req)
	reqData, _ := json.Marshal(req)
	writeStreamFrame(tlsConn, reqData)

	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respData, _, err := scanner.ReadFrame()
	tlsConn.SetReadDeadline(time.Time{})
	if err != nil {
		return err
	}

	var resp HandshakeResp
	if err := json.Unmarshal(respData, &resp); err != nil || !resp.Success {
		return fmt.Errorf("handshake rejected")
	}
	log.Debugf("[Conn %d] <= 收到握手响应 (HandshakeResp): %+v", connIndex, resp)

	if resp.Encrypt != c.encrypt {
		return fmt.Errorf("server encryption mismatch")
	}

	// 服从服务端下达的强制最高限速
	if c.brutal && resp.BrutalRx > 0 && resp.BrutalRx != clientTxRate {
		log.Infof("[Conn %d] 服从服务端指令，重新调整上行限速为: %d Mbps", connIndex, resp.BrutalRx)
		applyTCPBrutal(tcpConn, resp.BrutalRx) // 二次调用内核修改拥塞控制参数
	}

	log.Infof("[Conn %d] Linked! IPv4: %s | IPv6: %s | FEC Match: %v", connIndex, resp.IPv4, resp.IPv6, resp.FEC)

	c.sessionMu.Lock()
	isNewSession := false
	if c.serverSessionID != resp.SessionID {
		isNewSession = true
		c.serverSessionID = resp.SessionID
	}
	c.gwV4 = resp.GwV4
	c.gwV6 = resp.GwV6
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

	errChan := make(chan error, 2)
	connTxChan := make(chan []VPNFrame, 32)
	c.txPort.RegisterBackend(connTxChan, rttCache)
	defer c.txPort.UnregisterBackend(connTxChan)

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
					sendBuffer = appendPaddedFrame(sendBuffer, vf, c.cipherBlock, c.baseIV)
					if !c.fecMode && vf.Data != nil {
						putFrame(vf.Data)
					} // 非FEC释放
				}
				tlsConn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				_, err := tlsConn.Write(sendBuffer)
				tlsConn.SetWriteDeadline(time.Time{})
				if err != nil {
					errChan <- err
					return
				}
				atomic.AddUint64(&c.TxBytes, uint64(len(sendBuffer)))
				atomic.AddUint64(&c.TxPackets, uint64(len(frames)))
			case <-keepAliveTicker.C:
				sendBuffer = sendBuffer[:0]
				sendBuffer = appendPaddedFrame(sendBuffer, VPNFrame{Seq: 0, Data: nil}, nil, nil)
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
				if seq != 0 && c.cipherBlock != nil {
					xorCryptInPlace(frame, seq, c.cipherBlock, c.baseIV)
				}
				// 丢入重排缓冲区，后续的 Write 和 putFrame 由缓冲区内部接管
				c.rxReorder.Insert(seq, frame)
			}
		}
	}()

	select {
	case err := <-errChan:
		return err
	case <-runCtx.Done():
		return nil
	}
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
