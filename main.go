package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/google/uuid"
	utls "github.com/refraction-networking/utls"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/http2"
	"golang.org/x/sys/unix"
)

// ======================= 全局随机数池 =======================
const RandomPoolSize = 1024 * 1024

var (
	randomPool []byte
	log        *zap.SugaredLogger
)

func init() {
	randomPool = make([]byte, RandomPoolSize)
	_, err := rand.Read(randomPool)
	if err != nil {
		panic("Failed to initialize random pool: " + err.Error())
	}
}

func initLogger(level string) {
	config := zap.NewDevelopmentConfig()
	var l zapcore.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = zap.InfoLevel
	}
	config.Level = zap.NewAtomicLevelAt(l)
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	baseLogger, _ := config.Build()
	log = baseLogger.Sugar()
}

func fmtMAC(mac []byte) string {
	if len(mac) != 6 {
		return "invalid_mac"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// hashPSK 将明文 PSK 转换为 SHA256 防止明文传输
func hashPSK(psk string) string {
	h := sha256.Sum256([]byte(psk))
	return hex.EncodeToString(h[:])
}

// getCipherContext 根据 PSK 派生出 AES 块和基础 IV
func getCipherContext(psk string) (cipher.Block, []byte) {
	keyHash := sha256.Sum256([]byte(psk + "_enc_key"))
	ivHash := sha256.Sum256([]byte(psk + "_enc_iv"))
	block, err := aes.NewCipher(keyHash[:]) // 衍生为 AES-256
	if err != nil {
		panic(err)
	}
	return block, ivHash[:16]
}

// xorCryptInPlace 高速流式异或，原址修改数据（加解密通用）
func xorCryptInPlace(data []byte, seq uint32, block cipher.Block, baseIV []byte) {
	if len(data) == 0 || block == nil {
		return
	}
	iv := make([]byte, 16)
	copy(iv, baseIV)
	// 将包的序列号(Seq)混淆进 IV，确保每个数据包的异或密钥流完全不同
	binary.BigEndian.PutUint32(iv[12:], seq)

	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(data, data) // 高速异或位运算
}

// ======================= 高速环形去重器 (用于 FEC 过滤) =======================
type DeDuplicator struct {
	mu   sync.Mutex
	set  map[uint32]struct{}
	ring [4096]uint32
	idx  int
}

func NewDeDuplicator() *DeDuplicator {
	return &DeDuplicator{
		set: make(map[uint32]struct{}, 4096),
	}
}

func (d *DeDuplicator) IsDuplicate(seq uint32) bool {
	if seq == 0 {
		return false // 保活空包、控制帧不参与去重
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.set[seq]; exists {
		return true // 发现重复包！
	}

	// 淘汰最老的记录
	oldest := d.ring[d.idx]
	if oldest != 0 {
		delete(d.set, oldest)
	}

	// 加入新记录
	d.ring[d.idx] = seq
	d.set[seq] = struct{}{}
	d.idx = (d.idx + 1) % 4096

	return false
}

// ======================= 内存池与带有序列号的成帧协议 =======================
type VPNFrame struct {
	Seq  uint32
	Data []byte
}

var framePool = sync.Pool{
	New: func() any { return make([]byte, 32*1024) },
}

func getFrame() []byte { return framePool.Get().([]byte) }
func putFrame(b []byte) {
	if cap(b) >= 1500 && cap(b) <= 65536 {
		framePool.Put(b[:cap(b)])
	}
}

func getPaddingLength(dataLen int) int {
	if dataLen == 0 {
		return 100 + mathrand.IntN(201)
	}
	if dataLen < 200 {
		return 300 + mathrand.IntN(200)
	} else if dataLen < 800 {
		return 100 + mathrand.IntN(200)
	} else {
		return mathrand.IntN(100)
	}
}

// appendPaddedFrame 10 字节头部 [4B len][2B padLen][4B seq]
func appendPaddedFrame(buf []byte, vf VPNFrame, block cipher.Block, baseIV []byte) []byte {
	dataLen := 0
	if vf.Data != nil {
		dataLen = len(vf.Data)
	}
	padLen := getPaddingLength(dataLen)

	buf = append(buf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	headerStart := len(buf) - 10

	binary.BigEndian.PutUint32(buf[headerStart:headerStart+4], uint32(dataLen))
	binary.BigEndian.PutUint16(buf[headerStart+4:headerStart+6], uint16(padLen))
	binary.BigEndian.PutUint32(buf[headerStart+6:headerStart+10], vf.Seq)

	if dataLen > 0 {
		start := len(buf)
		buf = append(buf, vf.Data...)
		// == 如果有加密块且 Seq != 0，则执行异或加密 ==
		// (Seq=0 约定为空控制帧/握手帧，直接明文传输即可，因为外层还有一层 TLS)
		if block != nil && vf.Seq != 0 {
			xorCryptInPlace(buf[start:start+dataLen], vf.Seq, block, baseIV)
		}
	}

	if padLen > 0 {
		offset := mathrand.IntN(RandomPoolSize - padLen)
		buf = append(buf, randomPool[offset:offset+padLen]...)
	}

	return buf
}

// writeStreamFrame 发送无需去重的控制帧
func writeStreamFrame(w io.Writer, frame []byte) error {
	streamBuf := getFrame()[:0]
	streamBuf = appendPaddedFrame(streamBuf, VPNFrame{Seq: 0, Data: frame}, nil, nil)
	_, err := w.Write(streamBuf)
	putFrame(streamBuf[:cap(streamBuf)])
	return err
}

func generatePadding(min, max int) string {
	length := mathrand.IntN(max-min+1) + min
	offset := mathrand.IntN(RandomPoolSize - length)
	return hex.EncodeToString(randomPool[offset : offset+length])
}

// ======================= 流式帧扫描器 (读取 10 字节头) =======================
type FrameScanner struct {
	r      io.Reader
	buf    []byte
	offset int
}

func NewFrameScanner(r io.Reader) *FrameScanner {
	return &FrameScanner{r: r, buf: make([]byte, 0, 70*1024)}
}

func (fs *FrameScanner) ReadFrame() ([]byte, uint32, error) {
	const HeaderSize = 10
	const MaxDataLength = 65535 * 2

	for {
		available := len(fs.buf) - fs.offset

		if available >= HeaderSize {
			dataLen := int(binary.BigEndian.Uint32(fs.buf[fs.offset : fs.offset+4]))
			padLen := int(binary.BigEndian.Uint16(fs.buf[fs.offset+4 : fs.offset+6]))
			seq := binary.BigEndian.Uint32(fs.buf[fs.offset+6 : fs.offset+10])
			totalLen := dataLen + padLen

			if dataLen > MaxDataLength {
				fs.buf = fs.buf[:0]
				fs.offset = 0
				return nil, 0, fmt.Errorf("invalid frame data length: %d", dataLen)
			}

			if available >= HeaderSize+totalLen {
				if dataLen == 0 {
					fs.offset += HeaderSize + totalLen
					continue // 忽略空包
				}

				var frame []byte
				temp := getFrame()
				if dataLen > cap(temp) {
					putFrame(temp)
					frame = make([]byte, dataLen)
				} else {
					frame = temp[:dataLen]
				}

				copy(frame, fs.buf[fs.offset+HeaderSize:fs.offset+HeaderSize+dataLen])
				fs.offset += HeaderSize + totalLen
				return frame, seq, nil
			}
		}

		if fs.offset > 0 && (fs.offset == len(fs.buf) || fs.offset > 16384) {
			remaining := len(fs.buf) - fs.offset
			if remaining > 0 {
				copy(fs.buf, fs.buf[fs.offset:])
			}
			fs.buf = fs.buf[:remaining]
			fs.offset = 0
		}

		tailStart := len(fs.buf)
		requiredCap := tailStart + 2048

		available = len(fs.buf) - fs.offset
		if available >= HeaderSize {
			dataLen := int(binary.BigEndian.Uint32(fs.buf[fs.offset : fs.offset+4]))
			padLen := int(binary.BigEndian.Uint16(fs.buf[fs.offset+4 : fs.offset+6]))
			if fs.offset+HeaderSize+dataLen+padLen > requiredCap {
				requiredCap = fs.offset + HeaderSize + dataLen + padLen
			}
		}

		if cap(fs.buf) < requiredCap {
			newCap := cap(fs.buf) * 2
			if newCap < requiredCap {
				newCap = requiredCap
			}
			newBuf := make([]byte, len(fs.buf), newCap)
			copy(newBuf, fs.buf)
			fs.buf = newBuf
		}

		fs.buf = fs.buf[:cap(fs.buf)]
		n, err := fs.r.Read(fs.buf[tailStart:])
		fs.buf = fs.buf[:tailStart+n]

		if err != nil {
			if n == 0 || (err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection")) {
				return nil, 0, err
			}
		}
	}
}

// ======================= TCP Brutal & RTT 探测 =======================
const TCP_BRUTAL_PARAMS = 23301

func applyTCPBrutal(conn *net.TCPConn, rateMbps uint64) error {
	if rateMbps == 0 {
		return fmt.Errorf("TCP Brutal rate cannot be 0")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sysErr error
	err = raw.Control(func(fd uintptr) {
		err := unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "brutal")
		if err != nil {
			sysErr = fmt.Errorf("TCP_CONGESTION=brutal 未生效: %v", err)
			return
		}
		rateBps := rateMbps * 1000 * 1000 / 8
		b := make([]byte, 12)
		binary.LittleEndian.PutUint64(b[0:8], rateBps)
		binary.LittleEndian.PutUint32(b[8:12], 20)
		_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, fd, unix.IPPROTO_TCP, TCP_BRUTAL_PARAMS, uintptr(unsafe.Pointer(&b[0])), 12, 0)
		if errno != 0 {
			sysErr = fmt.Errorf("设置 TCP_BRUTAL_PARAMS 失败: %v", errno)
		}
	})
	if err != nil {
		return err
	}
	return sysErr
}

func getTCPRTT(conn *net.TCPConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var rtt uint32
	var sysErr error
	err = raw.Control(func(fd uintptr) {
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if err == nil {
			rtt = info.Rtt
		} else {
			sysErr = err
		}
	})
	if err != nil {
		return 0, err
	}
	return rtt, sysErr
}

func startRTTPoller(ctx context.Context, conn *net.TCPConn, rttCache *uint32) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if rtt, err := getTCPRTT(conn); err == nil && rtt > 0 {
				atomic.StoreUint32(rttCache, rtt)
			}
		}
	}
}

// ======================= TLS 伪装 =======================
func getServerTLSConfig(certFile, keyFile string) *tls.Config {
	var cert tls.Certificate
	var err error

	if certFile != "" && keyFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatalf("Failed to load custom TLS pair: %v", err)
		}
	} else {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		template := x509.Certificate{SerialNumber: big.NewInt(1)}
		certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
		if err != nil {
			panic(err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		cert, err = tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			panic(err)
		}
	}

	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}
}

type PrefixConn struct {
	net.Conn
	prefix []byte
}

func (c *PrefixConn) Read(p []byte) (n int, err error) {
	if len(c.prefix) > 0 {
		n = copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

type singleConnListener struct {
	conn net.Conn
	done chan struct{}
}

func (s *singleConnListener) Accept() (net.Conn, error) {
	select {
	case <-s.done:
		return nil, net.ErrClosed
	default:
		close(s.done)
		return s.conn, nil
	}
}
func (s *singleConnListener) Close() error   { return nil }
func (s *singleConnListener) Addr() net.Addr { return s.conn.LocalAddr() }

func serveFallbackHTTP(conn net.Conn, alpn string) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(403)
		w.Write([]byte(`<html><head><title>403 Forbidden</title></head><body><center><h1>403 Forbidden</h1></center><hr><center>nginx</center></body></html>`))
	})
	if alpn == "h2" {
		srv := &http2.Server{IdleTimeout: 60 * time.Second}
		srv.ServeConn(conn, &http2.ServeConnOpts{Handler: handler})
	} else {
		l := &singleConnListener{conn: conn, done: make(chan struct{})}
		srv := &http.Server{Handler: handler, IdleTimeout: 60 * time.Second}
		srv.Serve(l)
	}
}

func camouflageProbe(conn net.Conn) {
	defer conn.Close()
	junkBuf := getFrame()
	defer putFrame(junkBuf)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		if _, err := conn.Read(junkBuf); err != nil {
			return
		}
		time.Sleep(time.Duration(mathrand.IntN(150)+50) * time.Millisecond)
		fakePayloadLen := mathrand.IntN(300) + 100
		fakeFrame := getFrame()[:fakePayloadLen+2]
		fakeFrame[0] = 0x00
		fakeFrame[1] = byte(fakePayloadLen)
		rand.Read(fakeFrame[2:])
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, err := conn.Write(fakeFrame)
		putFrame(fakeFrame)
		if err != nil {
			return
		}
	}
}

// ======================= 网络接口配置 =======================
func setTapMac(tapName, macStr string) error {
	if macStr == "" {
		return nil
	}
	hwAddr, err := net.ParseMAC(macStr)
	if err != nil {
		return fmt.Errorf("invalid MAC format: %v", err)
	}
	link, err := netlink.LinkByName(tapName)
	if err != nil {
		return fmt.Errorf("tap %s not found: %v", tapName, err)
	}

	if len(hwAddr) > 0 && (hwAddr[0]&1) == 1 {
		return fmt.Errorf("cannot assign multicast/broadcast MAC address: %s", macStr)
	}

	netlink.LinkSetDown(link) // 拦截修改期间的网络占用
	if err := netlink.LinkSetHardwareAddr(link, hwAddr); err != nil {
		return fmt.Errorf("failed to set MAC address: %v", err)
	}
	log.Infof("Interface %s MAC set to %s", tapName, macStr)
	return nil
}

func setupPolicyRouting(tapName string, mark int, gwV4, gwV6 string) error {
	if mark <= 0 {
		return nil
	}
	link, err := netlink.LinkByName(tapName)
	if err != nil {
		return err
	}
	setup := func(gwStr string, family int) {
		if gwStr == "" {
			return
		}
		gw := net.ParseIP(gwStr)
		rule := netlink.NewRule()
		rule.Mark, rule.Table, rule.Family = uint32(mark), mark, family
		netlink.RuleDel(rule)
		netlink.RuleAdd(rule)
		route := &netlink.Route{LinkIndex: link.Attrs().Index, Gw: gw, Table: mark}
		netlink.RouteReplace(route)
	}
	setup(gwV4, netlink.FAMILY_V4)
	setup(gwV6, netlink.FAMILY_V6)
	log.Infof("🔀 Policy routing configured (fwmark: %d)", mark)
	return nil
}

func cleanPolicyRouting(tapName string, mark int, gwV4, gwV6 string) {
	if mark <= 0 {
		return
	}
	link, err := netlink.LinkByName(tapName)
	if err != nil {
		return
	}
	cleanup := func(gwStr string, family int) {
		if gwStr == "" {
			return
		}
		gw := net.ParseIP(gwStr)
		rule := netlink.NewRule()
		rule.Mark, rule.Table, rule.Family = uint32(mark), mark, family
		netlink.RuleDel(rule)
		route := &netlink.Route{LinkIndex: link.Attrs().Index, Gw: gw, Table: mark}
		netlink.RouteDel(route)
	}
	cleanup(gwV4, netlink.FAMILY_V4)
	cleanup(gwV6, netlink.FAMILY_V6)
}

// ======================= 协议结构 =======================
type HandshakeReq struct {
	ClientID string `json:"client_id"`
	PSK      string `json:"psk"`
	MAC      string `json:"mac,omitempty"`
	IPv4     string `json:"ipv4,omitempty"`
	IPv6     string `json:"ipv6,omitempty"`
	Padding  string `json:"padding,omitempty"`
	BrutalTx uint64 `json:"brutal_tx,omitempty"`
	BrutalRx uint64 `json:"brutal_rx,omitempty"`
	FEC      bool   `json:"fec,omitempty"`
	Encrypt  bool   `json:"encrypt,omitempty"`
}

type MacBinding struct {
	IPv4 string `json:"ipv4"`
	IPv6 string `json:"ipv6"`
}

type HandshakeResp struct {
	Success  bool   `json:"success"`
	Message  string `json:"message"`
	ClientID string `json:"client_id"`
	IPv4     string `json:"ipv4"`
	IPv6     string `json:"ipv6"`
	GwV4     string `json:"gw_v4,omitempty"`
	GwV6     string `json:"gw_v6,omitempty"`
	Padding  string `json:"padding,omitempty"`
	BrutalTx uint64 `json:"brutal_tx,omitempty"`
	BrutalRx uint64 `json:"brutal_rx,omitempty"`
	FEC      bool   `json:"fec,omitempty"`
	Encrypt  bool   `json:"encrypt,omitempty"`
}

// ======================= VSwitch =======================
type Port interface {
	ID() string
	WriteFrame(frame []byte) error
}
type macEntry struct {
	portID    string
	updatedAt time.Time
}

type VSwitch struct {
	mu       sync.RWMutex
	ports    map[string]Port
	macTable map[string]*macEntry
}

func NewVSwitch() *VSwitch {
	vs := &VSwitch{ports: make(map[string]Port), macTable: make(map[string]*macEntry)}
	go vs.purgeExpiredMACs() // 启动清理协程
	return vs
}
func (vs *VSwitch) purgeExpiredMACs() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		vs.mu.Lock()
		for mac, entry := range vs.macTable {
			// 如果一个 MAC 地址超过 30 分钟没有发包，就踢出转发表
			if time.Since(entry.updatedAt) > 30*time.Minute {
				delete(vs.macTable, mac)
			}
		}
		vs.mu.Unlock()
	}
}
func (vs *VSwitch) AddPort(p Port) {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	vs.ports[p.ID()] = p
	log.Debugf("[VSwitch] Port UP: %s", p.ID())
}
func (vs *VSwitch) RemovePort(portID string) {
	vs.mu.Lock()
	defer vs.mu.Unlock()
	delete(vs.ports, portID)
	for mac, entry := range vs.macTable {
		if entry.portID == portID {
			delete(vs.macTable, mac)
		}
	}
	log.Debugf("[VSwitch] Port DOWN: %s", portID)
}
func (vs *VSwitch) ProcessFrame(srcPortID string, frame []byte) {
	if len(frame) < 14 {
		return
	}
	dstMAC, srcMAC := frame[0:6], frame[6:12]
	strDstMAC, strSrcMAC := string(dstMAC), string(srcMAC)

	vs.mu.RLock()
	entry, exists := vs.macTable[strSrcMAC]
	needUpdate := !exists || entry.portID != srcPortID || time.Since(entry.updatedAt) > 5*time.Second
	vs.mu.RUnlock()

	if needUpdate {
		vs.mu.Lock()
		if _, checkExists := vs.macTable[strSrcMAC]; !checkExists {
			log.Debugf("[VSwitch] Learned NEW MAC %s on port %s", fmtMAC(srcMAC), srcPortID)
		}
		vs.macTable[strSrcMAC] = &macEntry{portID: srcPortID, updatedAt: time.Now()}
		vs.mu.Unlock()
	}

	var targetPortID string
	if (dstMAC[0] & 1) != 1 {
		vs.mu.RLock()
		if entry, exists := vs.macTable[strDstMAC]; exists {
			targetPortID = entry.portID
		}
		vs.mu.RUnlock()
	}

	if targetPortID != "" && targetPortID != srcPortID {
		vs.sendToPort(targetPortID, frame)
	} else if targetPortID == "" {
		vs.flood(srcPortID, frame)
	}
}
func (vs *VSwitch) sendToPort(targetPortID string, frame []byte) {
	vs.mu.RLock()
	port, exists := vs.ports[targetPortID]
	vs.mu.RUnlock()
	if exists {
		port.WriteFrame(frame)
	}
}
func (vs *VSwitch) flood(excludePortID string, frame []byte) {
	vs.mu.RLock()
	var targets []Port
	for id, port := range vs.ports {
		if id != excludePortID {
			targets = append(targets, port)
		}
	}
	vs.mu.RUnlock()
	for _, port := range targets {
		port.WriteFrame(frame)
	}
}

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

// ======================= 服务端 =======================
type ClientSession struct {
	Port        *AsyncPort
	IPv4        string
	IPv6        string
	MAC         string
	Dedup       *DeDuplicator
	ActiveConns int
	TxBytes     uint64
	RxBytes     uint64
	TxPackets   uint64
	RxPackets   uint64
}

type Server struct {
	psk        string
	v4Net      *net.IPNet
	v6Net      *net.IPNet
	v4Gw       string
	v6Gw       string
	usedV4     map[string]bool
	usedV6     map[string]bool
	mu         sync.Mutex
	tap        *water.Interface
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

	config := water.Config{DeviceType: water.TAP}
	config.Name = tapName
	tap, err := water.New(config)
	if err != nil {
		log.Fatalf("Server TAP error: %v", err)
	}
	srv.tap = tap

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
	} else {
		v4ip, v6ip := s.assignIPsLocked(req.IPv4, req.IPv6)
		port := NewAsyncPort(parentCtx, clientID, req.FEC)
		session = &ClientSession{Port: port, IPv4: v4ip, IPv6: v6ip, MAC: req.MAC, Dedup: NewDeDuplicator(), ActiveConns: 0}
		s.activeClients[clientID] = session
		if mac != "" {
			s.macToIP[mac] = MacBinding{IPv4: v4ip, IPv6: v6ip}
		}
		s.vswitch.AddPort(port)
		log.Infof("[%s] 新逻辑 Client 上线 (FEC=%v), Assigned IPs: %s, %s", clientID, req.FEC, v4ip, v6ip)
	}

	session.ActiveConns++
	v4ip, v6ip, port, dedup := session.IPv4, session.IPv6, session.Port, session.Dedup
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
	s.sendResp(conn, true, "OK", clientID, v4cidr, v6cidr, serverTxRate, clientTxRate, req.FEC, req.Encrypt)

	rttCache := new(uint32)
	atomic.StoreUint32(rttCache, 50000)
	go startRTTPoller(connCtx, tcpConn, rttCache)

	connTxChan := make(chan []VPNFrame, 32)
	port.RegisterBackend(connTxChan, rttCache)

	defer func() {
		port.UnregisterBackend(connTxChan)
		s.mu.Lock()
		session.ActiveConns--
		if session.ActiveConns <= 0 {
			delete(s.usedV4, session.IPv4)
			delete(s.usedV6, session.IPv6)
			delete(s.activeClients, clientID)
			s.vswitch.RemovePort(clientID)
			port.Close()
			log.Infof("[%s] 逻辑 Client 下线，所有连接均已断开，释放 IP", clientID)
		}
		s.mu.Unlock()
	}()

	go func() {
		sendBuffer := make([]byte, 0, 64*1024+4096)
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
				conn.Write(sendBuffer)
				atomic.AddUint64(&session.TxBytes, uint64(len(sendBuffer)))
				atomic.AddUint64(&session.TxPackets, uint64(len(frames)))
			case <-time.After(time.Duration(mathrand.IntN(3000)+4000) * time.Millisecond):
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

		// 使用 DeDuplicator 拦截网络放大报文
		if dedup.IsDuplicate(seq) {
			//log.Debugf("[%s] 拦截 FEC 冗余包 Seq: %d", clientID, seq)
			if frame != nil {
				putFrame(frame)
			}
			continue
		}

		if err == nil && frame != nil {
			atomic.AddUint64(&session.RxBytes, uint64(len(frame)))
			atomic.AddUint64(&session.RxPackets, 1)
			if seq != 0 && s.cipherBlock != nil {
				xorCryptInPlace(frame, seq, s.cipherBlock, s.baseIV)
			}
		}

		s.vswitch.ProcessFrame(clientID, frame)
		putFrame(frame)
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

func (s *Server) sendResp(w io.Writer, ok bool, msg, clientID, v4cidr, v6cidr string, srvTx, srvRx uint64, fec bool, encrypt bool) {
	resp := HandshakeResp{
		Success: ok, Message: msg, ClientID: clientID, IPv4: v4cidr, IPv6: v6cidr,
		GwV4: s.v4Gw, GwV6: s.v6Gw, Padding: generatePadding(100, 500), BrutalTx: srvTx, BrutalRx: srvRx, FEC: fec, Encrypt: encrypt,
	}
	log.Debugf("[%s] => 发送握手响应 (HandshakeResp): %+v", clientID, resp)
	d, _ := json.Marshal(resp)
	writeStreamFrame(w, d)
}

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
		return []string{addrStr}
	}

	return addrs
}

type Client struct {
	clientID    string
	psk         string
	targetAddrs []string
	tapName     string
	reqV4       string
	reqV6       string
	sni         string
	insecure    bool
	certHash    string
	fwmark      int
	brutal      bool
	brutalUp    uint64
	brutalDown  uint64
	tap         *water.Interface
	macAddr     string
	connsCount  int
	fecMode     bool
	txPort      *AsyncPort
	dedup       *DeDuplicator
	TxBytes     uint64
	RxBytes     uint64
	TxPackets   uint64
	RxPackets   uint64
	encrypt     bool
	cipherBlock cipher.Block
	baseIV      []byte
}

func startClient(ctx context.Context, psk, tapName, macAddr, addr, reqV4, reqV6, sni string, insecure bool, certHash string, fwmark int, brutal bool, brutalUp, brutalDown uint64, connsCount int, fec, encrypt bool) {
	log.Infof("Starting TCP TLS client process...")
	config := water.Config{DeviceType: water.TAP}
	config.Name = tapName
	iface, err := water.New(config)
	if err != nil {
		log.Fatalf("Client TAP creation error: %v", err)
	}
	go func() { <-ctx.Done(); iface.Close() }()

	if err := setTapMac(tapName, macAddr); err != nil {
		log.Warnf("Client failed to set tap MAC: %v", err)
	}

	actualMac := macAddr
	if actualMac == "" {
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
func (c *Client) negotiateUTLS(ctx context.Context, tcpConn *net.TCPConn) (*utls.UConn, error) {
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
	utlsConn := utls.UClient(tcpConn, utlsConf, clientHelloID)
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

	log.Infof("[Conn %d] Initiating connection...", connIndex)
	dialer := net.Dialer{Timeout: 5 * time.Second}
	rawConn, err := dialer.DialContext(runCtx, "tcp", c.targetAddrs[connIndex%len(c.targetAddrs)])
	if err != nil {
		return err
	}

	tcpConn := rawConn.(*net.TCPConn)
	tcpConn.SetKeepAlive(true)
	tcpConn.SetKeepAlivePeriod(15 * time.Second)
	tcpConn.SetNoDelay(true)
	tcpConn.SetReadBuffer(4 * 1024 * 1024)
	tcpConn.SetWriteBuffer(4 * 1024 * 1024)

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

	tlsConn, err := c.negotiateUTLS(runCtx, tcpConn)
	if err != nil {
		tcpConn.Close()
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

	if connIndex == 0 {
		c.setupInterface(resp.IPv4, resp.IPv6)
		setupPolicyRouting(c.tapName, c.fwmark, resp.GwV4, resp.GwV6)
		defer cleanPolicyRouting(c.tapName, c.fwmark, resp.GwV4, resp.GwV6)
	}

	rttCache := new(uint32)
	atomic.StoreUint32(rttCache, 50000)
	go startRTTPoller(runCtx, tcpConn, rttCache)

	errChan := make(chan error, 2)
	connTxChan := make(chan []VPNFrame, 32)
	c.txPort.RegisterBackend(connTxChan, rttCache)
	defer c.txPort.UnregisterBackend(connTxChan)

	go func() {
		sendBuffer := make([]byte, 0, 64*1024+4096)
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
				if _, err := tlsConn.Write(sendBuffer); err != nil {
					errChan <- err
					return
				}
				atomic.AddUint64(&c.TxBytes, uint64(len(sendBuffer)))
				atomic.AddUint64(&c.TxPackets, uint64(len(frames)))
			case <-time.After(time.Duration(mathrand.IntN(3000)+4000) * time.Millisecond):
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

			// 客户端去重器
			if c.dedup.IsDuplicate(seq) {
				//log.Debugf("[Conn %d] 拦截 FEC 冗余包 Seq: %d", connIndex, seq)
				if frame != nil {
					putFrame(frame)
				}
				continue
			}

			if err == nil && frame != nil {
				atomic.AddUint64(&c.RxBytes, uint64(len(frame)))
				atomic.AddUint64(&c.RxPackets, 1)
				if seq != 0 && c.cipherBlock != nil {
					xorCryptInPlace(frame, seq, c.cipherBlock, c.baseIV)
				}
			}

			c.tap.Write(frame)
			putFrame(frame)
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

func main() {
	mode := flag.String("mode", "", "server or client")
	psk := flag.String("psk", "quic_secret", "Pre-shared key")
	tapName := flag.String("tap", "tap0", "Name of the TAP device")
	macAddr := flag.String("mac", "", "Specify MAC address for TAP device (Client/Server)")
	addr := flag.String("addr", "0.0.0.0:4000", "Server: listen address (e.g., :4000) | Client: target addresses (comma-separated, e.g., 1.1.1.1:4000,[::1]:4000)")
	logLevel := flag.String("loglevel", "info", "Log level (e.g. info, debug)")

	v4cidr := flag.String("v4cidr", "10.0.0.0/24", "IPv4 CIDR block (Server only)")
	v6cidr := flag.String("v6cidr", "fd00::/64", "IPv6 CIDR block (Server only)")
	certFile := flag.String("cert", "", "TLS Certificate file (Server only)")
	keyFile := flag.String("key", "", "TLS Key file (Server only)")

	reqV4 := flag.String("req-v4", "", "Requested IPv4 (Client only)")
	reqV6 := flag.String("req-v6", "", "Requested IPv6 (Client only)")
	sni := flag.String("sni", "www.cloudflare.com", "SNI for TLS (Client only)")
	insecure := flag.Bool("insecure", false, "Skip TLS verify (Client only)")
	certHash := flag.String("cert-sha256", "", "Verify server cert SHA256 (hex encoded) (Client only)")
	fwmark := flag.Int("fwmark", 0, "Enable policy routing with specified fwmark (Client only)")

	brutal := flag.Bool("brutal", false, "Enable TCP Brutal congestion control")
	brutalUp := flag.Uint64("brutal-up", 100, "Brutal upload rate limit in Mbps")
	brutalDown := flag.Uint64("brutal-down", 500, "Brutal download rate limit in Mbps")

	conns := flag.Int("conns", 1, "Number of concurrent TCP connections for Load Balancing")
	fec := flag.Bool("fec", false, "Enable Packet Duplication FEC over Multipath")
	webAddr := flag.String("web", "", "Start Web Dashboard on specified address (e.g. :8080)")
	encrypt := flag.Bool("encrypt", false, "Enable inner payload AES-CTR XOR encryption")

	flag.Parse()
	initLogger(*logLevel)
	defer log.Sync()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *mode == "server" {
		startServer(ctx, *psk, *tapName, *macAddr, *addr, *v4cidr, *v6cidr, *certFile, *keyFile, *brutal, *brutalUp, *brutalDown, *webAddr, *encrypt)
	} else if *mode == "client" {
		if *fec && *conns < 2 {
			log.Warnf("FEC (Packet Duplication) is enabled but conns < 2. Falling back to single connection.")
		}
		startClient(ctx, *psk, *tapName, *macAddr, *addr, *reqV4, *reqV6, *sni, *insecure, *certHash, *fwmark, *brutal, *brutalUp, *brutalDown, *conns, *fec, *encrypt)
	} else {
		fmt.Println("Usage: go run main.go -mode server|client [flags...]")
		os.Exit(1)
	}

	log.Info("Program exited gracefully.")
}

// ======================= Web UI 与 监控 API =======================

type WebStats struct {
	Mode          string                 `json:"mode"`
	ActiveClients int                    `json:"active_clients"`
	Clients       map[string]interface{} `json:"clients,omitempty"`
	GlobalTxBytes uint64                 `json:"global_tx_bytes"`
	GlobalRxBytes uint64                 `json:"global_rx_bytes"`
}

var dashboardHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>VPN Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #121212; color: #e0e0e0; margin: 0; padding: 20px; }
        .card { background: #1e1e1e; border-radius: 8px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); margin-bottom: 20px; }
        h1, h2 { margin-top: 0; color: #bb86fc; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        th { background-color: #2c2c2c; }
        .btn { padding: 6px 12px; background-color: #cf6679; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .btn:hover { background-color: #ff7597; }
        /* 新增：高亮速率显示的颜色 */
        .speed { color: #03dac6; font-weight: bold; } 
    </style>
</head>
<body>
    <h1>🚀 VPN Dashboard (<span id="mode">加载中...</span>)</h1>
    <div class="card">
        <h2>系统状态</h2>
        <p>活跃连接数/设备: <strong id="active-clients">0</strong></p>
        <p>总发送: <strong id="total-tx">0 B</strong> | 总接收: <strong id="total-rx">0 B</strong></p>
        <p>总上传速率: <strong id="total-tx-speed" class="speed">0 B/s</strong> | 总下载速率: <strong id="total-rx-speed" class="speed">0 B/s</strong></p>
    </div>
    <div class="card" id="clients-container">
        <h2>客户端列表 / 本机详情</h2>
        <table>
            <thead>
                <tr>
                    <th>ID / Name</th>
                    <th>IPv4</th>
                    <th>MAC</th>
                    <th>TCP连接数</th>
                    <th>TX (发)</th>
                    <th>RX (收)</th>
                    <th>↑ 上传速率</th>
                    <th>↓ 下载速率</th>
                    <th>操作</th>
                </tr>
            </thead>
            <tbody id="clients-body">
            </tbody>
        </table>
    </div>

    <script>
        // 格式化字节或速率
        function formatBytes(bytes, isSpeed = false) {
            if (bytes === 0 || isNaN(bytes)) return '0 ' + (isSpeed ? 'B/s' : 'B');
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            const unit = sizes[i] + (isSpeed ? '/s' : '');
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + unit;
        }

        // 用于缓存上一次请求的数据和时间
        let previousClients = {};
        let lastFetchTime = 0;

        async function fetchStats() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                
                // 计算两次请求精确的时间差（秒）
                const now = performance.now();
                let timeDelta = lastFetchTime ? (now - lastFetchTime) / 1000 : 2; 
                lastFetchTime = now;

                document.getElementById('mode').innerText = data.mode.toUpperCase();
                document.getElementById('active-clients').innerText = data.active_clients;
                
                let tbody = '';
                let totalTx = 0, totalRx = 0;
                let totalTxSpeed = 0, totalRxSpeed = 0;
                
                const currentClientsState = {};

                const processClient = (id, c) => {
                    totalTx += c.tx_bytes;
                    totalRx += c.rx_bytes;
                    
                    let txSpeed = 0;
                    let rxSpeed = 0;
                    
                    // 如果存在上一次的数据，计算速率： (当前字节 - 上次字节) / 时间差
                    if (previousClients[id]) {
                        txSpeed = Math.max(0, (c.tx_bytes - previousClients[id].tx_bytes) / timeDelta);
                        rxSpeed = Math.max(0, (c.rx_bytes - previousClients[id].rx_bytes) / timeDelta);
                    }
                    
                    // 保存当前状态供下一次计算使用
                    currentClientsState[id] = { tx_bytes: c.tx_bytes, rx_bytes: c.rx_bytes };
                    
                    totalTxSpeed += txSpeed;
                    totalRxSpeed += rxSpeed;

                    return '<tr>' +
                        '<td>' + (id.length > 8 ? id.substring(0,8) + '...' : id) + '</td>' +
                        '<td>' + c.ipv4 + '</td>' +
                        '<td>' + c.mac + '</td>' +
                        '<td>' + c.active_conns + '</td>' +
                        '<td>' + formatBytes(c.tx_bytes) + '</td>' +
                        '<td>' + formatBytes(c.rx_bytes) + '</td>' +
                        '<td class="speed">' + formatBytes(txSpeed, true) + '</td>' +
                        '<td class="speed">' + formatBytes(rxSpeed, true) + '</td>' +
                        '<td>' + (data.mode === 'server' ? '<button class="btn" onclick="kickClient(\''+id+'\')">踢出</button>' : '-') + '</td>' +
                    '</tr>';
                };

                if (data.mode === 'server') {
                    for (const [id, c] of Object.entries(data.clients)) {
                        tbody += processClient(id, c);
                    }
                } else if (data.mode === 'client' && data.clients.local) {
                    tbody += processClient('local', data.clients.local);
                }

                // 更新全局缓存
                previousClients = currentClientsState;

                document.getElementById('clients-body').innerHTML = tbody;
                document.getElementById('total-tx').innerText = formatBytes(totalTx);
                document.getElementById('total-rx').innerText = formatBytes(totalRx);
                document.getElementById('total-tx-speed').innerText = formatBytes(totalTxSpeed, true);
                document.getElementById('total-rx-speed').innerText = formatBytes(totalRxSpeed, true);

            } catch (err) {
                console.error("获取统计数据失败", err);
            }
        }

        async function kickClient(id) {
            if(!confirm("确定要强制断开该客户端吗？")) return;
            await fetch('/api/control', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ action: 'kick', client_id: id })
            });
            fetchStats(); // 踢出后立即刷新
        }

        setInterval(fetchStats, 2000); // 每2秒刷新一次
        fetchStats();
    </script>
</body>
</html>`

func startWebServer(addr string, srv *Server, cli *Client) {
	mux := http.NewServeMux()

	// 仪表盘页面
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(dashboardHTML))
	})

	// 状态统计 API
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		stats := WebStats{Clients: make(map[string]interface{})}

		if srv != nil {
			stats.Mode = "server"
			srv.mu.Lock()
			stats.ActiveClients = len(srv.activeClients)
			for id, session := range srv.activeClients {
				stats.Clients[id] = map[string]interface{}{
					"ipv4":         session.IPv4,
					"ipv6":         session.IPv6,
					"mac":          session.MAC,
					"active_conns": session.ActiveConns,
					"tx_bytes":     atomic.LoadUint64(&session.TxBytes),
					"rx_bytes":     atomic.LoadUint64(&session.RxBytes),
					"tx_packets":   atomic.LoadUint64(&session.TxPackets),
					"rx_packets":   atomic.LoadUint64(&session.RxPackets),
				}
			}
			srv.mu.Unlock()
		} else if cli != nil {
			stats.Mode = "client"
			stats.ActiveClients = 1
			stats.Clients["local"] = map[string]interface{}{
				"client_id":    cli.clientID,
				"ipv4":         cli.reqV4,
				"mac":          cli.macAddr,
				"active_conns": cli.connsCount,
				"tx_bytes":     atomic.LoadUint64(&cli.TxBytes),
				"rx_bytes":     atomic.LoadUint64(&cli.RxBytes),
				"tx_packets":   atomic.LoadUint64(&cli.TxPackets),
				"rx_packets":   atomic.LoadUint64(&cli.RxPackets),
			}
		}

		json.NewEncoder(w).Encode(stats)
	})

	// 控制 API
	mux.HandleFunc("/api/control", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", 405)
			return
		}
		var req struct {
			Action   string `json:"action"`
			ClientID string `json:"client_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		if srv != nil && req.Action == "kick" {
			srv.mu.Lock()
			if session, exists := srv.activeClients[req.ClientID]; exists {
				// 强制关闭客户端所有底层的绑定 (这里直接调用 Port 关闭来触发断线)
				session.Port.Close()
				log.Infof("[WebUI] Force kicked client: %s", req.ClientID)
			}
			srv.mu.Unlock()
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "ok"}`))
	})

	log.Infof("🚀 Web Dashboard started at http://%s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Web Server failed: %v", err)
	}
}
