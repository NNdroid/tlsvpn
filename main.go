package main

import (
	"context"
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
	"math/big"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/http2"
	"golang.org/x/sys/unix"
)

// ======================= 全局随机数池 =======================
// 提前生成一个 1MB 的随机数组，用于极速填充
const RandomPoolSize = 1024 * 1024

var (
	randomPool []byte
	log        *zap.SugaredLogger
)

func init() {
	mathrand.Seed(time.Now().UnixNano())
	randomPool = make([]byte, RandomPoolSize)
	// 初始化填满真实随机数
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

// ======================= 内存池优化 (sync.Pool) =======================
var framePool = sync.Pool{
	New: func() any {
		return make([]byte, 2048)
	},
}

func getFrame() []byte {
	return framePool.Get().([]byte)
}

func putFrame(b []byte) {
	if cap(b) >= 1500 && cap(b) <= 65536 {
		framePool.Put(b[:cap(b)])
	}
}

// ======================= 分散填充与成帧逻辑 =======================

// getPaddingLength 计算需要填充的长度，以混淆真实包长
func getPaddingLength(dataLen int) int {
	// 如果是空包（如 KeepAlive），随机填充 100~300 字节
	if dataLen == 0 {
		return 100 + mathrand.Intn(201)
	}
	
	// 根据真实包长决定填充策略
	if dataLen < 200 {
		return 300 + mathrand.Intn(200) // 小包垫大
	} else if dataLen < 800 {
		return 100 + mathrand.Intn(200) // 中包垫一点
	} else {
		return mathrand.Intn(100)       // 大包稍微垫一点
	}
}

// appendPaddedFrame 将单个数据帧按照 [4B 数据长][2B 填充长][数据][填充] 的格式追加到 buffer 中
func appendPaddedFrame(buf []byte, frame []byte) []byte {
	dataLen := len(frame)
	padLen := getPaddingLength(dataLen)
	
	// 扩展 6 字节的头部
	buf = append(buf, 0, 0, 0, 0, 0, 0)
	headerStart := len(buf) - 6
	
	binary.BigEndian.PutUint32(buf[headerStart:headerStart+4], uint32(dataLen))
	binary.BigEndian.PutUint16(buf[headerStart+4:headerStart+6], uint16(padLen))
	
	if dataLen > 0 {
		buf = append(buf, frame...)
	}
	
	if padLen > 0 {
		// 从预生成的随机池中极速切取 Padding 数据
		offset := mathrand.Intn(RandomPoolSize - padLen)
		buf = append(buf, randomPool[offset:offset+padLen]...)
	}
	
	return buf
}

// writeStreamFrame 用于发送单个控制帧（例如握手响应），自带填充混淆
func writeStreamFrame(w io.Writer, frame []byte) error {
	// 预估大小：6字节头 + 数据长 + 最大可能填充(500)
	streamBuf := getFrame()[:0] 
	streamBuf = appendPaddedFrame(streamBuf, frame)
	
	_, err := w.Write(streamBuf)
	putFrame(streamBuf[:cap(streamBuf)]) // 恢复 cap 用于回收
	return err
}

func generatePadding(min, max int) string {
	length := mathrand.Intn(max-min+1) + min
	offset := mathrand.Intn(RandomPoolSize - length)
	return hex.EncodeToString(randomPool[offset : offset+length])
}

// ======================= 流式帧扫描器 (解包逻辑) =======================
type FrameScanner struct {
	r      io.Reader
	buf    []byte
	offset int
}

func NewFrameScanner(r io.Reader) *FrameScanner {
	return &FrameScanner{
		r:   r,
		buf: make([]byte, 0, 70*1024), 
	}
}

func (fs *FrameScanner) ReadFrame() ([]byte, error) {
	const HeaderSize = 6
	const MaxDataLength = 65535 * 2 // 容忍极限 GRO 大包

	for {
		available := len(fs.buf) - fs.offset
		
		// 1. 尝试快速剥离完整帧
		if available >= HeaderSize {
			dataLen := int(binary.BigEndian.Uint32(fs.buf[fs.offset : fs.offset+4]))
			padLen := int(binary.BigEndian.Uint16(fs.buf[fs.offset+4 : fs.offset+6]))
			totalLen := dataLen + padLen
			
			// 严格防越界校验
			if dataLen > MaxDataLength {
				log.Warnf("[FrameScanner] CORRUPTION DETECTED: Invalid data length %d.", dataLen)
				fs.buf = fs.buf[:0]
				fs.offset = 0
				return nil, fmt.Errorf("invalid frame data length: %d", dataLen)
			}
			
			// 如果当前 buffer 包含完整的帧（头+数据+填充）
			if available >= HeaderSize+totalLen {
				// 如果是空包（仅探测保活），跳过它，继续读取下一个
				if dataLen == 0 {
					fs.offset += HeaderSize + totalLen
					continue
				}
				
				var frame []byte
				temp := getFrame()
				
				if dataLen > cap(temp) {
					putFrame(temp)
					frame = make([]byte, dataLen) 
				} else {
					frame = temp[:dataLen]
				}
				
				// 只提取真实数据，自动丢弃尾部的 padLen
				copy(frame, fs.buf[fs.offset+HeaderSize : fs.offset+HeaderSize+dataLen])
				fs.offset += HeaderSize + totalLen
				return frame, nil
			}
		}

		// 2. 内存整理 (游标推进超过 16KB 时执行数据左移)
		if fs.offset > 0 && (fs.offset == len(fs.buf) || fs.offset > 16384) {
			remaining := len(fs.buf) - fs.offset
			if remaining > 0 {
				copy(fs.buf, fs.buf[fs.offset:])
			}
			fs.buf = fs.buf[:remaining]
			fs.offset = 0
		}

		// 3. 智能扩容 (防御性扩容预测)
		tailStart := len(fs.buf)
		requiredCap := tailStart + 2048 

		available = len(fs.buf) - fs.offset
		if available >= HeaderSize {
			dataLen := int(binary.BigEndian.Uint32(fs.buf[fs.offset : fs.offset+4]))
			padLen := int(binary.BigEndian.Uint16(fs.buf[fs.offset+4 : fs.offset+6]))
			if fs.offset + HeaderSize + dataLen + padLen > requiredCap {
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
				return nil, err
			}
		}
	}
}

// ======================= TCP Brutal 内核级拥塞控制 =======================
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

		_, _, errno := unix.Syscall6(
			unix.SYS_SETSOCKOPT,
			fd,
			unix.IPPROTO_TCP,
			TCP_BRUTAL_PARAMS,
			uintptr(unsafe.Pointer(&b[0])),
			12,
			0,
		)
		if errno != 0 {
			sysErr = fmt.Errorf("设置 TCP_BRUTAL_PARAMS 失败: %v", errno)
		}
	})
	if err != nil {
		return err
	}
	return sysErr
}

// ======================= TLS 证书管理 (伪装 h2) =======================
func getServerTLSConfig(certFile, keyFile string) *tls.Config {
	var cert tls.Certificate
	var err error

	if certFile != "" && keyFile != "" {
		cert, err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			log.Fatalf("Failed to load custom TLS pair: %v", err)
		}
		log.Infof("Loaded custom TLS certificate: %s", certFile)
	} else {
		log.Infof("No cert/key specified. Generating ephemeral memory certificate...")
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

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
}

// ======================= 策略路由 =======================
func setupPolicyRouting(tapName string, mark int, gwV4, gwV6 string) error {
	if mark <= 0 {
		return nil
	}
	link, err := netlink.LinkByName(tapName)
	if err != nil {
		return fmt.Errorf("failed to find tap dev %s: %v", tapName, err)
	}
	setup := func(gwStr string, family int) {
		if gwStr == "" {
			return
		}
		gw := net.ParseIP(gwStr)
		rule := netlink.NewRule()
		rule.Mark = uint32(mark)
		rule.Table = mark
		rule.Family = family
		netlink.RuleDel(rule)
		if err := netlink.RuleAdd(rule); err != nil {
			log.Warnf("Failed to add rule for fwmark %d: %v", mark, err)
		}
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       nil,
			Gw:        gw,
			Table:     mark,
		}
		if err := netlink.RouteReplace(route); err != nil {
			log.Warnf("Failed to replace route in table %d: %v", mark, err)
		}
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
		rule.Mark = uint32(mark)
		rule.Table = mark
		rule.Family = family
		netlink.RuleDel(rule)
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       nil,
			Gw:        gw,
			Table:     mark,
		}
		netlink.RouteDel(route)
	}
	cleanup(gwV4, netlink.FAMILY_V4)
	cleanup(gwV6, netlink.FAMILY_V6)
	log.Infof("🧹 Policy routing cleaned (fwmark: %d)", mark)
}

func camouflageProbe(conn net.Conn) {
	defer conn.Close()
	junkBuf := getFrame()
	defer putFrame(junkBuf)

	deadline := time.Now().Add(10 * time.Second)
	conn.SetReadDeadline(deadline)

	for {
		_, err := conn.Read(junkBuf)
		if err != nil {
			return
		}
		time.Sleep(time.Duration(mathrand.Intn(150)+50) * time.Millisecond)

		fakePayloadLen := mathrand.Intn(300) + 100
		fakeFrame := getFrame()[:fakePayloadLen+2]
		fakeFrame[0] = 0x00
		fakeFrame[1] = byte(fakePayloadLen)
		rand.Read(fakeFrame[2:])

		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, err = conn.Write(fakeFrame)
		putFrame(fakeFrame)
		if err != nil {
			return
		}
	}
}

// ======================= HTTP/1.1 & HTTP/2 长连接原生代理伪装 =======================
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
		w.Write([]byte(`<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx</center>
</body>
</html>
`))
	})

	if alpn == "h2" {
		srv := &http2.Server{
			IdleTimeout: 60 * time.Second,
		}
		srv.ServeConn(conn, &http2.ServeConnOpts{
			Handler: handler,
		})
	} else {
		l := &singleConnListener{conn: conn, done: make(chan struct{})}
		srv := &http.Server{
			Handler:     handler,
			IdleTimeout: 60 * time.Second,
		}
		srv.Serve(l)
	}
}

// ======================= 协议与配置 =======================
type HandshakeReq struct {
	PSK      string `json:"psk"`
	IPv4     string `json:"ipv4,omitempty"`
	IPv6     string `json:"ipv6,omitempty"`
	Padding  string `json:"padding,omitempty"`
	BrutalTx uint64 `json:"brutal_tx,omitempty"` 
	BrutalRx uint64 `json:"brutal_rx,omitempty"` 
}

type HandshakeResp struct {
	Success  bool   `json:"success"`
	Message  string `json:"message"`
	IPv4     string `json:"ipv4"`
	IPv6     string `json:"ipv6"`
	GwV4     string `json:"gw_v4,omitempty"`
	GwV6     string `json:"gw_v6,omitempty"`
	Padding  string `json:"padding,omitempty"`
	BrutalTx uint64 `json:"brutal_tx,omitempty"` 
	BrutalRx uint64 `json:"brutal_rx,omitempty"` 
}

func main() {
	mode := flag.String("mode", "", "server or client")
	psk := flag.String("psk", "quic_secret", "Pre-shared key")
	tapName := flag.String("tap", "tap0", "Name of the TAP device")
	addr := flag.String("addr", "0.0.0.0:4000", "Server address")
	logLevel := flag.String("loglevel", "info", "Log level")

	v4cidr := flag.String("v4cidr", "10.0.0.0/24", "IPv4 CIDR block (Server only)")
	v6cidr := flag.String("v6cidr", "fd00::/64", "IPv6 CIDR block (Server only)")
	certFile := flag.String("cert", "", "TLS Certificate file (Server only)")
	keyFile := flag.String("key", "", "TLS Key file (Server only)")

	reqV4 := flag.String("req-v4", "", "Requested IPv4 (Client only)")
	reqV6 := flag.String("req-v6", "", "Requested IPv6 (Client only)")
	sni := flag.String("sni", "www.cloudflare.com", "SNI for TLS (Client only)")
	insecure := flag.Bool("insecure", false, "Skip TLS verify (Client only)")
	certHash := flag.String("cert-sha256", "", "Verify server cert SHA256 (hex encoded) (Client only)")
	fwmark := flag.Int("fwmark", 0, "Enable policy routing with specified fwmark (e.g. 1911) (Client only)")

	brutal := flag.Bool("brutal", false, "Enable TCP Brutal congestion control")
	brutalUp := flag.Uint64("brutal-up", 100, "Brutal upload rate limit in Mbps")
	brutalDown := flag.Uint64("brutal-down", 500, "Brutal download rate limit in Mbps")

	flag.Parse()
	initLogger(*logLevel)
	defer log.Sync()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if *mode == "server" {
		startServer(ctx, *psk, *tapName, *addr, *v4cidr, *v6cidr, *certFile, *keyFile, *brutal, *brutalUp, *brutalDown)
	} else if *mode == "client" {
		startClient(ctx, *psk, *tapName, *addr, *reqV4, *reqV6, *sni, *insecure, *certHash, *fwmark, *brutal, *brutalUp, *brutalDown)
	} else {
		fmt.Println("Usage: go run main.go -mode server|client [flags...]")
		os.Exit(1)
	}

	log.Info("Program exited gracefully.")
}

// ======================= VSwitch 虚拟交换机 =======================
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
	return &VSwitch{
		ports:    make(map[string]Port),
		macTable: make(map[string]*macEntry),
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
	dstMAC := frame[0:6]
	srcMAC := frame[6:12]
	strDstMAC := string(dstMAC)
	strSrcMAC := string(srcMAC)

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

	isBUM := (dstMAC[0] & 1) == 1
	var targetPortID string
	if !isBUM {
		vs.mu.RLock()
		if entry, exists := vs.macTable[strDstMAC]; exists {
			targetPortID = entry.portID
		}
		vs.mu.RUnlock() 
	}

	if targetPortID != "" {
		if targetPortID != srcPortID {
			vs.sendToPort(targetPortID, frame)
		}
	} else {
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

// ======================= 异步端口 =======================
type AsyncPort struct {
	id     string
	ch     chan []byte
	writer func([][]byte) error
	ctx    context.Context
	cancel context.CancelFunc
}

func NewAsyncPort(ctx context.Context, id string, writer func([][]byte) error) *AsyncPort {
	pCtx, pCancel := context.WithCancel(ctx)
	p := &AsyncPort{
		id:     id,
		ch:     make(chan []byte, 4096),
		writer: writer,
		ctx:    pCtx,
		cancel: pCancel,
	}
	go p.run()
	return p
}

func (p *AsyncPort) ID() string { return p.id }

func (p *AsyncPort) WriteFrame(frame []byte) error {
	select {
	case <-p.ctx.Done():
		return fmt.Errorf("port %s closed", p.id)
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
		log.Warnf("[AsyncPort %s] BACKPRESSURE! Queue full, dropping frame.", p.id)
		if buf != nil {
			putFrame(buf)
		}
	}
	return nil
}

func (p *AsyncPort) run() {
	const MaxBatchBytes = 64 * 1024 
	batch := make([][]byte, 0, 128)
	var batchBytes int

	for {
		select {
		case <-p.ctx.Done():
			return
		case frame := <-p.ch:
			batch = append(batch, frame)
			batchBytes += len(frame)

			queueLen := len(p.ch)
			for i := 0; i < queueLen && batchBytes < MaxBatchBytes; i++ {
				f := <-p.ch
				batch = append(batch, f)
				batchBytes += len(f)
			}

			if err := p.writer(batch); err != nil {
				log.Debugf("[AsyncPort %s] Writer returned error: %v", p.id, err)
			}

			for _, f := range batch {
				if f != nil {
					putFrame(f)
				}
			}
			batch = batch[:0]
			batchBytes = 0
		}
	}
}

func (p *AsyncPort) Close() { p.cancel() }

// ======================= 服务端实现 =======================
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
}

func startServer(ctx context.Context, psk, tapName, addr, v4cidr, v6cidr, certFile, keyFile string, brutal bool, brutalUp, brutalDown uint64) {
	log.Infof("Starting TCP TLS server process...")
	_, v4net, _ := net.ParseCIDR(v4cidr)
	_, v6net, _ := net.ParseCIDR(v6cidr)

	srv := &Server{
		psk:        psk,
		v4Net:      v4net,
		v6Net:      v6net,
		usedV4:     make(map[string]bool),
		usedV6:     make(map[string]bool),
		vswitch:    NewVSwitch(),
		brutal:     brutal,
		brutalUp:   brutalUp,   
		brutalDown: brutalDown, 
	}

	srvV4IP := getFirstIP(v4net)
	srvV6IP := getFirstIP(v6net)
	srv.v4Gw = srvV4IP.String()
	srv.v6Gw = srvV6IP.String()

	srv.usedV4[srv.v4Gw] = true
	srv.usedV6[srv.v6Gw] = true

	config := water.Config{DeviceType: water.TAP}
	config.Name = tapName
	tap, err := water.New(config)
	if err != nil {
		log.Fatalf("Server TAP error: %v", err)
	}
	srv.tap = tap

	if link, err := netlink.LinkByName(tapName); err == nil {
		v4Addr, _ := netlink.ParseAddr(fmt.Sprintf("%s/%d", srv.v4Gw, maskSize(v4net.Mask)))
		netlink.AddrReplace(link, v4Addr)
		v6Addr, _ := netlink.ParseAddr(fmt.Sprintf("%s/%d", srv.v6Gw, maskSize(v6net.Mask)))
		netlink.AddrReplace(link, v6Addr)
		netlink.LinkSetUp(link)
		log.Infof("Server TAP configured: IPv4=%s, IPv6=%s", v4Addr.String(), v6Addr.String())
	}

	go func() {
		<-ctx.Done()
		srv.tap.Close()
	}()

	tapPortID := "TAP_LOCAL"
	tapPort := NewAsyncPort(ctx, tapPortID, func(frames [][]byte) error {
		for _, b := range frames {
			if len(b) > 0 {
				if _, err := srv.tap.Write(b); err != nil {
					return err
				}
			}
		}
		return nil
	})
	srv.vswitch.AddPort(tapPort)

	go func() {
		buf := make([]byte, 65536)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				rn, err := srv.tap.Read(buf)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					return
				}
				// 从 TAP 读取的真实数据不加 Padding，原样进入 VSwitch
				frame := getFrame()[:rn]
				copy(frame, buf[:rn])
				srv.vswitch.ProcessFrame(tapPortID, frame)
				putFrame(frame)
			}
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

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

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

			prefixConn := &PrefixConn{
				Conn:   c,
				prefix: peekBuf[:n],
			}

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

			prefixConn2 := &PrefixConn{
				Conn:   tlsConn,
				prefix: peekBuf2[:n2],
			}

			if peekBuf2[0] >= 0x20 {
				serveFallbackHTTP(prefixConn2, alpn) 
				return
			}

			srv.handleClient(ctx, prefixConn2, c, c.RemoteAddr().String())
		}(conn)
	}
}

func (s *Server) handleClient(parentCtx context.Context, conn net.Conn, tcpConn *net.TCPConn, clientID string) {
	connCtx, cancel := context.WithCancel(parentCtx)
	defer cancel()
	defer conn.Close()

	scanner := NewFrameScanner(conn)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reqData, err := scanner.ReadFrame()
	conn.SetReadDeadline(time.Time{})

	var req HandshakeReq

	if err != nil {
		log.Debugf("[%s] 隧道内帧读取异常: %v", clientID, err)
		camouflageProbe(conn)
		return
	}

	if err := json.Unmarshal(reqData, &req); err != nil || req.PSK != s.psk {
		log.Warnf("[%s] PSK 验证失败. 开启伪装焦油坑.", clientID)
		putFrame(reqData)
		camouflageProbe(conn)
		return
	}
	putFrame(reqData)

	serverTxRate := s.brutalUp 
	if req.BrutalRx > 0 && (s.brutalUp == 0 || req.BrutalRx < s.brutalUp) {
		serverTxRate = req.BrutalRx 
	}

	clientTxRate := s.brutalDown 
	if req.BrutalTx > 0 && (s.brutalDown == 0 || req.BrutalTx < s.brutalDown) {
		clientTxRate = req.BrutalTx 
	}

	if s.brutal && serverTxRate > 0 {
		if err := applyTCPBrutal(tcpConn, serverTxRate); err != nil {
			log.Warnf("[%s] TCP Brutal 下行限速应用失败: %v", clientID, err)
		} else {
			log.Infof("[%s] TCP Brutal 协商完成: 允许客户端发送 %d Mbps, 服务端发送 %d Mbps", clientID, clientTxRate, serverTxRate)
		}
	}

	v4ip, v6ip := s.assignIPs(req.IPv4, req.IPv6)
	defer func() {
		s.mu.Lock()
		delete(s.usedV4, v4ip)
		delete(s.usedV6, v6ip)
		s.mu.Unlock()
		s.vswitch.RemovePort(clientID)
	}()

	v4cidr := fmt.Sprintf("%s/%d", v4ip, maskSize(s.v4Net.Mask))
	v6cidr := fmt.Sprintf("%s/%d", v6ip, maskSize(s.v6Net.Mask))

	s.sendResp(conn, true, "OK", v4cidr, v6cidr, serverTxRate, clientTxRate)
	log.Infof("[%s] Tunnel established. Assigned V4: %s | V6: %s", clientID, v4cidr, v6cidr)

	clientPort := NewAsyncPort(connCtx, clientID, func() func(frames [][]byte) error {
		sendBuffer := make([]byte, 0, 64*1024+4096) 
		return func(frames [][]byte) error {
			sendBuffer = sendBuffer[:0] 
			// 每帧独立 Padding 混淆并合并
			for _, f := range frames {
				if f == nil {
					// 写入一个代表 KeepAlive 的空包，并加上随机填充
					sendBuffer = appendPaddedFrame(sendBuffer, nil)
				} else {
					sendBuffer = appendPaddedFrame(sendBuffer, f)
				}
			}

			_, err := conn.Write(sendBuffer)
			return err
		}
	}())
	s.vswitch.AddPort(clientPort)
	defer clientPort.Close()

	go func() {
		for {
			jitterDelay := time.Duration(mathrand.Intn(3000)+4000) * time.Millisecond
			select {
			case <-connCtx.Done():
				return
			case <-time.After(jitterDelay):
				clientPort.WriteFrame(nil) 
			}
		}
	}()

	for {
		select {
		case <-connCtx.Done():
			return
		default:
			frame, err := scanner.ReadFrame()
			if err != nil {
				log.Debugf("[%s] Tunnel TCP connection closed: %v", clientID, err)
				return
			}
			s.vswitch.ProcessFrame(clientID, frame)
			putFrame(frame)
		}
	}
}

func (s *Server) assignIPs(reqV4, reqV6 string) (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
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

func (s *Server) sendResp(w io.Writer, ok bool, msg, v4cidr, v6cidr string, srvTx, srvRx uint64) {
	d, _ := json.Marshal(HandshakeResp{
		Success: ok, Message: msg, IPv4: v4cidr, IPv6: v6cidr,
		GwV4: s.v4Gw, GwV6: s.v6Gw, Padding: generatePadding(100, 500),
		BrutalTx: srvTx, 
		BrutalRx: srvRx, 
	})
	writeStreamFrame(w, d)
}

// ======================= 客户端实现 =======================
type Client struct {
	psk        string
	serverAddr string
	tapName    string
	reqV4      string
	reqV6      string
	sni        string
	insecure   bool
	certHash   string
	fwmark     int
	brutal     bool
	brutalUp   uint64
	brutalDown uint64
	tap        *water.Interface
	tapTxChan  chan []byte
}

func startClient(ctx context.Context, psk, tapName, addr, reqV4, reqV6, sni string, insecure bool, certHash string, fwmark int, brutal bool, brutalUp, brutalDown uint64) {
	log.Infof("Starting TCP TLS client process...")
	config := water.Config{DeviceType: water.TAP}
	config.Name = tapName
	iface, err := water.New(config)
	if err != nil {
		log.Fatalf("Client TAP creation error: %v", err)
	}

	go func() {
		<-ctx.Done()
		iface.Close()
	}()

	c := &Client{
		psk: psk, serverAddr: addr, tapName: tapName, reqV4: reqV4, reqV6: reqV6,
		sni: sni, insecure: insecure, certHash: certHash, fwmark: fwmark,
		brutal: brutal, brutalUp: brutalUp, brutalDown: brutalDown, 
		tap: iface, tapTxChan: make(chan []byte, 4096),
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
			
			// 直接将提取的原始包塞入发送管道
			frame := getFrame()[:rn]
			copy(frame, buf[:rn])

			select {
			case <-ctx.Done():
				putFrame(frame)
				return
			case c.tapTxChan <- frame:
			default:
				putFrame(frame)
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			err := c.dialAndServe(ctx)
			log.Warnf("Tunnel down: %v. Reconnecting in 3s...", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
		}
	}
}

func (c *Client) dialAndServe(parentCtx context.Context) error {
	runCtx, runCancel := context.WithCancel(parentCtx)
	defer runCancel()

	tlsConf := &tls.Config{
		ServerName:         c.sni,
		InsecureSkipVerify: c.insecure,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	if c.certHash != "" {
		tlsConf.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificates provided by server")
			}
			hash := sha256.Sum256(rawCerts[0])
			hashStr := hex.EncodeToString(hash[:])
			if hashStr != c.certHash {
				return fmt.Errorf("cert SHA-256 mismatch. Expected %s, got %s", c.certHash, hashStr)
			}
			return nil
		}
	}

	log.Infof("Initiating TCP connection to Server: %s", c.serverAddr)
	tcpAddr, err := net.ResolveTCPAddr("tcp", c.serverAddr)
	if err != nil {
		return err
	}

	dialer := net.Dialer{Timeout: 5 * time.Second}
	rawConn, err := dialer.DialContext(runCtx, "tcp", tcpAddr.String())
	if err != nil {
		return fmt.Errorf("TCP dial failed: %v", err)
	}

	tcpConn := rawConn.(*net.TCPConn)
	tcpConn.SetKeepAlive(true)
	tcpConn.SetKeepAlivePeriod(15 * time.Second)
	tcpConn.SetNoDelay(true)
	tcpConn.SetReadBuffer(4 * 1024 * 1024) 
	tcpConn.SetWriteBuffer(4 * 1024 * 1024)

	if c.brutal {
		if err := applyTCPBrutal(tcpConn, c.brutalUp); err != nil {
			log.Warnf("TCP Brutal 启用失败: %v", err)
		} else {
			log.Infof("TCP Brutal 上行发送端已接管，硬限速: %d Mbps", c.brutalUp)
		}
	}

	tlsConn := tls.Client(tcpConn, tlsConf)
	if err := tlsConn.HandshakeContext(runCtx); err != nil {
		tcpConn.Close()
		return fmt.Errorf("TLS handshake failed: %v", err)
	}
	defer tlsConn.Close()

	log.Infof("Encrypted TLS transport established.")

	scanner := NewFrameScanner(tlsConn)
	req := HandshakeReq{
		PSK:        c.psk, 
		IPv4:       c.reqV4, 
		IPv6:       c.reqV6, 
		Padding:    generatePadding(100, 500),
		BrutalTx:   c.brutalUp,   
		BrutalRx:   c.brutalDown, 
	}
	reqData, _ := json.Marshal(req)
	if err := writeStreamFrame(tlsConn, reqData); err != nil {
		return fmt.Errorf("failed to send handshake: %v", err)
	}

	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respData, err := scanner.ReadFrame()
	if err != nil {
		return fmt.Errorf("handshake read error: %v", err)
	}
	tlsConn.SetReadDeadline(time.Time{})

	var resp HandshakeResp
	if err := json.Unmarshal(respData, &resp); err != nil || !resp.Success {
		putFrame(respData)
		return fmt.Errorf("handshake failed/rejected: %v", err)
	}
	putFrame(respData)

	log.Infof("Tunnel negotiated! IPv4: %s | IPv6: %s", resp.IPv4, resp.IPv6)

	if c.brutal && resp.BrutalRx > 0 && resp.BrutalRx != c.brutalUp {
		log.Infof("服务端强制调整客户端上行速率至: %d Mbps", resp.BrutalRx)
		applyTCPBrutal(tcpConn, resp.BrutalRx)
	}

	if err := c.setupInterface(resp.IPv4, resp.IPv6); err != nil {
		return fmt.Errorf("TAP interface setup failed: %v", err)
	}
	if err := setupPolicyRouting(c.tapName, c.fwmark, resp.GwV4, resp.GwV6); err != nil {
		log.Warnf("Policy routing setup failed: %v", err)
	}
	defer cleanPolicyRouting(c.tapName, c.fwmark, resp.GwV4, resp.GwV6)

	errChan := make(chan error, 2)

	go func() {
		const MaxBatchBytes = 64 * 1024
		batch := make([][]byte, 0, 128)
		sendBuffer := make([]byte, 0, MaxBatchBytes+4096)

		for {
			jitterDelay := time.Duration(mathrand.Intn(3000)+4000) * time.Millisecond
			select {
			case <-runCtx.Done():
				return
			case frame := <-c.tapTxChan:
				batch = append(batch, frame)
				batchBytes := len(frame)

			drainLoop:
				for batchBytes < MaxBatchBytes {
					select {
					case f := <-c.tapTxChan:
						batch = append(batch, f)
						batchBytes += len(f)
					default:
						break drainLoop
					}
				}

				sendBuffer = sendBuffer[:0]
				for _, f := range batch {
					// 每个包独立填充并合并
					if f != nil {
						sendBuffer = appendPaddedFrame(sendBuffer, f)
						putFrame(f)
					} else {
						sendBuffer = appendPaddedFrame(sendBuffer, nil)
					}
				}
				batch = batch[:0]

				if _, err := tlsConn.Write(sendBuffer); err != nil {
					errChan <- err
					return
				}

			case <-time.After(jitterDelay):
				sendBuffer = sendBuffer[:0]
				sendBuffer = appendPaddedFrame(sendBuffer, nil)
				if _, err := tlsConn.Write(sendBuffer); err != nil {
					errChan <- err
					return
				}
			}
		}
	}()

	go func() {
		for {
			select {
			case <-runCtx.Done():
				return
			default:
				frame, err := scanner.ReadFrame()
				if err != nil {
					errChan <- err
					return
				}
				if _, err := c.tap.Write(frame); err != nil {
					putFrame(frame)
					errChan <- err
					return
				}
				putFrame(frame)
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
func duplicateIP(ip net.IP) net.IP {
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}
func maskSize(m net.IPMask) int {
	ones, _ := m.Size()
	return ones
}
func getFirstIP(network *net.IPNet) net.IP {
	ip := duplicateIP(network.IP)
	incrementIP(ip)
	return ip
}