package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
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

// ======================= 运行时日志级别 + 环形缓冲 =======================

var atomicLogLevel = zap.NewAtomicLevelAt(zapcore.InfoLevel)

// logRing 供 Web 面板尾随的内存日志环形缓冲（不含堆栈，仅级别/时间/消息）
var logRing = newLogRing(500)

type logLine struct {
	Seq   uint64 `json:"seq"`
	Level string `json:"level"`
	Time  string `json:"time"`
	Msg   string `json:"msg"`
}

type logRingBuf struct {
	mu    sync.Mutex
	seq   uint64
	lines []logLine
	cap   int
}

func newLogRing(capacity int) *logRingBuf {
	return &logRingBuf{cap: capacity}
}

func (r *logRingBuf) add(e zapcore.Entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	r.lines = append(r.lines, logLine{
		Seq:   r.seq,
		Level: e.Level.CapitalString(),
		Time:  e.Time.Format("15:04:05.000"),
		Msg:   e.Message,
	})
	if len(r.lines) > r.cap {
		r.lines = r.lines[len(r.lines)-r.cap:]
	}
}

// snapshot 返回 seq 大于 after 的日志行
func (r *logRingBuf) snapshot(after uint64) []logLine {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []logLine{}
	for _, l := range r.lines {
		if l.Seq > after {
			out = append(out, l)
		}
	}
	return out
}

func initLogger(level string) {
	var l zapcore.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = zapcore.InfoLevel
	}
	atomicLogLevel.SetLevel(l)
	config := zap.NewDevelopmentConfig()
	config.Level = atomicLogLevel
	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	baseLogger, _ := config.Build()
	// 挂接环形缓冲，供 Web 面板尾随
	baseLogger = baseLogger.WithOptions(zap.Hooks(func(e zapcore.Entry) error {
		logRing.add(e)
		return nil
	}))
	log = baseLogger.Sugar()
}

// setRuntimeLogLevel 运行时调整日志级别（面板控制用）
func setRuntimeLogLevel(level string) error {
	var l zapcore.Level
	if err := l.UnmarshalText([]byte(strings.TrimSpace(level))); err != nil {
		return fmt.Errorf("invalid log level %q: %v", level, err)
	}
	atomicLogLevel.SetLevel(l)
	return nil
}

func currentLogLevelName() string {
	return atomicLogLevel.Level().String()
}

func main() {
	// 配置来源二选一：
	//   1) -c config.json —— JSON 配置文件为唯一来源（推荐，便于 review）
	//   2) 命令行标志     —— 兼容旧用法
	mode := flag.String("mode", "", "server or client")
	psk := flag.String("psk", "quic_secret", "Pre-shared key")
	tapName := flag.String("tap", "tap0", "Name of the TAP device")
	macAddr := flag.String("mac", "", "Specify MAC address for TAP device (Client/Server)")
	addr := flag.String("addr", "0.0.0.0:4000", "Server: listen address | Client: target addresses (comma-separated)")
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
	fec := flag.Bool("fec", false, "Enable FEC over Multipath (XOR parity when the server supports it, else packet duplication)")
	fecGroup := flag.Int("fec-group", 4, "XOR FEC group size K (2-64); parity overhead is 1/K")
	webAddr := flag.String("web", "", "Optional: start the Web Dashboard on this address (e.g. :8080). Omit to disable")
	webAuth := flag.String("web-auth", "", "Basic Auth for the Web Dashboard as user:pass (strongly recommended when -web binds a public address)")
	webCert := flag.String("web-cert", "", "Optional: TLS certificate for the Web Dashboard (HTTPS)")
	webKey := flag.String("web-key", "", "Optional: TLS key for the Web Dashboard (HTTPS)")
	encrypt := flag.Bool("encrypt", false, "Enable inner payload encryption (AES-256-GCM with per-session salts when the peer supports it)")
	socks5 := flag.String("socks5", "", "Route ALL outbound sockets through a SOCKS5 proxy (Client only)")

	configPath := flag.String("c", "", "Path to JSON config file (overrides all other flags)")
	printConfig := flag.Bool("print-config", false, "Print an example JSON config and exit")

	flag.Parse()

	if *printConfig {
		fmt.Println(exampleConfigJSON)
		return
	}

	// 组装配置：-c 优先，否则取命令行标志
	var cfg *Config
	if *configPath != "" {
		loaded, err := loadConfigFile(*configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		cfg = loaded
	} else {
		cfg = &Config{
			Mode: *mode, PSK: *psk, Tap: *tapName, Mac: *macAddr, Addr: *addr,
			LogLevel: *logLevel, Encrypt: *encrypt, Socks5: *socks5,
			Brutal: *brutal, BrutalUp: *brutalUp, BrutalDown: *brutalDown,
			Web:    WebConfig{Addr: *webAddr, Auth: *webAuth, Cert: *webCert, Key: *webKey},
			Server: ServerConfig{V4CIDR: *v4cidr, V6CIDR: *v6cidr, Cert: *certFile, Key: *keyFile},
			Client: ClientConfig{
				ReqV4: *reqV4, ReqV6: *reqV6, SNI: *sni, Insecure: *insecure,
				CertSHA256: *certHash, Fwmark: *fwmark, Conns: *conns,
				FEC: *fec, FecGroup: *fecGroup,
			},
		}
	}

	cfg.applyDefaults()
	initLogger(cfg.LogLevel)
	if *configPath != "" {
		log.Infof("Loaded configuration from %s", *configPath)
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}

	// 初始化全局出口：要么全部经由 SOCKS5，要么全部直连。
	if err := initGlobalProxy(cfg.Socks5, cfg.Client.Fwmark); err != nil {
		log.Fatalf("Invalid SOCKS5 option: %v", err)
	}
	if isSocks5Enabled() {
		log.Infof("🧦 SOCKS5 proxy enabled: all outbound sockets go through %s", globalSocks5Addr)
		if cfg.Client.Fwmark <= 0 {
			log.Warnf("⚠️  SOCKS5 is used without fwmark. If the tunnel becomes the default route, " +
				"the connection to the SOCKS5 proxy may be routed into the tunnel itself and deadlock.")
		}
	}

	// 面板安全提示：非回环 + 无认证 + 无 TLS 时给出明确告警
	if cfg.Web.Addr != "" {
		host, _, err := net.SplitHostPort(cfg.Web.Addr)
		public := err == nil && host != "" && host != "127.0.0.1" && host != "::1" && host != "localhost"
		if public && cfg.Web.Auth == "" && (cfg.Web.Cert == "" || cfg.Web.Key == "") {
			log.Warnf("⚠️  Web dashboard binds a non-loopback address (%s) without auth and without HTTPS. "+
				"Consider web.auth in the config.", cfg.Web.Addr)
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	switch cfg.Mode {
	case "server":
		if cfg.Client.FEC {
			log.Warnf("client FEC settings are ignored in server mode")
		}
		startServer(ctx, cfg)
	case "client":
		if cfg.Client.FEC && cfg.Client.Conns < 2 {
			log.Warnf("FEC is enabled but conns < 2. Multipath redundancy needs conns >= 2; " +
				"FEC will only guard against queue-overflow drops on the single link.")
		}
		startClient(ctx, cfg)
	default:
		fmt.Println("Usage: tlsvpn -c config.json   (or -mode server|client with flags; -print-config for a template)")
		os.Exit(1)
	}

	log.Info("Program exited gracefully.")
}
