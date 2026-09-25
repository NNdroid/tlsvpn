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
	// 配置唯一来源是 JSON 文件：-c 指定路径，-print-config 输出可编辑模板。
	// 旧的命令行参数面已整体移除——两套入口必然漂移，且面板 save_apply 写回
	// 的也是同一份 JSON（字段参考见 README）。
	configPath := flag.String("c", "", "Path to JSON config file (required)")
	printConfig := flag.Bool("print-config", false, "Print an example JSON config and exit")
	flag.Parse()

	if *printConfig {
		fmt.Println(exampleConfigJSON)
		return
	}

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "tlsvpn: a JSON config file is required: tlsvpn -c config.json")
		fmt.Fprintln(os.Stderr, "generate a template with: tlsvpn -print-config")
		os.Exit(2)
	}

	loaded, err := loadConfigFile(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	loaded.SourcePath = *configPath
	cfg := loaded
	cfg.applyDefaults()
	initLogger(cfg.LogLevel)
	log.Infof("Loaded configuration from %s", *configPath)
	if !cfg.EncryptPresent {
		log.Warnf("Config does not set 'encrypt'; defaulting to enabled. Write \"encrypt\": false to run without inner encryption")
	}
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid configuration: %v", err)
	}
	// 按日流量统计：恢复历史并启动采样协程（无配置文件来源时仅内存统计）
	dailyTraffic.OnConfig(cfg)
	// 填充策略全局生效（发送路径读取），支持面板热更
	if actual := setPadMode(cfg.PadMode); actual != cfg.PadMode {
		log.Warnf("Invalid pad_mode %q, using %s", cfg.PadMode, actual)
	} else {
		log.Infof("Confusion padding: %s", actual)
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
		if err := startServer(ctx, cfg); err != nil {
			log.Errorf("Server stopped with an error: %v", err)
			_ = log.Sync()
			os.Exit(1)
		}
	case "client":
		if cfg.Client.FEC && cfg.Client.Conns < 2 {
			log.Warnf("FEC is enabled but conns < 2. XOR parity is suppressed on a single TCP path " +
				"because TCP head-of-line blocking prevents parity from overtaking missing data; parity resumes when a second path is active.")
		}
		if err := startClient(ctx, cfg); err != nil {
			log.Errorf("Client stopped with an error: %v", err)
			_ = log.Sync()
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "Usage: tlsvpn -c config.json   (-print-config for a template)")
		os.Exit(1)
	}

	log.Info("Program exited gracefully.")
}
