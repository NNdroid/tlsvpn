package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"
)

var errInvalidWebAuth = errors.New("-web-auth must be in the form user:password")

var processStart = time.Now()

// ensureBasicAuthFormat 校验 -web-auth 格式 user:password
func ensureBasicAuthFormat(v string) error {
	if v == "" {
		return nil // 未配置认证是合法状态，运行时按需告警
	}
	if !strings.Contains(v, ":") {
		return errInvalidWebAuth
	}
	return nil
}

func constantTimeCredentialEqual(got, want string) bool {
	gotHash := sha256.Sum256([]byte(got))
	wantHash := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(gotHash[:], wantHash[:]) == 1
}

// appVersion 为可注入版本：`go build -ldflags "-X main.appVersion=<ver>"`
// 由 scripts/build.sh 从 git tag 写入；默认值保证 go test / 直接构建可用。
var appVersion = "1.1.0"

// ======================= Web UI 与 监控 API =======================

type WebStats struct {
	Mode          string                 `json:"mode"`
	Version       string                 `json:"version"`
	UptimeSec     uint64                 `json:"uptime_sec"`
	ActiveClients int                    `json:"active_clients"`
	Clients       map[string]interface{} `json:"clients,omitempty"`
	GlobalTxBytes uint64                 `json:"global_tx_bytes"`
	GlobalRxBytes uint64                 `json:"global_rx_bytes"`
	// 扩展观测
	LogLevel    string               `json:"log_level"`
	Dropped     uint64               `json:"dropped_frames"`
	TapErrors   uint64               `json:"tap_write_errors"`
	Fec         fecStatsJSON         `json:"fec"`
	Reorder     reorderStatsJSON     `json:"reorder"`
	Mem         memStatsJSON         `json:"mem"`
	IPPool      *ipPoolJSON          `json:"ip_pool,omitempty"`
	Banned      map[string]int64     `json:"banned,omitempty"`
	MACs        []MACEntry           `json:"mac_table,omitempty"`
	Conns       []connSnapshot       `json:"conns,omitempty"`        // client 模式连接明细
	ServerConns []serverConnSnapshot `json:"server_conns,omitempty"` // server 模式物理连接明细
	FecMode     string               `json:"fec_mode,omitempty"`     // client 模式 FEC 状态
	EncAlgo     int                  `json:"enc_algo,omitempty"`
	// client 模式会话级密钥代际。服务端逐连接有 session_epoch，客户端只有一条
	// 逻辑会话，故放在顶层；连接表按列展示它，代际漂移一眼可见。
	SessionEpoch uint64 `json:"session_epoch,omitempty"`
	// 按日流量统计（上行=client→server，下行=server→client，线路字节口径）
	Traffic *trafficSnapshotJSON `json:"traffic,omitempty"`
	// 服务端模式下各客户端的按日流量历史（客户端模式缺位）
	ClientTraffic []clientTrafficJSON `json:"client_traffic,omitempty"`
	// 面板"状态"页数据源：生效配置、运行时协商、宿主系统
	Cfg       runtimeCfgJSON `json:"cfg"`
	Negotiate runtimeNegJSON `json:"negotiate"`
	System    sysInfoJSON    `json:"system"`
}

// serverConnSnapshot 服务端单条物理连接的明细快照
type serverConnSnapshot struct {
	ClientID  string `json:"client_id"`
	Remote    string `json:"remote"`
	RttMs     uint32 `json:"rtt_ms"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxPackets uint64 `json:"tx_packets"`
	RxPackets uint64 `json:"rx_packets"`
	AgeSec    uint64 `json:"age_sec"`
	// 本连接的协商结果：FEC 分组、内层加密、密钥代际
	FEC        string `json:"fec"`
	EncAlgo    int    `json:"enc_algo"`
	SessionEnc bool   `json:"session_encrypt"`
	Epoch      uint64 `json:"session_epoch"`
	// TCP Brutal：本连接实际生效的整形速率与生效结果
	BrutalApplied bool   `json:"brutal_applied"`
	BrutalErr     string `json:"brutal_error,omitempty"`
	BrutalSrvTx   uint64 `json:"brutal_srv_tx_mbps"` // 服务端下发方向整形速率
	BrutalCliTx   uint64 `json:"brutal_cli_tx_mbps"` // 客户端上行方向整形速率
}

type fecStatsJSON struct {
	Enabled   bool   `json:"enabled"`
	ParityTx  uint64 `json:"parity_tx"`
	Recovered uint64 `json:"recovered"`
	Lost      uint64 `json:"lost"`
}

type reorderStatsJSON struct {
	GapEvents      uint64 `json:"gap_events"`
	TimeoutFlushes uint64 `json:"timeout_flushes"`
	SkippedFrames  uint64 `json:"skipped_frames"`
	DroppedFrames  uint64 `json:"dropped_frames"` // deliver queue 满时丢帧（慢 TAP 兜底）
}

func addReorderStats(dst *reorderStatsJSON, src ReorderBufferStats) {
	dst.GapEvents += src.GapEvents
	dst.TimeoutFlushes += src.TimeoutFlushes
	dst.SkippedFrames += src.SkippedFrames
	dst.DroppedFrames += src.DroppedFrames
}

type memStatsJSON struct {
	HeapAllocMB  float64 `json:"heap_alloc_mb"`
	SysMB        float64 `json:"sys_mb"`
	NumGoroutine int     `json:"num_goroutine"`
}

type ipPoolJSON struct {
	V4Used  int `json:"v4_used"`
	V4Total int `json:"v4_total"`
	V6Used  int `json:"v6_used"`
}

// sysInfoJSON 宿主平台与进程信息：面板用来区分"本机运行"与"经隧道访问"，
// 也用来判断 TCP Brutal 这类内核调优在架构上是否有意义（客户端跑 Windows、
// 服务端跑 Linux 时只有服务端真正做了 shaping）。
type sysInfoJSON struct {
	OS        string   `json:"os"`
	Arch      string   `json:"arch"`
	GoVersion string   `json:"go_version"`
	NumCPU    int      `json:"num_cpu"`
	Host      string   `json:"host,omitempty"`
	CfgPath   string   `json:"cfg_path,omitempty"`
	RestartNR []string `json:"needs_restart,omitempty"`
	// 尽力而为的系统指标：Linux 缺文件或非 Linux 时缺位，面板不渲染对应行
	Load      *loadJSON `json:"load,omitempty"`
	Mem       *memJSON  `json:"mem,omitempty"`
	FdOpen    int       `json:"fd_open,omitempty"`
	NumGC     uint32    `json:"num_gc,omitempty"`
	GCPauseMs float64   `json:"gc_pause_ms,omitempty"`
}

// brutalInfoJSON 服务端 TCP Brutal 的协商与生效结果。
// 配置值与内核实际状态分开设：内核没装 brutal 模块时 apply 必然失败，
// 把两者混在一起就无法区分"没配置"和"配置了但没生效"。
type brutalInfoJSON struct {
	Enabled       bool     `json:"enabled"`
	UpMbps        uint64   `json:"up_mbps"`
	DownMbps      uint64   `json:"down_mbps"`
	Supported     bool     `json:"kernel_supported"`
	KernelCurrent string   `json:"kernel_current,omitempty"`
	KernelAvail   []string `json:"kernel_available,omitempty"`
	AppliedConns  int      `json:"applied_conns"`
	TotalConns    int      `json:"total_conns"`
	MinUpMbps     uint64   `json:"min_up_mbps,omitempty"`
	MaxUpMbps     uint64   `json:"max_up_mbps,omitempty"`
	MinDownMbps   uint64   `json:"min_down_mbps,omitempty"`
	MaxDownMbps   uint64   `json:"max_down_mbps,omitempty"`
	Errors        []string `json:"errors,omitempty"`
}

// runtimeCfgJSON 生效配置的扁平快照（已脱敏）。不直接下发完整 Config：
// 面板需要的是"哪些开关现在是开/关"，而不是让浏览器缓存一份可保存的配置。
type runtimeCfgJSON struct {
	Mode           string       `json:"mode"`
	Encrypt        bool         `json:"encrypt"`
	EncAlgo        string       `json:"enc_algo"`
	MinEnc         string       `json:"min_enc"`
	PadMode        string       `json:"pad_mode"`
	Brutal         bool         `json:"brutal"`
	BrutalUp       uint64       `json:"brutal_up"`
	BrutalDown     uint64       `json:"brutal_down"`
	Socks5         bool         `json:"socks5"`
	FEC            bool         `json:"fec"`
	FecGroup       int          `json:"fec_group"`
	FecGroupMin    int          `json:"fec_group_min,omitempty"` // 服务端：接受的对端 FEC 分组 K 下限
	FecGroupMax    int          `json:"fec_group_max,omitempty"` // 服务端：接受的对端 FEC 分组 K 上限
	LogLevel       string       `json:"log_level"`
	Conns          int          `json:"conns"`
	Tap            string       `json:"tap"`
	Mac            string       `json:"mac"`
	Addr           string       `json:"addr"`
	WebAddr        string       `json:"web_addr"`
	WebAuth        bool         `json:"web_auth"`
	WebBind        string       `json:"web_bind"`
	WebHTTPS       bool         `json:"web_https"`
	EncryptPSK     bool         `json:"encrypt_psk"`
	SessionEnc     bool         `json:"session_encrypt"`
	MaxSess        int          `json:"max_sessions"`
	V4CIDR         string       `json:"v4_cidr,omitempty"`
	V6CIDR         string       `json:"v6_cidr,omitempty"`
	GwV4           string       `json:"gw_v4,omitempty"`
	GwV6           string       `json:"gw_v6,omitempty"`
	Fwmark         int          `json:"fwmark,omitempty"`          // 客户端：策略路由标记
	FwmarkPriority int          `json:"fwmark_priority,omitempty"` // 0 = 交给内核分配
	FwmarkTable    int          `json:"fwmark_table,omitempty"`    // 与 fwmark 同号
	ExtraRoutes    []string     `json:"extra_routes,omitempty"`    // 额外路由（iproute2 语法）
	SourceRules    []SourceRule `json:"source_rules,omitempty"`    // 按源地址前缀的规则
}

// runtimeNegJSON 运行时协商结果快照。客户端模式是端到端会话的实际参数，
// 服务端模式是本机作为接收端的配置意图（真实结果逐连接看 server_conns）。
type runtimeNegJSON struct {
	ProtocolVersion int               `json:"protocol_version"`
	FEC             bool              `json:"fec"`
	FecGroup        int               `json:"fec_group"`
	EncAlgo         int               `json:"enc_algo"`
	PadMode         string            `json:"pad_mode"`
	MinEnc          string            `json:"min_enc,omitempty"`
	SessionToken    bool              `json:"session_token"`
	SessionEpoch    uint64            `json:"session_epoch"`
	TxRateMbps      uint64            `json:"tx_rate_mbps"`
	RxRateMbps      uint64            `json:"rx_rate_mbps"`
	TLS             *TLSHandshakeInfo `json:"tls,omitempty"`
	Brutal          brutalInfoJSON    `json:"brutal"`
	// 策略路由生效状态。fwmark>0 但这里为 false 就意味着规则没装进内核，
	// 隧道在线而本机不通，只能靠面板看到。
	PolicyRouting    bool   `json:"policy_routing,omitempty"`
	PolicyRoutingErr string `json:"policy_routing_error,omitempty"`
}

// basicAuthWrapper 为管理面加一层 Basic Auth；expected 为空时放行
// （未配置 -web-auth，保持旧行为；文档强烈建议配置）。
func basicAuthWrapper(expected string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if expected == "" {
			next(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || !constantTimeCredentialEqual(user+":"+pass, expected) {
			w.Header().Set("WWW-Authenticate", `Basic realm="tlsvpn dashboard"`)
			http.Error(w, "Unauthorized", 401)
			return
		}
		next(w, r)
	}
}

// csrfGuard 管理动作的跨站防护：要求请求携带自定义头 X-Requested-With。
// Basic Auth 凭据会被浏览器自动附带，恶意网页可诱导管理员浏览器跨站 POST；
// 自定义头无法通过跨站 <form> 携带，且其存在不会触发 CORS 预检放行
// （响应侧不设 Access-Control-Allow-Origin，跨站脚本同样读不到结果）。
func csrfGuard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Requested-With") != "tlsvpn" {
			http.Error(w, "Missing X-Requested-With header (CSRF protection)", 403)
			return
		}
		next(w, r)
	}
}

func startWebServer(addr string, srv *Server, cli *Client, webAuth, webCert, webKey string, cfg *Config) {
	mgr := NewWebManager(srv, cli, cfg, nil)
	mux := http.NewServeMux()
	mgr.mux = mux
	auth := mgr.auth // 认证串可热更：经 mgr 读取当前配置

	// 趋势 RTT 采样与每客户端流量差分都依赖 mode 侧回调，在这里挂上
	if srv != nil {
		dailyTraffic.SetRTTSampler(srv.avgRTT)
		dailyTraffic.SetClientSampler(srv.sampleClientTraffic)
	} else if cli != nil {
		dailyTraffic.SetRTTSampler(cli.avgRTT)
	}

	// 仪表盘静态资源（与 API 一致地受认证保护）；no-store 语义见 webuiHandler
	mux.Handle("/", auth(webuiHandler().ServeHTTP))

	// 状态统计 API
	mux.HandleFunc("/api/stats", auth(func(w http.ResponseWriter, r *http.Request) {
		startWebStatsHandler(w, r, srv, cli)
	}))

	// 当前生效配置（面板"设置"页）
	mux.HandleFunc("/api/config", auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		redacted := *mgr.Config()
		redacted.PSK = ""
		redacted.Web.Auth = ""
		redacted.Socks5 = ""
		data, _ := json.MarshalIndent(&redacted, "", "  ")
		w.Write(data)
	}))

	// 日志尾随（环形缓冲）
	mux.HandleFunc("/api/logs", auth(func(w http.ResponseWriter, r *http.Request) {
		after := uint64(0)
		fmt.Sscanf(r.URL.Query().Get("after"), "%d", &after)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logRing.snapshot(after))
	}))

	// 长周期吞吐/RTT 趋势（range=1h|24h，默认 1h）
	mux.HandleFunc("/api/trend", auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		minutes := 60
		if r.URL.Query().Get("range") == "24h" {
			minutes = 1440
		}
		json.NewEncoder(w).Encode(dailyTraffic.TrendSnapshot(minutes))
	}))

	// Prometheus 文本格式指标
	mux.HandleFunc("/metrics", auth(handleMetrics(srv, cli)))

	// 控制 API（管理动作统一走 CSRF 头防护）
	mux.HandleFunc("/api/control", auth(csrfGuard(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", 405)
			return
		}
		var req struct {
			Action     string          `json:"action"`
			ClientID   string          `json:"client_id"`
			Level      string          `json:"level"`
			TTLMinutes int             `json:"ttl_minutes"`
			Config     json.RawMessage `json:"config"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if err := dec.Decode(&struct{}{}); err != io.EOF {
			http.Error(w, "request body must contain exactly one JSON value", 400)
			return
		}

		switch {
		case srv != nil && req.Action == "kick":
			srv.mu.RLock()
			session, exists := srv.activeClients[req.ClientID]
			srv.mu.RUnlock()
			if exists {
				srv.kickSession(session)
				session.sessionMu.Lock()
				n := len(session.conns)
				session.sessionMu.Unlock()
				log.Infof("[WebUI] Force kicked client: %s (%d conns)", req.ClientID, n)
			}
			writeOK(w)

		case srv != nil && req.Action == "ban":
			ttl := time.Duration(req.TTLMinutes) * time.Minute
			if srv.Ban(req.ClientID, ttl) {
				log.Infof("[WebUI] Banned client %s (ttl=%s)", req.ClientID, ttl)
			}
			writeOK(w)

		case srv != nil && req.Action == "unban":
			srv.Unban(req.ClientID)
			log.Infof("[WebUI] Unbanned client %s", req.ClientID)
			writeOK(w)

		case srv != nil && req.Action == "kickall":
			srv.mu.RLock()
			sessions := make([]*ClientSession, 0, len(srv.activeClients))
			for _, s2 := range srv.activeClients {
				sessions = append(sessions, s2)
			}
			srv.mu.RUnlock()
			for _, s2 := range sessions {
				srv.kickSession(s2)
			}
			log.Infof("[WebUI] Kicked all clients (%d)", len(sessions))
			writeOK(w)

		case req.Action == "loglevel":
			if err := setRuntimeLogLevel(req.Level); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			log.Infof("[WebUI] Log level set to %s", currentLogLevelName())
			writeOK(w)

		case cli != nil && req.Action == "reconnect":
			cli.ForceReconnect()
			log.Infof("[WebUI] Forced reconnect triggered")
			writeOK(w)

		case req.Action == "gc":
			debug.FreeOSMemory()
			log.Infof("[WebUI] Manual GC triggered")
			writeOK(w)

		case req.Action == "save" || req.Action == "save_apply":
			apply := req.Action == "save_apply"
			newCfg, needsRestart, err := mergeAndValidateConfig(mgr.Config(), req.Config, apply, srv, cli)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			// 1) 原子写回 JSON 文件（-c 启动时才有来源路径）
			if err := SaveConfigFile(newCfg); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			// 2) save 只持久化；save_apply 才改变当前进程。两种按钮语义
			// 必须不同，避免用户选择“仅保存”时意外断开现有连接。
			if apply {
				setRuntimeLogLevel(newCfg.LogLevel)
				mgr.SetConfig(newCfg)
				dailyTraffic.OnConfig(newCfg) // traffic_days/traffic_file 热更生效
				if srv != nil {
					srv.ApplyConfig(newCfg)
				}
				if cli != nil {
					cli.ApplyConfig(newCfg)
				}
			}
			log.Infof("[WebUI] Config %s (needs_restart: %v)", req.Action, needsRestart)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "needs_restart": needsRestart})

		default:
			http.Error(w, "Unknown action", 400)
		}
	})))

	log.Infof("🚀 Web Dashboard manager started (bind=%s, tls=%v)", mgr.Config().Web.Bind, webCert != "")
	go mgr.Run()
}

// mergeAndValidateConfig 解析面板提交的新配置，校验并计算需重启字段。
// apply=false 时仅校验不落盘不生效。
func mergeAndValidateConfig(old *Config, posted json.RawMessage, apply bool, srv *Server, cli *Client) (*Config, []string, error) {
	posted = stripDeprecatedSessionTokenConfig(posted)
	dec := json.NewDecoder(strings.NewReader(string(posted)))
	dec.DisallowUnknownFields()
	newCfg := &Config{}
	if err := dec.Decode(newCfg); err != nil {
		return nil, nil, fmt.Errorf("invalid config: %v", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, nil, fmt.Errorf("invalid config: expected exactly one JSON value")
	}
	// 面板提交的内容不允许自行改写来源路径与 mode 切换（mode 切换等于换进程形态）
	newCfg.SourcePath = old.SourcePath
	// GET /api/config 对凭据做了脱敏；面板回传空值表示“保留现有 secret”，
	// 而不是把运行中的认证信息清空。
	if newCfg.PSK == "" {
		newCfg.PSK = old.PSK
	}
	if newCfg.Web.Auth == "" {
		newCfg.Web.Auth = old.Web.Auth
	}
	if newCfg.Socks5 == "" {
		newCfg.Socks5 = old.Socks5
	}
	newCfg.applyDefaults()
	if err := newCfg.Validate(); err != nil {
		return nil, nil, err
	}
	var needsRestart []string
	if apply {
		if srv != nil {
			needsRestart = append(needsRestart, srv.NeedsRestart(newCfg)...)
		}
		if cli != nil {
			needsRestart = append(needsRestart, cli.NeedsRestart(newCfg)...)
		}
	}
	return newCfg, needsRestart, nil
}

func tlsScheme(cert, key string) string {
	if cert != "" && key != "" {
		return "https"
	}
	return "http"
}

func writeOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status": "ok"}`))
}

// handleMetrics 输出 Prometheus 文本格式指标
func handleMetrics(srv *Server, cli *Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		var b strings.Builder
		emit := func(name, help, typ, val string) {
			b.WriteString("# HELP " + name + " " + help + "\n# TYPE " + name + " " + typ + "\n" + name + " " + val + "\n")
		}
		emit("tlsvpn_uptime_seconds", "Process uptime in seconds", "gauge", fmt.Sprint(uint64(time.Since(processStart)/time.Second)))
		emit("tlsvpn_go_goroutines", "Number of goroutines", "gauge", fmt.Sprint(runtime.NumGoroutine()))
		emit("tlsvpn_heap_alloc_bytes", "Heap bytes allocated and still in use", "gauge", fmt.Sprint(ms.HeapAlloc))
		emit("tlsvpn_sys_bytes", "Total bytes of memory obtained from the OS", "gauge", fmt.Sprint(ms.Sys))

		if srv != nil {
			srv.mu.RLock()
			n := len(srv.activeClients)
			var tx, rx, pk uint64
			for _, s2 := range srv.activeClients {
				tx += atomic.LoadUint64(&s2.TxBytes)
				rx += atomic.LoadUint64(&s2.RxBytes)
				pk += atomic.LoadUint64(&s2.TxPackets) + atomic.LoadUint64(&s2.RxPackets)
			}
			srv.mu.RUnlock()
			emit("tlsvpn_active_clients", "Number of active client sessions", "gauge", fmt.Sprint(n))
			emit("tlsvpn_tx_bytes_total", "Total bytes sent to clients", "counter", fmt.Sprint(tx))
			emit("tlsvpn_rx_bytes_total", "Total bytes received from clients", "counter", fmt.Sprint(rx))
			emit("tlsvpn_packets_total", "Total frames relayed (tx+rx)", "counter", fmt.Sprint(pk))
			v4u, v4t, v6u := srv.IPPoolStatus()
			emit("tlsvpn_ip_pool_v4_used", "Allocated IPv4 addresses", "gauge", fmt.Sprint(v4u))
			emit("tlsvpn_ip_pool_v4_total", "IPv4 pool capacity", "gauge", fmt.Sprint(v4t))
			emit("tlsvpn_ip_pool_v6_used", "Allocated IPv6 addresses", "gauge", fmt.Sprint(v6u))
			srv.mu.RLock()
			var rec, lost, parity, portDropped uint64
			var reorder reorderStatsJSON
			for _, s2 := range srv.activeClients {
				if s2.FecDec != nil {
					r2, l2 := s2.FecDec.FECStats()
					rec += r2
					lost += l2
				}
				parity += s2.Port.ParitySent()
				portDropped += s2.Port.Dropped()
				if s2.RxReorder != nil {
					addReorderStats(&reorder, s2.RxReorder.Stats())
				}
			}
			srv.mu.RUnlock()
			emit("tlsvpn_fec_recovered_frames_total", "Frames recovered by XOR FEC", "counter", fmt.Sprint(rec))
			emit("tlsvpn_fec_lost_frames_total", "Frames confirmed lost despite FEC", "counter", fmt.Sprint(lost))
			emit("tlsvpn_fec_parity_frames_total", "Parity frames generated", "counter", fmt.Sprint(parity))
			emit("tlsvpn_port_dropped_frames_total", "Frames dropped due to backpressure", "counter", fmt.Sprint(portDropped))
			emit("tlsvpn_reorder_gap_events_total", "Observed sequence gaps", "counter", fmt.Sprint(reorder.GapEvents))
			emit("tlsvpn_reorder_timeout_flushes_total", "Gap timeouts that resumed delivery", "counter", fmt.Sprint(reorder.TimeoutFlushes))
			emit("tlsvpn_reorder_skipped_frames_total", "Missing sequence slots skipped after timeout", "counter", fmt.Sprint(reorder.SkippedFrames))
			emit("tlsvpn_tap_write_errors_total", "Frames dropped on TAP write failure", "counter", fmt.Sprint(srv.tapWriteErrs.Load()))
			if srv.vswitch != nil {
				emit("tlsvpn_spoofed_src_dropped_frames_total", "Frames dropped claiming another session's source MAC", "counter", fmt.Sprint(srv.vswitch.spoofDrops.Load()))
				emit("tlsvpn_broadcast_dropped_frames_total", "Broadcast frames dropped over the per-port flood budget", "counter", fmt.Sprint(srv.vswitch.floodDrops.Load()))
			}
			srv.bannedMu.Lock()
			banned := len(srv.banned)
			srv.bannedMu.Unlock()
			srv.pskFailMu.Lock()
			pskBuckets := len(srv.pskFail)
			srv.pskFailMu.Unlock()
			emit("tlsvpn_banned_clients", "Currently banned clients", "gauge", fmt.Sprint(banned))
			emit("tlsvpn_psk_fail_buckets", "Remote addresses with recent PSK failures", "gauge", fmt.Sprint(pskBuckets))
		}
		if cli != nil {
			emit("tlsvpn_tx_bytes_total", "Total bytes sent", "counter", fmt.Sprint(atomic.LoadUint64(&cli.TxBytes)))
			emit("tlsvpn_rx_bytes_total", "Total bytes received", "counter", fmt.Sprint(atomic.LoadUint64(&cli.RxBytes)))
			emit("tlsvpn_live_connections", "Live physical connections", "gauge", fmt.Sprint(atomic.LoadInt32(&cli.liveConns)))
			emit("tlsvpn_reconnect_attempts_total", "Reconnect attempts", "counter", fmt.Sprint(cli.ReconnectAttempts()))
			emit("tlsvpn_port_dropped_frames_total", "Frames dropped due to backpressure", "counter", fmt.Sprint(cli.txPort.Dropped()))
			emit("tlsvpn_fec_recovered_frames_total", "Frames recovered by XOR FEC", "counter", fmt.Sprint(cli.FECRecovered()))
			emit("tlsvpn_fec_lost_frames_total", "Frames confirmed lost despite FEC", "counter", fmt.Sprint(cli.FECLost()))
			if cli.rxReorder != nil {
				reorder := cli.rxReorder.Stats()
				emit("tlsvpn_reorder_gap_events_total", "Observed sequence gaps", "counter", fmt.Sprint(reorder.GapEvents))
				emit("tlsvpn_reorder_timeout_flushes_total", "Gap timeouts that resumed delivery", "counter", fmt.Sprint(reorder.TimeoutFlushes))
				emit("tlsvpn_reorder_skipped_frames_total", "Missing sequence slots skipped after timeout", "counter", fmt.Sprint(reorder.SkippedFrames))
			}
			emit("tlsvpn_tap_write_errors_total", "Frames dropped on TAP write failure", "counter", fmt.Sprint(cli.tapWriteErrs.Load()))
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.Write([]byte(b.String()))
	}
}

// startWebStatsHandler 输出运行状态 JSON（server/client 两种模式）
func startWebStatsHandler(w http.ResponseWriter, r *http.Request, srv *Server, cli *Client) {
	w.Header().Set("Content-Type", "application/json")
	stats := WebStats{Version: appVersion, Clients: make(map[string]interface{}), LogLevel: currentLogLevelName()}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	stats.Mem = memStatsJSON{
		HeapAllocMB:  float64(ms.HeapAlloc) / 1024 / 1024,
		SysMB:        float64(ms.Sys) / 1024 / 1024,
		NumGoroutine: runtime.NumGoroutine(),
	}

	if srv != nil {
		stats.Mode = "server"
		stats.UptimeSec = uint64(time.Since(srv.startedAt) / time.Second)
		srv.mu.RLock()
		stats.ActiveClients = len(srv.activeClients)
		type tmpSession struct {
			v4, v6, mac, fec        string
			conns, enc              int
			txB, rxB, txP, rxP, age uint64
		}
		snapClients := make(map[string]tmpSession, len(srv.activeClients))
		for id, session := range srv.activeClients {
			session.sessionMu.Lock()
			conns := session.ActiveConns
			session.sessionMu.Unlock()
			snapClients[id] = tmpSession{
				v4: session.IPv4, v6: session.IPv6, mac: session.MAC, fec: session.FecMode, enc: session.EncAlgo, conns: conns,
				txB: atomic.LoadUint64(&session.TxBytes),
				rxB: atomic.LoadUint64(&session.RxBytes),
				txP: atomic.LoadUint64(&session.TxPackets),
				rxP: atomic.LoadUint64(&session.RxPackets),
				age: uint64(time.Since(session.CreatedAt) / time.Second),
			}
		}
		stats.Banned = srv.BanList()
		var rec, lost, parity, portDropped uint64
		var reorder reorderStatsJSON
		for _, session := range srv.activeClients {
			if session.FecDec != nil {
				r2, l2 := session.FecDec.FECStats()
				rec += r2
				lost += l2
			}
			parity += session.Port.ParitySent()
			portDropped += session.Port.Dropped()
			if session.RxReorder != nil {
				addReorderStats(&reorder, session.RxReorder.Stats())
			}
		}
		stats.IPPool = &ipPoolJSON{}
		stats.IPPool.V4Used, stats.IPPool.V4Total, stats.IPPool.V6Used = srv.IPPoolStatus()
		stats.MACs = srv.MACSnapshot()
		srv.mu.RUnlock()
		// 注意：snapshotServerConns 内部会再次拿读锁，必须在 RUnlock 之后调用，
		// 否则同 goroutine 递归 RLock 在写者排队时会死锁。
		stats.ServerConns = srv.snapshotServerConns()
		stats.Fec = fecStatsJSON{Enabled: true, ParityTx: parity, Recovered: rec, Lost: lost}
		stats.Dropped = portDropped
		stats.Reorder = reorder
		stats.TapErrors = srv.tapWriteErrs.Load()

		cfg := srv.curCfg()
		stats.Cfg = snapshotCfg(cfg, "server")
		stats.Negotiate = srv.negSnapshot()
		// 逐连接 brutal 生效统计（服务端在握手时为每条 TCP 连接单独 setsockopt）
		if sb := srv.serverConnsBrutal(); sb.TotalConns > 0 {
			stats.Negotiate.Brutal.AppliedConns = sb.AppliedConns
			stats.Negotiate.Brutal.TotalConns = sb.TotalConns
			stats.Negotiate.Brutal.MinUpMbps = sb.MinUpMbps
			stats.Negotiate.Brutal.MaxUpMbps = sb.MaxUpMbps
			stats.Negotiate.Brutal.MinDownMbps = sb.MinDownMbps
			stats.Negotiate.Brutal.MaxDownMbps = sb.MaxDownMbps
			stats.Negotiate.Brutal.Errors = sb.Errors
		}
		var cfgPath string
		if cfg != nil {
			cfgPath = cfg.SourcePath
		}
		stats.System = sysInfo(cfgPath, srv.PendingRestart())

		for id, snap := range snapClients {
			stats.Clients[id] = map[string]interface{}{
				"ipv4": snap.v4, "ipv6": snap.v6, "mac": snap.mac, "active_conns": snap.conns,
				"tx_bytes": snap.txB, "rx_bytes": snap.rxB, "tx_packets": snap.txP, "rx_packets": snap.rxP,
				"fec": snap.fec, "enc_algo": snap.enc, "uptime_sec": snap.age,
			}
		}
	} else if cli != nil {
		stats.Mode = "client"
		stats.UptimeSec = uint64(time.Since(cli.startedAt) / time.Second)
		cli.sessionMu.Lock()
		v4, v6 := cli.assignedV4, cli.assignedV6
		mac := cli.macAddr
		sessionEpoch := cli.sessionEpoch
		cli.sessionMu.Unlock()
		stats.SessionEpoch = sessionEpoch
		conns := int(atomic.LoadInt32(&cli.liveConns))
		fec := cli.fecStatus
		lv := cli.live.Load()
		// encAlgoNone=0（TLS only）/ 2（AES-256-GCM）/ 4（AES-128-GCM）。
		// 算法号本身已无歧义，直接下发。
		enc := cli.encAlgo
		stats.ActiveClients = 1
		stats.Clients["local"] = map[string]interface{}{
			"client_id": cli.clientID, "ipv4": v4, "ipv6": v6, "mac": mac, "active_conns": conns,
			"tx_bytes": atomic.LoadUint64(&cli.TxBytes), "rx_bytes": atomic.LoadUint64(&cli.RxBytes),
			"tx_packets": atomic.LoadUint64(&cli.TxPackets), "rx_packets": atomic.LoadUint64(&cli.RxPackets),
			"fec": fec, "enc_algo": enc,
		}
		stats.Conns = cli.snapshotConns()
		if cli.txPort != nil {
			stats.Dropped = cli.txPort.Dropped()
			rec, lost := cli.FECStats()
			fecEnabled := lv != nil && lv.fecMode
			stats.Fec = fecStatsJSON{Enabled: fecEnabled, ParityTx: cli.txPort.ParitySent(), Recovered: rec, Lost: lost}
		}
		if cli.rxReorder != nil {
			addReorderStats(&stats.Reorder, cli.rxReorder.Stats())
		}
		stats.TapErrors = cli.tapWriteErrs.Load()
		stats.FecMode = fec
		stats.EncAlgo = enc

		cfg := cli.curCfg()
		stats.Cfg = snapshotCfg(cfg, "client")
		stats.Negotiate = cli.negSnapshot()
		var cfgPath string
		if cfg != nil {
			cfgPath = cfg.SourcePath
		}
		stats.System = sysInfo(cfgPath, cli.PendingRestart())
	}

	stats.System.Load = readLoadAvg()
	stats.System.Mem = readMemInfo()
	stats.System.FdOpen = countFDs()
	stats.System.NumGC = ms.NumGC
	stats.System.GCPauseMs = float64(ms.PauseTotalNs) / 1e6
	if ct := dailyTraffic.ClientSnapshot(); len(ct) > 0 {
		stats.ClientTraffic = ct
	}
	ts := dailyTraffic.Snapshot()
	stats.Traffic = &ts

	json.NewEncoder(w).Encode(stats)
}

// ======================= 运行时状态快照（面板"状态"页） =======================

// osType 平台类型：面板用它决定 brutal / 内核调优这类能力是否可能有意义。
func osType() string {
	switch runtime.GOOS {
	case "linux":
		return "Linux"
	case "windows":
		return "Windows"
	case "darwin":
		return "macOS"
	default:
		return runtime.GOOS
	}
}

// snapshotCfg 把生效配置压平成面板可直接渲染的扁平结构。
// 只读快照，不含任何密钥材料。
func snapshotCfg(cfg *Config, mode string) runtimeCfgJSON {
	out := runtimeCfgJSON{Mode: mode}
	if cfg == nil {
		return out
	}
	out.Encrypt = cfg.Encrypt
	out.EncAlgo = cfg.EncAlgo
	out.MinEnc = cfg.MinEnc
	out.PadMode = padModeName()
	out.Brutal = cfg.Brutal
	out.BrutalUp = cfg.BrutalUp
	out.BrutalDown = cfg.BrutalDown
	out.Socks5 = cfg.Socks5 != ""
	out.LogLevel = cfg.LogLevel
	out.Conns = cfg.Client.Conns
	out.Tap = cfg.Tap
	out.Mac = cfg.Mac
	out.Addr = cfg.Addr
	out.WebAddr = cfg.Web.Addr
	out.WebAuth = cfg.Web.Auth != ""
	out.WebBind = cfg.Web.Bind
	out.WebHTTPS = cfg.Web.Cert != "" && cfg.Web.Key != ""
	out.EncryptPSK = true
	out.SessionEnc = cfg.Encrypt
	out.MaxSess = cfg.Server.MaxSessions
	out.V4CIDR = cfg.Server.V4CIDR
	out.V6CIDR = cfg.Server.V6CIDR
	out.FEC = cfg.Client.FEC
	out.FecGroup = cfg.Client.FecGroup
	out.FecGroupMin = cfg.Server.FecGroupMin
	out.FecGroupMax = cfg.Server.FecGroupMax
	out.Fwmark = cfg.Client.Fwmark
	out.FwmarkPriority = cfg.Client.FwmarkPriority
	// 表号永远等于 fwmark 值，这不是巧合而是约定：面板把它显式列出来，
	// 免得用户拿错表号去看 ip route。
	out.FwmarkTable = cfg.Client.Fwmark
	out.ExtraRoutes = cfg.Client.ExtraRoutes
	out.SourceRules = cfg.Client.SourceRules
	return out
}

// sysInfo 宿主进程信息；Hostname 失败时留空（容器场景常见）。
func sysInfo(cfgPath string, pendingRestart []string) sysInfoJSON {
	host, _ := os.Hostname()
	return sysInfoJSON{
		OS:        osType(),
		Arch:      runtime.GOARCH,
		GoVersion: runtime.Version(),
		NumCPU:    runtime.NumCPU(),
		Host:      host,
		CfgPath:   cfgPath,
		RestartNR: pendingRestart,
	}
}

// serverNegSnapshot 服务端"本端视图"的协商快照。
// 服务端不消费单一会话：这里报告的是配置意图 + 按连接数摊薄后的每连接速率，
// 逐连接的真实结果在 server_conns 里。
func (s *Server) negSnapshot() runtimeNegJSON {
	s.mu.RLock()
	cfg := s.cfg.Load()
	encrypt := s.encrypt
	encAlgo := s.encAlgo
	minEnc := s.minEnc
	s.mu.RUnlock()

	n := runtimeNegJSON{ProtocolVersion: 2, SessionToken: true, PadMode: padModeName()}
	if cfg != nil {
		n.FEC = cfg.Client.FEC
		n.FecGroup = cfg.Client.FecGroup
		// 服务端预算按逻辑客户端分组，不是全机连接数均分。逐会话的实际范围
		// 由 serverConnsBrutal 在握手快照后补入。
		n.Brutal = brutalSummary(cfg.Brutal, cfg.BrutalUp, cfg.BrutalDown, 0)
	}
	if encrypt {
		n.EncAlgo = encAlgo
	}
	if minEnc > 0 {
		n.MinEnc = "gcm"
	}
	return n
}

// clientNegSnapshot 客户端端到端协商结果：服务端实际回传的取值 + 本机 shaping 状态。
func (c *Client) negSnapshot() runtimeNegJSON {
	c.sessionMu.Lock()
	neg := c.negInfo
	epoch := c.sessionEpoch
	c.sessionMu.Unlock()

	n := runtimeNegJSON{PadMode: padModeName()}
	if neg != nil {
		n.ProtocolVersion = neg.ProtocolVersion
		n.FEC = neg.FEC
		n.FecGroup = neg.FecGroup
		n.EncAlgo = neg.EncAlgo
		n.SessionToken = neg.SessionToken
		n.TxRateMbps = neg.TxRateMbps
		n.RxRateMbps = neg.RxRateMbps
		n.TLS = neg.TLS
	}
	if epoch != 0 {
		n.SessionEpoch = epoch
	}

	// 本机 shaping 状态：配置 + 平台支持 + 每条连接的实际生效结果
	lv := c.live.Load()
	var up uint64
	if lv != nil {
		up = lv.brutalUp
	}
	st := c.connsSummary()
	var down uint64
	if lv != nil {
		down = lv.brutalDown
	}
	// 客户端的 down 是它向服务端申请的每会话下行预算（shaping 由服务端执行），
	// 与配置页的 brutal_down 保持一致，避免两处数字对不上。
	n.Brutal = brutalSummary(lv != nil && lv.brutal, up, down, int64(st.total))
	n.Brutal.AppliedConns = st.applied
	n.Brutal.Errors = st.errs
	if st.total > 0 {
		n.Brutal.MinUpMbps = st.minUp
		n.Brutal.MaxUpMbps = st.maxUp
	}
	// 只在配了 fwmark 或 source_rules 时报状态：没配的时候这一栏不显示，
	// 免得"未生效"被误读成配置错误。
	if lv != nil && (lv.fwmark > 0 || len(lv.sourceRules) > 0) {
		n.PolicyRouting, n.PolicyRoutingErr = c.policyRoutingResult()
	}
	return n
}

// connBrutalSummary 客户端各连接 TCP Brutal 生效统计。
type connBrutalSummary struct {
	total, applied int
	minUp, maxUp   uint64
	errs           []string
}

func (c *Client) connsSummary() connBrutalSummary {
	lv := c.live.Load()
	var up uint64
	if lv != nil {
		up = lv.brutalUp
	}
	c.connsMu.Lock()
	defer c.connsMu.Unlock()
	var st connBrutalSummary
	for i := 0; i < int(c.connsCount); i++ {
		ci, ok := c.conns[i]
		if !ok {
			continue
		}
		st.total++
		br := ci.brutal.Load()
		if br != nil && br.Applied {
			st.applied++
		}
		if br != nil && br.Error != "" {
			// 各连接的失败原因通常完全相同（例如"平台不支持"），只保留互不相同的
			dup := false
			for _, e := range st.errs {
				if e == br.Error {
					dup = true
					break
				}
			}
			if !dup && len(st.errs) < 3 {
				st.errs = append(st.errs, br.Error)
			}
		}
		per := splitLegacyBrutalRate(up, int(c.connsCount), i)
		if up > 0 {
			if i == 0 || per < st.minUp {
				st.minUp = per
			}
			if per > st.maxUp {
				st.maxUp = per
			}
		}
	}
	return st
}

// brutalStatus 系统级 TCP Brutal 能力与状态。字段是面板协议的一部分，只有一份
// 定义、放公共代码里：brutalSystemStatus() 在 tap_other.go / net_linux.go 各有一份
// 平台实现，但类型必须两平台共用——定义在任一带 build tag 的文件里，另一侧就编不过。
type brutalStatus struct {
	supported bool
	current   string
	available []string
	err       string
}

// brutalSummary 系统级 + 配置的 brutal 状态摘要（不含逐连接统计，由各模式补）。
func brutalSummary(enabled bool, up, down uint64, conns int64) brutalInfoJSON {
	st := brutalSystemStatus()
	b := brutalInfoJSON{
		Enabled:       enabled,
		UpMbps:        up,
		DownMbps:      down,
		Supported:     st.supported,
		KernelCurrent: st.current,
		KernelAvail:   st.available,
		TotalConns:    int(conns),
	}
	if st.err != "" && !st.supported {
		b.Errors = []string{st.err}
	}
	if enabled && up > 0 && conns > 0 {
		b.MinUpMbps = splitLegacyBrutalRate(up, int(conns), int(conns)-1)
		b.MaxUpMbps = splitLegacyBrutalRate(up, int(conns), 0)
	}
	if enabled && down > 0 && conns > 0 {
		b.MinDownMbps = splitLegacyBrutalRate(down, int(conns), int(conns)-1)
		b.MaxDownMbps = splitLegacyBrutalRate(down, int(conns), 0)
	}
	return b
}

// serverConnsBrutal 汇总各会话的 brutal 生效情况，返回可并入 negotiate.brutal 的部分。
func (s *Server) serverConnsBrutal() brutalInfoJSON {
	out := brutalInfoJSON{}
	s.mu.RLock()
	sessions := make([]*ClientSession, 0, len(s.activeClients))
	for _, sess := range s.activeClients {
		sessions = append(sessions, sess)
	}
	s.mu.RUnlock()
	var applied, total int
	haveRates := false
	for _, sess := range sessions {
		sess.sessionMu.Lock()
		n := len(sess.conns)
		var sessionUp, sessionDown uint64
		for ci := range sess.conns {
			total++
			sessionUp = atomic.LoadUint64(&ci.brutalRx)
			sessionDown = atomic.LoadUint64(&ci.brutalTx)
			if br := ci.brutal.Load(); br != nil && br.Applied {
				applied++
			}
			if br := ci.brutal.Load(); br != nil && br.Error != "" {
				seen := false
				for _, e := range out.Errors {
					if e == br.Error {
						seen = true
						break
					}
				}
				if !seen && len(out.Errors) < 3 {
					out.Errors = append(out.Errors, br.Error)
				}
			}
		}
		sess.sessionMu.Unlock()
		if n > 0 {
			minUp, maxUp := splitLegacyBrutalRate(sessionUp, n, n-1), splitLegacyBrutalRate(sessionUp, n, 0)
			minDown, maxDown := splitLegacyBrutalRate(sessionDown, n, n-1), splitLegacyBrutalRate(sessionDown, n, 0)
			if !haveRates || minUp < out.MinUpMbps {
				out.MinUpMbps = minUp
			}
			if maxUp > out.MaxUpMbps {
				out.MaxUpMbps = maxUp
			}
			if !haveRates || minDown < out.MinDownMbps {
				out.MinDownMbps = minDown
			}
			if maxDown > out.MaxDownMbps {
				out.MaxDownMbps = maxDown
			}
			haveRates = true
		}
	}
	out.AppliedConns, out.TotalConns = applied, total
	return out
}

// curCfg 当前生效配置（server 从 atomic 槽取，client 从热更槽取）。
func (s *Server) curCfg() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Load()
}

// curCfg 当前生效配置（liveConfig 是热更快照）。
func (c *Client) curCfg() *Config {
	return c.cfgSnap.Load()
}

// PendingRestart 与启动时配置相比、无法热更因而需要重启的字段。
func (s *Server) PendingRestart() []string {
	if cfg := s.curCfg(); cfg != nil {
		return s.NeedsRestart(cfg)
	}
	return nil
}

// PendingRestart 与启动时配置相比、无法热更因而需要重启的字段。
func (c *Client) PendingRestart() []string {
	if cfg := c.curCfg(); cfg != nil {
		return c.NeedsRestart(cfg)
	}
	return nil
}
