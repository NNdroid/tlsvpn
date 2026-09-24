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

const dashboardHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>tlsvpn Dashboard</title>
<style>
:root { --bg:#121212; --fg:#e0e0e0; --card:#1e1e1e; --muted:#888; --sub:#999; --border:#333;
  --th:#2c2c2c; --thfg:#bbb; --field:#2a2a2a; --fieldfg:#ddd; --fieldbd:#444;
  --accent:#bb86fc; --accentfg:#121212; --teal:#03dac6; --err:#ff7597; --warn:#e1c94e;
  --ok:#4ee1a0; --okbg:#1b3a2f; --warnbg:#3a341b; --offbg:#333; --offfg:#888;
  --logbg:#0d0d0d; --grid:#2a2a2a; --btn:#cf6679; --btnhi:#ff7597;
  --blue:#3d5a80; --bluehi:#5b84b1; --gray:#444; --grayhi:#666; --shadow:0 4px 6px rgba(0,0,0,.3); }
:root[data-theme=light] { --bg:#f5f6fa; --fg:#1d2026; --card:#ffffff; --muted:#7a7f8a; --sub:#6b7078;
  --border:#e3e5eb; --th:#eef0f5; --thfg:#545964; --field:#ffffff; --fieldfg:#1d2026;
  --fieldbd:#cdd2db; --accent:#7c4dff; --accentfg:#ffffff; --teal:#00897b; --err:#c62828;
  --warn:#a97b00; --ok:#2e7d32; --okbg:#e3f4e8; --warnbg:#fff3d0; --offbg:#ebeef3;
  --offfg:#7a7f8a; --logbg:#ffffff; --grid:#e3e5eb; --btn:#c62828; --btnhi:#e53935;
  --blue:#3d5a80; --bluehi:#5b84b1; --gray:#6b7280; --grayhi:#9aa1ac; --shadow:0 4px 6px rgba(16,24,40,.10); }
body { font-family:'Segoe UI',Tahoma,sans-serif; background:var(--bg); color:var(--fg); margin:0; padding:20px; }
.wrap { max-width:1200px; margin:0 auto; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:14px; }
.card { background:var(--card); border-radius:8px; padding:14px 18px; box-shadow:var(--shadow); margin-bottom:14px; }
.card.wide { grid-column:1/-1; }
h1 { color:var(--accent); margin:0 0 12px; font-size:1.35em; display:flex; align-items:center; flex-wrap:wrap; gap:10px; }
h1 small { color:var(--muted); font-weight:normal; font-size:.55em; }
.kpi { font-size:1.5em; font-weight:bold; color:var(--teal); }
.kpi small { font-size:.55em; color:var(--muted); font-weight:normal; }
.sub { color:var(--sub); font-size:.84em; margin-top:3px; }
table { width:100%; border-collapse:collapse; margin-top:8px; }
th,td { padding:7px 9px; text-align:left; border-bottom:1px solid var(--border); font-size:.88em; white-space:nowrap; }
th { background:var(--th); color:var(--thfg); }
table.kv th,table.kv td:first-child { color:var(--sub); font-weight:600; width:38%; }
.speed { color:var(--teal); font-weight:bold; }
.badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:.78em; font-weight:600; }
.b-on { background:var(--okbg); color:var(--ok); } .b-dup { background:var(--warnbg); color:var(--warn); } .b-off { background:var(--offbg); color:var(--offfg); }
.btn { padding:3px 10px; background:var(--btn); color:white; border:none; border-radius:4px; cursor:pointer; font-size:.82em; margin-right:4px; }
.btn:hover { background:var(--btnhi); }
.btn.blue { background:var(--blue); } .btn.blue:hover { background:var(--bluehi); }
.btn.gray { background:var(--gray); } .btn.gray:hover { background:var(--grayhi); }
#chart { width:100%; height:170px; display:block; }
.legend { font-size:.8em; color:var(--sub); margin-top:6px; }
.legend span { margin-right:14px; }
.dot { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:4px; }
#logbox { background:var(--logbg); border:1px solid var(--border); border-radius:6px; padding:10px; height:220px; overflow-y:auto; font:12px/1.5 Consolas,monospace; }
#logbox .lv-WARN { color:var(--warn); } #logbox .lv-ERROR,#logbox .lv-PANIC { color:var(--err); } #logbox .lv-DEBUG { color:var(--muted); }
.logbar { display:flex; gap:8px; align-items:center; margin-top:8px; flex-wrap:wrap; }
.logbar select,.logbar input { background:var(--field); color:var(--fieldfg); border:1px solid var(--fieldbd); border-radius:4px; padding:4px 8px; font-size:.85em; }
	.logbar input { width:130px; }
.hd { background:var(--field); color:var(--fieldfg); border:1px solid var(--fieldbd); border-radius:4px; padding:4px; font-size:.5em; margin-left:6px; }
.tabs { display:flex; gap:6px; margin-bottom:10px; flex-wrap:wrap; }
.tabs button { background:var(--field); color:var(--thfg); border:none; border-radius:4px 4px 0 0; padding:6px 14px; cursor:pointer; font-size:.88em; }
.tabs button.on { background:var(--accent); color:var(--accentfg); font-weight:600; }
.pane { display:none; } .pane.on { display:block; }
.warnbar { background:var(--warnbg); color:var(--warn); border-radius:6px; padding:8px 12px; font-size:.86em; margin-bottom:12px; }
.mono { font-family:Consolas,monospace; }
footer { text-align:center; color:var(--muted); font-size:.78em; margin-top:16px; }
@media (max-width:640px){ th,td{padding:5px;} .hide-sm{display:none;} }
</style>
</head>
<body>
<div class="wrap">
<h1>🚀 tlsvpn <span id="mode">…</span><small id="meta"></small>
  <span style="margin-left:auto"></span>
	  <select id="lang" class="hd" onchange="setLang(this.value)">
    <option value="zh-CN">中文</option><option value="en">English</option>
  </select>
  <select id="theme" class="hd" onchange="setTheme(this.value)" data-i18n-title="theme_tip">
    <option value="system" data-i18n="theme.sys">-</option><option value="light" data-i18n="theme.light">-</option><option value="dark" data-i18n="theme.dark">-</option>
  </select>
  <select id="refresh" class="hd" onchange="setRefresh(this.value)" data-i18n-title="refresh_tip">
    <option value="2000">2s</option><option value="5000">5s</option><option value="10000">10s</option>
  </select>
</h1>
<div class="grid">
  <div class="card"><div class="sub" data-i18n="kpi.active">-</div><div class="kpi" id="active-clients">0</div><div class="sub" id="conns-sub">-</div></div>
  <div class="card"><div class="sub" data-i18n="kpi.tx">-</div><div class="kpi" id="total-tx">0 B</div><div class="sub" id="total-tx-speed" class="speed">-</div></div>
  <div class="card"><div class="sub" data-i18n="kpi.rx">-</div><div class="kpi" id="total-rx">0 B</div><div class="sub" id="total-rx-speed" class="speed">-</div></div>
  <div class="card"><div class="sub" data-i18n="kpi.uptime">-</div><div class="kpi" id="uptime">-</div><div class="sub"><span data-i18n="kpi.version">-</span> <span id="ver">-</span> · <a href="#" onclick="doAction('gc');return false;" style="color:var(--blue)" data-i18n="kpi.gc">-</a></div></div>
  <div class="card"><div class="sub" data-i18n="kpi.fec">-</div><div class="kpi" id="fec-kpi">-</div><div class="sub"><span data-i18n="kpi.parity">-</span> <span id="parity">-</span> · <span data-i18n="kpi.dropped">-</span> <span id="dropped">-</span> · <span data-i18n="kpi.reorder">-</span> <span id="reorder-skipped">-</span></div></div>
  <div class="card"><div class="sub" data-i18n="kpi.mem">-</div><div class="kpi" id="mem">-</div><div class="sub"><span data-i18n="kpi.goroutines">-</span> <span id="goroutines">-</span></div></div>
  <div class="card" id="ippool-card" style="display:none"><div class="sub" data-i18n="kpi.pool">-</div><div class="kpi" id="ippool-kpi">-</div><div class="sub"><span data-i18n="kpi.v6used">-</span> <span id="v6used">-</span></div></div>
</div>
<div class="card wide"><h2 data-i18n="chart.title">-</h2>
  <canvas id="chart" width="1160" height="170"></canvas>
  <div class="legend"><span><i class="dot" style="background:var(--teal)"></i><span data-i18n="legend.up">-</span></span><span><i class="dot" style="background:var(--accent)"></i><span data-i18n="legend.down">-</span></span></div></div>

<div class="card wide">
  <div class="tabs">
    <button class="on" data-pane="clients" onclick="showPane(this)" data-i18n="tab.clients">-</button>
    <button data-pane="conns" onclick="showPane(this)" data-i18n="tab.conns">-</button>
    <button data-pane="macs" onclick="showPane(this)" data-i18n="tab.macs">-</button>
	    <button data-pane="bans" onclick="showPane(this)" data-i18n="tab.bans">-</button>
    <button data-pane="status" onclick="showPane(this)" data-i18n="tab.status">-</button>
    <button data-pane="logs" onclick="showPane(this)" data-i18n="tab.logs">-</button>
    <button data-pane="settings" onclick="showPane(this)" data-i18n="tab.settings">-</button>
  </div>

  <div class="pane on" id="pane-clients">
    <div class="logbar"><input id="client-filter" data-i18n-ph="filter_ph" oninput="fetchStats()" style="width:220px"></div>
    <div style="overflow-x:auto"><table>
      <thead><tr><th data-i18n="th.id">-</th><th data-i18n="th.v4">-</th><th class="hide-sm" data-i18n="th.v6">-</th><th class="hide-sm" data-i18n="th.mac">-</th><th data-i18n="th.tcp">-</th><th data-i18n="th.tx">-</th><th data-i18n="th.rx">-</th><th data-i18n="th.txs">-</th><th data-i18n="th.rxs">-</th><th class="hide-sm" data-i18n="th.fec">-</th><th class="hide-sm" data-i18n="th.enc">-</th><th data-i18n="th.ops">-</th></tr></thead>
      <tbody id="clients-body"></tbody>
    </table></div>
  </div>

  <div class="pane" id="pane-conns">
    <div class="logbar"><input id="conn-filter" data-i18n-ph="filter_ph" oninput="fetchStats()" style="width:220px"></div>
    <div style="overflow-x:auto"><table>
      <thead><tr><th data-i18n="th.owner">-</th><th data-i18n="th.target">-</th><th data-i18n="th.remote">-</th><th data-i18n="th.state">-</th><th data-i18n="th.rtt">-</th><th data-i18n="th.tx">-</th><th data-i18n="th.rx">-</th><th class="hide-sm" data-i18n="th.retries">-</th>	<th class="hide-sm" data-i18n="th.age">-</th><th class="hide-sm" data-i18n="th.epoch">-</th><th class="hide-sm" data-i18n="th.enc">-</th><th class="hide-sm" data-i18n="th.fec">-</th><th class="hide-sm" data-i18n="th.brutal">-</th><th class="hide-sm" data-i18n="th.err">-</th><th data-i18n="th.ops">-</th></tr></thead>
      <tbody id="conns-body"></tbody>
    </table></div>
  </div>

  <div class="pane" id="pane-macs"><div style="overflow-x:auto"><table>
    <thead><tr><th data-i18n="th.mac">-</th><th data-i18n="m.port">-</th><th data-i18n="m.seen">-</th></tr></thead>
    <tbody id="macs-body"></tbody>
  </table></div></div>

  <div class="pane" id="pane-bans">
    <div class="logbar"><input id="ban-id" data-i18n-ph="bans.id_ph"><input id="ban-min" data-i18n-ph="bans.min_ph" style="width:170px">
    <button class="btn blue" onclick="addBan()" data-i18n="bans.add">-</button><button class="btn gray" onclick="fetchStats()" data-i18n="bans.refresh">-</button></div>
    <div style="overflow-x:auto"><table>
      <thead><tr><th data-i18n="th.id">-</th><th data-i18n="bans.left">-</th><th data-i18n="th.ops">-</th></tr></thead>
      <tbody id="bans-body"></tbody>
    </table></div>
  </div>

	  <div class="pane" id="pane-status">
    <div id="status-restart" class="warnbar" style="display:none"></div>
    <div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(300px,1fr))">
      <div class="card" style="margin-bottom:0">
        <h2 style="font-size:1.05em;margin:0 0 6px" data-i18n="stt.brutal">-</h2>
        <div style="overflow-x:auto"><table class="kv" id="st-brutal"></table></div>
      </div>
      <div class="card" style="margin-bottom:0">
        <h2 style="font-size:1.05em;margin:0 0 6px" data-i18n="stt.negt">-</h2>
        <div style="overflow-x:auto"><table class="kv" id="st-neg"></table></div>
      </div>
      <div class="card" style="margin-bottom:0">
        <h2 style="font-size:1.05em;margin:0 0 6px" data-i18n="stt.host">-</h2>
        <div style="overflow-x:auto"><table class="kv" id="st-sys"></table></div>
      </div>
      <div class="card" style="margin-bottom:0">
        <h2 style="font-size:1.05em;margin:0 0 6px" data-i18n="stt.cfg">-</h2>
        <div style="overflow-x:auto"><table class="kv" id="st-cfg"></table></div>
      </div>
    </div>
  </div>

  <div class="pane" id="pane-logs">
    <div id="logbox"></div>
    <div class="logbar">
      <label style="font-size:.85em;color:var(--sub)"><span data-i18n="logs.level">-</span>
        <select id="loglevel" onchange="setLogLevel(this.value)">
          <option value="debug">debug</option><option value="info">info</option>
          <option value="warn">warn</option><option value="error">error</option>
        </select>
      </label>
      <label style="font-size:.85em;color:var(--sub)"><input type="checkbox" id="autoscroll" checked> <span data-i18n="logs.autoscroll">-</span></label>
      <button class="btn gray" onclick="clearLog()" data-i18n="logs.clear">-</button>
      <button class="btn gray" onclick="downloadLog()" data-i18n="logs.download">-</button>
    </div>
  </div>

  <div class="pane" id="pane-settings">
    <div class="sub" style="margin-bottom:8px" data-i18n="set.hint">-</div>
    <div class="logbar"><button class="btn blue" onclick="loadConfig()" data-i18n="set.load">-</button>
      <button class="btn gray" onclick="saveConfig(false)" data-i18n="set.save">-</button>
      <button class="btn" onclick="saveConfig(true)" data-i18n="set.apply">-</button>
      <span id="cfg-status" style="font-size:.85em;color:var(--sub)"></span></div>
    <div style="margin-top:10px"><textarea id="cfg-editor" spellcheck="false"
      style="width:100%;height:340px;background:var(--logbg);color:var(--fg);border:1px solid var(--border);border-radius:6px;padding:10px;font:12px/1.5 Consolas,monospace"></textarea></div>
  </div>
</div>
<footer><span id="footer-text"></span> · <span id="tls-flag"></span></footer>
</div>
<script>
const I18N={
'zh-CN':{kpi:{active:'活跃客户端/设备',tcp:'TCP 连接',tx:'总发送',rx:'总接收',uptime:'运行时长',version:'版本',gc:'立即回收',fec:'FEC 恢复 / 确认丢失',parity:'校验帧',dropped:'丢帧(队列)',reorder:'重排跳过',mem:'内存',goroutines:'Goroutines:',pool:'IPv4 地址池',v6used:'IPv6 已分配:'},
 chart:{title:'吞吐趋势',win:'(近 120 秒)'},legend:{up:'上行',down:'下行'},
	tab:{clients:'客户端',conns:'连接明细',macs:'MAC 表',bans:'封禁',status:'运行状态',logs:'日志',settings:'设置'},
 th:{id:'ID',v4:'IPv4',v6:'IPv6',mac:'MAC',tcp:'TCP',tx:'TX (发)',rx:'RX (收)',txs:'↑ 速率',rxs:'↓ 速率',fec:'FEC',enc:'加密',brutal:'Brutal',ops:'操作',kick:'踢出',ban:'封禁',unban:'解封',owner:'客户端',target:'目标',remote:'对端',state:'状态',rtt:'RTT',retries:'重试',age:'在线',epoch:'密钥代际',err:'最近错误'},
 m:{port:'端口',seen:'最近活跃'},bans:{id_ph:'ClientID（可短前缀）',min_ph:'分钟（留空=永久）',add:'封禁',refresh:'刷新',left:'剩余'},
 logs:{level:'级别',autoscroll:'自动滚动',clear:'清屏',download:'下载日志'},
 filter_ph:'输入关键字过滤…',no_clients:'暂无客户端',no_conns:'无连接',no_macs:'尚未学习到 MAC',no_bans:'无封禁记录',srv_only:'仅服务端模式提供',
 perm:'永久',confirm_kick:'确定要强制断开该客户端吗？',confirm_ban:'确定封禁该客户端吗？',need_id:'请输入 ClientID',
 st:{up:'up',connecting:'connecting',skip:'未生效'},
 badge:{dup:'复制',off:'关闭',ctr:'CTR',plain:'明文'},
 u:{day:'天',hour:'时',min:'分',sec:'秒'},footer:'数据每 {n} 秒刷新',refresh_tip:'刷新间隔',
	tls_http:'HTTP（建议启用 HTTPS）',mode_local:'本机',theme_tip:'主题（跟随系统）',theme:{sys:'Auto',light:'Light',dark:'Dark'},
 cfgk:{mode:'运行模式',encrypt:'内层加密',min_enc:'最低加密要求',pad_mode:'填充模式',brutal:'TCP Brutal',brutal_up:'上行总量 (Mbps)',brutal_down:'下行总量 (Mbps)',socks5:'SOCKS5 代理',fec:'FEC',fec_group:'FEC 分组',fec_group_min:'FEC 分组下限',fec_group_max:'FEC 分组上限',log_level:'日志级别',conns:'并发连接数',tap:'TAP 设备',mac:'MAC 地址',addr:'服务端地址',web_addr:'面板监听',web_auth:'面板认证',web_bind:'面板绑定地址',web_https:'面板 HTTPS',encrypt_psk:'PSK 已配置',session_encrypt:'会话加密',max_sessions:'最大会话数',v4_cidr:'IPv4 网段',v6_cidr:'IPv6 网段',gw_v4:'IPv4 网关',gw_v6:'IPv6 网关',fwmark:'策略路由 fwmark',fwmark_priority:'规则优先级',fwmark_table:'路由表号',extra_routes:'额外路由',source_rules:'按源前缀路由'},
 stt:{title:'运行状态',host:'宿主与进程',negt:'协议协商结果',brutal:'TCP Brutal 明细',cfg:'生效配置快照',
   restart:'以下字段已修改，需要重启进程才能生效：',norestart:'无字段需要重启生效',noneg:'尚未与对端完成握手',
   noerr:'全部生效',kern_yes:'内核已支持',kern_no:'内核不支持',
   sys:{os:'操作系统',arch:'CPU 架构',go:'Go 版本',cpu:'CPU 核数',host:'主机名',cfgpath:'配置文件',ver:'程序版本'},
	  neg:{proto:'协议版本',fec:'FEC',grp:'FEC 分组',enc:'内层加密',pad:'填充模式',minenc:'最低加密要求',stoken:'Session Token',epoch:'密钥代际',tx:'客户端 → 服务端（上行）',rx:'服务端 → 客户端（下行）',prroute:'策略路由生效',tlsfp:'最近连接 ClientHello 指纹（非 JA3/JA4）',tlsver:'TLS 协商版本',tlscipher:'TLS 协商套件',tlsalpn:'TLS ALPN',tlssni:'TLS SNI',tlsoffer:'ClientHello 特征数'},
   brut:{en:'开关',up:'上行总量',down:'下行总量',kern:'内核支持',cur:'当前拥塞控制',avail:'可用拥塞控制',applied:'已生效 / 总数',perconn:'每连接速率',errs:'失败原因',off:'未启用'},
   yes:'是',no:'否'},
 set:{hint:'编辑 JSON 配置。保存：写回配置文件；保存并应用：写回并立即热更运行参数（列出的字段需重启生效）。',
   load:'重新加载',save:'保存',apply:'保存并应用',saved:'已保存',applied:'已保存并应用',restart_nr:'需重启生效:',loaded_err:'加载失败:'}},
'en':{kpi:{active:'Active clients',tcp:'TCP connections',tx:'Total sent',rx:'Total received',uptime:'Uptime',version:'Version',gc:'GC now',fec:'FEC recovered / confirmed lost',parity:'Parity frames',dropped:'Dropped (queue)',reorder:'Reorder skipped',mem:'Memory',goroutines:'Goroutines:',pool:'IPv4 pool',v6used:'IPv6 allocated:'},
 chart:{title:'Throughput',win:'(last 120s)'},legend:{up:'Up',down:'Down'},
	tab:{clients:'Clients',conns:'Connections',macs:'MAC table',bans:'Bans',status:'Runtime status',logs:'Logs',settings:'Settings'},
 th:{id:'ID',v4:'IPv4',v6:'IPv6',mac:'MAC',tcp:'TCP',tx:'TX',rx:'RX',txs:'↑ Rate',rxs:'↓ Rate',fec:'FEC',enc:'Encrypt',brutal:'Brutal',ops:'Actions',kick:'Kick',ban:'Ban',unban:'Unban',owner:'Client',target:'Target',remote:'Remote',state:'State',rtt:'RTT',retries:'Retries',age:'Uptime',epoch:'Epoch',err:'Last error'},
 m:{port:'Port',seen:'Last seen'},bans:{id_ph:'ClientID (short prefix ok)',min_ph:'Minutes (empty = permanent)',add:'Ban',refresh:'Refresh',left:'Remaining'},
 logs:{level:'Level',autoscroll:'Auto scroll',clear:'Clear',download:'Download'},
 filter_ph:'Type to filter…',no_clients:'No clients yet',no_conns:'No connections',no_macs:'No MACs learned yet',no_bans:'No banned clients',srv_only:'Server mode only',
 perm:'Permanent',confirm_kick:'Force-disconnect this client?',confirm_ban:'Ban this client?',need_id:'Please enter a ClientID',
 st:{up:'up',connecting:'connecting',skip:'Skipped'},
 badge:{dup:'Dup',off:'Off',ctr:'CTR',plain:'Plain'},
 u:{day:'d',hour:'h',min:'m',sec:'s'},footer:'Refreshing every {n}s',refresh_tip:'Refresh interval',
	tls_http:'HTTP (HTTPS recommended)',mode_local:'local',theme_tip:'Theme (follow system)',theme:{sys:'Auto',light:'Light',dark:'Dark'},
 cfgk:{mode:'Mode',encrypt:'Inner cipher',min_enc:'Minimum cipher',pad_mode:'Padding mode',brutal:'TCP Brutal',brutal_up:'Upstream total (Mbps)',brutal_down:'Downstream total (Mbps)',socks5:'SOCKS5 proxy',fec:'FEC',fec_group:'FEC group',fec_group_min:'FEC group floor',fec_group_max:'FEC group ceiling',log_level:'Log level',conns:'Concurrent conns',tap:'TAP device',mac:'MAC address',addr:'Server address',web_addr:'Dashboard listen',web_auth:'Dashboard auth',web_bind:'Dashboard bind',web_https:'Dashboard HTTPS',encrypt_psk:'PSK configured',session_encrypt:'Session encryption',max_sessions:'Max sessions',v4_cidr:'IPv4 CIDR',v6_cidr:'IPv6 CIDR',gw_v4:'IPv4 gateway',gw_v6:'IPv6 gateway',fwmark:'Policy routing fwmark',fwmark_priority:'Rule priority',fwmark_table:'Route table',extra_routes:'Extra routes',source_rules:'Source rules'},
 stt:{title:'Runtime status',host:'Host & process',negt:'Negotiated protocol',brutal:'TCP Brutal detail',cfg:'Effective config snapshot',
   restart:'These fields changed and require a process restart:',norestart:'Nothing pending restart',noneg:'Handshake with peer not completed yet',
   noerr:'All applied',kern_yes:'Kernel supported',kern_no:'Not supported by kernel',
   sys:{os:'OS',arch:'CPU arch',go:'Go version',cpu:'CPU cores',host:'Hostname',cfgpath:'Config file',ver:'App version'},
	  neg:{proto:'Protocol version',fec:'FEC',grp:'FEC group',enc:'Inner cipher',pad:'Padding mode',minenc:'Minimum cipher',stoken:'Session token',epoch:'Key epoch',tx:'Client → server (uplink)',rx:'Server → client (downlink)',prroute:'Policy routing applied',tlsfp:'Latest connection ClientHello fingerprint (not JA3/JA4)',tlsver:'Negotiated TLS version',tlscipher:'Negotiated TLS cipher',tlsalpn:'TLS ALPN',tlssni:'TLS SNI',tlsoffer:'ClientHello feature counts'},
   brut:{en:'Enabled',up:'Upstream total',down:'Downstream total',kern:'Kernel support',cur:'Current CC',avail:'Available CC',applied:'Applied / total',perconn:'Per-conn rate',errs:'Failure reasons',off:'Not enabled'},
   yes:'yes',no:'no'},
 set:{hint:'Edit the JSON config. Save: write back to the config file. Save & apply: write back and hot-apply runtime parameters (listed fields require a restart).',
   load:'Reload',save:'Save',apply:'Save & apply',saved:'Saved',applied:'Saved & applied',restart_nr:'Needs restart:',loaded_err:'Load failed:'}}};
	let LANG=localStorage.getItem('tlsvpn_lang')||((navigator.language||'zh-CN').toLowerCase().startsWith('zh')?'zh-CN':'en');
	function t(path){const dig=d=>{let o=d;for(const k of path.split('.'))o=o?o[k]:undefined;return o;};
  const cur=dig(I18N[LANG]);if(cur!==undefined)return cur;
  const en=dig(I18N['en']);if(en!==undefined)return en;return path;}
function applyI18n(){
  document.documentElement.lang=LANG;
  document.querySelectorAll('[data-i18n]').forEach(el=>el.textContent=t(el.dataset.i18n));
  document.querySelectorAll('[data-i18n-ph]').forEach(el=>el.placeholder=t(el.dataset.i18nPh));
	  document.getElementById('lang').value=LANG;
  document.getElementById('refresh').value=String(REFRESH);
  const th=document.getElementById('theme');
  if(th)th.value=THEME;
  applyTheme();
}
function setLang(v){localStorage.setItem('tlsvpn_lang',v);location.reload();}
function fmtDur(s){s=Math.floor(s);const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
  if(d>0)return d+t('u.day')+h+t('u.hour');if(h>0)return h+t('u.hour')+m+t('u.min');
  if(m>0)return m+t('u.min')+(s%60)+t('u.sec');return s+t('u.sec');}
function fmtBytes(b,s=false){
  if(!isFinite(b)||b<=0)return '0 '+(s?'B/s':'B');
  const u=['B','KB','MB','GB','TB'],i=Math.min(Math.floor(Math.log(b)/Math.log(1024)),4);
  return parseFloat((b/Math.pow(1024,i)).toFixed(2))+' '+u[i]+(s?'/s':'');
}
function badge(f){if(!f||f==='off')return '<span class="badge b-off">'+t('badge.off')+'</span>';
  if(f==='dup')return '<span class="badge b-dup">'+t('badge.dup')+'</span>';return '<span class="badge b-on">'+f+'</span>';}
function encBadge(a){if(a===2)return '<span class="badge b-on">GCM</span>';
  if(a===1)return '<span class="badge b-dup">'+t('badge.ctr')+'</span>';return '<span class="badge b-off">'+t('badge.plain')+'</span>';}
function stBadge(s){if(s==='up')return '<span class="badge b-on">'+t('st.up')+'</span>';
  if(s==='connecting')return '<span class="badge b-dup">'+t('st.connecting')+'</span>';
  return '<span class="badge b-off">'+(s||'-')+'</span>';}
function shortId(id,n){return id.length>n?id.slice(0,n)+'…':id;}
function esc(x){return String(x==null?'':x).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\x22/g,'&quot;').replace(/\x27/g,'&#39;');}
function showPane(btn){document.querySelectorAll('.tabs button').forEach(b=>b.classList.remove('on'));
  document.querySelectorAll('.pane').forEach(p=>p.classList.remove('on'));
  btn.classList.add('on');document.getElementById('pane-'+btn.dataset.pane).classList.add('on');
  if(btn.dataset.pane==='logs')startLogPoll();else stopLogPoll();
  if(btn.dataset.pane==='settings')loadConfig();}

function drawChart(){
	  const c=document.getElementById('chart'),ctx=c.getContext('2d'),W=c.width,H=c.height;
  ctx.clearRect(0,0,W,H);ctx.strokeStyle=cssv('--grid');
  for(let i=1;i<4;i++){ctx.beginPath();ctx.moveTo(0,H*i/4);ctx.lineTo(W,H*i/4);ctx.stroke();}
  if(txHist.length<2)return;
  const max=Math.max(...txHist,...rxHist,1);
  const plot=(h,col)=>{ctx.strokeStyle=col;ctx.lineWidth=2;ctx.beginPath();
    h.forEach((v,i)=>{const x=i/(MAXPTS-1)*W,y=H-6-(v/max)*(H-20);i?ctx.lineTo(x,y):ctx.moveTo(x,y);});ctx.stroke();};
	  plot(txHist,cssv('--teal'));plot(rxHist,cssv('--accent'));
  ctx.fillStyle=cssv('--muted');ctx.font='11px sans-serif';ctx.fillText(fmtBytes(max),4,12);
}

let REFRESH=parseInt(localStorage.getItem('tlsvpn_refresh')||'2000',10);
let statsTimer=null;
function setRefresh(v){REFRESH=parseInt(v,10);localStorage.setItem('tlsvpn_refresh',v);
  document.getElementById('footer-text').textContent=t('footer').replace('{n}',REFRESH/1000);
  restartLoop();}
function restartLoop(){if(statsTimer)clearInterval(statsTimer);statsTimer=setInterval(fetchStats,REFRESH);}

// 用带凭据的地址（http://admin:xx@host/ 打开面板）时，Chrome 拒绝构造任何 fetch——
// "Request cannot be constructed from a URL that includes credentials"——于是每一轮轮询都抛
// 同一条 TypeError，面板永远停在初始骨架上，日志里只剩一行重复报错，完全看不出是地址栏
// 里的凭据引起的。换成 Authorization 头 + 去掉 userinfo 的 URL 即可；同域请求带这个头
// 不触发预检，所以不影响未启用认证的情况。
const AUTH_HDR=(location.username||location.password)
  ?{Authorization:'Basic '+btoa(unescape(encodeURIComponent(location.username+':'+location.password)))}
  :{};
// location.origin 按规范不含 userinfo，是构造不带凭据 URL 的可靠基址
function url(path){return location.origin+path;}

async function api(path,opts){opts=opts||{};opts.headers=Object.assign({'X-Requested-With':'tlsvpn'},AUTH_HDR,opts.headers||{});return fetch(url(path),opts);}

function passFilter(obj,f){return !f||JSON.stringify(obj).toLowerCase().includes(f);}

async function fetchStats(){
  try{
    const res=await fetch(url('/api/stats'),AUTH_HDR);
    if(res.status===401){document.body.innerHTML='<div class="card"><h2>401</h2><p>'+t('logs.level')+': -web-auth user:pass</p></div>';return;}
    const data=await res.json();
    const now=performance.now();const dt=lastT?(now-lastT)/1000:2;lastT=now;

    document.getElementById('mode').innerText=data.mode.toUpperCase();
    document.getElementById('ver').innerText=data.version||'-';
    document.getElementById('uptime').innerText=fmtDur(data.uptime_sec||0);
    document.getElementById('loglevel').value=data.log_level||'info';
    document.getElementById('tls-flag').innerText=location.protocol==='https:'?'HTTPS':t('tls_http');

    const cf=(document.getElementById('client-filter').value||'').toLowerCase();
    let tbody='',tTx=0,tRx=0,tTxS=0,tRxS=0,cur={},tConns=0;
    const proc=(id,c)=>{
      tTx+=c.tx_bytes;tRx+=c.rx_bytes;tConns+=c.active_conns||0;
      let sx=0,sr=0;
      if(prev[id]){sx=Math.max(0,(c.tx_bytes-prev[id].tx_bytes)/dt);sr=Math.max(0,(c.rx_bytes-prev[id].rx_bytes)/dt);}
      cur[id]={tx_bytes:c.tx_bytes,rx_bytes:c.rx_bytes};tTxS+=sx;tRxS+=sr;
      tbody+='<tr><td title="'+esc(id)+'">'+esc(shortId(id,10))+'</td><td>'+esc(c.ipv4||'-')+'</td>'+
        '<td class="hide-sm">'+esc(c.ipv6||'-')+'</td>'+
        '<td class="hide-sm">'+esc(c.mac||'-')+'</td><td>'+c.active_conns+'</td>'+
        '<td>'+fmtBytes(c.tx_bytes)+'</td><td>'+fmtBytes(c.rx_bytes)+'</td>'+
        '<td class="speed">'+fmtBytes(sx,true)+'</td><td class="speed">'+fmtBytes(sr,true)+'</td>'+
        '<td class="hide-sm">'+badge(c.fec)+'</td><td class="hide-sm">'+encBadge(c.enc_algo)+'</td>'+
        '<td>'+(data.mode==='server'?'<button class="btn" onclick="kickClient(\''+id+'\')">'+t('th.kick')+'</button>'+
          '<button class="btn blue" onclick="banClient(\''+id+'\',0)">'+t('th.ban')+'</button>':'-')+'</td></tr>';
    };
    if(data.mode==='server'){for(const [id,c] of Object.entries(data.clients||{}))if(passFilter(Object.assign({id:id},c),cf))proc(id,c);}
    else if(data.clients&&data.clients.local)proc('local',data.clients.local);
    prev=cur;txHist.push(tTxS);rxHist.push(tRxS);
    if(txHist.length>MAXPTS){txHist.shift();rxHist.shift();}
    drawChart();

    document.getElementById('active-clients').innerText=data.active_clients;
    document.getElementById('conns-sub').innerText=t('kpi.tcp')+': '+tConns+(data.mode==='client'?' / '+((data.conns||[]).length):'');
    document.getElementById('total-tx').innerText=fmtBytes(tTx);
    document.getElementById('total-rx').innerText=fmtBytes(tRx);
    document.getElementById('total-tx-speed').innerText=fmtBytes(tTxS,true);
    document.getElementById('total-rx-speed').innerText=fmtBytes(tRxS,true);
    document.getElementById('clients-body').innerHTML=tbody||'<tr><td colspan="12" style="color:var(--muted)">'+t('no_clients')+'</td></tr>';

    const f=data.fec||{};
    document.getElementById('fec-kpi').innerHTML=(f.recovered||0)+' <small>/</small> '+(f.lost||0);
    document.getElementById('parity').innerText=f.parity_tx||0;
    document.getElementById('dropped').innerText=data.dropped_frames||0;
	const ro=data.reorder||{};
	document.getElementById('reorder-skipped').innerText=ro.skipped_frames||0;
    const m=data.mem||{};
    document.getElementById('mem').innerHTML=(m.heap_alloc_mb||0).toFixed(1)+'<small> MB</small>';
    document.getElementById('goroutines').innerText=m.num_goroutine||0;

    if(data.ip_pool){document.getElementById('ippool-card').style.display='';
      document.getElementById('ippool-kpi').innerHTML=data.ip_pool.v4_used+'<small> / '+data.ip_pool.v4_total+'</small>';
      document.getElementById('v6used').innerText=data.ip_pool.v6_used;}

    const meta=[];if(data.enc_algo===2)meta.push('GCM');else if(data.enc_algo===1)meta.push(t('badge.ctr'));
    if(data.fec_mode&&data.fec_mode!=='off')meta.push('FEC '+data.fec_mode);
    document.getElementById('meta').innerText=meta.join(' · ');

	    renderConns(data);renderMacs(data);renderBans(data);renderStatus(data);
  }catch(e){console.error('stats fetch failed',e);}
}

	// ---------- "运行状态" 页：宿主/协商/brutal/配置 四块明细 ----------
// 空值不占行：面板上留一堆空行只会让人误以为字段缺失是故障
function kv(el,rows){
  el.innerHTML=rows.length?rows.map(r=>'<tr><th>'+esc(r[0])+'</th><td>'+r[1]+'</td></tr>').join(''):'';
}
function yn(v){return v?'<span class="badge b-on">'+t('stt.yes')+'</span>':'<span class="badge b-off">'+t('stt.no')+'</span>';}
function mtxt(v){return '<span class="mono">'+esc(v)+'</span>';}
function ntxt(){return '<span style="color:var(--muted)">-</span>';}
function encName(a){return a===2?'AES-256-GCM':(a===0?'none (TLS only)':String(a));}
function rateRange(lo,hi){if(!lo&&!hi)return '-';return (lo===hi?String(lo):lo+'~'+hi)+' Mbps';}
function renderStatus(data){
  const sys=data.system||{},neg=data.negotiate||{},b=neg.brutal||{},tls=neg.tls||{},cfg=data.cfg||{};
  const rw=document.getElementById('status-restart');
  const rn=sys.needs_restart||[];
  if(rn.length){rw.style.display='';rw.innerHTML='<strong>'+t('stt.restart')+'</strong><br><span class="mono">'+esc(rn.join(', '))+'</span>';}
  else{rw.style.display='none';}
  kv(document.getElementById('st-sys'),[
    [t('stt.sys.os'),esc(sys.os||'-')+' '+mtxt(sys.arch||'')],
    [t('stt.sys.go'),mtxt(sys.go_version||'-')],
    [t('stt.sys.cpu'),sys.num_cpu||'-'],
    [t('stt.sys.host'),mtxt(sys.host||'-')],
    [t('stt.sys.cfgpath'),mtxt(sys.cfg_path||'-')],
    [t('stt.sys.ver'),mtxt(data.version||'-')+' · '+fmtDur(data.uptime_sec||0)],
  ]);
  // 密钥代际与端到端 shaping 速率是"一条会话"的概念，服务端不消费单一会话，
  // 逐连接结果看"连接明细"页，这里只在客户端模式显示。
  const nrw=[
    [t('stt.neg.proto'),neg.protocol_version?('v'+neg.protocol_version):ntxt()],
    [t('stt.neg.enc'),neg.enc_algo?encName(neg.enc_algo):ntxt()],
    [t('stt.neg.fec'),yn(!!neg.fec)],
    [t('stt.neg.grp'),neg.fec_group?String(neg.fec_group):ntxt()],
    [t('stt.neg.pad'),neg.pad_mode?mtxt(neg.pad_mode):ntxt()],
    [t('stt.neg.minenc'),neg.min_enc?mtxt(neg.min_enc):ntxt()],
    [t('stt.neg.stoken'),yn(!!neg.session_token)],
  ];
  if(data.mode==='client'){
    nrw.push([t('stt.neg.epoch'),neg.session_epoch?String(neg.session_epoch):ntxt()]);
    nrw.push([t('stt.neg.tx'),(neg.tx_rate_mbps||0)+' Mbps']);
    nrw.push([t('stt.neg.rx'),(neg.rx_rate_mbps||0)+' Mbps']);
	  nrw.push([t('stt.neg.tlsfp'),tls.fingerprint_sha256?mtxt(tls.fingerprint_kind+':'+tls.fingerprint_sha256):ntxt()]);
	  nrw.push([t('stt.neg.tlsver'),tls.version?mtxt(tls.version+' (0x'+Number(tls.version_id||0).toString(16).padStart(4,'0')+')'):ntxt()]);
	  nrw.push([t('stt.neg.tlscipher'),tls.cipher_suite?mtxt(tls.cipher_suite+' (0x'+Number(tls.cipher_suite_id||0).toString(16).padStart(4,'0')+')'):ntxt()]);
	  nrw.push([t('stt.neg.tlsalpn'),tls.alpn?mtxt(tls.alpn):ntxt()]);
	  nrw.push([t('stt.neg.tlssni'),tls.sni?mtxt(tls.sni):ntxt()]);
	  nrw.push([t('stt.neg.tlsoffer'),tls.fingerprint_sha256?mtxt((tls.offered_cipher_suites||[]).length+' cipher / '+(tls.offered_signature_schemes||[]).length+' sig / '+(tls.offered_groups||[]).length+' group / '+(tls.offered_alpn||[]).length+' ALPN'):ntxt()]);
    // 配了 fwmark 才显示：策略路由是否真的装进内核，以及失败原因。
    if(neg.policy_routing!==undefined){
      nrw.push([t('stt.neg.prroute'),neg.policy_routing_error
        ?'<span class="badge b-off">'+esc(neg.policy_routing_error)+'</span>'
        :yn(!!neg.policy_routing)]);
    }
  }
  kv(document.getElementById('st-neg'),nrw);
  kv(document.getElementById('st-brutal'),[
    [t('stt.brut.en'),yn(!!b.enabled)],
    [t('stt.brut.up'),(b.up_mbps||0)+' Mbps'],
    [t('stt.brut.down'),(b.down_mbps||0)+' Mbps'],
    [t('stt.brut.kern'),b.kernel_supported?'<span class="badge b-on">'+t('stt.kern_yes')+'</span>':'<span class="badge b-off">'+t('stt.kern_no')+'</span>'],
    [t('stt.brut.cur'),b.kernel_current?mtxt(b.kernel_current):ntxt()],
    [t('stt.brut.avail'),(b.kernel_available&&b.kernel_available.length)?mtxt(b.kernel_available.join(', ')):ntxt()],
    [t('stt.brut.applied'),(b.applied_conns||0)+' / '+(b.total_conns||0)],
    [t('stt.brut.perconn'),'<span class="mono">'+rateRange(b.min_up_mbps,b.max_up_mbps)+' / '+rateRange(b.min_down_mbps,b.max_down_mbps)+'</span>'],
    [t('stt.brut.errs'),(b.errors&&b.errors.length)?'<span style="color:var(--err)">'+esc(b.errors.join('; '))+'</span>':'<span class="badge b-on">'+t('stt.noerr')+'</span>'],
  ]);
  kv(document.getElementById('st-cfg'),Object.keys(cfg).map(function(k){
    const v=cfg[k];let cell;
    if(typeof v==='boolean')cell=yn(v);
    else if(Array.isArray(v))cell=v.length?mtxt(v.map(function(x){
      // 对象元素（source_rules）直接 join 会变成 [object Object]，转成 JSON 展示
      return typeof x==='object'&&x!==null?JSON.stringify(x):x;
    }).join(' ; ')):ntxt();
    else if(v===undefined||v===null||v==='')cell=ntxt();
    else cell=mtxt(v);
    const lab=t('cfgk.'+k);
    return [lab==='cfgk.'+k?k:lab,cell];
  }));
}

function renderConns(data){
  const tb=document.getElementById('conns-body');
  let rows=[];
  if(data.mode==='server'){
    (data.server_conns||[]).forEach(c=>rows.push({owner:shortId(c.client_id,10),fullId:c.client_id,target:'',remote:c.remote,state:'up',rtt:c.rtt_ms,tx:c.tx_bytes,rx:c.rx_bytes,retries:'',age:c.age_sec,epoch:c.session_epoch||0,err:'',enc:c.enc_algo,fec:c.fec||'',brut:c.brutal_applied,brutErr:c.brutal_error||'',up:c.brutal_cli_tx_mbps||0,down:c.brutal_srv_tx_mbps||0}));
  }else{
    (data.conns||[]).forEach(c=>rows.push({owner:'local',fullId:null,target:c.target,remote:c.remote,state:c.state,rtt:c.rtt_ms,tx:c.tx_bytes,rx:c.rx_bytes,retries:c.retries,age:c.age_sec,epoch:data.session_epoch||0,err:c.last_error||'',enc:data.enc_algo,fec:data.fec_mode||'',brut:c.brutal_applied,brutErr:c.brutal_error||'',up:c.brutal_tx_mbps||0,down:c.brutal_rx_mbps||0}));
  }
  const f=(document.getElementById('conn-filter').value||'').toLowerCase();
  if(f)rows=rows.filter(r=>JSON.stringify(r).toLowerCase().includes(f));
  tb.innerHTML=rows.map(r=>{
    const st=r.state==='up'?'<span class="badge b-on">'+t('st.up')+'</span>':
      r.state==='connecting'?'<span class="badge b-dup">'+t('st.connecting')+'</span>':
      '<span class="badge b-off">'+esc(r.state||'-')+'</span>';
    const rtt=r.rtt>=100000?'-':r.rtt+' ms';
    // Brutal 列同时是"为什么没生效"的入口：速率生效显示双向速率，
    // 配置了但内核/平台不支持显示"未生效"，悬停看具体原因。
    let brutTxt='-',brutCls='b-off',brutTip='brutal off';
    if(r.brutErr){brutTxt=t('st.skip');brutCls='b-dup';brutTip='brutal skipped: '+r.brutErr;}
    else if(r.brut===true){brutTxt=r.up+'↑/'+r.down+'↓';brutCls='b-on';brutTip='brutal shaping '+r.up+' Mbps upstream / '+r.down+' Mbps downstream';}
    const brut='<span class="badge '+brutCls+'">'+brutTxt+'</span>';
    const ops=(data.mode==='server'&&r.fullId)?'<button class="btn" onclick="kickClient(\''+r.fullId+'\')">'+t('th.kick')+'</button>':'';
    return '<tr><td>'+esc(r.owner)+'</td><td>'+esc(r.target||'-')+'</td><td>'+esc(r.remote||'-')+'</td><td title="'+esc(brutTip)+'">'+st+'</td>'+
      '<td>'+rtt+'</td><td>'+fmtBytes(r.tx)+'</td><td>'+fmtBytes(r.rx)+'</td>'+
      '<td class="hide-sm">'+(r.retries===''?'-':r.retries)+'</td><td class="hide-sm">'+(r.age?fmtDur(r.age):'-')+'</td>'+
      '<td class="hide-sm" title="'+esc(r.epoch?'session key epoch '+r.epoch:'no epoch yet')+'">'+(r.epoch?r.epoch:'-')+'</td>'+
      '<td class="hide-sm">'+encBadge(r.enc)+'</td><td class="hide-sm">'+badge(r.fec)+'</td>'+
      '<td class="hide-sm" title="'+esc(brutTip)+'">'+brut+'</td>'+
      '<td class="hide-sm" style="color:var(--err)" title="'+esc(r.err||r.brutErr)+'">'+esc(String(r.err||r.brutErr).slice(0,40))+'</td><td>'+ops+'</td></tr>';
  }).join('')||'<tr><td colspan="15" style="color:var(--muted)">'+t('no_conns')+'</td></tr>';
}
function renderMacs(data){
  const tb=document.getElementById('macs-body');
  if(data.mode!=='server'){tb.innerHTML='<tr><td colspan="3" style="color:var(--muted)">'+t('srv_only')+'</td></tr>';return;}
  const list=data.mac_table||[];
  tb.innerHTML=list.map(e=>'<tr><td>'+esc(e.mac)+'</td><td>'+esc(e.port)+'</td><td>'+e.age_sec+'s</td></tr>').join('')||
    '<tr><td colspan="3" style="color:var(--muted)">'+t('no_macs')+'</td></tr>';
}
function renderBans(data){
  const tb=document.getElementById('bans-body');
  if(data.mode!=='server'){tb.innerHTML='<tr><td colspan="3" style="color:var(--muted)">'+t('srv_only')+'</td></tr>';return;}
  const bans=data.banned||{};
  tb.innerHTML=Object.entries(bans).map(([id,left])=>'<tr><td title="'+esc(id)+'">'+esc(shortId(id,18))+'</td>'+
    '<td>'+(left===0?'<span class="badge b-dup">'+t('perm')+'</span>':fmtDur(left))+'</td>'+
    '<td><button class="btn gray" onclick="unban(\''+id+'\')">'+t('th.unban')+'</button></td></tr>').join('')||
    '<tr><td colspan="3" style="color:var(--muted)">'+t('no_bans')+'</td></tr>';
}

async function kickClient(id){if(!confirm(t('confirm_kick')))return;
  await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'kick',client_id:id})});fetchStats();}
async function banClient(id,minutes){if(!confirm(t('confirm_ban')))return;
  await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'ban',client_id:id,ttl_minutes:minutes})});fetchStats();}
async function addBan(){const id=document.getElementById('ban-id').value.trim();if(!id)return alert(t('need_id'));
  const m=parseInt(document.getElementById('ban-min').value,10);
  await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'ban',client_id:id,ttl_minutes:isNaN(m)?0:m})});
  document.getElementById('ban-id').value='';document.getElementById('ban-min').value='';fetchStats();}
async function unban(id){await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'unban',client_id:id})});fetchStats();}
async function doAction(action){await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:action})});fetchStats();}
async function setLogLevel(v){await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'loglevel',level:v})});}

// ---------- 设置页：配置查看/保存/热应用 ----------
async function loadConfig(){
  const st=document.getElementById('cfg-status');
  try{
    const res=await fetch(url('/api/config'),AUTH_HDR);
    if(!res.ok){st.textContent=t('set.loaded_err')+' HTTP '+res.status;return;}
    document.getElementById('cfg-editor').value=await res.text();
    st.textContent='';
  }catch(e){st.textContent=t('set.loaded_err')+' '+e;}
}
async function saveConfig(apply){
  const st=document.getElementById('cfg-status');
  let cfg;
  try{cfg=JSON.parse(document.getElementById('cfg-editor').value);}
  catch(e){st.textContent='JSON: '+e.message;return;}
  try{
    const res=await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:apply?'save_apply':'save',config:cfg})});
    const data=await res.json().catch(()=>({}));
    if(!res.ok){st.textContent=(data.error||('HTTP '+res.status));return;}
    if(apply){
      st.textContent=t('set.applied')+(data.needs_restart&&data.needs_restart.length?(' · '+t('set.restart_nr')+' '+data.needs_restart.join(', ')):'');
      setTimeout(fetchStats,500);
    }else{
      st.textContent=t('set.saved');
    }
  }catch(e){st.textContent=String(e);}
}

let logSeq=0,logTimer=null;
function startLogPoll(){stopLogPoll();pollLogs();logTimer=setInterval(pollLogs,2000);}
function stopLogPoll(){if(logTimer){clearInterval(logTimer);logTimer=null;}}
async function pollLogs(){
  try{
    const res=await fetch(url('/api/logs?after='+logSeq),AUTH_HDR);
    if(!res.ok)return;
    const lines=await res.json();
    if(!lines.length)return;
    const box=document.getElementById('logbox');
    box.innerHTML+=lines.map(l=>'<div class="lv-'+l.level+'">['+l.time+'] '+l.level+' '+esc(l.msg)+'</div>').join('');
    logSeq=lines[lines.length-1].seq;
    if(document.getElementById('autoscroll').checked)box.scrollTop=box.scrollHeight;
  }catch(e){}
}
function clearLog(){logSeq=0;document.getElementById('logbox').innerHTML='';}
function downloadLog(){
  const blob=new Blob([document.getElementById('logbox').innerText],{type:'text/plain;charset=utf-8'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download='tlsvpn-dashboard-'+new Date().toISOString().replace(/[:.]/g,'-')+'.log';a.click();
}

	let THEME=localStorage.getItem('tlsvpn_theme')||'system';
function cssv(n){return getComputedStyle(document.documentElement).getPropertyValue(n).trim()||'#888';}
function isDark(){return THEME==='dark'||(THEME==='system'&&matchMedia('prefers-color-scheme: dark').matches);}
function applyTheme(){
  document.documentElement.dataset.theme=isDark()?'dark':'light';
  const el=document.getElementById('theme');
  if(el)el.value=THEME;
}
function setTheme(v){THEME=v;localStorage.setItem('tlsvpn_theme',v);applyTheme();
  if(txHist.length||rxHist.length)drawChart();}
matchMedia('prefers-color-scheme: dark').addEventListener('change',function(){if(THEME==='system'){applyTheme();if(txHist.length||rxHist.length)drawChart();}});

let prev={},lastT=0;const txHist=[],rxHist=[];const MAXPTS=60;
applyI18n();setRefresh(String(REFRESH));fetchStats();
</script>
</body>
</html>`

func startWebServer(addr string, srv *Server, cli *Client, webAuth, webCert, webKey string, cfg *Config) {
	mgr := NewWebManager(srv, cli, cfg, nil)
	mux := http.NewServeMux()
	mgr.mux = mux
	auth := mgr.auth // 认证串可热更：经 mgr 读取当前配置

	// 仪表盘页面（与 API 一致地受认证保护）
	mux.HandleFunc("/", auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// no-store：面板 HTML 编译进二进制，版本换了旧页面不会自己变，
		// 不换地址栏就看不到新代码，排查时会被误判成"改了没生效"。
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte(dashboardHTML))
	}))

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
		// encAlgoNone=0（无内层加密，只剩 TLS）/ encAlgoGCM=2（AES-256-GCM），
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
		// 服务端 encrypt 开启时对所有会话给出 GCM：无内层加密的回退路径已移除。
		n.EncAlgo = encAlgoGCM
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
