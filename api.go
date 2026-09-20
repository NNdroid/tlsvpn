package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
	Mem         memStatsJSON         `json:"mem"`
	IPPool      *ipPoolJSON          `json:"ip_pool,omitempty"`
	Banned      map[string]int64     `json:"banned,omitempty"`
	MACs        []MACEntry           `json:"mac_table,omitempty"`
	Conns       []connSnapshot       `json:"conns,omitempty"`        // client 模式连接明细
	ServerConns []serverConnSnapshot `json:"server_conns,omitempty"` // server 模式物理连接明细
	FecMode     string               `json:"fec_mode,omitempty"`     // client 模式 FEC 状态
	EncAlgo     int                  `json:"enc_algo,omitempty"`
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
}

type fecStatsJSON struct {
	Enabled   bool   `json:"enabled"`
	ParityTx  uint64 `json:"parity_tx"`
	Recovered uint64 `json:"recovered"`
	Lost      uint64 `json:"lost"`
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

// basicAuthWrapper 为管理面加一层 Basic Auth；expected 为空时放行
// （未配置 -web-auth，保持旧行为；文档强烈建议配置）。
func basicAuthWrapper(expected string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if expected == "" {
			next(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(user+":"+pass), []byte(expected)) != 1 {
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
body { font-family:'Segoe UI',Tahoma,sans-serif; background:#121212; color:#e0e0e0; margin:0; padding:20px; }
.wrap { max-width:1200px; margin:0 auto; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:14px; }
.card { background:#1e1e1e; border-radius:8px; padding:14px 18px; box-shadow:0 4px 6px rgba(0,0,0,.3); margin-bottom:14px; }
.card.wide { grid-column:1/-1; }
h1 { color:#bb86fc; margin:0 0 12px; font-size:1.35em; display:flex; align-items:center; flex-wrap:wrap; gap:10px; }
h1 small { color:#888; font-weight:normal; font-size:.55em; }
.kpi { font-size:1.5em; font-weight:bold; color:#03dac6; }
.kpi small { font-size:.55em; color:#888; font-weight:normal; }
.sub { color:#999; font-size:.84em; margin-top:3px; }
table { width:100%; border-collapse:collapse; margin-top:8px; }
th,td { padding:7px 9px; text-align:left; border-bottom:1px solid #333; font-size:.88em; white-space:nowrap; }
th { background:#2c2c2c; color:#bbb; }
.speed { color:#03dac6; font-weight:bold; }
.badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:.78em; font-weight:600; }
.b-on { background:#1b3a2f; color:#4ee1a0; } .b-dup { background:#3a341b; color:#e1c94e; } .b-off { background:#333; color:#888; }
.btn { padding:3px 10px; background:#cf6679; color:white; border:none; border-radius:4px; cursor:pointer; font-size:.82em; margin-right:4px; }
.btn:hover { background:#ff7597; }
.btn.blue { background:#3d5a80; } .btn.blue:hover { background:#5b84b1; }
.btn.gray { background:#444; } .btn.gray:hover { background:#666; }
#chart { width:100%; height:170px; display:block; }
.legend { font-size:.8em; color:#999; margin-top:6px; }
.legend span { margin-right:14px; }
.dot { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:4px; }
#logbox { background:#0d0d0d; border-radius:6px; padding:10px; height:220px; overflow-y:auto; font:12px/1.5 Consolas,monospace; }
#logbox .lv-WARN { color:#e1c94e; } #logbox .lv-ERROR,#logbox .lv-PANIC { color:#ff7597; } #logbox .lv-DEBUG { color:#666; }
.logbar { display:flex; gap:8px; align-items:center; margin-top:8px; flex-wrap:wrap; }
.logbar select,.logbar input { background:#2a2a2a; color:#ddd; border:1px solid #444; border-radius:4px; padding:4px 8px; font-size:.85em; }
.logbar input { width:130px; }
.tabs { display:flex; gap:6px; margin-bottom:10px; flex-wrap:wrap; }
.tabs button { background:#2a2a2a; color:#bbb; border:none; border-radius:4px 4px 0 0; padding:6px 14px; cursor:pointer; font-size:.88em; }
.tabs button.on { background:#bb86fc; color:#121212; font-weight:600; }
.pane { display:none; } .pane.on { display:block; }
footer { text-align:center; color:#666; font-size:.78em; margin-top:16px; }
@media (max-width:640px){ th,td{padding:5px;} .hide-sm{display:none;} }
</style>
</head>
<body>
<div class="wrap">
<h1>🚀 tlsvpn <span id="mode">…</span><small id="meta"></small>
  <span style="margin-left:auto"></span>
  <select id="lang" onchange="setLang(this.value)" style="background:#2a2a2a;color:#ddd;border:1px solid #444;border-radius:4px;padding:4px;font-size:.5em;">
    <option value="zh-CN">中文</option><option value="en">English</option>
  </select>
  <select id="refresh" onchange="setRefresh(this.value)" style="background:#2a2a2a;color:#ddd;border:1px solid #444;border-radius:4px;padding:4px;font-size:.5em;" data-i18n-title="refresh_tip">
    <option value="2000">2s</option><option value="5000">5s</option><option value="10000">10s</option>
  </select>
</h1>
<div class="grid">
  <div class="card"><div class="sub" data-i18n="kpi.active">-</div><div class="kpi" id="active-clients">0</div><div class="sub" id="conns-sub">-</div></div>
  <div class="card"><div class="sub" data-i18n="kpi.tx">-</div><div class="kpi" id="total-tx">0 B</div><div class="sub" id="total-tx-speed" class="speed">-</div></div>
  <div class="card"><div class="sub" data-i18n="kpi.rx">-</div><div class="kpi" id="total-rx">0 B</div><div class="sub" id="total-rx-speed" class="speed">-</div></div>
  <div class="card"><div class="sub" data-i18n="kpi.uptime">-</div><div class="kpi" id="uptime">-</div><div class="sub"><span data-i18n="kpi.version">-</span> <span id="ver">-</span> · <a href="#" onclick="doAction('gc');return false;" style="color:#5b84b1" data-i18n="kpi.gc">-</a></div></div>
  <div class="card"><div class="sub" data-i18n="kpi.fec">-</div><div class="kpi" id="fec-kpi">-</div><div class="sub"><span data-i18n="kpi.parity">-</span> <span id="parity">-</span> · <span data-i18n="kpi.dropped">-</span> <span id="dropped">-</span></div></div>
  <div class="card"><div class="sub" data-i18n="kpi.mem">-</div><div class="kpi" id="mem">-</div><div class="sub"><span data-i18n="kpi.goroutines">-</span> <span id="goroutines">-</span></div></div>
  <div class="card" id="ippool-card" style="display:none"><div class="sub" data-i18n="kpi.pool">-</div><div class="kpi" id="ippool-kpi">-</div><div class="sub"><span data-i18n="kpi.v6used">-</span> <span id="v6used">-</span></div></div>
</div>
<div class="card wide"><h2 data-i18n="chart.title">-</h2>
  <canvas id="chart" width="1160" height="170"></canvas>
  <div class="legend"><span><i class="dot" style="background:#03dac6"></i><span data-i18n="legend.up">-</span></span><span><i class="dot" style="background:#bb86fc"></i><span data-i18n="legend.down">-</span></span></div></div>

<div class="card wide">
  <div class="tabs">
    <button class="on" data-pane="clients" onclick="showPane(this)" data-i18n="tab.clients">-</button>
    <button data-pane="conns" onclick="showPane(this)" data-i18n="tab.conns">-</button>
    <button data-pane="macs" onclick="showPane(this)" data-i18n="tab.macs">-</button>
    <button data-pane="bans" onclick="showPane(this)" data-i18n="tab.bans">-</button>
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
      <thead><tr><th data-i18n="th.owner">-</th><th data-i18n="th.target">-</th><th data-i18n="th.remote">-</th><th data-i18n="th.state">-</th><th data-i18n="th.rtt">-</th><th data-i18n="th.tx">-</th><th data-i18n="th.rx">-</th><th class="hide-sm" data-i18n="th.retries">-</th><th class="hide-sm" data-i18n="th.age">-</th><th class="hide-sm" data-i18n="th.err">-</th><th data-i18n="th.ops">-</th></tr></thead>
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

  <div class="pane" id="pane-logs">
    <div id="logbox"></div>
    <div class="logbar">
      <label style="font-size:.85em;color:#999"><span data-i18n="logs.level">-</span>
        <select id="loglevel" onchange="setLogLevel(this.value)">
          <option value="debug">debug</option><option value="info">info</option>
          <option value="warn">warn</option><option value="error">error</option>
        </select>
      </label>
      <label style="font-size:.85em;color:#999"><input type="checkbox" id="autoscroll" checked> <span data-i18n="logs.autoscroll">-</span></label>
      <button class="btn gray" onclick="clearLog()" data-i18n="logs.clear">-</button>
      <button class="btn gray" onclick="downloadLog()" data-i18n="logs.download">-</button>
    </div>
  </div>

  <div class="pane" id="pane-settings">
    <div class="sub" style="margin-bottom:8px" data-i18n="set.hint">-</div>
    <div class="logbar"><button class="btn blue" onclick="loadConfig()" data-i18n="set.load">-</button>
      <button class="btn gray" onclick="saveConfig(false)" data-i18n="set.save">-</button>
      <button class="btn" onclick="saveConfig(true)" data-i18n="set.apply">-</button>
      <span id="cfg-status" style="font-size:.85em;color:#999"></span></div>
    <div style="margin-top:10px"><textarea id="cfg-editor" spellcheck="false"
      style="width:100%;height:340px;background:#0d0d0d;color:#cde;border:1px solid #333;border-radius:6px;padding:10px;font:12px/1.5 Consolas,monospace"></textarea></div>
  </div>
</div>
<footer><span id="footer-text"></span> · <span id="tls-flag"></span></footer>
</div>
<script>
const I18N={
'zh-CN':{kpi:{active:'活跃客户端/设备',tcp:'TCP 连接',tx:'总发送',rx:'总接收',uptime:'运行时长',version:'版本',gc:'立即回收',fec:'FEC 恢复 / 确认丢失',parity:'校验帧',dropped:'丢帧(队列)',mem:'内存',goroutines:'Goroutines:',pool:'IPv4 地址池',v6used:'IPv6 已分配:'},
 chart:{title:'吞吐趋势',win:'(近 120 秒)'},legend:{up:'上行',down:'下行'},
 tab:{clients:'客户端',conns:'连接明细',macs:'MAC 表',bans:'封禁',logs:'日志',settings:'设置'},
 th:{id:'ID',v4:'IPv4',v6:'IPv6',mac:'MAC',tcp:'TCP',tx:'TX (发)',rx:'RX (收)',txs:'↑ 速率',rxs:'↓ 速率',fec:'FEC',enc:'加密',ops:'操作',kick:'踢出',ban:'封禁',unban:'解封',owner:'客户端',target:'目标',remote:'对端',state:'状态',rtt:'RTT',retries:'重试',age:'在线',err:'最近错误'},
 m:{port:'端口',seen:'最近活跃'},bans:{id_ph:'ClientID（可短前缀）',min_ph:'分钟（留空=永久）',add:'封禁',refresh:'刷新',left:'剩余'},
 logs:{level:'级别',autoscroll:'自动滚动',clear:'清屏',download:'下载日志'},
 filter_ph:'输入关键字过滤…',no_clients:'暂无客户端',no_conns:'无连接',no_macs:'尚未学习到 MAC',no_bans:'无封禁记录',srv_only:'仅服务端模式提供',
 perm:'永久',confirm_kick:'确定要强制断开该客户端吗？',confirm_ban:'确定封禁该客户端吗？',need_id:'请输入 ClientID',
 st:{up:'up',connecting:'connecting'},
 badge:{dup:'复制',off:'关闭',ctr:'CTR',plain:'明文'},
 u:{day:'天',hour:'时',min:'分',sec:'秒'},footer:'数据每 {n} 秒刷新',refresh_tip:'刷新间隔',
 tls_http:'HTTP（建议启用 HTTPS）',mode_local:'本机',
 set:{hint:'编辑 JSON 配置。保存：写回配置文件；保存并应用：写回并立即热更运行参数（列出的字段需重启生效）。',
   load:'重新加载',save:'保存',apply:'保存并应用',saved:'已保存',applied:'已保存并应用',restart_nr:'需重启生效:',loaded_err:'加载失败:'}},
'en':{kpi:{active:'Active clients',tcp:'TCP connections',tx:'Total sent',rx:'Total received',uptime:'Uptime',version:'Version',gc:'GC now',fec:'FEC recovered / confirmed lost',parity:'Parity frames',dropped:'Dropped (queue)',mem:'Memory',goroutines:'Goroutines:',pool:'IPv4 pool',v6used:'IPv6 allocated:'},
 chart:{title:'Throughput',win:'(last 120s)'},legend:{up:'Up',down:'Down'},
 tab:{clients:'Clients',conns:'Connections',macs:'MAC table',bans:'Bans',logs:'Logs',settings:'Settings'},
 th:{id:'ID',v4:'IPv4',v6:'IPv6',mac:'MAC',tcp:'TCP',tx:'TX',rx:'RX',txs:'↑ Rate',rxs:'↓ Rate',fec:'FEC',enc:'Encrypt',ops:'Actions',kick:'Kick',ban:'Ban',unban:'Unban',owner:'Client',target:'Target',remote:'Remote',state:'State',rtt:'RTT',retries:'Retries',age:'Uptime',err:'Last error'},
 m:{port:'Port',seen:'Last seen'},bans:{id_ph:'ClientID (short prefix ok)',min_ph:'Minutes (empty = permanent)',add:'Ban',refresh:'Refresh',left:'Remaining'},
 logs:{level:'Level',autoscroll:'Auto scroll',clear:'Clear',download:'Download'},
 filter_ph:'Type to filter…',no_clients:'No clients yet',no_conns:'No connections',no_macs:'No MACs learned yet',no_bans:'No banned clients',srv_only:'Server mode only',
 perm:'Permanent',confirm_kick:'Force-disconnect this client?',confirm_ban:'Ban this client?',need_id:'Please enter a ClientID',
 st:{up:'up',connecting:'connecting'},
 badge:{dup:'Dup',off:'Off',ctr:'CTR',plain:'Plain'},
 u:{day:'d',hour:'h',min:'m',sec:'s'},footer:'Refreshing every {n}s',refresh_tip:'Refresh interval',
 tls_http:'HTTP (HTTPS recommended)',mode_local:'local',
 set:{hint:'Edit the JSON config. Save: write back to the config file. Save & apply: write back and hot-apply runtime parameters (listed fields require a restart).',
   load:'Reload',save:'Save',apply:'Save & apply',saved:'Saved',applied:'Saved & applied',restart_nr:'Needs restart:',loaded_err:'Load failed:'}}};
let LANG=localStorage.getItem('tlsvpn_lang')||((navigator.language||'zh-CN').toLowerCase().startsWith('zh')?'zh-CN':'en');
function t(path){let o=I18N[LANG];for(const k of path.split('.'))o=o?o[k]:undefined;return o===undefined?(I18N['en'][path]||path):o;}
function applyI18n(){
  document.documentElement.lang=LANG;
  document.querySelectorAll('[data-i18n]').forEach(el=>el.textContent=t(el.dataset.i18n));
  document.querySelectorAll('[data-i18n-ph]').forEach(el=>el.placeholder=t(el.dataset.i18nPh));
  document.getElementById('lang').value=LANG;
  document.getElementById('refresh').value=String(REFRESH);
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
function esc(x){return String(x==null?'':x).replace(/</g,'&lt;');}
function showPane(btn){document.querySelectorAll('.tabs button').forEach(b=>b.classList.remove('on'));
  document.querySelectorAll('.pane').forEach(p=>p.classList.remove('on'));
  btn.classList.add('on');document.getElementById('pane-'+btn.dataset.pane).classList.add('on');
  if(btn.dataset.pane==='logs')startLogPoll();else stopLogPoll();
  if(btn.dataset.pane==='settings')loadConfig();}

function drawChart(){
  const c=document.getElementById('chart'),ctx=c.getContext('2d'),W=c.width,H=c.height;
  ctx.clearRect(0,0,W,H);ctx.strokeStyle='#2a2a2a';
  for(let i=1;i<4;i++){ctx.beginPath();ctx.moveTo(0,H*i/4);ctx.lineTo(W,H*i/4);ctx.stroke();}
  if(txHist.length<2)return;
  const max=Math.max(...txHist,...rxHist,1);
  const plot=(h,col)=>{ctx.strokeStyle=col;ctx.lineWidth=2;ctx.beginPath();
    h.forEach((v,i)=>{const x=i/(MAXPTS-1)*W,y=H-6-(v/max)*(H-20);i?ctx.lineTo(x,y):ctx.moveTo(x,y);});ctx.stroke();};
  plot(txHist,'#03dac6');plot(rxHist,'#bb86fc');
  ctx.fillStyle='#888';ctx.font='11px sans-serif';ctx.fillText(fmtBytes(max),4,12);
}

let REFRESH=parseInt(localStorage.getItem('tlsvpn_refresh')||'2000',10);
let statsTimer=null;
function setRefresh(v){REFRESH=parseInt(v,10);localStorage.setItem('tlsvpn_refresh',v);
  document.getElementById('footer-text').textContent=t('footer').replace('{n}',REFRESH/1000);
  restartLoop();}
function restartLoop(){if(statsTimer)clearInterval(statsTimer);statsTimer=setInterval(fetchStats,REFRESH);}

async function api(path,opts){opts=opts||{};opts.headers=Object.assign({'X-Requested-With':'tlsvpn'},opts.headers||{});return fetch(path,opts);}

function passFilter(obj,f){return !f||JSON.stringify(obj).toLowerCase().includes(f);}

async function fetchStats(){
  try{
    const res=await fetch('/api/stats');
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
    document.getElementById('clients-body').innerHTML=tbody||'<tr><td colspan="12" style="color:#777">'+t('no_clients')+'</td></tr>';

    const f=data.fec||{};
    document.getElementById('fec-kpi').innerHTML=(f.recovered||0)+' <small>/</small> '+(f.lost||0);
    document.getElementById('parity').innerText=f.parity_tx||0;
    document.getElementById('dropped').innerText=data.dropped_frames||0;
    const m=data.mem||{};
    document.getElementById('mem').innerHTML=(m.heap_alloc_mb||0).toFixed(1)+'<small> MB</small>';
    document.getElementById('goroutines').innerText=m.num_goroutine||0;

    if(data.ip_pool){document.getElementById('ippool-card').style.display='';
      document.getElementById('ippool-kpi').innerHTML=data.ip_pool.v4_used+'<small> / '+data.ip_pool.v4_total+'</small>';
      document.getElementById('v6used').innerText=data.ip_pool.v6_used;}

    const meta=[];if(data.enc_algo===2)meta.push('GCM');else if(data.enc_algo===1)meta.push(t('badge.ctr'));
    if(data.fec_mode&&data.fec_mode!=='off')meta.push('FEC '+data.fec_mode);
    document.getElementById('meta').innerText=meta.join(' · ');

    renderConns(data);renderMacs(data);renderBans(data);
  }catch(e){console.error('stats fetch failed',e);}
}

function renderConns(data){
  const tb=document.getElementById('conns-body');
  let rows=[];
  if(data.mode==='server'){
    (data.server_conns||[]).forEach(c=>rows.push({owner:shortId(c.client_id,10),fullId:c.client_id,target:'',remote:c.remote,state:'up',rtt:c.rtt_ms,tx:c.tx_bytes,rx:c.rx_bytes,retries:'',age:c.age_sec,err:''}));
  }else{
    (data.conns||[]).forEach(c=>rows.push({owner:'local',fullId:null,target:c.target,remote:c.remote,state:c.state,rtt:c.rtt_ms,tx:c.tx_bytes,rx:c.rx_bytes,retries:c.retries,age:c.age_sec,err:c.last_error||''}));
  }
  const f=(document.getElementById('conn-filter').value||'').toLowerCase();
  if(f)rows=rows.filter(r=>JSON.stringify(r).toLowerCase().includes(f));
  tb.innerHTML=rows.map(r=>{
    const st=r.state==='up'?'<span class="badge b-on">'+t('st.up')+'</span>':
      r.state==='connecting'?'<span class="badge b-dup">'+t('st.connecting')+'</span>':
      '<span class="badge b-off">'+esc(r.state||'-')+'</span>';
    const rtt=r.rtt>=100000?'-':r.rtt+' ms';
    const ops=(data.mode==='server'&&r.fullId)?'<button class="btn" onclick="kickClient(\''+r.fullId+'\')">'+t('th.kick')+'</button>':'';
    return '<tr><td>'+esc(r.owner)+'</td><td>'+esc(r.target||'-')+'</td><td>'+esc(r.remote||'-')+'</td><td>'+st+'</td>'+
      '<td>'+rtt+'</td><td>'+fmtBytes(r.tx)+'</td><td>'+fmtBytes(r.rx)+'</td>'+
      '<td class="hide-sm">'+(r.retries===''?'-':r.retries)+'</td><td class="hide-sm">'+(r.age?fmtDur(r.age):'-')+'</td>'+
      '<td class="hide-sm" style="color:#c66" title="'+esc(r.err)+'">'+esc(String(r.err).slice(0,40))+'</td><td>'+ops+'</td></tr>';
  }).join('')||'<tr><td colspan="11" style="color:#777">'+t('no_conns')+'</td></tr>';
}
function renderMacs(data){
  const tb=document.getElementById('macs-body');
  if(data.mode!=='server'){tb.innerHTML='<tr><td colspan="3" style="color:#777">'+t('srv_only')+'</td></tr>';return;}
  const list=data.mac_table||[];
  tb.innerHTML=list.map(e=>'<tr><td>'+esc(e.mac)+'</td><td>'+esc(e.port)+'</td><td>'+e.age_sec+'s</td></tr>').join('')||
    '<tr><td colspan="3" style="color:#777">'+t('no_macs')+'</td></tr>';
}
function renderBans(data){
  const tb=document.getElementById('bans-body');
  if(data.mode!=='server'){tb.innerHTML='<tr><td colspan="3" style="color:#777">'+t('srv_only')+'</td></tr>';return;}
  const bans=data.banned||{};
  tb.innerHTML=Object.entries(bans).map(([id,left])=>'<tr><td title="'+esc(id)+'">'+esc(shortId(id,18))+'</td>'+
    '<td>'+(left===0?'<span class="badge b-dup">'+t('perm')+'</span>':fmtDur(left))+'</td>'+
    '<td><button class="btn gray" onclick="unban(\''+id+'\')">'+t('th.unban')+'</button></td></tr>').join('')||
    '<tr><td colspan="3" style="color:#777">'+t('no_bans')+'</td></tr>';
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
    const res=await fetch('/api/config');
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
    const res=await fetch('/api/logs?after='+logSeq);
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
		w.Write([]byte(dashboardHTML))
	}))

	// 状态统计 API
	mux.HandleFunc("/api/stats", auth(func(w http.ResponseWriter, r *http.Request) {
		startWebStatsHandler(w, r, srv, cli)
	}))

	// 当前生效配置（面板"设置"页）
	mux.HandleFunc("/api/config", auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data, _ := json.MarshalIndent(mgr.Config(), "", "  ")
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
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
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
			// 2) 热更：日志级别 + web 监听 + 双端可热更字段
			setRuntimeLogLevel(newCfg.LogLevel)
			mgr.SetConfig(newCfg)
			if srv != nil {
				srv.ApplyConfig(newCfg)
			}
			if cli != nil {
				cli.ApplyConfig(newCfg)
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
	dec := json.NewDecoder(strings.NewReader(string(posted)))
	dec.DisallowUnknownFields()
	newCfg := &Config{}
	if err := dec.Decode(newCfg); err != nil {
		return nil, nil, fmt.Errorf("invalid config: %v", err)
	}
	// 面板提交的内容不允许自行改写来源路径与 mode 切换（mode 切换等于换进程形态）
	newCfg.SourcePath = old.SourcePath
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
			var rec, lost, parity uint64
			for _, s2 := range srv.activeClients {
				if s2.FecDec != nil {
					r2, l2 := s2.FecDec.FECStats()
					rec += r2
					lost += l2
				}
				parity += s2.Port.ParitySent()
			}
			srv.mu.RUnlock()
			emit("tlsvpn_fec_recovered_frames_total", "Frames recovered by XOR FEC", "counter", fmt.Sprint(rec))
			emit("tlsvpn_fec_lost_frames_total", "Frames confirmed lost despite FEC", "counter", fmt.Sprint(lost))
			emit("tlsvpn_fec_parity_frames_total", "Parity frames generated", "counter", fmt.Sprint(parity))
			emit("tlsvpn_tap_write_errors_total", "Frames dropped on TAP write failure", "counter", fmt.Sprint(srv.tapWriteErrs.Load()))
			if srv.vswitch != nil {
				emit("tlsvpn_spoofed_src_dropped_frames_total", "Frames dropped claiming another session's source MAC", "counter", fmt.Sprint(srv.vswitch.spoofDrops.Load()))
				emit("tlsvpn_broadcast_dropped_frames_total", "Broadcast frames dropped over the per-port flood budget", "counter", fmt.Sprint(srv.vswitch.floodDrops.Load()))
			}
			srv.mu.RLock()
			banned := len(srv.banned)
			pskBuckets := len(srv.pskFail)
			srv.mu.RUnlock()
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
				v4: session.IPv4, v6: session.IPv6, mac: session.MAC, fec: session.FecMode, enc: encAlgoForDisplay(session.EncAlgo, session.Encrypt), conns: conns,
				txB: atomic.LoadUint64(&session.TxBytes),
				rxB: atomic.LoadUint64(&session.RxBytes),
				txP: atomic.LoadUint64(&session.TxPackets),
				rxP: atomic.LoadUint64(&session.RxPackets),
				age: uint64(time.Since(session.CreatedAt) / time.Second),
			}
		}
		stats.Banned = srv.BanList()
		var rec, lost, parity uint64
		for _, session := range srv.activeClients {
			if session.FecDec != nil {
				r2, l2 := session.FecDec.FECStats()
				rec += r2
				lost += l2
			}
			parity += session.Port.ParitySent()
		}
		stats.IPPool = &ipPoolJSON{}
		stats.IPPool.V4Used, stats.IPPool.V4Total, stats.IPPool.V6Used = srv.IPPoolStatus()
		stats.MACs = srv.MACSnapshot()
		srv.mu.RUnlock()
		// 注意：snapshotServerConns 内部会再次拿读锁，必须在 RUnlock 之后调用，
		// 否则同 goroutine 递归 RLock 在写者排队时会死锁。
		stats.ServerConns = srv.snapshotServerConns()
		stats.Fec = fecStatsJSON{Enabled: true, ParityTx: parity, Recovered: rec, Lost: lost}
		stats.TapErrors = srv.tapWriteErrs.Load()

		for id, snap := range snapClients {
			stats.Clients[id] = map[string]interface{}{
				"ipv4": snap.v4, "ipv6": snap.v6, "mac": snap.mac, "active_conns": snap.conns,
				"tx_bytes": snap.txB, "rx_bytes": snap.rxB, "tx_packets": snap.txP, "rx_packets": snap.rxP,
				"fec": snap.fec, "enc_algo": snap.enc, "uptime_sec": snap.age,
			}
		}
		stats.ServerConns = srv.snapshotServerConns()
	} else if cli != nil {
		stats.Mode = "client"
		stats.UptimeSec = uint64(time.Since(cli.startedAt) / time.Second)
		cli.sessionMu.Lock()
		v4, v6 := cli.assignedV4, cli.assignedV6
		mac := cli.macAddr
		cli.sessionMu.Unlock()
		conns := int(atomic.LoadInt32(&cli.liveConns))
		fec := cli.fecStatus
		lv := cli.live.Load()
		// 发射前归一化成 0/1/2：原始算法号里 0 同时表示"未加密"和 legacy CTR，
		// 而 GCM-v2=3 面板不认识会落进"明文"兜底分支。
		enc := encAlgoForDisplay(cli.encAlgo, lv != nil && lv.encrypt)
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
		stats.TapErrors = cli.tapWriteErrs.Load()
		stats.FecMode = fec
		stats.EncAlgo = enc
	}

	json.NewEncoder(w).Encode(stats)
}
