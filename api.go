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

const appVersion = "1.1.0"

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
	LogLevel string           `json:"log_level"`
	Dropped  uint64           `json:"dropped_frames"`
	Fec      fecStatsJSON     `json:"fec"`
	Mem      memStatsJSON     `json:"mem"`
	IPPool   *ipPoolJSON      `json:"ip_pool,omitempty"`
	Banned   map[string]int64 `json:"banned,omitempty"`
	MACs     []MACEntry       `json:"mac_table,omitempty"`
	Conns    []connSnapshot   `json:"conns,omitempty"`    // client 模式连接明细
	FecMode  string           `json:"fec_mode,omitempty"` // client 模式 FEC 状态
	EncAlgo  int              `json:"enc_algo,omitempty"`
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
h1 { color:#bb86fc; margin:0 0 12px; font-size:1.35em; }
h1 small { color:#888; font-weight:normal; font-size:.55em; margin-left:8px; }
h2 { margin:0 0 10px; color:#bb86fc; font-size:1.02em; }
.kpi { font-size:1.5em; font-weight:bold; color:#03dac6; }
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
.logbar input { width:110px; }
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
<h1>🚀 tlsvpn <span id="mode">…</span><small id="meta"></small></h1>
<div class="grid">
  <div class="card"><div class="sub">活跃客户端/设备</div><div class="kpi" id="active-clients">0</div><div class="sub" id="conns-sub">TCP 连接: -</div></div>
  <div class="card"><div class="sub">总发送</div><div class="kpi" id="total-tx">0 B</div><div class="sub">↑ <span id="total-tx-speed" class="speed">0 B/s</span></div></div>
  <div class="card"><div class="sub">总接收</div><div class="kpi" id="total-rx">0 B</div><div class="sub">↓ <span id="total-rx-speed" class="speed">0 B/s</span></div></div>
  <div class="card"><div class="sub">运行时长</div><div class="kpi" id="uptime">-</div><div class="sub">版本 <span id="ver">-</span> · GC <a href="#" onclick="doAction('gc');return false;" style="color:#5b84b1">立即回收</a></div></div>
  <div class="card"><div class="sub">FEC 恢复 / 确认丢失</div><div class="kpi" id="fec-kpi">-</div><div class="sub">校验帧 <span id="parity">-</span> · 丢帧(队列) <span id="dropped">-</span></div></div>
  <div class="card"><div class="sub">内存 / 协程</div><div class="kpi" id="mem">-</div><div class="sub">Goroutines: <span id="goroutines">-</span></div></div>
  <div class="card" id="ippool-card" style="display:none"><div class="sub">IPv4 地址池</div><div class="kpi" id="ippool-kpi">-</div><div class="sub">IPv6 已分配: <span id="v6used">-</span></div></div>
</div>
<div class="card wide"><h2>吞吐趋势 <span style="font-size:.7em;color:#888">(近 120 秒)</span></h2>
  <canvas id="chart" width="1160" height="170"></canvas>
  <div class="legend"><span><i class="dot" style="background:#03dac6"></i>上行</span><span><i class="dot" style="background:#bb86fc"></i>下行</span></div></div>

<div class="card wide">
  <div class="tabs">
    <button class="on" data-pane="clients" onclick="showPane(this)">客户端</button>
    <button data-pane="conns" onclick="showPane(this)">连接明细</button>
    <button data-pane="macs" id="macs-tab" onclick="showPane(this)">MAC 表</button>
    <button data-pane="bans" id="bans-tab" onclick="showPane(this)">封禁</button>
    <button data-pane="logs" onclick="showPane(this)">日志</button>
  </div>

  <div class="pane on" id="pane-clients">
    <div style="overflow-x:auto"><table>
      <thead><tr><th>ID</th><th>IPv4</th><th class="hide-sm">IPv6</th><th class="hide-sm">MAC</th><th>TCP</th><th>TX (发)</th><th>RX (收)</th><th>↑ 速率</th><th>↓ 速率</th><th class="hide-sm">FEC</th><th class="hide-sm">加密</th><th>操作</th></tr></thead>
      <tbody id="clients-body"></tbody>
    </table></div>
  </div>

  <div class="pane" id="pane-conns"><div style="overflow-x:auto"><table>
    <thead><tr><th>#</th><th>目标</th><th>对端</th><th>状态</th><th>RTT</th><th>TX</th><th>RX</th><th class="hide-sm">重试</th><th class="hide-sm">在线</th><th class="hide-sm">最近错误</th><th>操作</th></tr></thead>
    <tbody id="conns-body"><tr><td colspan="11" style="color:#777">仅客户端模式提供</td></tr></tbody>
  </table></div></div>

  <div class="pane" id="pane-macs"><div style="overflow-x:auto"><table>
    <thead><tr><th>MAC</th><th>端口</th><th>最近活跃</th></tr></thead>
    <tbody id="macs-body"><tr><td colspan="3" style="color:#777">仅服务端模式提供</td></tr></tbody>
  </table></div></div>

  <div class="pane" id="pane-bans">
    <div class="logbar"><input id="ban-id" placeholder="ClientID（可短前缀）"><input id="ban-min" placeholder="分钟（留空=永久）" style="width:150px">
    <button class="btn blue" onclick="addBan()">封禁</button><button class="btn gray" onclick="loadBans()">刷新</button></div>
    <div style="overflow-x:auto"><table>
      <thead><tr><th>ClientID</th><th>剩余</th><th>操作</th></tr></thead>
      <tbody id="bans-body"><tr><td colspan="3" style="color:#777">仅服务端模式提供</td></tr></tbody>
    </table></div>
  </div>

  <div class="pane" id="pane-logs">
    <div id="logbox"></div>
    <div class="logbar">
      <label style="font-size:.85em;color:#999">级别
        <select id="loglevel" onchange="setLogLevel(this.value)">
          <option value="debug">debug</option><option value="info">info</option>
          <option value="warn">warn</option><option value="error">error</option>
        </select>
      </label>
      <label style="font-size:.85em;color:#999"><input type="checkbox" id="autoscroll" checked> 自动滚动</label>
      <button class="btn gray" onclick="logSeq=0;document.getElementById('logbox').innerHTML=''">清屏</button>
    </div>
  </div>
</div>
<footer>tlsvpn dashboard · 数据每 2 秒刷新 · <span id="tls-flag"></span></footer>
</div>
<script>
const MAXPTS=60;let prev={},lastT=0;const txHist=[],rxHist=[];
let logSeq=0,logTimer=null;

function fmtBytes(b,s=false){
  if(!isFinite(b)||b<=0)return '0 '+(s?'B/s':'B');
  const u=['B','KB','MB','GB','TB'],i=Math.min(Math.floor(Math.log(b)/Math.log(1024)),4);
  return parseFloat((b/Math.pow(1024,i)).toFixed(2))+' '+u[i]+(s?'/s':'');
}
function fmtDur(s){s=Math.floor(s);const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
  if(d>0)return d+'天'+h+'时';if(h>0)return h+'时'+m+'分';if(m>0)return m+'分'+(s%60)+'秒';return s+'秒';}
function badge(f){if(!f||f==='off')return '<span class="badge b-off">关闭</span>';
  if(f==='dup')return '<span class="badge b-dup">复制</span>';return '<span class="badge b-on">'+f+'</span>';}
function encBadge(a){if(a===2)return '<span class="badge b-on">GCM</span>';
  if(a===1)return '<span class="badge b-dup">CTR</span>';return '<span class="badge b-off">明文</span>';}
function showPane(btn){document.querySelectorAll('.tabs button').forEach(b=>b.classList.remove('on'));
  document.querySelectorAll('.pane').forEach(p=>p.classList.remove('on'));
  btn.classList.add('on');document.getElementById('pane-'+btn.dataset.pane).classList.add('on');
  if(btn.dataset.pane==='logs')startLogPoll();else stopLogPoll();}

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

async function api(path,opts){opts=opts||{};opts.headers=Object.assign({'X-Requested-With':'tlsvpn'},opts.headers||{});return fetch(path,opts);}

async function fetchStats(){
  try{
    const res=await fetch('/api/stats');
    if(res.status===401){document.body.innerHTML='<div class="card"><h2>401</h2><p>需要认证：请用 <code>-web-auth user:pass</code> 配置的凭据登录。</p></div>';return;}
    const data=await res.json();
    const now=performance.now();const dt=lastT?(now-lastT)/1000:2;lastT=now;

    document.getElementById('mode').innerText=data.mode.toUpperCase();
    document.getElementById('ver').innerText=data.version||'-';
    document.getElementById('uptime').innerText=fmtDur(data.uptime_sec||0);
    document.getElementById('loglevel').value=data.log_level||'info';
    document.getElementById('tls-flag').innerText=location.protocol==='https:'?'HTTPS':'HTTP（建议 -web-cert 启用 HTTPS）';

    let tbody='',tTx=0,tRx=0,tTxS=0,tRxS=0,cur={},tConns=0;
    const proc=(id,c)=>{
      tTx+=c.tx_bytes;tRx+=c.rx_bytes;tConns+=c.active_conns||0;
      let sx=0,sr=0;
      if(prev[id]){sx=Math.max(0,(c.tx_bytes-prev[id].tx_bytes)/dt);sr=Math.max(0,(c.rx_bytes-prev[id].rx_bytes)/dt);}
      cur[id]={tx_bytes:c.tx_bytes,rx_bytes:c.rx_bytes};tTxS+=sx;tRxS+=sr;
      const sid=id.length>10?id.slice(0,10)+'…':id;
      tbody+='<tr><td title="'+id+'">'+sid+'</td><td>'+(c.ipv4||'-')+'</td><td class="hide-sm">'+(c.ipv6||'-')+'</td>'+
        '<td class="hide-sm">'+(c.mac||'-')+'</td><td>'+c.active_conns+'</td>'+
        '<td>'+fmtBytes(c.tx_bytes)+'</td><td>'+fmtBytes(c.rx_bytes)+'</td>'+
        '<td class="speed">'+fmtBytes(sx,true)+'</td><td class="speed">'+fmtBytes(sr,true)+'</td>'+
        '<td class="hide-sm">'+badge(c.fec)+'</td><td class="hide-sm">'+encBadge(c.enc_algo)+'</td>'+
        '<td>'+(data.mode==='server'?'<button class="btn" onclick="kickClient(\''+id+'\')">踢出</button>'+
          '<button class="btn blue" onclick="banClient(\''+id+'\',0)">封禁</button>':'-')+'</td></tr>';
    };
    if(data.mode==='server'){for(const [id,c] of Object.entries(data.clients||{}))proc(id,c);}
    else if(data.clients&&data.clients.local)proc('local',data.clients.local);
    prev=cur;txHist.push(tTxS);rxHist.push(tRxS);
    if(txHist.length>MAXPTS){txHist.shift();rxHist.shift();}
    drawChart();

    document.getElementById('active-clients').innerText=data.active_clients;
    document.getElementById('conns-sub').innerText='TCP 连接: '+tConns+(data.mode==='client'?' / '+((data.conns||[]).length):'');
    document.getElementById('total-tx').innerText=fmtBytes(tTx);
    document.getElementById('total-rx').innerText=fmtBytes(tRx);
    document.getElementById('total-tx-speed').innerText=fmtBytes(tTxS,true);
    document.getElementById('total-rx-speed').innerText=fmtBytes(tRxS,true);
    document.getElementById('clients-body').innerHTML=tbody||'<tr><td colspan="12" style="color:#777">暂无客户端</td></tr>';

    const f=data.fec||{};
    document.getElementById('fec-kpi').innerHTML=(f.recovered||0)+' <small style="font-size:.6em;color:#888">/</small> '+(f.lost||0);
    document.getElementById('parity').innerText=f.parity_tx||0;
    document.getElementById('dropped').innerText=data.dropped_frames||0;
    const m=data.mem||{};
    document.getElementById('mem').innerHTML=(m.heap_alloc_mb||0).toFixed(1)+'<small style="font-size:.55em;color:#888"> MB</small>';
    document.getElementById('goroutines').innerText=m.num_goroutine||0;

    if(data.ip_pool){document.getElementById('ippool-card').style.display='';
      document.getElementById('ippool-kpi').innerHTML=data.ip_pool.v4_used+'<small style="font-size:.55em;color:#888"> / '+data.ip_pool.v4_total+'</small>';
      document.getElementById('v6used').innerText=data.ip_pool.v6_used;}

    const meta=[];if(data.enc_algo===2)meta.push('GCM 加密');else if(data.enc_algo===1)meta.push('CTR 加密(旧)');
    if(data.fec_mode&&data.fec_mode!=='off')meta.push('FEC '+data.fec_mode);
    document.getElementById('meta').innerText=meta.join(' · ');

    renderConns(data);renderMacs(data);renderBans(data);
  }catch(e){console.error('获取统计数据失败',e);}
}

function renderConns(data){
  const list=data.conns||[];
  if(data.mode!=='client'){document.getElementById('conns-body').innerHTML='<tr><td colspan="11" style="color:#777">仅客户端模式提供</td></tr>';return;}
  document.getElementById('conns-body').innerHTML=list.map(c=>'<tr><td>'+c.index+'</td><td>'+c.target+'</td><td>'+(c.remote||'-')+'</td>'+
    '<td>'+(c.state==='up'?'<span class="badge b-on">up</span>':c.state==='connecting'?'<span class="badge b-dup">connecting</span>':'<span class="badge b-off">'+c.state+'</span>')+'</td>'+
    '<td>'+(c.rtt_ms>=100000?'-':c.rtt_ms+' ms')+'</td><td>'+fmtBytes(c.tx_bytes)+'</td><td>'+fmtBytes(c.rx_bytes)+'</td>'+
    '<td class="hide-sm">'+c.retries+'</td><td class="hide-sm">'+(c.age_sec?fmtDur(c.age_sec):'-')+'</td>'+
    '<td class="hide-sm" style="color:#c66" title="'+(c.last_error||'')+'">'+((c.last_error||'').slice(0,40))+'</td>'+
    '<td><button class="btn gray" onclick="doAction(\'reconnect\')">重连</button></td></tr>').join('')||
    '<tr><td colspan="11" style="color:#777">无连接</td></tr>';
}
function renderMacs(data){
  const t=document.getElementById('macs-body');
  if(data.mode!=='server'){t.innerHTML='<tr><td colspan="3" style="color:#777">仅服务端模式提供</td></tr>';return;}
  const list=data.mac_table||[];
  t.innerHTML=list.map(e=>'<tr><td>'+e.mac+'</td><td>'+e.port+'</td><td>'+e.age_sec+' 秒前</td></tr>').join('')||
    '<tr><td colspan="3" style="color:#777">尚未学习到 MAC</td></tr>';
}
function renderBans(data){
  const t=document.getElementById('bans-body');
  if(data.mode!=='server'){t.innerHTML='<tr><td colspan="3" style="color:#777">仅服务端模式提供</td></tr>';return;}
  const bans=data.banned||{};
  t.innerHTML=Object.entries(bans).map(([id,left])=>'<tr><td title="'+id+'">'+(id.length>18?id.slice(0,18)+'…':id)+'</td>'+
    '<td>'+(left===0?'<span class="badge b-dup">永久</span>':fmtDur(left))+'</td>'+
    '<td><button class="btn gray" onclick="unban(\''+id+'\')">解封</button></td></tr>').join('')||
    '<tr><td colspan="3" style="color:#777">无封禁记录</td></tr>';
}

async function kickClient(id){if(!confirm('确定要强制断开该客户端吗？'))return;await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'kick',client_id:id})});fetchStats();}
async function banClient(id,minutes){if(!confirm('确定封禁该客户端吗？'))return;await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'ban',client_id:id,ttl_minutes:minutes})});fetchStats();}
async function addBan(){const id=document.getElementById('ban-id').value.trim();if(!id)return alert('请输入 ClientID');
  const m=parseInt(document.getElementById('ban-min').value,10);await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'ban',client_id:id,ttl_minutes:isNaN(m)?0:m})});
  document.getElementById('ban-id').value='';document.getElementById('ban-min').value='';fetchStats();}
async function unban(id){await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'unban',client_id:id})});fetchStats();}
async function doAction(action,extra){await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.assign({action:action},extra||{}))});fetchStats();}
async function setLogLevel(v){await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'loglevel',level:v})});}

function startLogPoll(){
  stopLogPoll();pollLogs();logTimer=setInterval(pollLogs,2000);
}
function stopLogPoll(){if(logTimer){clearInterval(logTimer);logTimer=null;}}
async function pollLogs(){
  try{
    const res=await fetch('/api/logs?after='+logSeq);
    if(!res.ok)return;
    const lines=await res.json();
    if(!lines.length)return;
    const box=document.getElementById('logbox');
    box.innerHTML+=lines.map(l=>'<div class="lv-'+l.level+'">['+l.time+'] '+l.level+' '+l.msg.replace(/</g,'&lt;')+'</div>').join('');
    logSeq=lines[lines.length-1].seq;
    if(document.getElementById('autoscroll').checked)box.scrollTop=box.scrollHeight;
  }catch(e){}
}

setInterval(fetchStats,2000);fetchStats();
</script>
</body>
</html>`

func startWebServer(addr string, srv *Server, cli *Client, webAuth, webCert, webKey string) {
	mux := http.NewServeMux()

	// 仪表盘页面（与 API 一致地受认证保护）
	mux.HandleFunc("/", basicAuthWrapper(webAuth, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(dashboardHTML))
	}))

	// 状态统计 API
	mux.HandleFunc("/api/stats", basicAuthWrapper(webAuth, func(w http.ResponseWriter, r *http.Request) {
		startWebStatsHandler(w, r, srv, cli)
	}))

	// 日志尾随（环形缓冲）
	mux.HandleFunc("/api/logs", basicAuthWrapper(webAuth, func(w http.ResponseWriter, r *http.Request) {
		after := uint64(0)
		fmt.Sscanf(r.URL.Query().Get("after"), "%d", &after)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(logRing.snapshot(after))
	}))

	// Prometheus 文本格式指标（只读，无认证时也建议反代侧限制）
	mux.HandleFunc("/metrics", basicAuthWrapper(webAuth, handleMetrics(srv, cli)))

	// 控制 API（管理动作统一走 CSRF 头防护）
	mux.HandleFunc("/api/control", basicAuthWrapper(webAuth, csrfGuard(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", 405)
			return
		}
		var req struct {
			Action     string `json:"action"`
			ClientID   string `json:"client_id"`
			Level      string `json:"level"`
			TTLMinutes int    `json:"ttl_minutes"`
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

		default:
			http.Error(w, "Unknown action", 400)
		}
	})))

	log.Infof("🚀 Web Dashboard started at %s://%s", tlsScheme(webCert, webKey), addr)
	var err error
	if webCert != "" && webKey != "" {
		err = http.ListenAndServeTLS(addr, webCert, webKey, mux)
	} else {
		err = http.ListenAndServe(addr, mux)
	}
	if err != nil {
		log.Errorf("Web Server failed: %v", err)
	}
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
			}
			srv.mu.RUnlock()
			emit("tlsvpn_fec_recovered_frames_total", "Frames recovered by XOR FEC", "counter", fmt.Sprint(rec))
			emit("tlsvpn_fec_lost_frames_total", "Frames confirmed lost despite FEC", "counter", fmt.Sprint(lost))
			emit("tlsvpn_fec_parity_frames_total", "Parity frames generated", "counter", fmt.Sprint(parity))
			srv.mu.RLock()
			banned := len(srv.banned)
			srv.mu.RUnlock()
			emit("tlsvpn_banned_clients", "Currently banned clients", "gauge", fmt.Sprint(banned))
		}
		if cli != nil {
			emit("tlsvpn_tx_bytes_total", "Total bytes sent", "counter", fmt.Sprint(atomic.LoadUint64(&cli.TxBytes)))
			emit("tlsvpn_rx_bytes_total", "Total bytes received", "counter", fmt.Sprint(atomic.LoadUint64(&cli.RxBytes)))
			emit("tlsvpn_live_connections", "Live physical connections", "gauge", fmt.Sprint(atomic.LoadInt32(&cli.liveConns)))
			emit("tlsvpn_reconnect_attempts_total", "Reconnect attempts", "counter", fmt.Sprint(cli.ReconnectAttempts()))
			emit("tlsvpn_port_dropped_frames_total", "Frames dropped due to backpressure", "counter", fmt.Sprint(cli.txPort.Dropped()))
			emit("tlsvpn_fec_recovered_frames_total", "Frames recovered by XOR FEC", "counter", fmt.Sprint(cli.FECRecovered()))
			emit("tlsvpn_fec_lost_frames_total", "Frames confirmed lost despite FEC", "counter", fmt.Sprint(cli.FECLost()))
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
		stats.Fec = fecStatsJSON{Enabled: true, ParityTx: parity, Recovered: rec, Lost: lost}

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
		cli.sessionMu.Unlock()
		conns := int(atomic.LoadInt32(&cli.liveConns))
		fec := cli.fecStatus
		enc := cli.encAlgo
		stats.ActiveClients = 1
		if enc == 0 && cli.encrypt {
			enc = 1 // legacy CTR 依旧算"已加密"
		}
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
			stats.Fec = fecStatsJSON{Enabled: cli.fecMode, ParityTx: cli.txPort.ParitySent(), Recovered: rec, Lost: lost}
		}
		stats.FecMode = fec
		stats.EncAlgo = enc
	}

	json.NewEncoder(w).Encode(stats)
}
