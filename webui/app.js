const I18N={
'zh-CN':{kpi:{active:'活跃客户端/设备',tcp:'TCP 连接',tx:'总发送',rx:'总接收',uptime:'运行时长',version:'版本',gc:'立即回收',fec:'FEC 恢复 / 确认丢失',parity:'校验帧',dropped:'丢帧(队列)',reorder:'重排跳过',mem:'内存',goroutines:'Goroutines:',pool:'IPv4 地址池',v6used:'IPv6 已分配:'},
 chart:{title:'吞吐趋势',win:'(近 120 秒)'},legend:{up:'上行',down:'下行'},
	tab:{clients:'客户端',conns:'连接明细',macs:'MAC 表',bans:'封禁',traffic:'流量',status:'运行状态',logs:'日志',settings:'设置'},
 tr:{today_up:'今日上行',today_down:'今日下行',today_total:'今日合计',daily:'每日流量',up:'上行',down:'下行',total:'合计',date:'日期',caption:'近 {n} 天',empty:'暂无按日统计数据'},
 th:{id:'ID',v4:'IPv4',v6:'IPv6',mac:'MAC',tcp:'TCP',tx:'TX (发)',rx:'RX (收)',txs:'↑ 速率',rxs:'↓ 速率',fec:'FEC',enc:'加密',brutal:'Brutal',ops:'操作',kick:'踢出',ban:'封禁',unban:'解封',owner:'客户端',target:'目标',remote:'对端',state:'状态',rtt:'RTT',retries:'重试',age:'在线',epoch:'密钥代际',err:'最近错误'},
 m:{port:'端口',seen:'最近活跃'},bans:{id_ph:'ClientID（可短前缀）',min_ph:'分钟（留空=永久）',add:'封禁',refresh:'刷新',left:'剩余'},
 logs:{level:'级别',autoscroll:'自动滚动',clear:'清屏',download:'下载日志'},
 filter_ph:'输入关键字过滤…',filter_none:'无匹配结果',filter_clear:'清除过滤',filter_tip:'按 / 快速聚焦',no_clients:'暂无客户端',no_conns:'无连接',no_macs:'尚未学习到 MAC',no_bans:'无封禁记录',srv_only:'仅服务端模式提供',
 perm:'永久',confirm_kick:'确定要强制断开该客户端吗？',confirm_ban:'确定封禁该客户端吗？',need_id:'请输入 ClientID',
 st:{up:'up',connecting:'connecting',skip:'未生效'},
 badge:{dup:'复制',off:'关闭',ctr:'CTR',plain:'明文'},
 u:{day:'天',hour:'时',min:'分',sec:'秒'},footer:'数据每 {n} 秒刷新',refresh_tip:'刷新间隔',
	tls_http:'HTTP（建议启用 HTTPS）',mode_local:'本机',theme_tip:'主题（跟随系统）',theme:{sys:'Auto',light:'Light',dark:'Dark'},
 cfgk:{traffic_days:'流量统计保留天数',traffic_file:'流量统计文件',mode:'运行模式',encrypt:'内层加密',enc_algo:'内层算法',min_enc:'最低加密要求',pad_mode:'填充模式',brutal:'TCP Brutal',brutal_up:'上行总量 (Mbps)',brutal_down:'下行总量 (Mbps)',socks5:'SOCKS5 代理',fec:'FEC',fec_group:'FEC 分组',fec_group_min:'FEC 分组下限',fec_group_max:'FEC 分组上限',log_level:'日志级别',conns:'并发连接数',tap:'TAP 设备',mac:'MAC 地址',addr:'服务端地址',web_addr:'面板监听',web_auth:'面板认证',web_bind:'面板绑定地址',web_https:'面板 HTTPS',encrypt_psk:'PSK 已配置',session_encrypt:'会话加密',max_sessions:'最大会话数',v4_cidr:'IPv4 网段',v6_cidr:'IPv6 网段',gw_v4:'IPv4 网关',gw_v6:'IPv6 网关',fwmark:'策略路由 fwmark',fwmark_priority:'规则优先级',fwmark_table:'路由表号',extra_routes:'额外路由',source_rules:'按源前缀路由'},
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
	tab:{clients:'Clients',conns:'Connections',macs:'MAC table',bans:'Bans',traffic:'Traffic',status:'Runtime status',logs:'Logs',settings:'Settings'},
 tr:{today_up:'Up today',today_down:'Down today',today_total:'Total today',daily:'Daily traffic',up:'Up',down:'Down',total:'Total',date:'Date',caption:'Last {n} days',empty:'No daily traffic data yet'},
 th:{id:'ID',v4:'IPv4',v6:'IPv6',mac:'MAC',tcp:'TCP',tx:'TX',rx:'RX',txs:'↑ Rate',rxs:'↓ Rate',fec:'FEC',enc:'Encrypt',brutal:'Brutal',ops:'Actions',kick:'Kick',ban:'Ban',unban:'Unban',owner:'Client',target:'Target',remote:'Remote',state:'State',rtt:'RTT',retries:'Retries',age:'Uptime',epoch:'Epoch',err:'Last error'},
 m:{port:'Port',seen:'Last seen'},bans:{id_ph:'ClientID (short prefix ok)',min_ph:'Minutes (empty = permanent)',add:'Ban',refresh:'Refresh',left:'Remaining'},
 logs:{level:'Level',autoscroll:'Auto scroll',clear:'Clear',download:'Download'},
 filter_ph:'Type to filter…',filter_none:'No matches',filter_clear:'Clear filter',filter_tip:'Press / to focus',no_clients:'No clients yet',no_conns:'No connections',no_macs:'No MACs learned yet',no_bans:'No banned clients',srv_only:'Server mode only',
 perm:'Permanent',confirm_kick:'Force-disconnect this client?',confirm_ban:'Ban this client?',need_id:'Please enter a ClientID',
 st:{up:'up',connecting:'connecting',skip:'Skipped'},
 badge:{dup:'Dup',off:'Off',ctr:'CTR',plain:'Plain'},
 u:{day:'d',hour:'h',min:'m',sec:'s'},footer:'Refreshing every {n}s',refresh_tip:'Refresh interval',
	tls_http:'HTTP (HTTPS recommended)',mode_local:'local',theme_tip:'Theme (follow system)',theme:{sys:'Auto',light:'Light',dark:'Dark'},
 cfgk:{traffic_days:'Traffic retention days',traffic_file:'Traffic stats file',mode:'Mode',encrypt:'Inner cipher',enc_algo:'Inner algorithm',min_enc:'Minimum cipher',pad_mode:'Padding mode',brutal:'TCP Brutal',brutal_up:'Upstream total (Mbps)',brutal_down:'Downstream total (Mbps)',socks5:'SOCKS5 proxy',fec:'FEC',fec_group:'FEC group',fec_group_min:'FEC group floor',fec_group_max:'FEC group ceiling',log_level:'Log level',conns:'Concurrent conns',tap:'TAP device',mac:'MAC address',addr:'Server address',web_addr:'Dashboard listen',web_auth:'Dashboard auth',web_bind:'Dashboard bind',web_https:'Dashboard HTTPS',encrypt_psk:'PSK configured',session_encrypt:'Session encryption',max_sessions:'Max sessions',v4_cidr:'IPv4 CIDR',v6_cidr:'IPv6 CIDR',gw_v4:'IPv4 gateway',gw_v6:'IPv6 gateway',fwmark:'Policy routing fwmark',fwmark_priority:'Rule priority',fwmark_table:'Route table',extra_routes:'Extra routes',source_rules:'Source rules'},
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
function setSeg(id,val){
  const seg=document.getElementById(id);if(!seg)return;
  seg.querySelectorAll('button').forEach(b=>b.classList.toggle('on',b.dataset.v===val));
}
function applyI18n(){
  document.documentElement.lang=LANG;
  document.querySelectorAll('[data-i18n]').forEach(el=>el.textContent=t(el.dataset.i18n));
  document.querySelectorAll('[data-i18n-ph]').forEach(el=>el.placeholder=t(el.dataset.i18nPh));
  document.querySelectorAll('[data-i18n-title]').forEach(el=>el.title=t(el.dataset.i18nTitle));
  setSeg('lang-seg',LANG);
  setSeg('refresh-seg',String(REFRESH_S));
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
function encBadge(a){if(a===2)return '<span class="badge b-on">AES-256-GCM</span>';
  if(a===4)return '<span class="badge b-on">AES-128-GCM</span>';
  return '<span class="badge b-off">'+t('badge.plain')+'</span>';}
function stBadge(s){if(s==='up')return '<span class="badge b-on">'+t('st.up')+'</span>';
  if(s==='connecting')return '<span class="badge b-dup">'+t('st.connecting')+'</span>';
  return '<span class="badge b-off">'+(s||'-')+'</span>';}
function shortId(id,n){return id.length>n?id.slice(0,n)+'…':id;}
function esc(x){return String(x==null?'':x).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\x22/g,'&quot;').replace(/\x27/g,'&#39;');}
// hi 在已转义的文本上高亮首个命中（查询词为小写）；无命中原样返回
function hi(s,q){
  if(!q)return s;
  const i=s.toLowerCase().indexOf(q);
  return i<0?s:s.slice(0,i)+'<mark>'+s.slice(i,i+q.length)+'</mark>'+s.slice(i+q.length);
}
function showPane(id){
  document.querySelectorAll('#tabs button').forEach(b=>b.classList.toggle('on',b.dataset.pane===id));
  document.querySelectorAll('.pane').forEach(p=>p.classList.remove('on'));
  document.getElementById('pane-'+id).classList.add('on');
  if(id==='logs')startLogPoll();else stopLogPoll();
  if(id==='settings')loadConfig();
}
document.getElementById('tabs').addEventListener('click',function(ev){
  const btn=ev.target.closest('button');if(!btn)return;
  showPane(btn.dataset.pane);
});

function drawChart(){
  const c=document.getElementById('chart'),ctx=c.getContext('2d');
  const dpr=window.devicePixelRatio||1;
  const W=c.clientWidth||1100,H=c.clientHeight||216;
  if(c.width!==Math.round(W*dpr)||c.height!==Math.round(H*dpr)){c.width=Math.round(W*dpr);c.height=Math.round(H*dpr);}
  ctx.setTransform(dpr,0,0,dpr,0,0);
  ctx.clearRect(0,0,W,H);
  ctx.strokeStyle=cssv('--grid');ctx.lineWidth=1;
  for(let g=1;g<4;g++){ctx.beginPath();ctx.moveTo(0,H*g/4+.5);ctx.lineTo(W,H*g/4+.5);ctx.stroke();}
  if(txHist.length<2)return;
  const max=Math.max(...txHist,...rxHist,1);
  const series=(h,col)=>{
    const pts=h.map((v,i)=>({x:i/(MAXPTS-1)*W,y:H-10-(v/max)*(H-30)}));
    const grad=ctx.createLinearGradient(0,0,0,H);
    grad.addColorStop(0,col+'3d');grad.addColorStop(1,col+'00');
    ctx.beginPath();ctx.moveTo(pts[0].x,pts[0].y);
    for(let i=1;i<pts.length-1;i++){const xc=(pts[i].x+pts[i+1].x)/2,yc=(pts[i].y+pts[i+1].y)/2;ctx.quadraticCurveTo(pts[i].x,pts[i].y,xc,yc);}
    ctx.lineTo(pts[pts.length-1].x,pts[pts.length-1].y);
    ctx.strokeStyle=col;ctx.lineWidth=2;ctx.lineJoin='round';ctx.lineCap='round';ctx.stroke();
    ctx.lineTo(W,H);ctx.lineTo(0,H);ctx.closePath();ctx.fillStyle=grad;ctx.fill();
  };
  series(rxHist,cssv('--down'));
  series(txHist,cssv('--up'));
  ctx.fillStyle=cssv('--sub');ctx.font='11px sans-serif';
  ctx.fillText(fmtBytes(max,true),6,14);
}

// 刷新间隔以秒存储（兼容旧版存毫秒的值）；面板顶栏为分段按钮
let REFRESH_S=parseInt(localStorage.getItem('tlsvpn_refresh')||'2',10);
if(REFRESH_S!==2&&REFRESH_S!==5&&REFRESH_S!==10){
  const ms=REFRESH_S;
  REFRESH_S=(ms===2000||ms===5000||ms===10000)?ms/1000:2;
}
let REFRESH=REFRESH_S*1000;
let statsTimer=null;
function setRefresh(sec){REFRESH_S=sec;REFRESH=sec*1000;localStorage.setItem('tlsvpn_refresh',String(sec));
  setSeg('refresh-seg',String(sec));
  document.getElementById('footer-text').textContent=t('footer').replace('{n}',sec);
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

const NO_TXT={clients:'no_clients',conns:'no_conns',macs:'no_macs',bans:'no_bans'};
function emptyRow(key,cols,total){
  if(!total)return '<tr><td class="empty" colspan="'+cols+'">'+t(NO_TXT[key])+'</td></tr>';
  return '<tr><td class="empty" colspan="'+cols+'">'+t('filter_none')+
    ' <button class="btn ghost sm" onclick="clearFilter(\''+key+'\')">'+t('filter_clear')+'</button></td></tr>';
}
function setCount(id,f,shown,total){
  const el=document.getElementById(id);if(!el)return;
  el.textContent=f?(shown+' / '+total):'';
}
// 过滤框：纯本地过滤——基于最近一次 /api/stats 的缓存重渲染表格，不打 API；
// 140ms 防抖，×/Esc 一键清空，命中片段 <mark> 高亮，计数徽章显示 命中/总数。
const Q={clients:'',conns:'',macs:''};
function attachSearch(key){
  const box=document.getElementById('search-'+key);if(!box)return;
  const input=box.querySelector('.search-input');
  const clear=box.querySelector('.search-clear');
  let timer=null;
  input.addEventListener('input',function(){
    clear.classList.toggle('show',!!input.value);
    clearTimeout(timer);
    timer=setTimeout(function(){Q[key]=input.value.trim().toLowerCase();rerenderTables();},140);
  });
  clear.addEventListener('click',function(){input.value='';Q[key]='';clear.classList.remove('show');rerenderTables();input.focus();});
  input.addEventListener('keydown',function(e){if(e.key==='Escape')clear.click();});
}
function clearFilter(key){
  const box=document.getElementById('search-'+key);if(!box)return;
  box.querySelector('.search-input').value='';
  box.querySelector('.search-clear').classList.remove('show');
  Q[key]='';
  rerenderTables();
}
// "/" 聚焦当前页签的过滤框（输入控件已聚焦时不拦截）
document.addEventListener('keydown',function(e){
  if(e.key!=='/')return;
  const tag=(document.activeElement&&document.activeElement.tagName)||'';
  if(tag==='INPUT'||tag==='TEXTAREA'||tag==='SELECT')return;
  const pane=document.querySelector('.pane.on');if(!pane)return;
  const key=pane.id.replace('pane-','');
  if(key!=='clients'&&key!=='conns'&&key!=='macs')return;
  const box=document.getElementById('search-'+key);
  if(box){box.querySelector('.search-input').focus();e.preventDefault();}
});

let lastStats=null,lastSpeeds={};
async function fetchStats(){
  try{
    const res=await fetch(url('/api/stats'),AUTH_HDR);
    if(res.status===401){document.body.innerHTML='<div class="card"><h2>401</h2><p>'+t('logs.level')+': -web-auth user:pass</p></div>';return;}
    const data=await res.json();
    lastStats=data;
    const now=performance.now();const dt=lastT?(now-lastT)/1000:2;lastT=now;

    document.getElementById('mode').innerText=data.mode.toUpperCase();
    const chip=document.getElementById('mode-chip');
    if(chip)chip.classList.toggle('client',data.mode!=='server');
    document.getElementById('ver').innerText=data.version||'-';
    document.getElementById('uptime').innerText=fmtDur(data.uptime_sec||0);
    document.getElementById('loglevel').value=data.log_level||'info';
    document.getElementById('tls-flag').innerText=location.protocol==='https:'?'HTTPS':t('tls_http');

    // 速率/总量统计覆盖全部客户端；过滤只作用于表格行
    const speeds={};let tTx=0,tRx=0,tTxS=0,tRxS=0,cur={},tConns=0;
    const proc=(id,c)=>{
      tTx+=c.tx_bytes;tRx+=c.rx_bytes;tConns+=c.active_conns||0;
      let sx=0,sr=0;
      if(prev[id]){sx=Math.max(0,(c.tx_bytes-prev[id].tx_bytes)/dt);sr=Math.max(0,(c.rx_bytes-prev[id].rx_bytes)/dt);}
      cur[id]={tx_bytes:c.tx_bytes,rx_bytes:c.rx_bytes};
      speeds[id]={sx:sx,sr:sr};
      tTxS+=sx;tRxS+=sr;
    };
    if(data.mode==='server'){for(const [id,c] of Object.entries(data.clients||{}))proc(id,c);}
    else if(data.clients&&data.clients.local)proc('local',data.clients.local);
    prev=cur;lastSpeeds=speeds;
    txHist.push(tTxS);rxHist.push(tRxS);
    if(txHist.length>MAXPTS){txHist.shift();rxHist.shift();}
    drawChart();

    document.getElementById('active-clients').innerText=data.active_clients;
    document.getElementById('conns-sub').innerText=t('kpi.tcp')+': '+tConns+(data.mode==='client'?' / '+((data.conns||[]).length):'');
    document.getElementById('total-tx').innerText=fmtBytes(tTx);
    document.getElementById('total-rx').innerText=fmtBytes(tRx);
    document.getElementById('total-tx-speed').innerText=fmtBytes(tTxS,true);
    document.getElementById('total-rx-speed').innerText=fmtBytes(tRxS,true);
    document.getElementById('live-up').innerText=fmtBytes(tTxS,true);
    document.getElementById('live-down').innerText=fmtBytes(tRxS,true);
    renderClientsTable(data);

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

    const meta=[];if(data.enc_algo===2)meta.push('AES-256-GCM');else if(data.enc_algo===4)meta.push('AES-128-GCM');
    if(data.fec_mode&&data.fec_mode!=='off')meta.push('FEC '+data.fec_mode);
    document.getElementById('meta').innerText=meta.join(' · ');

	renderConnsTable(data);renderMacsTable(data);renderBansTable(data);renderTraffic(data);renderStatus(data);
  }catch(e){console.error('stats fetch failed',e);}
}

// 过滤输入时不重新拉取：对最近一次快照重渲染各表格
function rerenderTables(){
  if(!lastStats)return;
  renderClientsTable(lastStats);
  renderConnsTable(lastStats);
  renderMacsTable(lastStats);
  renderBansTable(lastStats);
}

function renderClientsTable(data){
  const f=Q.clients;
  const entries=data.mode==='server'?Object.entries(data.clients||{}):(data.clients&&data.clients.local?[['local',data.clients.local]]:[]);
  let rows='',shown=0;
  for(const [id,c] of entries){
    if(!passFilter(Object.assign({id:id},c),f))continue;
    shown++;
    const sp=lastSpeeds[id]||{sx:0,sr:0};
    rows+='<tr><td class="num dim" title="'+esc(id)+'">'+hi(esc(shortId(id,10)),f)+'</td>'+
      '<td class="num">'+hi(esc(c.ipv4||'-'),f)+'</td>'+
      '<td class="hide-sm num dim">'+hi(esc(c.ipv6||'-'),f)+'</td>'+
      '<td class="hide-sm num dim">'+hi(esc(c.mac||'-'),f)+'</td>'+
      '<td class="num">'+c.active_conns+'</td>'+
      '<td class="num">'+fmtBytes(c.tx_bytes)+'</td><td class="num">'+fmtBytes(c.rx_bytes)+'</td>'+
      '<td class="num speed">'+fmtBytes(sp.sx,true)+'</td><td class="num speed dn">'+fmtBytes(sp.sr,true)+'</td>'+
      '<td class="hide-sm">'+badge(c.fec)+'</td><td class="hide-sm">'+encBadge(c.enc_algo)+'</td>'+
      '<td>'+(data.mode==='server'?'<button class="btn danger sm" onclick="kickClient(\''+id+'\')">'+t('th.kick')+'</button>'+
        '<button class="btn ghost sm" onclick="banClient(\''+id+'\',0)">'+t('th.ban')+'</button>':'-')+'</td></tr>';
  }
  document.getElementById('clients-body').innerHTML=rows||emptyRow('clients',12,entries.length);
  setCount('client-count',f,shown,entries.length);
}

// ---------- "运行状态" 页：宿主/协商/brutal/配置 四块明细 ----------
// 空值不占行：面板上留一堆空行只会让人误以为字段缺失是故障
function kv(el,rows){
  el.innerHTML=rows.length?rows.map(r=>'<tr><th>'+esc(r[0])+'</th><td>'+r[1]+'</td></tr>').join(''):'';
}
function yn(v){return v?'<span class="badge b-on">'+t('stt.yes')+'</span>':'<span class="badge b-off">'+t('stt.no')+'</span>';}
function mtxt(v){return '<span class="mono">'+esc(v)+'</span>';}
function ntxt(){return '<span style="color:var(--sub)">-</span>';}
function encName(a){return a===2?'AES-256-GCM':(a===4?'AES-128-GCM':(a===0?'none (TLS only)':String(a)));}
function rateRange(lo,hi2){if(!lo&&!hi2)return '-';return (lo===hi2?String(lo):lo+'~'+hi2)+' Mbps';}
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

function renderConnsTable(data){
  const tb=document.getElementById('conns-body');
  let rows=[];
  if(data.mode==='server'){
    (data.server_conns||[]).forEach(c=>rows.push({owner:shortId(c.client_id,10),fullId:c.client_id,target:'',remote:c.remote,state:'up',rtt:c.rtt_ms,tx:c.tx_bytes,rx:c.rx_bytes,retries:'',age:c.age_sec,epoch:c.session_epoch||0,err:'',enc:c.enc_algo,fec:c.fec||'',brut:c.brutal_applied,brutErr:c.brutal_error||'',up:c.brutal_cli_tx_mbps||0,down:c.brutal_srv_tx_mbps||0}));
  }else{
    (data.conns||[]).forEach(c=>rows.push({owner:'local',fullId:null,target:c.target,remote:c.remote,state:c.state,rtt:c.rtt_ms,tx:c.tx_bytes,rx:c.rx_bytes,retries:c.retries,age:c.age_sec,epoch:data.session_epoch||0,err:c.last_error||'',enc:data.enc_algo,fec:data.fec_mode||'',brut:c.brutal_applied,brutErr:c.brutal_error||'',up:c.brutal_tx_mbps||0,down:c.brutal_rx_mbps||0}));
  }
  const f=Q.conns;
  const all=rows.length;
  if(f)rows=rows.filter(r=>JSON.stringify(r).toLowerCase().includes(f));
  const total=rows.length;
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
    const ops=(data.mode==='server'&&r.fullId)?'<button class="btn danger sm" onclick="kickClient(\''+r.fullId+'\')">'+t('th.kick')+'</button>':'';
    return '<tr><td class="num dim">'+hi(esc(r.owner),f)+'</td><td class="num">'+hi(esc(r.target||'-'),f)+'</td><td class="num">'+hi(esc(r.remote||'-'),f)+'</td><td title="'+esc(brutTip)+'">'+st+'</td>'+
      '<td class="num">'+rtt+'</td><td class="num">'+fmtBytes(r.tx)+'</td><td class="num">'+fmtBytes(r.rx)+'</td>'+
      '<td class="hide-sm num">'+(r.retries===''?'-':r.retries)+'</td><td class="hide-sm num dim">'+(r.age?fmtDur(r.age):'-')+'</td>'+
      '<td class="hide-sm num dim" title="'+esc(r.epoch?'session key epoch '+r.epoch:'no epoch yet')+'">'+(r.epoch?r.epoch:'-')+'</td>'+
      '<td class="hide-sm">'+encBadge(r.enc)+'</td><td class="hide-sm">'+badge(r.fec)+'</td>'+
      '<td class="hide-sm" title="'+esc(brutTip)+'">'+brut+'</td>'+
      '<td class="hide-sm" style="color:var(--err)" title="'+esc(r.err||r.brutErr)+'">'+esc(String(r.err||r.brutErr).slice(0,40))+'</td><td>'+ops+'</td></tr>';
  }).join('')||emptyRow('conns',15,all);
  setCount('conn-count',f,rows.length,all);
}
function renderMacsTable(data){
  const tb=document.getElementById('macs-body');
  if(data.mode!=='server'){
    tb.innerHTML='<tr><td colspan="3" class="empty">'+t('srv_only')+'</td></tr>';
    setCount('mac-count','',0,0);return;
  }
  const f=Q.macs;
  const list=data.mac_table||[];
  let rows='',shown=0;
  list.forEach(e=>{
    if(!passFilter(e,f))return;
    shown++;
    rows+='<tr><td class="num">'+hi(esc(e.mac),f)+'</td><td class="num dim">'+hi(esc(e.port),f)+'</td><td class="num dim">'+e.age_sec+'s</td></tr>';
  });
  tb.innerHTML=rows||emptyRow('macs',3,list.length);
  setCount('mac-count',f,shown,list.length);
}
function renderBansTable(data){
  const tb=document.getElementById('bans-body');
  if(data.mode!=='server'){tb.innerHTML='<tr><td colspan="3" class="empty">'+t('srv_only')+'</td></tr>';return;}
  const bans=data.banned||{};
  tb.innerHTML=Object.entries(bans).map(([id,left])=>'<tr><td class="num dim" title="'+esc(id)+'">'+esc(shortId(id,18))+'</td>'+
    '<td>'+(left===0?'<span class="badge b-dup">'+t('perm')+'</span>':'<span class="badge b-on">'+fmtDur(left)+'</span>')+'</td>'+
    '<td><button class="btn ghost sm" onclick="unban(\''+id+'\')">'+t('th.unban')+'</button></td></tr>').join('')||
    '<tr><td colspan="3" class="empty">'+t('no_bans')+'</td></tr>';
}

// ---------- 流量页：今日汇总 + 每日柱状图 + 日表 ----------
function renderTraffic(data){
  const tr=data.traffic;if(!tr)return;
  document.getElementById('tr-up').innerText=fmtBytes(tr.up||0);
  document.getElementById('tr-down').innerText=fmtBytes(tr.down||0);
  document.getElementById('tr-total').innerText=fmtBytes((tr.up||0)+(tr.down||0));
  document.getElementById('tr-caption').innerText=t('tr.caption').replace('{n}',tr.days);
  drawTrafficChart(tr.daily||[]);
  const tb=document.getElementById('traffic-body');
  const days=(tr.daily||[]).slice().reverse();
  const rows=days.map(d=>'<tr><td class="num dim">'+esc(d.date)+'</td><td class="num speed">'+fmtBytes(d.up)+'</td>'+
    '<td class="num speed dn">'+fmtBytes(d.down)+'</td><td class="num">'+fmtBytes(d.up+d.down)+'</td></tr>').join('');
  tb.innerHTML=rows||'<tr><td colspan="4" class="empty">'+t('tr.empty')+'</td></tr>';
}
function drawTrafficChart(daily){
  const c=document.getElementById('traffic-chart'),ctx=c.getContext('2d');
  const dpr=window.devicePixelRatio||1;
  const W=c.clientWidth||1100,H=c.clientHeight||220;
  if(c.width!==Math.round(W*dpr)||c.height!==Math.round(H*dpr)){c.width=Math.round(W*dpr);c.height=Math.round(H*dpr);}
  ctx.setTransform(dpr,0,0,dpr,0,0);
  ctx.clearRect(0,0,W,H);
  const days=daily.slice(-60); // 柱宽可读性：最多渲染最近 60 天
  ctx.fillStyle=cssv('--sub');ctx.font='12px sans-serif';
  if(!days.length){ctx.fillText(t('tr.empty'),10,22);return;}
  const max=Math.max(1,...days.map(d=>d.up+d.down));
  ctx.strokeStyle=cssv('--grid');ctx.lineWidth=1;
  for(let g=1;g<4;g++){ctx.beginPath();ctx.moveTo(0,H*g/4+.5);ctx.lineTo(W,H*g/4+.5);ctx.stroke();}
  const bw=W/days.length;
  const barW=Math.max(2,Math.min(26,bw*0.36));
  days.forEach((d,i)=>{
    const cx=(i+0.5)*bw;
    const hu=(d.up/max)*(H-34),hd=(d.down/max)*(H-34);
    ctx.fillStyle=cssv('--up');
    if(hu>0)ctx.fillRect(cx-barW-1,H-24-hu,barW,hu);
    ctx.fillStyle=cssv('--down');
    if(hd>0)ctx.fillRect(cx+1,H-24-hd,barW,hd);
  });
  // 日期刻度按柱数稀疏标注（MM-DD），避免拥挤
  ctx.fillStyle=cssv('--sub');ctx.font='10px sans-serif';
  const step=Math.ceil(days.length/10);
  days.forEach((d,i)=>{
    if(i%step===0)ctx.fillText(d.date.slice(5),Math.max(2,(i+0.5)*bw-14),H-8);
  });
  ctx.fillStyle=cssv('--sub');ctx.font='11px sans-serif';
  ctx.fillText(fmtBytes(max),6,12);
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
    box.innerHTML+=lines.map(l=>'<div class="ln lv-'+l.level+'"><span class="ts">['+l.time+']</span><span class="lv">'+l.level+'</span><span class="msg">'+esc(l.msg)+'</span></div>').join('');
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
  setSeg('theme-seg',THEME);
}
function setTheme(v){THEME=v;localStorage.setItem('tlsvpn_theme',v);applyTheme();
  if(txHist.length||rxHist.length)drawChart();}
matchMedia('prefers-color-scheme: dark').addEventListener('change',function(){if(THEME==='system'){applyTheme();if(txHist.length||rxHist.length)drawChart();}});

['clients','conns','macs'].forEach(attachSearch);
let prev={},lastT=0;const txHist=[],rxHist=[];const MAXPTS=60;
applyI18n();setRefresh(REFRESH_S);fetchStats();
window.addEventListener('resize',drawChart);
