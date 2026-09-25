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
 cfgk:{mode:'运行模式',encrypt:'内层加密',enc_algo:'内层算法',min_enc:'最低加密要求',pad_mode:'填充模式',brutal:'TCP Brutal',brutal_up:'上行总量 (Mbps)',brutal_down:'下行总量 (Mbps)',socks5:'SOCKS5 代理',fec:'FEC',fec_group:'FEC 分组',fec_group_min:'FEC 分组下限',fec_group_max:'FEC 分组上限',log_level:'日志级别',conns:'并发连接数',tap:'TAP 设备',mac:'MAC 地址',addr:'服务端地址',web_addr:'面板监听',web_auth:'面板认证',web_bind:'面板绑定地址',web_https:'面板 HTTPS',encrypt_psk:'PSK 已配置',session_encrypt:'会话加密',max_sessions:'最大会话数',v4_cidr:'IPv4 网段',v6_cidr:'IPv6 网段',gw_v4:'IPv4 网关',gw_v6:'IPv6 网关',fwmark:'策略路由 fwmark',fwmark_priority:'规则优先级',fwmark_table:'路由表号',extra_routes:'额外路由',source_rules:'按源前缀路由'},
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
 cfgk:{mode:'Mode',encrypt:'Inner cipher',enc_algo:'Inner algorithm',min_enc:'Minimum cipher',pad_mode:'Padding mode',brutal:'TCP Brutal',brutal_up:'Upstream total (Mbps)',brutal_down:'Downstream total (Mbps)',socks5:'SOCKS5 proxy',fec:'FEC',fec_group:'FEC group',fec_group_min:'FEC group floor',fec_group_max:'FEC group ceiling',log_level:'Log level',conns:'Concurrent conns',tap:'TAP device',mac:'MAC address',addr:'Server address',web_addr:'Dashboard listen',web_auth:'Dashboard auth',web_bind:'Dashboard bind',web_https:'Dashboard HTTPS',encrypt_psk:'PSK configured',session_encrypt:'Session encryption',max_sessions:'Max sessions',v4_cidr:'IPv4 CIDR',v6_cidr:'IPv6 CIDR',gw_v4:'IPv4 gateway',gw_v6:'IPv6 gateway',fwmark:'Policy routing fwmark',fwmark_priority:'Rule priority',fwmark_table:'Route table',extra_routes:'Extra routes',source_rules:'Source rules'},
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
function encBadge(a){if(a===2)return '<span class="badge b-on">AES-256-GCM</span>';
  if(a===4)return '<span class="badge b-on">AES-128-GCM</span>';
  return '<span class="badge b-off">'+t('badge.plain')+'</span>';}
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

    const meta=[];if(data.enc_algo===2)meta.push('AES-256-GCM');else if(data.enc_algo===4)meta.push('AES-128-GCM');
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
function encName(a){return a===2?'AES-256-GCM':(a===4?'AES-128-GCM':(a===0?'none (TLS only)':String(a)));}
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
