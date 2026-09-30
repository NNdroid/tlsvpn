#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def read(rel):
    return (ROOT / rel).read_text(encoding='utf-8')


def write(rel, text):
    (ROOT / rel).write_text(text, encoding='utf-8')


def once(text, old, new, label):
    if old not in text:
        raise SystemExit(f'missing marker for {label}')
    return text.replace(old, new, 1)


def common_frontend():
    p = ROOT / 'webui/app.js'
    s = p.read_text(encoding='utf-8')

    s = once(s,
"""async function fetchStats(){
  try{
    const res=await fetch(url('/api/stats'),AUTH_HDR);
    if(res.status===401){showUnauthorized();return;}
    const data=await res.json();""",
"""function applyStats(data){
  if(!data)return;
  try{""", 'stats transport split')
    s = once(s, "}catch(e){console.error('stats fetch failed',e);}\n}", "}catch(e){console.error('stats render failed',e);}\n}", 'stats catch')

    old_refresh = """let REFRESH=REFRESH_S*1000;
let statsTimer=null;
function setRefresh(sec){REFRESH_S=sec;REFRESH=sec*1000;localStorage.setItem('tlsvpn_refresh',String(sec));
  setSeg('refresh-seg',String(sec));
  document.getElementById('footer-text').textContent=t('footer').replace('{n}',sec);
  restartLoop();}
function restartLoop(){if(statsTimer)clearInterval(statsTimer);statsTimer=setInterval(fetchStats,REFRESH);
  // 2 分钟视图跟着面板刷新周期走，刷新间隔改了也要同步换掉趋势定时器
  if(chartRange==='2m')startTrendTimer();}
"""
    new_refresh = """let REFRESH=REFRESH_S*1000;
function setRefresh(sec){REFRESH_S=sec;REFRESH=sec*1000;localStorage.setItem('tlsvpn_refresh',String(sec));
  setSeg('refresh-seg',String(sec));
  document.getElementById('footer-text').textContent=t('footer').replace('{n}',sec);
  if(window.tlsvpnStreamRestart)window.tlsvpnStreamRestart();}
"""
    s = once(s, old_refresh, new_refresh, 'stats timer removal')

    s = s.replace("setTimeout(fetchStats,500);", "setTimeout(function(){if(window.tlsvpnStreamRestart)window.tlsvpnStreamRestart();},500);")
    s = s.replace("  if(id==='logs')startLogPoll();else stopLogPoll();\n", "")
    s = s.replace("  pollLogs();\n", "")

    s = once(s,
             "let evItems=[],evSeq=0,evES=null,evTimer=null,evBad=0,evLvl='all',evMode='';\nconst EV_MAX=300,EV_POLL_MS=2500;",
             "let evItems=[],evSeq=0,evLvl='all',evMode='reconn';\nconst EV_MAX=300;",
             'event transport state')
    start = s.index('function evOpenSSE(){')
    end = s.index('function setEvLvl(v){', start)
    replacement = """function evStreamState(mode){
  evMode=mode||'reconn';
  evLive();
}
function applyEvents(list){
  if(!Array.isArray(list))return;
  list.forEach(evPush);
}
"""
    s = s[:start] + replacement + s[end:]
    s = s.replace("  let txt=t('ev.poll');\n  if(evMode==='sse'){cls='ok';txt=t('ev.live');}\n  else if(evMode==='reconn'){cls='warn';txt=t('ev.reconn');}",
                  "  let txt=t('ev.reconn');\n  if(evMode==='sse'){cls='ok';txt=t('ev.live');}\n  else{cls='warn';txt=t('ev.reconn');}")

    log_re = re.compile(r"let logSeq=0,logTimer=null,logFilter='';\nfunction startLogPoll\(\)\{.*?\nasync function pollLogs\(\)\{\n  try\{\n    const res=await fetch\(url\('/api/logs\?after='\+logSeq\),AUTH_HDR\);\n    if\(!res\.ok\)return;\n    const lines=await res\.json\(\);\n(?P<body>.*?)  \}catch\(e\)\{\}\n\}", re.S)
    m = log_re.search(s)
    if not m:
        raise SystemExit('missing log polling block')
    body = m.group('body')
    new_log = """let logSeq=0,logFilter='';
function applyLogs(lines){
  if(!Array.isArray(lines)||!lines.length)return;
  lines=lines.filter(function(l){return l&&l.seq>logSeq;});
  if(!lines.length)return;
  try{
""" + body + """  }catch(e){console.error('log render failed',e);}
}"""
    s = s[:m.start()] + new_log + s[m.end():]
    s = s.replace("  logSeq=0;logFilter='';", "  logFilter='';")

    trend_start = s.index("let chartRange='2m',trendTimer=null,trendData=null;")
    trend_end = s.index('// 图表重绘统一入口', trend_start)
    new_trend = """let chartRange='2m',trendData=null;
// 趋势数据与统计快照共用 /api/stream SSE；切换范围时重建长连接，
// 浏览器不再定时请求 /api/trend。
function setRange(v){
  chartRange=v;setSeg('range-seg',v);
  trendData=null;
  redrawChart();
  if(window.tlsvpnStreamRestart)window.tlsvpnStreamRestart();
}
function applyTrend(d){
  if(!d)return;
  if(chartRange==='2m'&&d.step_sec!==1){trendData=null;return;}
  trendData=d;
  drawTrendChart(d.points||[]);
}
"""
    s = s[:trend_start] + new_trend + s[trend_end:]

    s = once(s, 'setRefresh(REFRESH_S);setRange(chartRange);fetchStats();\nevStart();',
                'setRefresh(REFRESH_S);setRange(chartRange);', 'startup polling removal')

    for forbidden in [
        "fetch(url('/api/stats')", "fetch(url('/api/trend')", "fetch(url('/api/logs')",
        "fetch(url('/api/events')", 'setInterval(fetchStats', 'setInterval(fetchTrend',
        'setInterval(pollLogs', 'EV_POLL_MS', 'evPollStart()', 'evOpenSSE()'
    ]:
        if forbidden in s:
            raise SystemExit(f'legacy polling marker remains in app.js: {forbidden}')
    p.write_text(s, encoding='utf-8')

    idx = read('webui/index.html')
    idx = idx.replace('onclick="fetchStats()"', 'onclick="window.tlsvpnStreamRestart&&window.tlsvpnStreamRestart()"')
    write('webui/index.html', idx)


STREAM_JS = r'''// Single live WebUI transport. Periodic dashboard data is SSE-only: the browser never
// polls /api/stats, /api/trend, /api/logs or /api/events. EventSource reconnects itself;
// URL/basic-auth sessions use the same SSE wire format through fetch()+ReadableStream.
(function(){
  'use strict';

  let source=null,controller=null,retryTimer=null,retryMs=1000,generation=0;
  const TYPES=['stats','trend','logs','events'];

  function streamPath(){
    const q=new URLSearchParams();
    q.set('interval_ms',String(Math.max(250,Number(REFRESH)||2000)));
    q.set('range',String(chartRange||'2m'));
    q.set('log_after',String(typeof logSeq==='number'?logSeq:0));
    q.set('event_after',String(typeof evSeq==='number'?evSeq:0));
    return '/api/stream?'+q.toString();
  }

  function applyFrame(type,text){
    if(!text)return;
    try{
      const payload=JSON.parse(text);
      if(type==='stats')applyStats(payload);
      else if(type==='trend')applyTrend(payload);
      else if(type==='logs')applyLogs(payload);
      else if(type==='events')applyEvents(payload);
    }catch(err){
      console.error('dashboard SSE '+type+' decode failed',err);
    }
  }

  function setLive(mode){
    if(typeof evStreamState==='function')evStreamState(mode);
  }

  function stopTransport(){
    generation++;
    if(retryTimer){clearTimeout(retryTimer);retryTimer=null;}
    if(source){try{source.close();}catch(e){}source=null;}
    if(controller){try{controller.abort();}catch(e){}controller=null;}
  }

  function scheduleReconnect(myGen){
    if(myGen!==generation||retryTimer)return;
    setLive('reconn');
    retryTimer=setTimeout(function(){
      retryTimer=null;
      if(myGen===generation)start();
    },retryMs);
    retryMs=Math.min(10000,Math.round(retryMs*1.7));
  }

  function startEventSource(myGen,path){
    let es;
    try{es=new EventSource(url(path));}catch(err){scheduleReconnect(myGen);return;}
    source=es;
    TYPES.forEach(function(type){
      es.addEventListener(type,function(ev){if(myGen===generation)applyFrame(type,ev.data);});
    });
    es.onopen=function(){
      if(myGen!==generation)return;
      retryMs=1000;
      setLive('sse');
    };
    // Native EventSource owns reconnect/backoff. There is deliberately no HTTP polling fallback.
    es.onerror=function(){if(myGen===generation)setLive('reconn');};
  }

  function parseBlock(block){
    let event='message',data=[];
    block.split(/\r?\n/).forEach(function(line){
      if(line.startsWith('event:'))event=line.slice(6).trim();
      else if(line.startsWith('data:'))data.push(line.slice(5).replace(/^ /,''));
    });
    return {event:event,data:data.join('\n')};
  }

  async function startFetchStream(myGen,path){
    controller=new AbortController();
    try{
      const headers=Object.assign({'Accept':'text/event-stream'},AUTH_HDR||{});
      const res=await fetch(url(path),{signal:controller.signal,headers:headers,cache:'no-store'});
      if(res.status===401){showUnauthorized();return;}
      if(!res.ok||!res.body)throw new Error('SSE HTTP '+res.status);
      retryMs=1000;
      setLive('sse');
      const reader=res.body.getReader(),dec=new TextDecoder();
      let buf='';
      while(myGen===generation){
        const part=await reader.read();
        if(part.done)break;
        buf+=dec.decode(part.value,{stream:true}).replace(/\r\n/g,'\n');
        let cut;
        while((cut=buf.indexOf('\n\n'))>=0){
          const block=buf.slice(0,cut);buf=buf.slice(cut+2);
          if(!block||block[0]===':')continue;
          const frame=parseBlock(block);
          if(TYPES.indexOf(frame.event)>=0)applyFrame(frame.event,frame.data);
        }
      }
      if(myGen===generation)scheduleReconnect(myGen);
    }catch(err){
      if(myGen===generation&&!(err&&err.name==='AbortError'))scheduleReconnect(myGen);
    }
  }

  function start(){
    stopTransport();
    const myGen=generation;
    const path=streamPath();
    setLive('reconn');
    if(AUTH_HDR&&AUTH_HDR.Authorization)startFetchStream(myGen,path);
    else startEventSource(myGen,path);
  }

  window.tlsvpnStreamRestart=start;
  window.addEventListener('beforeunload',stopTransport);
  start();
})();
'''


def patch_go_backend():
    api = read('api.go')
    marker = "\t// 状态统计 API\n\tmux.HandleFunc(\"/api/stats\", auth(func(w http.ResponseWriter, r *http.Request) {\n\t\tstartWebStatsHandler(w, r, srv, cli)\n\t}))\n"
    repl = "\t// WebUI 单一 SSE 数据通道；兼容 JSON API 仍保留给脚本/测试。\n\tmux.HandleFunc(\"/api/stream\", auth(func(w http.ResponseWriter, r *http.Request) {\n\t\thandleDashboardStream(w, r, srv, cli)\n\t}))\n\n" + marker
    api = once(api, marker, repl, 'Go /api/stream route')
    write('api.go', api)

    wh = read('webui.go')
    wh = once(wh,
              '"<script src=\\\"frameviz.js\\\"></script>\\n<script src=\\\"metrics.js\\\"></script>\\n</body>"',
              '"<script src=\\\"frameviz.js\\\"></script>\\n<script src=\\\"metrics.js\\\"></script>\\n<script src=\\\"stream.js\\\"></script>\\n</body>"',
              'Go stream asset injection')
    write('webui.go', wh)


def patch_smoke():
    p = ROOT / 'scripts/webui_browser_smoke.mjs'
    s = p.read_text(encoding='utf-8')
    s = s.replace("for (const asset of ['frameviz.js', 'metrics.js'])", "for (const asset of ['frameviz.js', 'metrics.js', 'stream.js'])")
    s = once(s, 'const openStreams = new Set();', "const openStreams = new Set();\nconst legacyPollHits = [];", 'smoke request ledger')
    old = """    if (u.pathname === '/api/events') {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', connection: 'keep-alive' });
      res.write(': browser-smoke\\n\\n');
      openStreams.add(res);
      res.on('close', () => openStreams.delete(res));
      return;
    }
    if (u.pathname === '/api/stats') {
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify(statsFixture()));
      return;
    }
"""
    new = """    if (u.pathname === '/api/stream') {
      res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', connection: 'keep-alive' });
      const emit = (name, value) => res.write(`event: ${name}\\ndata: ${JSON.stringify(value)}\\n\\n`);
      emit('stats', statsFixture());
      emit('trend', { step_sec: 1, points: [] });
      emit('logs', []);
      emit('events', []);
      res.write(': browser-smoke\\n\\n');
      openStreams.add(res);
      res.on('close', () => openStreams.delete(res));
      return;
    }
    if (['/api/stats','/api/trend','/api/logs','/api/events'].includes(u.pathname)) {
      legacyPollHits.push(u.pathname);
      res.writeHead(418, { 'content-type': 'application/json' });
      res.end('{\"error\":\"legacy polling forbidden\"}');
      return;
    }
"""
    s = once(s, old, new, 'smoke unified SSE server')
    s = s.replace("if (url.startsWith(origin) && !url.includes('/api/events')) {", "if (url.startsWith(origin) && !url.includes('/api/stream')) {")
    s = once(s, "await browser.close();\nfor (const stream of openStreams) stream.end();",
                "if (legacyPollHits.length) failures.push('legacy polling requests observed: '+legacyPollHits.join(', '));\nawait browser.close();\nfor (const stream of openStreams) stream.end();",
                'smoke legacy poll assertion')
    s = s.replace('WebUI browser smoke passed: no page errors, console errors, or static asset failures across all locales.',
                  'WebUI browser smoke passed: SSE-only transport, no legacy polling, page errors, console errors, or static asset failures across all locales.')
    p.write_text(s, encoding='utf-8')


def add_contract_test():
    test = r'''package main

import (
    "os"
    "strings"
    "testing"
)

func TestWebUIUsesUnifiedSSEWithoutPolling(t *testing.T) {
    app, err := os.ReadFile("webui/app.js")
    if err != nil { t.Fatal(err) }
    s := string(app)
    forbidden := []string{
        "fetch(url('/api/stats')", "fetch(url('/api/trend')", "fetch(url('/api/logs')",
        "fetch(url('/api/events')", "setInterval(fetchStats", "setInterval(fetchTrend",
        "setInterval(pollLogs", "EV_POLL_MS",
    }
    for _, x := range forbidden {
        if strings.Contains(s, x) { t.Fatalf("legacy polling marker remains: %s", x) }
    }
    stream, err := os.ReadFile("webui/stream.js")
    if err != nil { t.Fatal(err) }
    ss := string(stream)
    for _, x := range []string{"/api/stream", "EventSource", "applyStats(payload)", "applyTrend(payload)", "applyLogs(payload)", "applyEvents(payload)"} {
        if !strings.Contains(ss, x) { t.Fatalf("stream.js missing %q", x) }
    }
}
'''
    write('webui_sse_test.go', test)


common_frontend()
write('webui/stream.js', STREAM_JS)
patch_go_backend()
patch_smoke()
add_contract_test()

# One-shot migration: do not leave generator/workflow clutter in the final PR.
for rel in ['scripts/apply_webui_all_sse.py', '.github/workflows/apply-webui-all-sse.yml']:
    q = ROOT / rel
    if q.exists():
        q.unlink()

print('all-SSE WebUI migration applied')
