from pathlib import Path
p=Path('webui/app.js')
s=p.read_text()

def rep(old,new,n=1):
    global s
    if s.count(old)<n:
        raise SystemExit(f'expected {n}, got {s.count(old)} for {old[:100]!r}')
    s=s.replace(old,new,n)

rep("function ntxt(){return '<span style=\"color:var(--sub)\">-</span>';}\n",
    "function ntxt(){return '<span style=\"color:var(--sub)\">-</span>';}\n"
    "function peerSummary(p){\n"
    "  if(!p)return '';\n"
    "  const a=[];\n"
    "  if(p.hostname)a.push(p.hostname);\n"
    "  const impl=[p.implementation,p.version].filter(Boolean).join(' ');if(impl)a.push(impl);\n"
    "  const plat=[p.os,p.os_version,p.arch].filter(Boolean).join(' ');if(plat)a.push(plat);\n"
    "  if(p.kernel)a.push('kernel '+p.kernel);\n"
    "  return a.join(' · ');\n"
    "}\n",1)

rep("  const sys=data.system||{},neg=data.negotiate||{},b=neg.brutal||{},tls=neg.tls||{},cfg=data.cfg||{};",
    "  const sys=data.system||{},neg=data.negotiate||{},b=neg.brutal||{},tls=neg.tls||{},cfg=data.cfg||{},peer=data.peer||{};",1)

rep("  if(data.mode==='client'){\n    nrw.push([t('stt.neg.epoch'),neg.session_epoch?String(neg.session_epoch):ntxt()]);",
    "  if(data.mode==='client'){\n    if(peerSummary(peer))nrw.push([t('tp.peer'),mtxt(peerSummary(peer))]);\n    nrw.push([t('stt.neg.epoch'),neg.session_epoch?String(neg.session_epoch):ntxt()]);",1)

old="      '<td class=\"num dim\" title=\"'+esc(r.id)+'\">'+hi(esc(shortId(r.id,10)),f)+'</td>'+\n"
new="      '<td class=\"num dim\" title=\"'+esc(r.id)+'\">'+hi(esc(shortId(r.id,10)),f)+(r.c.peer_info&&r.c.peer_info.hostname?'<br><span class=\"dim\">'+hi(esc(r.c.peer_info.hostname),f)+'</span>':'')+'</td>'+\n"
rep(old,new,1)

rep("function tpPeerNodes(data){\n  const cfg=data.cfg||{},np=data.negotiate||{},tl=np.tls||{},ci=data.cert;\n  const rs=[];",
    "function tpPeerNodes(data){\n  const cfg=data.cfg||{},np=data.negotiate||{},tl=np.tls||{},ci=data.cert,peer=data.peer||{};\n  const rs=[];\n  if(peer.hostname)rs.push([t('tp.host'),'<span class=\"mono\">'+esc(peer.hostname)+'</span>']);\n  if(peer.implementation||peer.version)rs.push([t('kpi.version'),'<span class=\"mono\">'+esc([peer.implementation,peer.version].filter(Boolean).join(' '))+'</span>']);\n  if(peer.os||peer.os_version||peer.arch)rs.push([t('stt.sys.os'),'<span class=\"mono\">'+esc([peer.os,peer.os_version,peer.arch].filter(Boolean).join(' '))+'</span>']);",1)

needle="      if(c.mac)rs.push([t('tp.mac2'),'<span class=\"mono\">'+esc(c.mac)+'</span>']);\n      if(b.n){"
replacement="      if(c.mac)rs.push([t('tp.mac2'),'<span class=\"mono\">'+esc(c.mac)+'</span>']);\n      const pi=c.peer_info||{};\n      if(pi.hostname)rs.push([t('tp.host'),'<span class=\"mono\">'+esc(pi.hostname)+'</span>']);\n      if(pi.implementation||pi.version)rs.push([t('kpi.version'),'<span class=\"mono\">'+esc([pi.implementation,pi.version].filter(Boolean).join(' '))+'</span>']);\n      if(pi.os||pi.os_version||pi.arch)rs.push([t('stt.sys.os'),'<span class=\"mono\">'+esc([pi.os,pi.os_version,pi.arch].filter(Boolean).join(' '))+'</span>']);\n      if(b.n){"
rep(needle,replacement,1)

p.write_text(s)
