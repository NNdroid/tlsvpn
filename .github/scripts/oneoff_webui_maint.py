from pathlib import Path
import struct

root = Path('.')
web = root / 'webui'
icons = web / 'icons'
icons.mkdir(parents=True, exist_ok=True)

svgs = {
    'os-linux.svg': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="16" rx="3" fill="#111827"/><path d="M7 9l3 3-3 3M12 15h5" fill="none" stroke="#e5e7eb" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    'os-windows.svg': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path fill="#2563eb" d="M3 4.6l8-1.1v8H3v-6.9zm9-1.3l9-1.3v9.5h-9V3.3zM3 12.5h8v8L3 19.4v-6.9zm9 0h9V22l-9-1.3v-8.2z"/></svg>',
    'os-macos.svg': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path fill="#64748b" d="M16.7 12.8c0-2.3 1.9-3.4 2-3.5-1.1-1.6-2.8-1.8-3.4-1.8-1.4-.2-2.8.9-3.5.9-.7 0-1.8-.9-3-.9-1.5 0-3 .9-3.8 2.2-1.6 2.8-.4 7 1.2 9.3.8 1.1 1.7 2.4 2.9 2.3 1.2 0 1.6-.7 3.1-.7s1.9.7 3.1.7c1.3 0 2.1-1.1 2.8-2.2.9-1.3 1.3-2.6 1.3-2.7-.1 0-2.7-1-2.7-3.6zM14.4 6c.6-.8 1.1-2 1-3.2-1 .1-2.2.7-2.9 1.5-.6.7-1.1 1.9-1 3 1.1.1 2.2-.5 2.9-1.3z"/></svg>',
    'os-android.svg': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><g fill="#3ddc84"><path d="M7 8h10a2 2 0 012 2v7a2 2 0 01-2 2H7a2 2 0 01-2-2v-7a2 2 0 012-2z"/><path d="M7.4 7A5.2 5.2 0 0112 4a5.2 5.2 0 014.6 3H7.4z"/></g><g stroke="#3ddc84" stroke-width="1.4" stroke-linecap="round"><path d="M8.4 4.5L7 2.5M15.6 4.5L17 2.5M3.5 10v6M20.5 10v6M8 19v2.5M16 19v2.5"/></g><g fill="#fff"><circle cx="9.5" cy="6.1" r=".55"/><circle cx="14.5" cy="6.1" r=".55"/></g></svg>',
    'os-bsd.svg': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9" fill="#dc2626"/><path d="M8 8.5l2.5 2.5L8 13.5M12 14h4" fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    'os-generic.svg': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="14" rx="2" fill="#64748b"/><rect x="8" y="19" width="8" height="2" rx="1" fill="#64748b"/><path d="M6 7h12v8H6z" fill="#e2e8f0"/></svg>',
    'arch-x86_64.svg': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="3" fill="#0f766e"/><text x="12" y="14.5" text-anchor="middle" font-family="Arial,sans-serif" font-size="6.5" font-weight="700" fill="#fff">x64</text></svg>',
    'arch-x86.svg': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="3" fill="#0f766e"/><text x="12" y="14.5" text-anchor="middle" font-family="Arial,sans-serif" font-size="6.2" font-weight="700" fill="#fff">x86</text></svg>',
    'arch-arm64.svg': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="3" fill="#0284c7"/><text x="12" y="14.5" text-anchor="middle" font-family="Arial,sans-serif" font-size="6" font-weight="700" fill="#fff">ARM64</text></svg>',
    'arch-arm.svg': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="3" fill="#0284c7"/><text x="12" y="14.5" text-anchor="middle" font-family="Arial,sans-serif" font-size="7" font-weight="700" fill="#fff">ARM</text></svg>',
    'arch-riscv64.svg': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="3" fill="#7c3aed"/><text x="12" y="14.5" text-anchor="middle" font-family="Arial,sans-serif" font-size="5.2" font-weight="700" fill="#fff">RV64</text></svg>',
    'arch-mips.svg': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="3" fill="#d97706"/><text x="12" y="14.5" text-anchor="middle" font-family="Arial,sans-serif" font-size="5.7" font-weight="700" fill="#fff">MIPS</text></svg>',
    'arch-loong64.svg': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect x="4" y="4" width="16" height="16" rx="3" fill="#be123c"/><text x="12" y="14.5" text-anchor="middle" font-family="Arial,sans-serif" font-size="5" font-weight="700" fill="#fff">LA64</text></svg>',
    'arch-generic.svg': '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><rect x="5" y="5" width="14" height="14" rx="2" fill="#64748b"/><g stroke="#64748b" stroke-width="1.4"><path d="M8 2v3M12 2v3M16 2v3M8 19v3M12 19v3M16 19v3M2 8h3M2 12h3M2 16h3M19 8h3M19 12h3M19 16h3"/></g><circle cx="12" cy="12" r="3" fill="#e2e8f0"/></svg>',
}
for name, data in svgs.items():
    (icons / name).write_text(data + '\n', encoding='utf-8')

# Generate a real 32-bit ICO locally.
w = h = 32
rows = []
for y in range(h):
    row = []
    for x in range(w):
        dx, dy = x - 15.5, y - 15.5
        bg = dx*dx + dy*dy <= 14*14
        b,g,r,a = (210,105,37,255) if bg else (0,0,0,0)
        if 9 <= x <= 22 and 14 <= y <= 24:
            b,g,r,a = (255,255,255,255)
        if 11 <= x <= 20 and 8 <= y <= 18 and not (13 <= x <= 18 and 11 <= y <= 18):
            b,g,r,a = (255,255,255,255)
        row.append(bytes((b,g,r,a)))
    rows.append(b''.join(row))
xor = b''.join(reversed(rows))
and_stride = ((w + 31)//32)*4
and_mask = b'\x00' * (and_stride*h)
bih = struct.pack('<IIIHHIIIIII', 40, w, h*2, 1, 32, 0, len(xor), 0,0,0,0)
image = bih + xor + and_mask
(web/'favicon.ico').write_bytes(struct.pack('<HHH',0,1,1) + struct.pack('<BBBBHHII',w,h,0,0,1,32,len(image),22) + image)

for html_name in ('index.html', 'login.html'):
    p = web / html_name
    s = p.read_text(encoding='utf-8')
    if '/favicon.ico' not in s:
        s = s.replace('</head>', '  <link rel="icon" href="/favicon.ico" sizes="any">\n</head>', 1)
    p.write_text(s, encoding='utf-8')

css = web / 'style.css'
css_text = css.read_text(encoding='utf-8')
if '/* local platform badges */' not in css_text:
    css_text += '''\n\n/* local platform badges */\n.platform-badge{display:inline-flex;align-items:center;gap:6px;vertical-align:middle;white-space:nowrap}\n.platform-icon{width:17px;height:17px;display:inline-block;object-fit:contain;vertical-align:-3px;flex:0 0 17px}\n.platform-summary{display:inline-flex;align-items:center;gap:8px;flex-wrap:wrap}\n.platform-icons-only{display:inline-flex;gap:4px;align-items:center;margin-top:3px}\n.platform-icons-only .platform-icon{width:15px;height:15px;flex-basis:15px}\n'''
    css.write_text(css_text, encoding='utf-8')

app = web / 'app.js'
js = app.read_text(encoding='utf-8')
if 'function platformAssetName(kind,value)' not in js:
    js += r'''

function platformAssetName(kind,value){
  const v=String(value||'').trim().toLowerCase();
  if(kind==='os'){
    if(/windows|win32|mingw|msys/.test(v))return 'os-windows.svg';
    if(/darwin|macos|mac os|osx/.test(v))return 'os-macos.svg';
    if(/android/.test(v))return 'os-android.svg';
    if(/freebsd|openbsd|netbsd|dragonfly/.test(v))return 'os-bsd.svg';
    if(/linux|openwrt|immortalwrt|debian|ubuntu|alpine|fedora|centos|rhel|rocky|arch/.test(v))return 'os-linux.svg';
    return 'os-generic.svg';
  }
  if(/amd64|x86_64|x64/.test(v))return 'arch-x86_64.svg';
  if(/(^|[^0-9])386|i[3-6]86|(^|[^a-z])x86([^_]|$)/.test(v))return 'arch-x86.svg';
  if(/arm64|aarch64/.test(v))return 'arch-arm64.svg';
  if(/(^|[^a-z])arm(v[5-9])?([^a-z]|$)/.test(v))return 'arch-arm.svg';
  if(/riscv64/.test(v))return 'arch-riscv64.svg';
  if(/mips/.test(v))return 'arch-mips.svg';
  if(/loong64|loongarch/.test(v))return 'arch-loong64.svg';
  return 'arch-generic.svg';
}
function platformBadge(kind,value,label){
  const raw=String(value||'').trim(), text=String(label===undefined?raw:label||'').trim();
  if(!raw&&!text)return '';
  return '<span class="platform-badge"><img class="platform-icon" src="icons/'+platformAssetName(kind,raw)+'" alt="" loading="lazy" decoding="async"><span class="mono">'+esc(text||raw)+'</span></span>';
}
function platformIconsOnly(os,arch){
  const parts=[];
  if(os)parts.push('<img class="platform-icon" src="icons/'+platformAssetName('os',os)+'" alt="" title="'+esc(os)+'" loading="lazy" decoding="async">');
  if(arch)parts.push('<img class="platform-icon" src="icons/'+platformAssetName('arch',arch)+'" alt="" title="'+esc(arch)+'" loading="lazy" decoding="async">');
  return parts.length?'<span class="platform-icons-only">'+parts.join('')+'</span>':'';
}
function platformSummary(os,version,arch){
  const parts=[];
  if(os)parts.push(platformBadge('os',os,os));
  if(version)parts.push('<span class="mono dim">'+esc(version)+'</span>');
  if(arch)parts.push(platformBadge('arch',arch,arch));
  return parts.length?'<span class="platform-summary">'+parts.join('')+'</span>':'<span class="mono">-</span>';
}
'''

js = js.replace("[t('stt.sys.os'),esc(sys.os||'-')+' '+mtxt(sys.arch||'')],", "[t('stt.sys.os'),platformSummary(sys.os,'',sys.arch)],")
js = js.replace("'<span class=\"mono\">'+esc([peer.os,peer.os_version,peer.arch].filter(Boolean).join(' '))+'</span>'", "platformSummary(peer.os,peer.os_version,peer.arch)")
js = js.replace("'<span class=\"mono\">'+esc([pi.os,pi.os_version,pi.arch].filter(Boolean).join(' '))+'</span>'", "platformSummary(pi.os,pi.os_version,pi.arch)")
host = "(r.c.peer_info&&r.c.peer_info.hostname?'<br><span class=\"dim\">'+hi(esc(r.c.peer_info.hostname),f)+'</span>':'')"
if host in js and 'platformIconsOnly(r.c.peer_info.os,r.c.peer_info.arch)' not in js:
    js = js.replace(host, host + "+(r.c.peer_info&&(r.c.peer_info.os||r.c.peer_info.arch)?'<br>'+platformIconsOnly(r.c.peer_info.os,r.c.peer_info.arch):'')", 1)
app.write_text(js, encoding='utf-8')

(root / 'webui_platform_assets_test.go').write_text(r'''package main

import (
    "io/fs"
    "net/http/httptest"
    "strings"
    "testing"
)

func TestWebUIPlatformAssetsAndFavicon(t *testing.T) {
    index, err := fs.ReadFile(webuiFS, "webui/index.html")
    if err != nil { t.Fatal(err) }
    if !strings.Contains(string(index), "/favicon.ico") { t.Fatal("index.html missing local favicon") }
    app, err := fs.ReadFile(webuiFS, "webui/app.js")
    if err != nil { t.Fatal(err) }
    for _, needle := range []string{"platformSummary", "platformAssetName", "icons/"} {
        if !strings.Contains(string(app), needle) { t.Fatalf("app.js missing %q", needle) }
    }
    for _, name := range []string{"os-linux.svg", "os-windows.svg", "os-macos.svg", "os-android.svg", "arch-x86_64.svg", "arch-arm64.svg", "arch-riscv64.svg"} {
        if _, err := fs.ReadFile(webuiFS, "webui/icons/"+name); err != nil { t.Fatalf("missing %s: %v", name, err) }
    }
    b, err := fs.ReadFile(webuiFS, "webui/favicon.ico")
    if err != nil || len(b) < 100 { t.Fatalf("invalid favicon.ico: len=%d err=%v", len(b), err) }
    rr := httptest.NewRecorder()
    req := httptest.NewRequest("GET", "/favicon.ico", nil)
    webuiHandler().ServeHTTP(rr, req)
    if rr.Code != 200 || rr.Body.Len() < 100 { t.Fatalf("favicon response status=%d len=%d", rr.Code, rr.Body.Len()) }
}
''', encoding='utf-8')
