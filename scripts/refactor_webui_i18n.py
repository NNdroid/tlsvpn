from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]

def p(rel): return ROOT / rel
def read(rel): return p(rel).read_text(encoding='utf-8')
def write(rel, data): p(rel).write_text(data, encoding='utf-8')

# 1) Split the monolithic locale tables and language helpers out of app.js.
app = read('webui/app.js')
marker = '\n// 浏览器语言'
if not app.startswith('const I18N={') or marker not in app:
    raise SystemExit('unexpected app.js i18n layout')
mi = app.index(marker)
dict_src = app[:mi].rstrip()
setseg = app.index('function setSeg(', mi)
setlang = app.index('function setLang(', setseg)
fmtdur = app.index('function fmtDur(', setlang)
helper_src = app[mi+1:setseg].rstrip() + '\n\n' + app[setlang:fmtdur].rstrip()
app_new = app[setseg:setlang] + app[fmtdur:]

# 2) Move metric-specific locale overrides into the same locale source.
metrics = read('webui/metrics.js')
ms = metrics.index('  function setSchedWords(')
me = metrics.rindex('\n})();')
metric_i18n = metrics[ms:me].rstrip()
metrics_new = metrics[:ms].rstrip() + '\n})();\n'

# 3) Move frame visualizer locale strings into the same locale source.
frame = read('webui/frameviz.js')
ls = frame.index('  const L={')
le = frame.index('  const s=L[lang]||L.en;')
frame_i18n = frame[ls:le].replace('  const L=', 'const FRAMEVIZ_I18N=', 1).rstrip()
fstart = frame.index('  const lang=')
send = frame.index('\n', le) + 1
frame_new = frame[:fstart] + '  const s=FRAMEVIZ_I18N[LANG]||FRAMEVIZ_I18N.en;\n' + frame[send:]

# 4) Fold the generated zh-TW locale into i18n.js as well.
zh_tw = read('webui/zh-tw.js').rstrip()
i18n = (
    '// TLSVPN WebUI internationalization: single source of truth for all locales.\n'
    '// Loaded before app.js, metrics.js and frameviz.js.\n'
    + dict_src + '\n\n'
    + zh_tw + '\n\n'
    + '(() => {\n' + metric_i18n + '\n})();\n\n'
    + frame_i18n + '\n\n'
    + helper_src + '\n'
)
write('webui/i18n.js', i18n)
write('webui/app.js', app_new)
write('webui/metrics.js', metrics_new)
write('webui/frameviz.js', frame_new)

# 5) Load i18n before app.js; remove compatibility locale assets.
idx = read('webui/index.html')
if '<script src="i18n.js"></script>' not in idx:
    idx = idx.replace('<script src="app.js"></script>', '<script src="i18n.js"></script>\n<script src="app.js"></script>', 1)
idx = idx.replace('<script src="zh-tw.js"></script>\n', '')
idx = idx.replace('<script src="frameviz-zh-tw.js"></script>\n', '')
write('webui/index.html', idx)

# Go embed/file-server glue.
if p('webui.go').exists():
    wg = read('webui.go')
    old = '<script src=\\"zh-tw.js\\"></script>\\n<script src=\\"frameviz.js\\"></script>\\n<script src=\\"frameviz-zh-tw.js\\"></script>\\n<script src=\\"metrics.js\\"></script>\\n</body>'
    new = '<script src=\\"frameviz.js\\"></script>\\n<script src=\\"metrics.js\\"></script>\\n</body>'
    if old not in wg:
        raise SystemExit('webui.go injection layout changed')
    write('webui.go', wg.replace(old, new, 1))

    wt = read('web_test.go')
    wt = wt.replace(
        'if !strings.Contains(string(indexBody), `<script src="app.js"></script>`) ||\n\t\t!strings.Contains(string(indexBody), `style.css`) {',
        'if !strings.Contains(string(indexBody), `<script src="i18n.js"></script>`) ||\n\t\t!strings.Contains(string(indexBody), `<script src="app.js"></script>`) ||\n\t\t!strings.Contains(string(indexBody), `style.css`) {',
        1,
    )
    old_assert = 'if !strings.Contains(string(jsBody), "const I18N={") {\n\t\tt.Fatal("/app.js must serve the dashboard script")\n\t}'
    if old_assert not in wt:
        raise SystemExit('web_test.go app assertion layout changed')
    wt = wt.replace(old_assert, 'if strings.Contains(string(jsBody), "const I18N={") {\n\t\tt.Fatal("/app.js must not embed locale dictionaries")\n\t}', 1)
    anchor = '\tif cc := resp.Header.Get("Cache-Control"); cc != "no-store" {\n\t\tt.Fatalf("/app.js Cache-Control = %q, want no-store", cc)\n\t}\n'
    if anchor not in wt:
        raise SystemExit('web_test.go cache assertion layout changed')
    addition = anchor + '''\n\tresp, err = client.Get(root + "i18n.js")\n\tif err != nil || resp.StatusCode != http.StatusOK {\n\t\tt.Fatalf("GET /i18n.js: status=%v err=%v", resp, err)\n\t}\n\ti18nBody, _ := io.ReadAll(resp.Body)\n\tresp.Body.Close()\n\tif !strings.Contains(string(i18nBody), "const I18N={") || !strings.Contains(string(i18nBody), "const FRAMEVIZ_I18N=") {\n\t\tt.Fatal("/i18n.js must contain all dashboard locale dictionaries")\n\t}\n'''
    write('web_test.go', wt.replace(anchor, addition, 1))

    frame_test = r'''package main

import (
    "io"
    "net/http/httptest"
    "strings"
    "testing"
)

func TestWebUII18nAndFrameVisualizerAreInjected(t *testing.T) {
    ts := httptest.NewServer(webuiHandler())
    defer ts.Close()
    resp, err := ts.Client().Get(ts.URL + "/")
    if err != nil { t.Fatal(err) }
    body, _ := io.ReadAll(resp.Body)
    resp.Body.Close()
    html := string(body)
    i18nPos := strings.Index(html, `<script src="i18n.js"></script>`)
    appPos := strings.Index(html, `<script src="app.js"></script>`)
    if i18nPos < 0 || appPos < 0 || i18nPos > appPos { t.Fatal("i18n.js must load before app.js") }
    for _, want := range []string{`data-v="zh-TW"`, `>繁中</button>`, `<script src="frameviz.js"></script>`, `<script src="metrics.js"></script>`} {
        if !strings.Contains(html, want) { t.Fatalf("index response missing %q", want) }
    }
    for _, stale := range []string{`zh-tw.js`, `frameviz-zh-tw.js`} {
        if strings.Contains(html, stale) { t.Fatalf("index still references obsolete locale asset %q", stale) }
    }
    assets := []struct{ path string; want []string }{
        {"/i18n.js", []string{"const I18N={", "const FRAMEVIZ_I18N=", "'zh-CN'", "'zh-TW'", "'de'", "'fr'", "'ja'", "Frame format example", "FEC recovery rate"}},
        {"/frameviz.js", []string{"FRAMEVIZ_I18N[LANG]", "AES-256-GCM", "12 KiB", "16 KiB", "padLen=0", "1 MiB"}},
        {"/metrics.js", []string{"assigned - p.assigned", "_share_pct", "_queue_eta_us"}},
    }
    for _, a := range assets {
        resp, err = ts.Client().Get(ts.URL + a.path)
        if err != nil { t.Fatal(err) }
        b, _ := io.ReadAll(resp.Body)
        resp.Body.Close()
        if resp.StatusCode != 200 { t.Fatalf("%s status=%d", a.path, resp.StatusCode) }
        src := string(b)
        for _, want := range a.want { if !strings.Contains(src, want) { t.Fatalf("%s missing %q", a.path, want) } }
        if a.path != "/i18n.js" && strings.Contains(src, "const I18N={") { t.Fatalf("%s must not embed locale dictionaries", a.path) }
    }
    for _, old := range []string{"/zh-tw.js", "/frameviz-zh-tw.js"} {
        resp, err = ts.Client().Get(ts.URL + old)
        if err != nil { t.Fatal(err) }
        io.Copy(io.Discard, resp.Body)
        resp.Body.Close()
        if resp.StatusCode != 404 { t.Fatalf("obsolete asset %s must be 404, got %d", old, resp.StatusCode) }
    }
}
'''
    write('webui_frameviz_test.go', frame_test)

# Rust embedded asset table and tests.
if p('src/webui_assets.rs').exists():
    assets = read('src/webui_assets.rs')
    if '"/i18n.js"' not in assets:
        needle = '    match path {\n        "/app.js" => Some((\n'
        repl = '    match path {\n        "/i18n.js" => Some((\n            include_bytes!("../webui/i18n.js"),\n            "application/javascript; charset=utf-8",\n        )),\n        "/app.js" => Some((\n'
        if needle not in assets:
            raise SystemExit('webui_assets app route layout changed')
        assets = assets.replace(needle, repl, 1)
    assets = re.sub(r'\n        "/frameviz-zh-tw\.js" => Some\(\(\n            include_bytes!\("\.\./webui/frameviz-zh-tw\.js"\),\n            "application/javascript; charset=utf-8",\n        \)\),', '', assets)
    assets = re.sub(r'\n        "/zh-tw\.js" => Some\(\(\n            include_bytes!\("\.\./webui/zh-tw\.js"\),\n            "application/javascript; charset=utf-8",\n        \)\),', '', assets)
    write('src/webui_assets.rs', assets)

    ds = read('tests/dashboard_script_test.rs')
    start = ds.index('#[test]\nfn webui_matches_shared_static_asset_contract()')
    mid = ds.index('#[test]\nfn rust_embed_table_covers_primary_assets()', start)
    end = ds.index('#[test]\nfn rust_webui_backend_matches_go_management_contract()', mid)
    first = r'''#[test]
fn webui_matches_shared_static_asset_contract() {
    let root = webui();
    let index = fs::read_to_string(root.join("index.html")).expect("index.html");
    let app = fs::read_to_string(root.join("app.js")).expect("app.js");
    let i18n = fs::read_to_string(root.join("i18n.js")).expect("i18n.js");
    let css = fs::read_to_string(root.join("style.css")).expect("style.css");
    let frameviz = fs::read_to_string(root.join("frameviz.js")).expect("frameviz.js");
    assert!(index.contains("/favicon.ico"));
    let i18n_pos = index.find("src=\"i18n.js\"").expect("i18n.js script");
    let app_pos = index.find("src=\"app.js\"").expect("app.js script");
    assert!(i18n_pos < app_pos, "i18n.js must load before app.js");
    assert!(index.contains("data-v=\"zh-TW\""));
    assert!(!index.contains("zh-tw.js") && !index.contains("frameviz-zh-tw.js"));
    assert!(!app.contains("const I18N={"));
    for marker in ["const I18N={", "const FRAMEVIZ_I18N=", "'zh-CN'", "'zh-TW'", "'de'", "'fr'", "'ja'", "Frame format example", "FEC recovery rate"] {
        assert!(i18n.contains(marker), "i18n.js missing {marker:?}");
    }
    assert!(app.contains("platformAssetName"));
    assert!(app.contains("/api/stats"));
    assert!(css.contains("platform-badge"));
    for marker in ["FRAMEVIZ_I18N[LANG]", "AES-256-GCM", "AES-128-GCM", "ChaCha20-Poly1305", "XChaCha20-Poly1305", "1514 B", "1530 B", "12 KiB", "16 KiB", "padLen=0", "4 B BE", "seq=0", "1 MiB"] {
        assert!(frameviz.contains(marker), "frameviz missing {marker:?}");
    }
    for file in ["favicon.ico", "i18n.js", "frameviz.js", "icons/os-linux.svg", "icons/os-windows.svg", "icons/os-macos.svg", "icons/os-android.svg", "icons/arch-x86_64.svg", "icons/arch-arm64.svg", "icons/arch-riscv64.svg"] {
        let meta = fs::metadata(root.join(file)).unwrap_or_else(|e| panic!("missing {file}: {e}"));
        assert!(meta.len() > 0, "empty asset: {file}");
    }
    for old in ["zh-tw.js", "frameviz-zh-tw.js"] { assert!(!root.join(old).exists(), "obsolete asset remains: {old}"); }
}

'''
    second = r'''#[test]
fn rust_embed_table_covers_primary_assets() {
    let src = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/webui_assets.rs")).expect("webui_assets.rs");
    for route in ["/", "/index.html", "/style.css", "/i18n.js", "/app.js", "/frameviz.js", "/metrics.js", "/favicon.ico", "/icons/os-linux.svg"] {
        assert!(src.contains(&format!("\"{route}\"")), "embed table missing {route}");
    }
    assert!(!src.contains("/zh-tw.js") && !src.contains("/frameviz-zh-tw.js"));
}

'''
    write('tests/dashboard_script_test.rs', ds[:start] + first + second + ds[end:])

    wm = read('tests/webui_metrics_test.rs')
    old = 'let app = html.find("<script src=\\"app.js\\"></script>").expect("app.js script");'
    if old in wm:
        wm = wm.replace(old, 'let i18n = html.find("<script src=\\"i18n.js\\"></script>").expect("i18n.js script");\n    let app = html.find("<script src=\\"app.js\\"></script>").expect("app.js script");\n    assert!(i18n < app, "i18n.js must load before app.js");', 1)
    write('tests/webui_metrics_test.rs', wm)

# 6) Old locale shims are intentionally removed: there is one locale source now.
for rel in ['webui/zh-tw.js', 'webui/frameviz-zh-tw.js']:
    q = p(rel)
    if q.exists(): q.unlink()

print('WebUI i18n refactor generated successfully')
