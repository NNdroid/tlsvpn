package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// newTestWebManager 构造一个 bind=tunnel 的面板管理器。v4Gw/v6Gw 直接写进
// Server 字段，不启动真实服务端；v6Gw 传 "" 表示无 v6 地址池。
func newTestWebManager(port int, v4Gw, v6Gw string) *WebManager {
	cfg := &Config{Web: WebConfig{Addr: fmt.Sprintf("127.0.0.1:%d", port), Bind: "tunnel"}}
	mgr := NewWebManager(&Server{v4Gw: v4Gw, v6Gw: v6Gw}, nil, cfg, http.NewServeMux())
	mgr.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mgr
}

func closeAllListeners(mgr *WebManager) {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	for _, wl := range mgr.listeners {
		wl.l.Close()
	}
	mgr.listeners = nil
}

func openSpecs(mgr *WebManager) []listenSpec {
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	out := make([]listenSpec, len(mgr.listeners))
	for i, wl := range mgr.listeners {
		out[i] = wl.spec
	}
	return out
}

// 部分成功语义：v4 能绑、v6 绑不上时，v4 必须照常 serve，
// 不能因为 v6 失败把已经打开的监听一起关掉。
func TestWebPartialBindKeepsWorkingListener(t *testing.T) {
	port := freePort(t)
	mgr := newTestWebManager(port, "127.0.0.1", "fd99:10:5:8::1")
	defer closeAllListeners(mgr)

	mgr.rebindIfNeeded()

	specs := openSpecs(mgr)
	if len(specs) != 1 || specs[0].ip != "127.0.0.1" {
		t.Fatalf("expect only the v4 listener open (v6 pending), got %+v", specs)
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if err != nil {
		t.Fatalf("panel not reachable on the tunnel v4 address: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("unexpected response body %q", body)
	}
}

// 隧道 v6 地址不可用时不影响 v4；地址消失后只关该监听，v4 不受牵连。
func TestWebDropsListenerWhenAddressDisappears(t *testing.T) {
	port := freePort(t)
	mgr := newTestWebManager(port, "127.0.0.1", "fd99:10:5:8::1")
	defer closeAllListeners(mgr)

	mgr.rebindIfNeeded()
	mgr.srv.v6Gw = "" // 模拟 v6 地址消失（配置指纹不变，走增量路径）
	mgr.rebindIfNeeded()

	specs := openSpecs(mgr)
	if len(specs) != 1 || specs[0].ip != "127.0.0.1" {
		t.Fatalf("expect only the v4 listener to remain, got %+v", specs)
	}
}

// 无 v6 地址池时不产生 v6 规格，也不影响 v4 监听。
func TestWebNoV6Pool(t *testing.T) {
	port := freePort(t)
	mgr := newTestWebManager(port, "127.0.0.1", "")
	defer closeAllListeners(mgr)

	mgr.rebindIfNeeded()

	specs := openSpecs(mgr)
	if len(specs) != 1 || specs[0].ip != "127.0.0.1" {
		t.Fatalf("expect a single v4 listener, got %+v", specs)
	}
}

// 配置指纹变化（换端口/换证书）必须整体重建：旧监听关闭、新监听打开。
func TestWebRebuildOnPortChange(t *testing.T) {
	oldPort, newPort := freePort(t), freePort(t)
	mgr := newTestWebManager(oldPort, "127.0.0.1", "")
	defer closeAllListeners(mgr)

	mgr.rebindIfNeeded()
	if len(openSpecs(mgr)) != 1 {
		t.Fatalf("expect the old listener to be open")
	}

	mgr.SetConfig(&Config{Web: WebConfig{Addr: fmt.Sprintf("127.0.0.1:%d", newPort), Bind: "tunnel"}})
	mgr.rebindIfNeeded()

	specs := openSpecs(mgr)
	if len(specs) != 1 || specs[0].port != newPort {
		t.Fatalf("expect 1 listener on new port %d, got %+v", newPort, specs)
	}
}

// 认证串热更不改指纹：已打开的监听保持不动，不重复开端口。
func TestWebAuthChangeKeepsListeners(t *testing.T) {
	port := freePort(t)
	mgr := newTestWebManager(port, "127.0.0.1", "")
	defer closeAllListeners(mgr)

	mgr.rebindIfNeeded()
	mgr.mu.Lock()
	before := mgr.listeners[0].l
	mgr.mu.Unlock()

	mgr.SetConfig(&Config{Web: WebConfig{
		Addr: fmt.Sprintf("127.0.0.1:%d", port), Bind: "tunnel", Auth: "admin:s3cret",
	}})
	mgr.rebindIfNeeded()

	mgr.mu.Lock()
	after := mgr.listeners[0].l
	mgr.mu.Unlock()

	if before != after {
		t.Fatal("auth change must not rebuild the listener")
	}
}

// 同一失败集合 30s 内只上报一次：2s 一轮的轮询不该把日志刷成刷屏。
func TestWebOnceWarnDedups(t *testing.T) {
	mgr := &WebManager{}
	if !mgr.onceWarn("listen|[fd99:10:5:8::1]:8000: err") {
		t.Fatal("first report must pass through")
	}
	if mgr.onceWarn("listen|[fd99:10:5:8::1]:8000: err") {
		t.Fatal("same key within 30s must be suppressed")
	}
	if !mgr.onceWarn("listen|10.5.8.1:8000: err") {
		t.Fatal("a different failing set must pass through")
	}
}

// 面板静态资源（webui/ 经 go:embed 嵌入）：/、/app.js、/style.css 必须可访问
// 且带 no-store（资产随二进制升级但 URL 不变）；目录列表与未知文件不得暴露。
func TestWebUIServesEmbeddedAssets(t *testing.T) {
	port := freePort(t)
	base := fmt.Sprintf("127.0.0.1:%d", port)
	startWebServer(base, nil, nil, "", "", "", &Config{Web: WebConfig{Addr: base}})

	client := &http.Client{Timeout: 2 * time.Second}
	root := fmt.Sprintf("http://%s/", base)

	// 监听由 mgr.Run 首轮建立，startWebServer 返回时未必已就绪
	deadline := time.Now().Add(5 * time.Second)
	var indexBody []byte
	for {
		resp, err := client.Get(root)
		if err == nil {
			indexBody, _ = io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("dashboard not reachable on %s: %v", root, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !strings.Contains(string(indexBody), `<script src="app.js"></script>`) ||
		!strings.Contains(string(indexBody), `style.css`) {
		t.Fatal("index page must reference the external webui assets")
	}

	resp, err := client.Get(root + "app.js")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /app.js: status=%v err=%v", resp, err)
	}
	jsBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(jsBody), "const I18N={") {
		t.Fatal("/app.js must serve the dashboard script")
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("/app.js Cache-Control = %q, want no-store", cc)
	}

	resp, err = client.Get(root + "style.css")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /style.css: status=%v err=%v", resp, err)
	}
	resp.Body.Close()

	// 目录列表与未知路径不允许暴露
	for _, path := range []string{"webui/", "nonexistent.js", "../web.go"} {
		resp, err := client.Get(root + path)
		if err != nil {
			t.Fatalf("GET /%s: %v", path, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("GET /%s must be 404, got %d", path, resp.StatusCode)
		}
	}
}
