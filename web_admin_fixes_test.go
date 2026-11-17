package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ======================= ban TTL 校验（/api/control 与 MCP 共享） =======================

func TestValidateBanTTLMinutes(t *testing.T) {
	for _, ttl := range []int{0, 1, 60, 10080} {
		if err := validateBanTTLMinutes(ttl); err != nil {
			t.Fatalf("ttl=%d must be valid: %v", ttl, err)
		}
	}
	// 用平台可表达的最大 int（32 位=2^31-1，64 位=2^63-1 的同型截取）承载
	// "超大值经 time.Duration 乘法回绕" 的测试意图，保证 386 下可编译。
	hugeTTL := int(^uint32(0) >> 1)
	for _, ttl := range []int{-1, -60, 10081, hugeTTL} {
		if err := validateBanTTLMinutes(ttl); err == nil {
			t.Fatalf("ttl=%d must be rejected", ttl)
		}
	}
}

// TestControlBanRejectsInvalidTTL /api/control 的 ban 分支必须拒绝负值/超大
// ttl_minutes（经 time.Duration 乘法回绕成 <=0 会被 Server.Ban 当永久封禁）。
func TestControlBanRejectsInvalidTTL(t *testing.T) {
	srv := statsAuditServer()
	port := freePort(t)
	base := fmt.Sprintf("127.0.0.1:%d", port)
	startWebServer(base, srv, nil, "", "", "", &Config{Web: WebConfig{Addr: base}})

	// startWebServer 的监听经 goSafe(mgr.Run) 异步启动（2s rebind 循环），
	// 立即 POST 会偶发 connect refused。先轮询等待 listener 就绪。
	waitListener(t, base, 3*time.Second)

	post := func(ttl string) int {
		body := fmt.Sprintf(`{"action":"ban","client_id":"c1","ttl_minutes":%s}`, ttl)
		req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s/api/control", base), strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Requested-With", "tlsvpn")
		req.Header.Set("Content-Type", "application/json")
		resp, err := (&http.Client{Timeout: 3 * time.Second}).Do(req)
		if err != nil {
			t.Fatalf("POST /api/control ttl=%s: %v", ttl, err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}

	for _, ttl := range []string{"-5", "10081", "4611686018427387904"} {
		if code := post(ttl); code != http.StatusBadRequest {
			t.Fatalf("ttl=%s must be rejected with 400, got %d", ttl, code)
		}
	}
	if srv.IsBanned("c1") {
		t.Fatal("invalid ttl must not ban the client")
	}
	if code := post("1"); code != http.StatusOK {
		t.Fatalf("valid ttl status=%d, want 200", code)
	}
	if !srv.IsBanned("c1") {
		t.Fatal("valid ttl must ban the client")
	}
	srv.Unban("c1")
}

// ======================= HSTS（仅 TLS listener） =======================

func TestHSTSOnlyOnTLSListener(t *testing.T) {
	start := func(t *testing.T, cert, key string) (*WebManager, net.Listener) {
		t.Helper()
		cfg := &Config{Web: WebConfig{Addr: "127.0.0.1:0", Cert: cert, Key: key}}
		mgr := NewWebManager(&Server{}, nil, cfg, http.NewServeMux())
		mgr.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go mgr.serve(l)
		return mgr, l
	}

	_, l := start(t, "cert.pem", "key.pem")
	defer l.Close()
	resp, err := http.Get("http://" + l.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := resp.Header.Get("Strict-Transport-Security"); got != "max-age=31536000; includeSubDomains" {
		t.Fatalf("TLS-mode listener must send HSTS, got %q", got)
	}

	_, l2 := start(t, "", "")
	defer l2.Close()
	resp2, err := http.Get("http://" + l2.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if got := resp2.Header.Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("plain listener must not send HSTS, got %q", got)
	}
}

// ======================= loadWebTLS 文件指纹缓存 =======================

// writeTestCertPair 生成一对自签证书/私钥 PEM 供 loadWebTLS 测试使用。
func writeTestCertPair(t *testing.T, dir, base string) (certPath, keyPath string, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: base},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certPath = filepath.Join(dir, base+"-cert.pem")
	keyPath = filepath.Join(dir, base+"-key.pem")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, keyPEM
}

func TestWebTLSReloadOnChange(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, keyPEM := writeTestCertPair(t, dir, "a")
	mgr := &WebManager{}
	cfg := &Config{Web: WebConfig{Cert: certPath, Key: keyPath}}

	c1, err := mgr.loadWebTLS(cfg)
	if err != nil || c1 == nil || len(c1.Certificates) != 1 {
		t.Fatalf("first load: cfg=%v err=%v", c1, err)
	}
	// 路径与 mtime/size 指纹均未变化：必须命中缓存（同一 *tls.Config），不再读盘解析
	c2, err := mgr.loadWebTLS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if c2 != c1 {
		t.Fatal("unchanged cert/key must reuse the cached TLS config")
	}
	// mtime 变化（证书热替换场景）：必须重新加载
	future := time.Now().Add(10 * time.Second)
	if err := os.Chtimes(certPath, future, future); err != nil {
		t.Fatal(err)
	}
	c3, err := mgr.loadWebTLS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if c3 == c1 {
		t.Fatal("mtime change must reload the key pair")
	}
	// key 路径变化：必须重新加载
	key2 := filepath.Join(dir, "b-key.pem")
	if err := os.WriteFile(key2, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	c4, err := mgr.loadWebTLS(&Config{Web: WebConfig{Cert: certPath, Key: key2}})
	if err != nil {
		t.Fatal(err)
	}
	if c4 == c3 {
		t.Fatal("key path change must reload the key pair")
	}
	// cert/key 留空：返回 nil 并清空缓存
	c5, err := mgr.loadWebTLS(&Config{})
	if err != nil || c5 != nil {
		t.Fatalf("no TLS config expected, got %v err=%v", c5, err)
	}
	if mgr.tlsCached != nil {
		t.Fatal("cache must be cleared when TLS is disabled")
	}
}

// ======================= MCP 请求体 peek 上限（1MB，不再 64KB 截断） =======================

func TestMCPRequestMethodLargeBody(t *testing.T) {
	// 700KB 合法 JSON-RPC：必须完整解析出 method/tool，且 body 原样回填
	pad := strings.Repeat("x", 700<<10)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tlsvpn_status","note":"` + pad + `"}}`
	req := httptest.NewRequest(http.MethodPost, "http://x/mcp", strings.NewReader(body))
	method, tool := mcpRequestMethod(req)
	if method != "tools/call" || tool != "tlsvpn_status" {
		t.Fatalf("mcpRequestMethod=(%q,%q), large body must not be truncated", method, tool)
	}
	rest, err := io.ReadAll(req.Body)
	if err != nil || string(rest) != body {
		t.Fatalf("body not restored intact: len=%d err=%v", len(rest), err)
	}

	// 超过 1MB：peek 返回空、不消费剩余流；handler 看到完整 body，
	// 由其 MaxRequestBodyBytes 正常拒绝（413）。
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tlsvpn_status","note":"` + strings.Repeat("y", (1<<20)+4096) + `"}}`
	req2 := httptest.NewRequest(http.MethodPost, "http://x/mcp", strings.NewReader(big))
	method2, tool2 := mcpRequestMethod(req2)
	if method2 != "" || tool2 != "" {
		t.Fatalf("oversized body must not be parsed, got (%q,%q)", method2, tool2)
	}
	rest2, err := io.ReadAll(req2.Body)
	if err != nil || len(rest2) != len(big) {
		t.Fatalf("oversized body must stay intact for the handler: len=%d want=%d err=%v", len(rest2), len(big), err)
	}
}

// ======================= 进程级 stats 缓存与去三重序列化 =======================

func TestWebStatsCacheReuse(t *testing.T) {
	s := statsAuditServer()

	// 同一实例 1s 内连续两次调用复用同一次构建
	st1, enc1, err := cachedWebStats(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	st2, enc2, err := cachedWebStats(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st1 != st2 || string(enc1) != string(enc2) {
		t.Fatal("calls within TTL must reuse the same build")
	}

	// SSE（dashboardCapture）路径命中缓存：1s 内状态变化对第二个 viewer 不可见
	c1 := &dashboardCapture{}
	startWebStatsHandler(c1, httptest.NewRequest("GET", "/api/stream", nil), s, nil)
	session := &ClientSession{Port: &AsyncPort{}, IPv4: "10.0.0.2", CreatedAt: time.Now(), conns: map[*connInfo]struct{}{}}
	s.mu.Lock()
	s.activeClients["a"] = session
	s.mu.Unlock()
	c2 := &dashboardCapture{}
	startWebStatsHandler(c2, httptest.NewRequest("GET", "/api/stream", nil), s, nil)
	if c1.body.String() != c2.body.String() {
		t.Fatal("SSE capture path must replay cached stats within TTL")
	}

	// 直调 /api/stats 不经 capture：保持实时构建，状态变化立即可见
	rr := httptest.NewRecorder()
	startWebStatsHandler(rr, httptest.NewRequest("GET", "/api/stats", nil), s, nil)
	var got WebStats
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode direct stats: %v: %s", err, rr.Body.String())
	}
	if got.RetainedSessions != 1 {
		t.Fatalf("direct /api/stats must be live, retained=%d", got.RetainedSessions)
	}
	if !strings.Contains(rr.Body.String(), `"retained_sessions":1`) {
		t.Fatalf("direct /api/stats JSON mismatch: %s", rr.Body.String())
	}

	// 不同实例指针不串值：缓存键包含 srv/cli 指纹
	s2 := statsAuditServer()
	st3, _, err := cachedWebStats(s2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st3 == st2 {
		t.Fatal("a different server instance must not reuse the cached build")
	}
}

// waitListener 轮询直到 addr 可建立 TCP 连接或超时。
func waitListener(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("listener %s not ready within %v: %v", addr, timeout, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
