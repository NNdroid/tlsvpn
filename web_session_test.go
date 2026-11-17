package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDashboardSessionLoginLifecycle(t *testing.T) {
	expected := "admin:s3cret"

	bad := httptest.NewRecorder()
	handleDashboardLogin(bad, httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"bad"}`)), expected, false)
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("bad login status=%d", bad.Code)
	}

	rr := httptest.NewRecorder()
	handleDashboardLogin(rr, httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"s3cret"}`)), expected, false)
	if rr.Code != http.StatusOK {
		t.Fatalf("login status=%d body=%s", rr.Code, rr.Body.String())
	}
	res := rr.Result()
	var cookie *http.Cookie
	for _, c := range res.Cookies() {
		if c.Name == webSessionCookie {
			cookie = c
		}
	}
	if cookie == nil || cookie.Value == "" {
		t.Fatal("missing session cookie")
	}
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("unsafe cookie: %+v", cookie)
	}
	if !dashboardSessions.valid(cookie.Value, expected) {
		t.Fatal("fresh session rejected")
	}
	if dashboardSessions.valid(cookie.Value, "admin:new-password") {
		t.Fatal("session survived auth credential change")
	}
}

func TestWebUILoginPageEmbedded(t *testing.T) {
	h := webuiHandler()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("login page status=%d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"/api/login", "English", "Français", "Deutsch", "简体中文", "繁體中文", "日本語"} {
		if !strings.Contains(body, want) {
			t.Fatalf("login page missing %q", want)
		}
	}
}

func TestLoginThrottle(t *testing.T) {
	th := newIPFailThrottle(loginThrottleMax, loginThrottleWin)
	ip := "10.0.0.1"
	if th.blocked(ip) {
		t.Fatal("fresh IP must not be blocked")
	}
	for i := 0; i < loginThrottleMax; i++ {
		th.record(ip)
	}
	if !th.blocked(ip) {
		t.Fatal("after max failures the IP must be blocked")
	}
	if th.blocked("10.0.0.2") {
		t.Fatal("another IP must not be blocked by this IP's failures")
	}
	th.reset(ip)
	if th.blocked(ip) {
		t.Fatal("after reset the IP must not be blocked")
	}
}

func TestLoginThrottleBlocksHTTP(t *testing.T) {
	old := loginThrottler
	loginThrottler = newIPFailThrottle(loginThrottleMax, loginThrottleWin)
	defer func() { loginThrottler = old }()
	ip := "203.0.113.9"
	for i := 0; i < loginThrottleMax; i++ {
		loginThrottler.record(ip)
	}
	req := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"username":"a","password":"b"}`))
	req.RemoteAddr = ip + ":5555"
	rr := httptest.NewRecorder()
	handleDashboardLogin(rr, req, "admin:s3cret", false)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after max failures, got %d", rr.Code)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After on 429")
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	for _, hdr := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Content-Security-Policy"} {
		if rr.Header().Get(hdr) == "" {
			t.Fatalf("missing security header %s", hdr)
		}
	}
	csp := rr.Header().Get("Content-Security-Policy")
	if csp != "" && csp != "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" {
		t.Fatalf("unexpected CSP: %s", csp)
	}
}

// TestIPFailThrottleBoundedMap 海量唯一 IP 失败后表长度必须有界：容量兜底按
// 最近失败时间丢最旧，最旧的条目被逐出，最新的保留。
func TestIPFailThrottleBoundedMap(t *testing.T) {
	th := newIPFailThrottle(loginThrottleMax, loginThrottleWin)
	th.maxIPs = 1000
	th.sweepEvery = 1 << 30 // 关闭采样清扫，专测容量兜底路径
	for i := 0; i < 1500; i++ {
		th.record(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))
	}
	if len(th.fails) > 1000 {
		t.Fatalf("throttle map must stay bounded, got %d entries", len(th.fails))
	}
	if _, ok := th.fails["10.0.0.4"]; ok {
		t.Fatal("oldest entry must have been evicted")
	}
	if _, ok := th.fails["10.0.5.203"]; !ok {
		t.Fatal("newest entry must survive eviction")
	}
	if th.blocked("10.0.5.203") {
		t.Fatal("single failure must not block")
	}
}

// TestIPFailThrottleSweepExpired 过期条目必须在 record 顺带的采样式清扫中被
// 删除；仍在窗口内的条目原样保留，blocked 判定语义不变。
func TestIPFailThrottleSweepExpired(t *testing.T) {
	th := newIPFailThrottle(8, 20*time.Millisecond)
	th.sweepEvery = 1
	th.record("10.9.9.1")
	th.record("10.9.9.2")
	time.Sleep(40 * time.Millisecond)
	th.record("10.9.9.3")
	if len(th.fails) != 1 {
		t.Fatalf("expired entries must be swept, got %d entries", len(th.fails))
	}
	if _, ok := th.fails["10.9.9.3"]; !ok {
		t.Fatal("fresh entry must survive the sweep")
	}
	if th.blocked("10.9.9.1") {
		t.Fatal("swept IP must not be blocked")
	}
	for i := 0; i < loginThrottleMax; i++ {
		th.record("10.9.9.3")
	}
	if !th.blocked("10.9.9.3") {
		t.Fatal("after max failures the IP must still be blocked")
	}
}

// TestDashboardCookieBehindProxy behind_proxy=true 时 cookie 一律 Secure，不再
// 依赖客户端可控的 X-Forwarded-Proto；false 时维持现逻辑。
func TestDashboardCookieBehindProxy(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/login", nil)

	write := func(behindProxy bool, r *http.Request) *http.Cookie {
		rr := httptest.NewRecorder()
		setDashboardSessionCookie(rr, r, "tok", behindProxy)
		res := rr.Result()
		for _, c := range res.Cookies() {
			if c.Name == webSessionCookie {
				return c
			}
		}
		return nil
	}

	if c := write(true, req); c == nil || !c.Secure {
		t.Fatalf("behind_proxy=true must force Secure cookie, got %+v", c)
	}
	if c := write(false, req); c == nil || c.Secure {
		t.Fatalf("plain request without behind_proxy must stay non-Secure, got %+v", c)
	}
	xfp := req.Clone(req.Context())
	xfp.Header.Set("X-Forwarded-Proto", "https")
	if c := write(false, xfp); c == nil || !c.Secure {
		t.Fatalf("X-Forwarded-Proto=https must stay Secure without behind_proxy, got %+v", c)
	}

	// 登录全流程同样带 behindProxy：登录成功下发的 cookie 必须 Secure。
	rr := httptest.NewRecorder()
	login := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"s3cret"}`))
	handleDashboardLogin(rr, login, "admin:s3cret", true)
	if rr.Code != http.StatusOK {
		t.Fatalf("login status=%d", rr.Code)
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == webSessionCookie && !c.Secure {
			t.Fatal("login cookie must be Secure when behind_proxy=true")
		}
	}
}
