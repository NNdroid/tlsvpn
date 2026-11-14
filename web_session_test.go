package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDashboardSessionLoginLifecycle(t *testing.T) {
	expected := "admin:s3cret"

	bad := httptest.NewRecorder()
	handleDashboardLogin(bad, httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"bad"}`)), expected)
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("bad login status=%d", bad.Code)
	}

	rr := httptest.NewRecorder()
	handleDashboardLogin(rr, httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"s3cret"}`)), expected)
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
	handleDashboardLogin(rr, req, "admin:s3cret")
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
