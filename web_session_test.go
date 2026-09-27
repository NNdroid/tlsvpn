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
	if bad.Code != http.StatusUnauthorized { t.Fatalf("bad login status=%d", bad.Code) }

	rr := httptest.NewRecorder()
	handleDashboardLogin(rr, httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"s3cret"}`)), expected)
	if rr.Code != http.StatusOK { t.Fatalf("login status=%d body=%s", rr.Code, rr.Body.String()) }
	res := rr.Result()
	var cookie *http.Cookie
	for _, c := range res.Cookies() { if c.Name == webSessionCookie { cookie = c } }
	if cookie == nil || cookie.Value == "" { t.Fatal("missing session cookie") }
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode { t.Fatalf("unsafe cookie: %+v", cookie) }
	if !dashboardSessions.valid(cookie.Value, expected) { t.Fatal("fresh session rejected") }
	if dashboardSessions.valid(cookie.Value, "admin:new-password") { t.Fatal("session survived auth credential change") }
}

func TestWebUILoginPageEmbedded(t *testing.T) {
	h := webuiHandler()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/login", nil))
	if rr.Code != http.StatusOK { t.Fatalf("login page status=%d", rr.Code) }
	body := rr.Body.String()
	for _, want := range []string{"/api/login", "English", "Français", "Deutsch", "简体中文", "繁體中文", "日本語"} {
		if !strings.Contains(body, want) { t.Fatalf("login page missing %q", want) }
	}
}
