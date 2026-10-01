package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type listenSpec struct {
	ip   string
	port int
}

func (s listenSpec) key() string { return s.ip + "|" + strconv.Itoa(s.port) }

type webListener struct {
	spec listenSpec
	l    net.Listener
}

type WebManager struct {
 diagnostics *diagnosticHistory
	srv *Server
	cli *Client
	mux *http.ServeMux
	cfg atomic.Value
	mu sync.Mutex
	listeners []*webListener
	cfgStamp string
	lastWarn string
	lastWarnAt time.Time
}

func NewWebManager(srv *Server, cli *Client, cfg *Config, mux *http.ServeMux) *WebManager {
	w := &WebManager{srv: srv, cli: cli, mux: mux}
	w.cfg.Store(cfg)
	return w
}
func (w *WebManager) Config() *Config { return w.cfg.Load().(*Config) }
func (w *WebManager) SetConfig(c *Config) { w.cfg.Store(c) }

func webPort(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil { return 8080 }
	p, err := strconv.Atoi(port)
	if err != nil || p <= 0 || p > 65535 { return 8080 }
	return p
}

func (w *WebManager) currentSpecs() []listenSpec {
	cfg := w.Config()
	port := webPort(cfg.Web.Addr)
	if cfg.Web.Bind != "tunnel" {
		host, _, err := net.SplitHostPort(cfg.Web.Addr)
		if err != nil { host = "" }
		return []listenSpec{{ip: strings.Trim(host, "[]"), port: port}}
	}
	var ips []string
	if w.srv != nil {
		ips = []string{w.srv.v4Gw, w.srv.v6Gw}
	} else if w.cli != nil {
		w.cli.sessionMu.Lock()
		ips = []string{w.cli.assignedV4, w.cli.assignedV6}
		w.cli.sessionMu.Unlock()
	}
	out := make([]listenSpec, 0, 2)
	for _, ip := range ips {
		ip = strings.Trim(ip, "[]")
		if ip == "" || net.ParseIP(ip) == nil { continue }
		out = append(out, listenSpec{ip: ip, port: port})
	}
	return out
}

func cfgStamp(cfg *Config) string {
	return strings.Join([]string{cfg.Web.Bind, cfg.Web.Cert, cfg.Web.Key, strconv.Itoa(webPort(cfg.Web.Addr))}, "##")
}

func (w *WebManager) Run() {
	for {
		w.sampleDiagnostics()
		w.rebindIfNeeded()
		time.Sleep(2 * time.Second)
	}
}

func (w *WebManager) rebindIfNeeded() {
	cfg := w.Config()
	specs := w.currentSpecs()
	w.mu.Lock()
	defer w.mu.Unlock()
	var tlsCfg *tls.Config
	if len(specs) > 0 {
		var err error
		tlsCfg, err = loadWebTLS(cfg)
		if err != nil {
			if w.onceWarn("tls|" + cfg.Web.Cert + "|" + cfg.Web.Key) { log.Errorf("[Web] load TLS pair: %v (keeping current listeners)", err) }
			return
		}
	}
	if stamp := cfgStamp(cfg); stamp != w.cfgStamp {
		for _, wl := range w.listeners { wl.l.Close() }
		w.listeners = nil
		w.cfgStamp = stamp
	}
	if len(specs) == 0 { return }
	want := make(map[string]struct{}, len(specs))
	for _, sp := range specs { want[sp.key()] = struct{}{} }
	kept := w.listeners[:0]
	for _, wl := range w.listeners {
		if _, ok := want[wl.spec.key()]; !ok { wl.l.Close(); continue }
		kept = append(kept, wl)
	}
	w.listeners = kept
	var missing []listenSpec
	for _, sp := range specs {
		found := false
		for _, wl := range w.listeners { if wl.spec.key() == sp.key() { found = true; break } }
		if !found { missing = append(missing, sp) }
	}
	if len(missing) == 0 { return }
	var failed []string
	for _, sp := range missing {
		addr := net.JoinHostPort(sp.ip, strconv.Itoa(sp.port))
		l, err := net.Listen("tcp", addr)
		if err != nil { failed = append(failed, fmt.Sprintf("%s: %v", addr, err)); continue }
		if tlsCfg != nil { l = tls.NewListener(l, tlsCfg) }
		w.listeners = append(w.listeners, &webListener{spec: sp, l: l})
		go w.serve(l)
		log.Infof("[Web] listening on %s (bind=%s, auth=%v, tls=%v)", addr, cfg.Web.Bind, cfg.Web.Auth != "", tlsCfg != nil)
	}
	if len(failed) > 0 && w.onceWarn("listen|"+strings.Join(failed, "|")) { log.Warnf("[Web] %s (other listeners still serving, will retry)", strings.Join(failed, "; ")) }
}

func loadWebTLS(cfg *Config) (*tls.Config, error) {
	if cfg.Web.Cert == "" || cfg.Web.Key == "" { return nil, nil }
	cert, err := tls.LoadX509KeyPair(cfg.Web.Cert, cfg.Web.Key)
	if err != nil { return nil, err }
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}, nil
}

func (w *WebManager) serve(l net.Listener) {
	httpSrv := &http.Server{Handler: w.mux, ReadHeaderTimeout: 5*time.Second, ReadTimeout: 15*time.Second, WriteTimeout: 30*time.Second, IdleTimeout: 60*time.Second}
	if err := httpSrv.Serve(l); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) { log.Warnf("[Web] serve stopped: %v", err) }
}

func (w *WebManager) onceWarn(key string) bool {
	if key == w.lastWarn && time.Since(w.lastWarnAt) < 30*time.Second { return false }
	w.lastWarn = key
	w.lastWarnAt = time.Now()
	return true
}

// auth uses an HttpOnly cookie session instead of browser Basic Auth prompts.
// The existing web.auth user:password setting remains the credential source.
// Login endpoints are handled here so every dashboard/API route shares exactly
// the same authentication boundary and EventSource can authenticate by cookie.
func (w *WebManager) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		expected := w.Config().Web.Auth
		if expected == "" {
			next(rw, r)
			return
		}
		switch r.URL.Path {
		case "/api/login":
			handleDashboardLogin(rw, r, expected)
			return
		case "/api/logout":
			handleDashboardLogout(rw, r)
			return
		case "/api/auth/status":
			rw.Header().Set("Content-Type", "application/json")
			rw.Header().Set("Cache-Control", "no-store")
			if dashboardSessions.valid(dashboardSessionToken(r), expected) { _, _ = rw.Write([]byte(`{"authenticated":true}`)) } else { _, _ = rw.Write([]byte(`{"authenticated":false}`)) }
			return
		}
		if dashboardSessions.valid(dashboardSessionToken(r), expected) {
			next(rw, r)
			return
		}
		if r.URL.Path == "/login" || r.URL.Path == "/login.html" || r.URL.Path == "/login.css" || r.URL.Path == "/login.js" {
			next(rw, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/metrics" {
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusUnauthorized)
			_, _ = rw.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
		http.Redirect(rw, r, "/login", http.StatusSeeOther)
	}
}
