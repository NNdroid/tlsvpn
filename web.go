package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
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
	srv         *Server
	cli         *Client
	mux         *http.ServeMux
	mcp         http.Handler
	cfg         atomic.Value
	mu          sync.Mutex
	listeners   []*webListener
	cfgStamp    string
	lastWarn    string
	lastWarnAt  time.Time
	// TLS 证书热加载缓存：rebindIfNeeded 每 2s 跑一次，无条件 LoadX509KeyPair
	// 等于反复读盘+解析。记录上次加载的路径与文件指纹（mtime+size），仅在
	// 路径或指纹变化（含热替换证书）时重载。字段仅在持有 mu 的 rebindIfNeeded
	// 内读写，无额外锁需求。
	tlsFp     webTLSFingerprint
	tlsCached *tls.Config
}

// webTLSFingerprint 证书/密钥文件的变化指纹。全部字段可比较，== 判等即可
// 判断是否需要重新 LoadX509KeyPair。
type webTLSFingerprint struct {
	certPath string
	keyPath  string
	certMod  time.Time
	keyMod   time.Time
	certSize int64
	keySize  int64
}

func NewWebManager(srv *Server, cli *Client, cfg *Config, mux *http.ServeMux) *WebManager {
	w := &WebManager{srv: srv, cli: cli, mux: mux}
	w.cfg.Store(cfg)
	w.mcp = newMCPHTTPHandler(w)
	return w
}
func (w *WebManager) Config() *Config     { return w.cfg.Load().(*Config) }
func (w *WebManager) SetConfig(c *Config) { w.cfg.Store(c) }

func webPort(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 8080
	}
	p, err := strconv.Atoi(port)
	if err != nil || p <= 0 || p > 65535 {
		return 8080
	}
	return p
}

func (w *WebManager) currentSpecs() []listenSpec {
	cfg := w.Config()
	port := webPort(cfg.Web.Addr)
	if cfg.Web.Bind != "tunnel" {
		host, _, err := net.SplitHostPort(cfg.Web.Addr)
		if err != nil {
			host = ""
		}
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
		if ip == "" || net.ParseIP(ip) == nil {
			continue
		}
		out = append(out, listenSpec{ip: ip, port: port})
	}
	return out
}

func cfgStamp(cfg *Config) string {
	return strings.Join([]string{cfg.Web.Bind, cfg.Web.Cert, cfg.Web.Key, strconv.Itoa(webPort(cfg.Web.Addr))}, "##")
}

func (w *WebManager) Run() {
	for {
		w.sampleTCPObservations()
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
	// auth_mode=none + 公网部署面：MCP 写工具（配置保存/踢人/封禁）完全无认证，
	// 仅靠 80-bit 随机路径遮挡，路径一旦泄漏（日志、referer、代理）即全面失守。
	// 每次 rebind 检查一次，onceWarn 30s 去重避免 2s 轮询刷屏。
	if normalizeMCPAuthMode(cfg.Web.MCP.AuthMode) == mcpAuthNone && cfg.Web.MCP.deployAllowsPublic() {
		if w.onceWarn("mcp_none_public") {
			log.Warnf("[Web] MCP auth_mode=none with deploy=%s: MCP write tools are fully unauthenticated on the public face and gated only by the random endpoint path; configure web.mcp authentication", cfg.Web.MCP.Deploy)
		}
	}
	var tlsCfg *tls.Config
	if len(specs) > 0 {
		var err error
		tlsCfg, err = w.loadWebTLS(cfg)
		if err != nil {
			if w.onceWarn("tls|" + cfg.Web.Cert + "|" + cfg.Web.Key) {
				log.Errorf("[Web] load TLS pair: %v (keeping current listeners)", err)
			}
			return
		}
	}
	if stamp := cfgStamp(cfg); stamp != w.cfgStamp {
		for _, wl := range w.listeners {
			wl.l.Close()
		}
		w.listeners = nil
		w.cfgStamp = stamp
	}
	if len(specs) == 0 {
		return
	}
	want := make(map[string]struct{}, len(specs))
	for _, sp := range specs {
		want[sp.key()] = struct{}{}
	}
	kept := w.listeners[:0]
	for _, wl := range w.listeners {
		if _, ok := want[wl.spec.key()]; !ok {
			wl.l.Close()
			continue
		}
		kept = append(kept, wl)
	}
	w.listeners = kept
	var missing []listenSpec
	for _, sp := range specs {
		found := false
		for _, wl := range w.listeners {
			if wl.spec.key() == sp.key() {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, sp)
		}
	}
	if len(missing) == 0 {
		return
	}
	var failed []string
	for _, sp := range missing {
		addr := net.JoinHostPort(sp.ip, strconv.Itoa(sp.port))
		l, err := net.Listen("tcp", addr)
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s: %v", addr, err))
			continue
		}
		if tlsCfg != nil {
			l = tls.NewListener(l, tlsCfg)
		}
		w.listeners = append(w.listeners, &webListener{spec: sp, l: l})
		goSafe1(w.serve, l)
		log.Infof("[Web] listening on %s (bind=%s, auth=%v, mcp_auth=%s, tls=%v)", addr, cfg.Web.Bind, cfg.Web.Auth != "", normalizeMCPAuthMode(cfg.Web.MCP.AuthMode), tlsCfg != nil)
	}
	if len(failed) > 0 && w.onceWarn("listen|"+strings.Join(failed, "|")) {
		log.Warnf("[Web] %s (other listeners still serving, will retry)", strings.Join(failed, "; "))
	}
}

// loadWebTLS 加载面板 TLS 证书对，带文件指纹缓存：rebindIfNeeded 每 2s 调用
// 一次，无条件 LoadX509KeyPair 会对每对 listener 反复读盘解析。路径或
// mtime/size 指纹不变时直接复用上次结果；文件被热替换（内容变化）仍会重载。
// 仅在持有 w.mu 的 rebindIfNeeded 中调用。
func (w *WebManager) loadWebTLS(cfg *Config) (*tls.Config, error) {
	certPath, keyPath := cfg.Web.Cert, cfg.Web.Key
	if certPath == "" || keyPath == "" {
		w.tlsFp = webTLSFingerprint{}
		w.tlsCached = nil
		return nil, nil
	}
	ci, err := os.Stat(certPath)
	if err != nil {
		return nil, fmt.Errorf("stat cert: %w", err)
	}
	ki, err := os.Stat(keyPath)
	if err != nil {
		return nil, fmt.Errorf("stat key: %w", err)
	}
	fp := webTLSFingerprint{
		certPath: certPath, keyPath: keyPath,
		certMod: ci.ModTime(), keyMod: ki.ModTime(),
		certSize: ci.Size(), keySize: ki.Size(),
	}
	if w.tlsCached != nil && fp == w.tlsFp {
		return w.tlsCached, nil
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	w.tlsFp = fp
	w.tlsCached = &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}
	return w.tlsCached, nil
}

func (w *WebManager) serve(l net.Listener) {
	// TLS listener（配置了 web.cert/key）追加 HSTS：告诉浏览器此后仅以 https
	// 访问面板，阻断 SSL 剥离/降级重放。明文 listener 下发 HSTS 会被浏览器
	// 忽略且语义错误，仅在 TLS 模式注入。listener 的 TLS 属性由 cfgStamp 决定，
	// cert/key 热更会整体重建 listener，serve 内读到的配置与该 listener 一致。
	var handler http.Handler = securityHeaders(w.mux)
	if cfg := w.Config(); cfg.Web.Cert != "" && cfg.Web.Key != "" {
		handler = hstsHeader(handler)
	}
	httpSrv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	if err := httpSrv.Serve(l); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		log.Warnf("[Web] serve stopped: %v", err)
	}
}

func (w *WebManager) onceWarn(key string) bool {
	if key == w.lastWarn && time.Since(w.lastWarnAt) < 30*time.Second {
		return false
	}
	w.lastWarn = key
	w.lastWarnAt = time.Now()
	return true
}

func mcpBasicAuthValid(r *http.Request, expected string) bool {
	user, pass, ok := r.BasicAuth()
	return ok && constantTimeCredentialEqual(user+":"+pass, expected)
}

// securityHeaders 统一设置 WebUI 响应的安全头。面板是管理面：即使已认证，
// 也值得防点击劫持（frame-ancestors/X-Frame-Options）、MIME 嗅探（nosniff）
// 与引用泄漏（Referrer-Policy）。CSP 允许 'unsafe-inline' 以兼容现有大量内联
// onclick/style，但默认源收紧为 'self'，阻断任何外部脚本/资源注入。
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data:; font-src 'self'; connect-src 'self'; "+
				"frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}

// hstsHeader TLS listener 专用的 HSTS 头（见 serve 内注释）。一年 max-age 覆盖
// 典型证书周期，includeSubDomains 防止面板域下的子域被用于降级攻击。
func hstsHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// auth uses an HttpOnly cookie session instead of browser Basic Auth prompts.
// The dashboard keeps web.auth as its credential source. MCP shares the same
// listener/TLS/port but its authentication policy is independently configured
// under web.mcp; the backward-compatible default is inherit_web. OAuth protected
// resource metadata is intentionally public when oauth_jwt mode is enabled.
func (w *WebManager) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		mcpCfg := w.Config().Web.MCP
		// MCP 端点与 OAuth metadata 只在内网面部署时拦截；deploy=public 时
		// 内网 listener 不暴露 MCP，路径回落到普通 Web 处理（静态 404 / api 401）。
		if mcpCfg.deployAllowsInternal() && isMCPMetadataPath(r.URL.Path) {
			w.serveMCPMetadata(rw, r)
			return
		}
		if mcpCfg.deployAllowsInternal() && mcpCfg.matchesPath(r.URL.Path) {
			w.serveMCP(rw, r)
			return
		}

		expected := w.Config().Web.Auth
		if expected == "" {
			next(rw, r)
			return
		}
		switch r.URL.Path {
		case "/api/login":
			handleDashboardLogin(rw, r, expected, w.Config().Web.BehindProxy)
			return
		case "/api/logout":
			handleDashboardLogout(rw, r, w.Config().Web.BehindProxy)
			return
		case "/api/auth/status":
			rw.Header().Set("Content-Type", "application/json")
			rw.Header().Set("Cache-Control", "no-store")
			if dashboardSessions.valid(dashboardSessionToken(r), expected) {
				_, _ = rw.Write([]byte(`{"authenticated":true}`))
			} else {
				_, _ = rw.Write([]byte(`{"authenticated":false}`))
			}
			return
		}
		if dashboardSessions.valid(dashboardSessionToken(r), expected) {
			next(rw, r)
			return
		}
		if r.URL.Path == "/login" || r.URL.Path == "/login.html" {
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
