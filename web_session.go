package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	webSessionCookie = "tlsvpn_session"
	webSessionTTL    = 24 * time.Hour
	basicTokenPrefix = "basic:"
)

type webSession struct {
	expires  time.Time
	authHash [32]byte
}

type webSessionStore struct {
	mu       sync.Mutex
	sessions map[string]webSession
}

var dashboardSessions = webSessionStore{sessions: make(map[string]webSession)}

// ipFailThrottle 每 IP 的失败限速（滑动窗口）。窗口内失败次数达到阈值即判定
// 为在线爆破，返回 429 直到窗口滑出或成功认证。阈值/窗口宽松，误锁正常客户
// 端风险低，同时让远程爆破基本不可行。dashboard 登录与 MCP 认证各自独立实例。
type ipFailThrottle struct {
	mu    sync.Mutex
	fails map[string][]time.Time // ip -> 最近失败时间戳
	max   int
	win   time.Duration
}

const (
	loginThrottleMax = 8
	loginThrottleWin = time.Minute
	// MCP 认证失败阈值略宽：MCP 客户端（AI agent）可能因 token 过期重试几次，
	// 且部分 agent 会并发多个请求。仍足以挡住对 inherit_web/basic 口令的爆破。
	mcpAuthThrottleMax = 10
	mcpAuthThrottleWin = time.Minute
)

var (
	loginThrottler   = newIPFailThrottle(loginThrottleMax, loginThrottleWin)
	mcpAuthThrottler = newIPFailThrottle(mcpAuthThrottleMax, mcpAuthThrottleWin)
)

func newIPFailThrottle(max int, win time.Duration) *ipFailThrottle {
	return &ipFailThrottle{fails: make(map[string][]time.Time), max: max, win: win}
}

func (t *ipFailThrottle) blocked(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	kept := t.fails[ip][:0]
	for _, ts := range t.fails[ip] {
		if now.Sub(ts) < t.win {
			kept = append(kept, ts)
		}
	}
	if len(kept) == 0 {
		delete(t.fails, ip)
		return false
	}
	t.fails[ip] = kept
	return len(kept) >= t.max
}

func (t *ipFailThrottle) record(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.fails[ip] = append(t.fails[ip], time.Now())
}

func (t *ipFailThrottle) reset(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.fails, ip)
}

func webAuthHash(auth string) [32]byte { return sha256.Sum256([]byte(auth)) }

func (s *webSessionStore) create(auth string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	now := time.Now()
	s.mu.Lock()
	for k, v := range s.sessions {
		if now.After(v.expires) {
			delete(s.sessions, k)
		}
	}
	s.sessions[token] = webSession{expires: now.Add(webSessionTTL), authHash: webAuthHash(auth)}
	s.mu.Unlock()
	return token, nil
}

func (s *webSessionStore) valid(token, auth string) bool {
	if token == "" || auth == "" {
		return false
	}
	// Keep explicit Basic Auth compatible for scripts and automation. The
	// middleware never emits WWW-Authenticate, so browsers still use /login.
	if strings.HasPrefix(token, basicTokenPrefix) {
		encoded := strings.TrimPrefix(token, basicTokenPrefix)
		credential, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return false
		}
		return constantTimeCredentialEqual(string(credential), auth)
	}
	now := time.Now()
	h := webAuthHash(auth)
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.sessions[token]
	if !ok || now.After(v.expires) || subtle.ConstantTimeCompare(v.authHash[:], h[:]) != 1 {
		if ok {
			delete(s.sessions, token)
		}
		return false
	}
	v.expires = now.Add(webSessionTTL)
	s.sessions[token] = v
	return true
}

func (s *webSessionStore) revoke(token string) {
	if token == "" || strings.HasPrefix(token, basicTokenPrefix) {
		return
	}
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

func dashboardSessionToken(r *http.Request) string {
	if c, err := r.Cookie(webSessionCookie); err == nil && c.Value != "" {
		return c.Value
	}
	if user, pass, ok := r.BasicAuth(); ok {
		credential := base64.RawURLEncoding.EncodeToString([]byte(user + ":" + pass))
		return basicTokenPrefix + credential
	}
	return ""
}

func setDashboardSessionCookie(w http.ResponseWriter, r *http.Request, token string) {
	https := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{
		Name: webSessionCookie, Value: token, Path: "/", MaxAge: int(webSessionTTL.Seconds()),
		HttpOnly: true, Secure: https, SameSite: http.SameSiteLaxMode,
	})
}

func clearDashboardSessionCookie(w http.ResponseWriter, r *http.Request) {
	https := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	http.SetCookie(w, &http.Cookie{
		Name: webSessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: https, SameSite: http.SameSiteLaxMode,
	})
}

func handleDashboardLogin(w http.ResponseWriter, r *http.Request, expected string) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// 在线口令爆破防护：每 IP 滑动窗口内失败次数超阈值直接 429，不给 150ms
	// 睡眠之外再给攻击者逐次试错的机会。成功登录重置该 IP 计数。
	ip := mcpRemoteHost(r)
	if loginThrottler.blocked(ip) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "Too many login attempts, try again later", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if expected == "" || !constantTimeCredentialEqual(req.Username+":"+req.Password, expected) {
		loginThrottler.record(ip)
		time.Sleep(150 * time.Millisecond)
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}
	loginThrottler.reset(ip)
	token, err := dashboardSessions.create(expected)
	if err != nil {
		http.Error(w, "Unable to create session", http.StatusInternalServerError)
		return
	}
	setDashboardSessionCookie(w, r, token)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func handleDashboardLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dashboardSessions.revoke(dashboardSessionToken(r))
	clearDashboardSessionCookie(w, r)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
