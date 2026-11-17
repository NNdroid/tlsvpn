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
	mu         sync.Mutex
	fails      map[string][]time.Time // ip -> 最近失败时间戳
	order      []string               // IP 首次记录的插入序队列，容量兜底时从头逐出
	max        int
	win        time.Duration
	maxIPs     int // 表项容量上限，超过则清扫+丢最旧
	sweepEvery int // 每 N 次 record 采样式清扫一次；测试可调小
	records    int
}

const (
	loginThrottleMax = 8
	loginThrottleWin = time.Minute
	// MCP 认证失败阈值略宽：MCP 客户端（AI agent）可能因 token 过期重试几次，
	// 且部分 agent 会并发多个请求。仍足以挡住对 inherit_web/basic 口令的爆破。
	mcpAuthThrottleMax = 10
	mcpAuthThrottleWin = time.Minute

	// ipFailThrottleMaxIPs 表项容量上限。blocked 只在被查询的 IP 上顺手剪枝，
	// 从未被再次访问的 IP 会永久滞留；海量伪造源地址的扫描可把表撑到无界。
	// 超限先清扫过期条目，仍满则按最近失败时间丢最旧。
	ipFailThrottleMaxIPs = 65536
	// ipFailThrottleSweepEvery 每 N 次 record 采样式全量清扫一次过期条目。
	ipFailThrottleSweepEvery = 64
)

var (
	loginThrottler   = newIPFailThrottle(loginThrottleMax, loginThrottleWin)
	mcpAuthThrottler = newIPFailThrottle(mcpAuthThrottleMax, mcpAuthThrottleWin)
)

func newIPFailThrottle(max int, win time.Duration) *ipFailThrottle {
	return &ipFailThrottle{
		fails:      make(map[string][]time.Time),
		max:        max,
		win:        win,
		maxIPs:     ipFailThrottleMaxIPs,
		sweepEvery: ipFailThrottleSweepEvery,
	}
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
	now := time.Now()
	t.fails[ip] = append(t.fails[ip], now)
	if len(t.fails[ip]) == 1 {
		// 新 IP 入队：容量兜底按插入序丢最旧。时钟粒度（Windows 单调钟毫秒级）
		// 不足以按时间戳排序，插入序是确定性的"最旧"定义。
		t.order = append(t.order, ip)
	}
	// 无界增长防护：blocked 从不删除从未被再次查询的 IP，这里在 record 时
	// 顺带采样式清扫过期条目；表满则强制清扫，仍满按插入序丢最旧。
	t.records++
	if (t.sweepEvery > 0 && t.records%t.sweepEvery == 0) || len(t.fails) > t.maxIPs {
		t.sweepLocked(now)
	}
	if len(t.fails) > t.maxIPs {
		t.evictOldestLocked(len(t.fails) - t.maxIPs + t.maxIPs/16)
	}
	// 陈旧队列项（sweep 整键删除后遗留）超过阈值时压缩去重，保持队列有界
	if len(t.order) > len(t.fails)+1024 {
		t.compactOrderLocked()
	}
}

// sweepLocked 全量删除已滑出窗口的失败时间戳，整条 IP 记录全部过期时连 key
// 一起删除。仍在窗口内的条目原样保留，blocked 判定语义不变。
func (t *ipFailThrottle) sweepLocked(now time.Time) {
	for ip, ts := range t.fails {
		kept := ts[:0]
		for _, v := range ts {
			if now.Sub(v) < t.win {
				kept = append(kept, v)
			}
		}
		if len(kept) == 0 {
			delete(t.fails, ip)
			continue
		}
		t.fails[ip] = kept
	}
}

// evictOldestLocked 容量兜底：按插入序从头逐出 n 条 IP（最旧优先），让活跃
// 攻击者的计数尽量存活，只牺牲最陈旧的记录。队列项可能已被 sweep 整键清扫，
// 跳过即可；逐出量按 1/16 容量取整批，摊薄逐出开销。
func (t *ipFailThrottle) evictOldestLocked(n int) {
	for n > 0 && len(t.order) > 0 {
		ip := t.order[0]
		t.order = t.order[1:]
		if _, ok := t.fails[ip]; !ok {
			continue
		}
		delete(t.fails, ip)
		n--
	}
}

// compactOrderLocked 压缩插入序队列：剔除已被 sweep/blocked/reset 删除的 IP
// 与重复项。仅存量 IP 保留其在队列中的相对顺序。
func (t *ipFailThrottle) compactOrderLocked() {
	seen := make(map[string]struct{}, len(t.fails))
	order := t.order[:0]
	for _, ip := range t.order {
		if _, live := t.fails[ip]; !live {
			continue
		}
		if _, dup := seen[ip]; dup {
			continue
		}
		seen[ip] = struct{}{}
		order = append(order, ip)
	}
	t.order = order
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

// dashboardCookieHTTPS 判定 session cookie 是否应带 Secure。X-Forwarded-Proto
// 是客户端可控头：直连部署下攻击者可借它把 Secure 抹掉/伪造，但明文本机部署
// 本就无 TLS 可言，维持现逻辑仅作尽力而为；显式声明 behind_proxy 的部署里
// TLS 在上游代理终结，本进程永远看到明文请求，此时一律按 https 处理，不再
// 依赖客户端可控头。
func dashboardCookieHTTPS(r *http.Request, behindProxy bool) bool {
	if behindProxy {
		return true
	}
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func setDashboardSessionCookie(w http.ResponseWriter, r *http.Request, token string, behindProxy bool) {
	https := dashboardCookieHTTPS(r, behindProxy)
	http.SetCookie(w, &http.Cookie{
		Name: webSessionCookie, Value: token, Path: "/", MaxAge: int(webSessionTTL.Seconds()),
		HttpOnly: true, Secure: https, SameSite: http.SameSiteLaxMode,
	})
}

func clearDashboardSessionCookie(w http.ResponseWriter, r *http.Request, behindProxy bool) {
	https := dashboardCookieHTTPS(r, behindProxy)
	http.SetCookie(w, &http.Cookie{
		Name: webSessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: https, SameSite: http.SameSiteLaxMode,
	})
}

func handleDashboardLogin(w http.ResponseWriter, r *http.Request, expected string, behindProxy bool) {
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
	setDashboardSessionCookie(w, r, token, behindProxy)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func handleDashboardLogout(w http.ResponseWriter, r *http.Request, behindProxy bool) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dashboardSessions.revoke(dashboardSessionToken(r))
	clearDashboardSessionCookie(w, r, behindProxy)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}
