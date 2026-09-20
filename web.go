package main

import (
	"crypto/subtle"
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

// ======================= Web 监听管理（隧道 IP 绑定 + 热更新） =======================
//
// web.bind = "tunnel" 时，面板只监听隧道自身 IP：
//   - server：地址池网关 IP（IPv4 + IPv6 各一个 listener）；
//   - client：握手分配的隧道 IP（首个会话建立后才出现，随 IP 变化自动重绑）。
// web.bind = "all"（默认）时保持旧行为：监听全部接口。
//
// 端口取自 web.addr。证书/密钥、认证串均支持面板热更：端口/证书/绑定模式
// 变化时旧 listener 全部关闭并重建。
//
// 监听是「逐个成功」而非「全有或全无」：IPv4 与 IPv6 各自独立打开，某个
// 地址绑定失败（隧道 IP 未就绪、IPv6 被禁、地址仍处 tentative）只让该地址
// 缺位并记 warning 等下一轮重试，不会把已经能用的监听一起关掉。对
// bind=tunnel 这更合理——ULA/IPv6 在不少网管环境下本来就不保证可用。

type listenSpec struct {
	ip   string // 空 = 全部接口
	port int
}

func (s listenSpec) key() string { return s.ip + "|" + strconv.Itoa(s.port) }

// webListener 一个已打开的监听及其对应规格。规格与 listener 成对保存，
// 增量增删时靠 spec.key() 配对。
type webListener struct {
	spec listenSpec
	l    net.Listener
}

type WebManager struct {
	srv *Server
	cli *Client

	mux *http.ServeMux

	cfg atomic.Value // *Config：认证/证书/端口热更数据源

	mu         sync.Mutex
	listeners  []*webListener
	cfgStamp   string // 当前监听所依据的配置指纹（端口/证书/绑定模式）
	lastWarn   string // 最近一次上报的告警 key（同 key 30s 内只报一次）
	lastWarnAt time.Time
}

func NewWebManager(srv *Server, cli *Client, cfg *Config, mux *http.ServeMux) *WebManager {
	w := &WebManager{srv: srv, cli: cli, mux: mux}
	w.cfg.Store(cfg)
	return w
}

func (w *WebManager) Config() *Config     { return w.cfg.Load().(*Config) }
func (w *WebManager) SetConfig(c *Config) { w.cfg.Store(c) }

// webPort 从 web.addr 解析端口；非法时回落 8080
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

// currentSpecs 计算当前应监听的地址集合（ip 为空表示全部接口）
func (w *WebManager) currentSpecs() []listenSpec {
	cfg := w.Config()
	port := webPort(cfg.Web.Addr)
	if cfg.Web.Bind != "tunnel" {
		return []listenSpec{{ip: "", port: port}}
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

// cfgStamp 影响 listener 身份的配置要素：绑定模式、证书、密钥、端口。
// 任一项变化都要整体重建监听；只有隧道 IP 变化时才做增量增删。
func cfgStamp(cfg *Config) string {
	return strings.Join([]string{
		cfg.Web.Bind, cfg.Web.Cert, cfg.Web.Key, strconv.Itoa(webPort(cfg.Web.Addr)),
	}, "##")
}

// Run 监听规格轮询循环（进程生命周期内运行）
func (w *WebManager) Run() {
	for {
		w.rebindIfNeeded()
		time.Sleep(2 * time.Second)
	}
}

func (w *WebManager) rebindIfNeeded() {
	cfg := w.Config()
	specs := w.currentSpecs()
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(specs) == 0 {
		// 隧道 IP 尚未就绪（client 首个会话建立前等），保留现状等下一轮
		return
	}

	// 配置身份变化 → 整体重建。必须关旧再开新：证书/端口同址时两个
	// listener 无法并存（EADDRINUSE），先开后关会让换证书永远不生效。
	if stamp := cfgStamp(cfg); stamp != w.cfgStamp {
		for _, wl := range w.listeners {
			wl.l.Close()
		}
		w.listeners = nil
		w.cfgStamp = stamp
	}

	// 关闭规格已消失的监听（如删掉 v6_cidr、bind 从 tunnel 切回 all）
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

	// 逐个打开缺的：成功即 serve，失败只影响自身，下一轮继续重试
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

	tlsCfg, err := loadWebTLS(cfg)
	if err != nil {
		if w.onceWarn("tls|" + cfg.Web.Cert + "|" + cfg.Web.Key) {
			log.Errorf("[Web] load TLS pair: %v (keeping current listeners)", err)
		}
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
		go w.serve(l)
		log.Infof("[Web] listening on %s (bind=%s, auth=%v, tls=%v)",
			addr, cfg.Web.Bind, cfg.Web.Auth != "", tlsCfg != nil)
	}
	if len(failed) > 0 && w.onceWarn("listen|"+strings.Join(failed, "|")) {
		log.Warnf("[Web] %s (other listeners still serving, will retry)", strings.Join(failed, "; "))
	}
}

// loadWebTLS 加载面板证书；未配置证书时返回 nil（纯 HTTP）
func loadWebTLS(cfg *Config) (*tls.Config, error) {
	if cfg.Web.Cert == "" || cfg.Web.Key == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.Web.Cert, cfg.Web.Key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}, nil
}

// serve 起 http.Serve 循环。listener 被主动 Close() 后 http.Serve 返回是
// 正常路径（规格变更、监听重建），不记日志。
func (w *WebManager) serve(l net.Listener) {
	if err := http.Serve(l, w.mux); err != nil && !errors.Is(err, net.ErrClosed) {
		log.Warnf("[Web] serve stopped: %v", err)
	}
}

// onceWarn 同一 key 的告警 30s 内只返回一次 true。轮询每 2s 一轮，地址
// 迟迟不就绪或证书缺失不该把日志刷成刷屏。
func (w *WebManager) onceWarn(key string) bool {
	if key == w.lastWarn && time.Since(w.lastWarnAt) < 30*time.Second {
		return false
	}
	w.lastWarn = key
	w.lastWarnAt = time.Now()
	return true
}

// auth 认证中间件：认证串从当前配置动态读取（面板热更即时生效）
func (w *WebManager) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		expected := w.Config().Web.Auth
		if expected == "" {
			next(rw, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(user+":"+pass), []byte(expected)) != 1 {
			rw.Header().Set("WWW-Authenticate", `Basic realm="tlsvpn dashboard"`)
			http.Error(rw, "Unauthorized", 401)
			return
		}
		next(rw, r)
	}
}
