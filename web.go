package main

import (
	"crypto/subtle"
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// ======================= Web 监听管理（隧道 IP 绑定 + 热更新） =======================
//
// web.bind = "tunnel" 时，面板只监听隧道自身 IP：
//   - server：地址池网关 IP（IPv4 + IPv6 各一个 listener）；
//   - client：握手分配的隧道 IP（首个会话建立后才出现，随 IP 变化自动重绑）。
// web.bind = "all"（默认）时保持旧行为：监听全部接口。
//
// 端口取自 web.addr。证书/密钥、认证串均支持面板热更：任一参与元素变化时
// 旧 listener 全部关闭并重建。绑定失败（如隧道 IP 尚未就绪）保留旧 listener
// 并在下个轮询周期重试。

type listenSpec struct {
	ip   string // 空 = 全部接口
	port int
}

func (s listenSpec) key() string { return s.ip + "|" + strconv.Itoa(s.port) }

type WebManager struct {
	srv *Server
	cli *Client

	mux *http.ServeMux

	cfg atomic.Value // *Config：认证/证书/端口热更数据源

	mu        sync.Mutex
	listeners []net.Listener
	lastSpec  string
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

// specKey 规格指纹：任一参与元素变化都触发重绑
func (w *WebManager) specKey(specs []listenSpec) string {
	cfg := w.Config()
	parts := []string{cfg.Web.Bind, cfg.Web.Cert, cfg.Web.Key}
	for _, s := range specs {
		parts = append(parts, s.key())
	}
	return strings.Join(parts, "##")
}

// Run 监听规格轮询循环（进程生命周期内运行）
func (w *WebManager) Run() {
	for {
		w.rebindIfNeeded()
		time.Sleep(2 * time.Second)
	}
}

func (w *WebManager) rebindIfNeeded() {
	specs := w.currentSpecs()
	key := w.specKey(specs)
	w.mu.Lock()
	defer w.mu.Unlock()
	if key == w.lastSpec {
		return
	}
	// 先全部打开新 listener，全部成功才替换 —— 任一失败保留旧监听
	var fresh []net.Listener
	tlsCfg := (*tls.Config)(nil)
	cfg := w.Config()
	if cfg.Web.Cert != "" && cfg.Web.Key != "" {
		cert, err := tls.LoadX509KeyPair(cfg.Web.Cert, cfg.Web.Key)
		if err != nil {
			log.Errorf("[Web] load TLS pair: %v (keeping current listeners)", err)
			return
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}
	}
	for _, sp := range specs {
		host := sp.ip
		l, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(sp.port)))
		if err != nil {
			for _, f := range fresh {
				f.Close()
			}
			log.Errorf("[Web] listen on %s failed: %v (will retry)", net.JoinHostPort(host, strconv.Itoa(sp.port)), err)
			return
		}
		if tlsCfg != nil {
			l = tls.NewListener(l, tlsCfg)
		}
		fresh = append(fresh, l)
	}
	// 全部成功：关闭旧监听，启动新 serve 循环
	for _, old := range w.listeners {
		old.Close()
	}
	w.listeners = fresh
	w.lastSpec = key
	for _, l := range fresh {
		go func(l net.Listener) {
			for {
				if err := http.Serve(l, w.mux); err != nil {
					log.Errorf("[Web] serve stopped: %v", err)
					return
				}
			}
		}(l)
	}
	zap.L().Sugar().Infof("[Web] listening on %s (%s, auth=%v, tls=%v)",
		specSummary(specs), cfg.Web.Bind, cfg.Web.Auth != "", tlsCfg != nil)
}

func specSummary(specs []listenSpec) string {
	parts := make([]string, 0, len(specs))
	for _, s := range specs {
		host := s.ip
		if host == "" {
			host = "0.0.0.0"
		}
		parts = append(parts, net.JoinHostPort(host, strconv.Itoa(s.port)))
	}
	return strings.Join(parts, ", ")
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
