package main

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	xproxy "golang.org/x/net/proxy"
)

// ======================= SOCKS5 全局代理 =======================
//
// 设计原则：程序中所有对外发起的 socket 要么全部经过 SOCKS5 代理，要么全部直连。
// 通过全局的 globalDialer 统一出口，避免出现部分连接绕过代理导致的流量泄漏。

var (
	// globalSocks5Addr 为空表示不启用代理（全部直连）
	globalSocks5Addr string
	// globalDialer 是全局统一的拨号器（直连或经由 SOCKS5）
	globalDialer xproxy.ContextDialer = newBaseDialer(0)
)

// newBaseDialer 构造底层拨号器。所有真实的物理连接最终都由它发起：
//   - 直连模式下它直接连 VPN 服务端；
//   - SOCKS5 模式下它连的是代理服务器（由 x/net/proxy 内部调用）。
//
// 因此 SO_MARK 与 KeepAlive 必须设置在这一层，才能覆盖两种模式。
func newBaseDialer(fwmark int) *net.Dialer {
	return &net.Dialer{
		Timeout: 5 * time.Second,
		// KeepAlive 作用于本地 socket，与是否经过代理无关，两种模式下都应生效
		KeepAlive: 15 * time.Second,
		Control:   socketMarkControl(fwmark),
	}
}

// isSocks5Enabled 返回是否启用了 SOCKS5 全局代理
func isSocks5Enabled() bool { return globalSocks5Addr != "" }

// parseSocks5 解析 socks5 配置字符串，支持以下形式：
//
//	127.0.0.1:1080
//	user:pass@127.0.0.1:1080
//	socks5://user:pass@127.0.0.1:1080
//	socks5h://127.0.0.1:1080
//
// 返回 host:port 与认证信息（无认证时 auth 为 nil）。
func parseSocks5(raw string) (string, *xproxy.Auth, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", nil, fmt.Errorf("empty socks5 address")
	}

	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", nil, fmt.Errorf("invalid socks5 url: %v", err)
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "socks5" && scheme != "socks5h" {
			return "", nil, fmt.Errorf("unsupported proxy scheme %q (only socks5/socks5h)", u.Scheme)
		}
		var auth *xproxy.Auth
		if u.User != nil {
			pass, _ := u.User.Password()
			auth = &xproxy.Auth{User: u.User.Username(), Password: pass}
		}
		if u.Host == "" {
			return "", nil, fmt.Errorf("socks5 url missing host")
		}
		return u.Host, auth, nil
	}

	// 裸格式：[user:pass@]host:port
	var auth *xproxy.Auth
	host := s
	if idx := strings.LastIndex(s, "@"); idx >= 0 {
		cred := s[:idx]
		host = s[idx+1:]
		user := cred
		pass := ""
		if ci := strings.Index(cred, ":"); ci >= 0 {
			user, pass = cred[:ci], cred[ci+1:]
		}
		auth = &xproxy.Auth{User: user, Password: pass}
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		return "", nil, fmt.Errorf("invalid socks5 address %q: %v", host, err)
	}
	return host, auth, nil
}

// initGlobalProxy 初始化全局拨号器。raw 为空时保持直连模式。
// fwmark > 0 时，底层 socket 会被打上 SO_MARK 以配合策略路由绕过 TAP 隧道。
func initGlobalProxy(raw string, fwmark int) error {
	base := newBaseDialer(fwmark)
	if strings.TrimSpace(raw) == "" {
		globalSocks5Addr = ""
		globalDialer = base
		return nil
	}

	host, auth, err := parseSocks5(raw)
	if err != nil {
		return err
	}

	d, err := xproxy.SOCKS5("tcp", host, auth, base)
	if err != nil {
		return fmt.Errorf("create socks5 dialer failed: %v", err)
	}
	cd, ok := d.(xproxy.ContextDialer)
	if !ok {
		return fmt.Errorf("socks5 dialer does not support context")
	}

	globalSocks5Addr = host
	globalDialer = cd
	return nil
}

// dialContext 是全局唯一的对外拨号入口，所有 socket 都必须经过这里。
func dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return globalDialer.DialContext(ctx, network, addr)
}

// underlyingTCPConn 取出真实的本地 TCP socket。
// 直连时即 conn 本身；SOCKS5 模式下 x/net/proxy 返回的连接内部持有到代理服务器的
// TCP 连接，通过 NetConn() 或类型断言逐层解包取得。取不到时返回 nil。
//
// 与 asTCPConn 的区别：本函数用于 NoDelay / 缓冲区这类“本地 socket 属性”，
// 代理模式下依然应当生效；asTCPConn 则用于端到端语义的调优，代理下必须跳过。
func underlyingTCPConn(conn net.Conn) *net.TCPConn {
	for i := 0; i < 4 && conn != nil; i++ {
		if tc, ok := conn.(*net.TCPConn); ok {
			return tc
		}
		type netConner interface{ NetConn() net.Conn }
		if nc, ok := conn.(netConner); ok {
			conn = nc.NetConn()
			continue
		}
		type wrapped interface{ Unwrap() net.Conn }
		if w, ok := conn.(wrapped); ok {
			conn = w.Unwrap()
			continue
		}
		return nil
	}
	return nil
}

// asTCPConn 尝试从 conn 中提取底层的 *net.TCPConn，仅用于 Brutal / RTT 这类
// 依赖“端到端链路”语义的内核调优。
//
// 代理模式下本地 socket 的对端是代理服务器而非 VPN 服务端，此时读到的 RTT 是
// “到代理的延迟”，据此调参会误导限速与负载均衡决策，因此直接返回 nil 让调用方跳过。
// 注意：KeepAlive / SO_MARK 等与端到端无关的设置已在 newBaseDialer 中统一处理。
func asTCPConn(conn net.Conn) *net.TCPConn {
	if isSocks5Enabled() {
		return nil
	}
	tc, _ := conn.(*net.TCPConn)
	return tc
}
