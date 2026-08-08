package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// ==========================================
// SOCKS5 地址解析测试
// ==========================================

func TestParseSocks5(t *testing.T) {
	cases := []struct {
		name     string
		in       string
		wantHost string
		wantUser string
		wantPass string
		wantAuth bool
		wantErr  bool
	}{
		{name: "裸 host:port", in: "127.0.0.1:1080", wantHost: "127.0.0.1:1080"},
		{name: "带认证", in: "alice:s3cret@127.0.0.1:1080", wantHost: "127.0.0.1:1080", wantUser: "alice", wantPass: "s3cret", wantAuth: true},
		{name: "socks5 scheme", in: "socks5://1.2.3.4:1080", wantHost: "1.2.3.4:1080"},
		{name: "socks5h scheme", in: "socks5h://1.2.3.4:1080", wantHost: "1.2.3.4:1080"},
		{name: "scheme 带认证", in: "socks5://bob:pw@1.2.3.4:1080", wantHost: "1.2.3.4:1080", wantUser: "bob", wantPass: "pw", wantAuth: true},
		{name: "IPv6", in: "[::1]:1080", wantHost: "[::1]:1080"},
		{name: "空密码", in: "user:@127.0.0.1:1080", wantHost: "127.0.0.1:1080", wantUser: "user", wantPass: "", wantAuth: true},
		{name: "前后空白", in: "  127.0.0.1:1080  ", wantHost: "127.0.0.1:1080"},

		{name: "空字符串", in: "", wantErr: true},
		{name: "只有空白", in: "   ", wantErr: true},
		{name: "缺端口", in: "127.0.0.1", wantErr: true},
		{name: "http scheme 必须拒绝", in: "http://1.2.3.4:8080", wantErr: true},
		{name: "socks4 scheme 必须拒绝", in: "socks4://1.2.3.4:1080", wantErr: true},
		{name: "scheme 缺 host", in: "socks5://", wantErr: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			host, auth, err := parseSocks5(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("输入 %q 预期报错，实际成功 host=%q", c.in, host)
				}
				return
			}
			if err != nil {
				t.Fatalf("输入 %q 预期成功，实际报错: %v", c.in, err)
			}
			if host != c.wantHost {
				t.Errorf("host 不符，预期 %q 实际 %q", c.wantHost, host)
			}
			if c.wantAuth {
				if auth == nil {
					t.Fatalf("预期解析出认证信息，实际为 nil")
				}
				if auth.User != c.wantUser || auth.Password != c.wantPass {
					t.Errorf("认证信息不符，预期 %q/%q 实际 %q/%q", c.wantUser, c.wantPass, auth.User, auth.Password)
				}
			} else if auth != nil {
				t.Errorf("预期无认证信息，实际拿到 %+v", auth)
			}
		})
	}
}

// TestInitGlobalProxyDirect 校验未启用代理时保持直连，且全局状态正确
func TestInitGlobalProxyDirect(t *testing.T) {
	t.Cleanup(func() { _ = initGlobalProxy("", 0) })

	if err := initGlobalProxy("", 0); err != nil {
		t.Fatalf("直连模式初始化失败: %v", err)
	}
	if isSocks5Enabled() {
		t.Error("未配置 -socks5 时 isSocks5Enabled 应为 false")
	}
	if globalSocks5Addr != "" {
		t.Errorf("直连模式下 globalSocks5Addr 应为空，实际 %q", globalSocks5Addr)
	}
	if globalDialer == nil {
		t.Error("globalDialer 不应为 nil")
	}
}

// TestInitGlobalProxyInvalid 校验非法配置必须报错，避免静默降级为直连造成流量泄漏
func TestInitGlobalProxyInvalid(t *testing.T) {
	t.Cleanup(func() { _ = initGlobalProxy("", 0) })

	for _, bad := range []string{"127.0.0.1", "http://1.2.3.4:8080", "socks4://1.2.3.4:1080"} {
		if err := initGlobalProxy(bad, 0); err == nil {
			t.Errorf("非法配置 %q 必须报错，否则会静默直连导致流量泄漏", bad)
		}
	}
}

// ==========================================
// 内嵌 SOCKS5 测试服务器
// ==========================================

// testSocks5Server 是一个最小可用的 SOCKS5 服务器，仅用于测试。
// 支持 无认证 与 用户名/密码认证 两种模式，仅实现 CONNECT 命令。
type testSocks5Server struct {
	ln       net.Listener
	user     string
	pass     string
	mu       sync.Mutex
	conned   []string // 记录所有被请求连接的目标地址，用于断言流量确实走了代理
	wg       sync.WaitGroup
	closeOne sync.Once
}

func newTestSocks5Server(t *testing.T, user, pass string) *testSocks5Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动测试 SOCKS5 服务器失败: %v", err)
	}
	s := &testSocks5Server{ln: ln, user: user, pass: pass}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(s.Close)
	return s
}

func (s *testSocks5Server) Addr() string { return s.ln.Addr().String() }

func (s *testSocks5Server) Close() {
	s.closeOne.Do(func() {
		s.ln.Close()
		s.wg.Wait()
	})
}

// Targets 返回被请求过的目标地址快照
func (s *testSocks5Server) Targets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.conned))
	copy(out, s.conned)
	return out
}

func (s *testSocks5Server) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer c.Close()
			if err := s.handle(c); err != nil {
				// 测试服务器：握手失败直接断开即可
				return
			}
		}()
	}
}

func (s *testSocks5Server) handle(c net.Conn) error {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	br := make([]byte, 2)
	if _, err := io.ReadFull(c, br); err != nil {
		return err
	}
	if br[0] != 0x05 {
		return fmt.Errorf("不支持的 SOCKS 版本 %d", br[0])
	}
	methods := make([]byte, int(br[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}

	needAuth := s.user != ""
	want := byte(0x00)
	if needAuth {
		want = 0x02
	}
	ok := false
	for _, m := range methods {
		if m == want {
			ok = true
			break
		}
	}
	if !ok {
		c.Write([]byte{0x05, 0xFF})
		return fmt.Errorf("客户端不支持所需认证方法 %d", want)
	}
	if _, err := c.Write([]byte{0x05, want}); err != nil {
		return err
	}

	if needAuth {
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(c, hdr); err != nil {
			return err
		}
		if hdr[0] != 0x01 {
			return fmt.Errorf("错误的认证子协议版本 %d", hdr[0])
		}
		u := make([]byte, int(hdr[1]))
		if _, err := io.ReadFull(c, u); err != nil {
			return err
		}
		pl := make([]byte, 1)
		if _, err := io.ReadFull(c, pl); err != nil {
			return err
		}
		p := make([]byte, int(pl[0]))
		if _, err := io.ReadFull(c, p); err != nil {
			return err
		}
		if string(u) != s.user || string(p) != s.pass {
			c.Write([]byte{0x01, 0x01})
			return fmt.Errorf("认证失败")
		}
		if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
			return err
		}
	}

	// CONNECT 请求
	req := make([]byte, 4)
	if _, err := io.ReadFull(c, req); err != nil {
		return err
	}
	if req[1] != 0x01 {
		c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("仅支持 CONNECT，收到 cmd=%d", req[1])
	}

	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return err
		}
		host = net.IP(b).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, b); err != nil {
			return err
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return err
		}
		host = net.IP(b).String()
	default:
		return fmt.Errorf("不支持的地址类型 %d", req[3])
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return err
	}
	target := net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(pb)))

	s.mu.Lock()
	s.conned = append(s.conned, target)
	s.mu.Unlock()

	upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return err
	}
	defer upstream.Close()

	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}

	c.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, c); done <- struct{}{} }()
	go func() { io.Copy(c, upstream); done <- struct{}{} }()
	<-done
	return nil
}

// ==========================================
// SOCKS5 端到端拨号测试
// ==========================================

// startEchoServer 启动一个回显服务器，作为代理的上游目标
func startEchoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动 echo 服务器失败: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

// TestDialThroughSocks5 验证启用代理后流量确实经过 SOCKS5，而非直连
func TestDialThroughSocks5(t *testing.T) {
	t.Cleanup(func() { _ = initGlobalProxy("", 0) })

	echo := startEchoServer(t)
	px := newTestSocks5Server(t, "", "")

	if err := initGlobalProxy(px.Addr(), 0); err != nil {
		t.Fatalf("初始化 SOCKS5 失败: %v", err)
	}
	if !isSocks5Enabled() {
		t.Fatal("isSocks5Enabled 应为 true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := dialContext(ctx, "tcp", echo)
	if err != nil {
		t.Fatalf("经由 SOCKS5 拨号失败: %v", err)
	}
	defer conn.Close()

	msg := []byte("hello through socks5")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	got := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if string(got) != string(msg) {
		t.Errorf("回显不符，预期 %q 实际 %q", msg, got)
	}

	// 关键断言：代理服务器必须记录到这次连接，证明流量没有绕过代理
	targets := px.Targets()
	if len(targets) != 1 || targets[0] != echo {
		t.Errorf("流量未经过代理！代理记录的目标: %v，预期 [%s]", targets, echo)
	}
}

// TestDialThroughSocks5WithAuth 验证用户名/密码认证链路
func TestDialThroughSocks5WithAuth(t *testing.T) {
	t.Cleanup(func() { _ = initGlobalProxy("", 0) })

	echo := startEchoServer(t)
	px := newTestSocks5Server(t, "alice", "s3cret")

	if err := initGlobalProxy("alice:s3cret@"+px.Addr(), 0); err != nil {
		t.Fatalf("初始化带认证的 SOCKS5 失败: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialContext(ctx, "tcp", echo)
	if err != nil {
		t.Fatalf("带认证拨号失败: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	got := make([]byte, 4)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if string(got) != "ping" {
		t.Errorf("回显不符: %q", got)
	}
	if len(px.Targets()) != 1 {
		t.Errorf("代理未记录连接: %v", px.Targets())
	}
}

// TestSocks5WrongCredentials 验证错误凭据必须失败，而不是退化成直连
func TestSocks5WrongCredentials(t *testing.T) {
	t.Cleanup(func() { _ = initGlobalProxy("", 0) })

	echo := startEchoServer(t)
	px := newTestSocks5Server(t, "alice", "s3cret")

	if err := initGlobalProxy("alice:WRONG@"+px.Addr(), 0); err != nil {
		t.Fatalf("初始化失败: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialContext(ctx, "tcp", echo)
	if err == nil {
		conn.Close()
		t.Fatal("凭据错误时必须拨号失败，绝不能退化为直连")
	}
}

// TestDirectDialDoesNotUseProxy 对照组：直连模式下代理不应收到任何连接
func TestDirectDialDoesNotUseProxy(t *testing.T) {
	t.Cleanup(func() { _ = initGlobalProxy("", 0) })

	echo := startEchoServer(t)
	px := newTestSocks5Server(t, "", "")

	if err := initGlobalProxy("", 0); err != nil {
		t.Fatalf("直连初始化失败: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialContext(ctx, "tcp", echo)
	if err != nil {
		t.Fatalf("直连失败: %v", err)
	}
	defer conn.Close()

	if n := len(px.Targets()); n != 0 {
		t.Errorf("直连模式下代理不应收到连接，实际收到 %d 条", n)
	}
}

// TestUnderlyingTCPConnDirect 直连时应能取到底层 socket 以便设置 NoDelay 等
func TestUnderlyingTCPConnDirect(t *testing.T) {
	t.Cleanup(func() { _ = initGlobalProxy("", 0) })
	_ = initGlobalProxy("", 0)

	echo := startEchoServer(t)
	conn, err := dialContext(context.Background(), "tcp", echo)
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	defer conn.Close()

	if underlyingTCPConn(conn) == nil {
		t.Error("直连模式下应能取到底层 *net.TCPConn")
	}
	if asTCPConn(conn) == nil {
		t.Error("直连模式下 asTCPConn 应返回非 nil，Brutal/RTT 才能生效")
	}
}

// TestAsTCPConnNilUnderProxy 代理模式下 asTCPConn 必须返回 nil，
// 否则 Brutal/RTT 会基于"到代理的延迟"做出错误决策
func TestAsTCPConnNilUnderProxy(t *testing.T) {
	t.Cleanup(func() { _ = initGlobalProxy("", 0) })

	echo := startEchoServer(t)
	px := newTestSocks5Server(t, "", "")
	if err := initGlobalProxy(px.Addr(), 0); err != nil {
		t.Fatalf("初始化失败: %v", err)
	}

	conn, err := dialContext(context.Background(), "tcp", echo)
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	defer conn.Close()

	if asTCPConn(conn) != nil {
		t.Error("代理模式下 asTCPConn 必须返回 nil 以跳过端到端内核调优")
	}
}

// TestSocks5ProxyUnreachable 代理不可达时必须报错
func TestSocks5ProxyUnreachable(t *testing.T) {
	t.Cleanup(func() { _ = initGlobalProxy("", 0) })

	// 占用一个端口后立刻释放，得到一个大概率无人监听的地址
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("准备端口失败: %v", err)
	}
	dead := ln.Addr().String()
	ln.Close()

	if err := initGlobalProxy(dead, 0); err != nil {
		t.Fatalf("初始化失败: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := dialContext(ctx, "tcp", "192.0.2.1:80")
	if err == nil {
		conn.Close()
		t.Fatal("代理不可达时必须报错")
	}
	if strings.Contains(err.Error(), "no such host") {
		t.Logf("注意：错误信息与预期不同，但仍为失败: %v", err)
	}
}
