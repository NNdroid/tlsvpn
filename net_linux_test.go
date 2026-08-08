//go:build linux
// +build linux

package main

import (
	"context"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// TestBrutalAndRTTNilSafe 验证代理模式下 tcpConn 为 nil 时不会 panic。
// 这是 SOCKS5 支持的关键保护：原实现使用强制类型断言，走代理后会直接崩溃。
func TestBrutalAndRTTNilSafe(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("nil 连接不应导致 panic: %v", r)
		}
	}()

	if err := applyTCPBrutal(nil, 100); err == nil {
		t.Error("nil 连接应返回错误而非成功")
	}
	if _, err := getTCPRTT(nil); err == nil {
		t.Error("nil 连接应返回错误而非成功")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var cache uint32
	startRTTPoller(ctx, nil, &cache) // 应立即返回且不 panic
}

// TestSocketMarkControlNilWhenDisabled fwmark<=0 时不应产生 Control 回调，
// 避免给未启用该特性的用户增加无谓的 syscall 开销
func TestSocketMarkControlNilWhenDisabled(t *testing.T) {
	if socketMarkControl(0) != nil {
		t.Error("fwmark=0 时 Control 回调应为 nil")
	}
	if socketMarkControl(-1) != nil {
		t.Error("fwmark 为负时 Control 回调应为 nil")
	}
	if socketMarkControl(100) == nil {
		t.Error("fwmark>0 时必须返回非 nil 的 Control 回调")
	}
}

// TestSocketMarkActuallyApplied 这是 SO_MARK 修复的核心验证：
// 实际建立连接后回读 SO_MARK，确认 mark 真的写进了 socket。
// 若不生效，策略路由不会命中，隧道流量会被卷入自身形成环路死锁。
//
// 需要 CAP_NET_ADMIN，非 root 环境会跳过。
func TestSocketMarkActuallyApplied(t *testing.T) {
	const mark = 0x64

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动监听失败: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	d := &net.Dialer{Control: socketMarkControl(mark)}
	conn, err := d.Dial("tcp", ln.Addr().String())
	if err != nil {
		if isPermErr(err) {
			t.Skipf("设置 SO_MARK 需要 CAP_NET_ADMIN，当前环境无权限，跳过: %v", err)
		}
		t.Fatalf("拨号失败: %v", err)
	}
	defer conn.Close()

	tc, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatal("预期得到 *net.TCPConn")
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		t.Fatalf("获取 SyscallConn 失败: %v", err)
	}

	var got int
	var gerr error
	if err := raw.Control(func(fd uintptr) {
		got, gerr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
	}); err != nil {
		t.Fatalf("Control 失败: %v", err)
	}
	if gerr != nil {
		t.Fatalf("读取 SO_MARK 失败: %v", gerr)
	}
	if got != mark {
		t.Errorf("SO_MARK 未生效！预期 %d 实际 %d —— 策略路由将无法命中，存在隧道环路风险", mark, got)
	}
}

// TestGlobalProxyAppliesMark 验证 fwmark 经由 initGlobalProxy 正确传递到底层 dialer
func TestGlobalProxyAppliesMark(t *testing.T) {
	const mark = 0x65
	t.Cleanup(func() { _ = initGlobalProxy("", 0) })

	if err := initGlobalProxy("", mark); err != nil {
		t.Fatalf("初始化失败: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	conn, err := dialContext(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		if isPermErr(err) {
			t.Skipf("需要 CAP_NET_ADMIN，跳过: %v", err)
		}
		t.Fatalf("拨号失败: %v", err)
	}
	defer conn.Close()

	tc := underlyingTCPConn(conn)
	if tc == nil {
		t.Fatal("应能取到底层 TCP 连接")
	}
	raw, _ := tc.SyscallConn()
	var got int
	raw.Control(func(fd uintptr) {
		got, _ = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK)
	})
	if got != mark {
		t.Errorf("经 initGlobalProxy 设置的 fwmark 未生效，预期 %d 实际 %d", mark, got)
	}
}

func isPermErr(err error) bool {
	for err != nil {
		if err == syscall.EPERM || err == syscall.EACCES {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
