//go:build linux
// +build linux

package main

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// socketMarkControl 返回一个 net.Dialer.Control 回调，在 socket 建立连接*之前*
// 为其打上 SO_MARK。这是策略路由（setupPolicyRouting）能够生效的前提：
// 只有带 mark 的 socket 才会命中独立路由表，从而绕过 TAP 隧道走物理网卡。
//
// 若不设置 SO_MARK，隧道建立后默认路由指向 TAP，承载隧道自身的连接会被卷入
// 隧道内部，形成路由环路导致连接死锁。
func socketMarkControl(mark int) func(network, address string, c syscall.RawConn) error {
	if mark <= 0 {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
		}); err != nil {
			return err
		}
		return sockErr
	}
}

// probeSocketMark 一次性探测当前进程能否设置 SO_MARK（需要 CAP_NET_ADMIN 或 root）。
// 用一个即建即关的 UDP socket 试打 mark，不产生任何网络流量；否则缺权限时只能
// 在每次 dial 报 EPERM，故障暴露太晚。mark<=0 视为未启用，恒成功。
func probeSocketMark(mark int) error {
	if mark <= 0 {
		return nil
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("create probe socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, mark); err != nil {
		return fmt.Errorf("set SO_MARK %d: %w", mark, err)
	}
	return nil
}
