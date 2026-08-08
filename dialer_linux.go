//go:build linux
// +build linux

package main

import (
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
