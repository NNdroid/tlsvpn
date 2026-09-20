//go:build !linux
// +build !linux

package main

import "syscall"

// ifaNoDAD 非 Linux 无 netlink 地址标志；保持同名以免 server.go/client.go
// 里的赋值代码被 GOOS 分割（真实取值见 net_linux.go）。
const ifaNoDAD = 0

// socketMarkControl 在非 Linux 平台上无 SO_MARK 概念，返回 nil 表示不做特殊处理。
func socketMarkControl(mark int) func(network, address string, c syscall.RawConn) error {
	return nil
}
