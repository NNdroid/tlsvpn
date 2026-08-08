//go:build !linux
// +build !linux

package main

import "syscall"

// socketMarkControl 在非 Linux 平台上无 SO_MARK 概念，返回 nil 表示不做特殊处理。
func socketMarkControl(mark int) func(network, address string, c syscall.RawConn) error {
	return nil
}
