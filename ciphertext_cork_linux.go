//go:build linux
// +build linux

package main

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// setTCPCork enables/disables Linux TCP_CORK on the real transport socket.
// With cork enabled the kernel may hold only the final partial TCP segment while
// complete MSS-sized segments continue to leave normally.
func setTCPCork(conn *net.TCPConn, enabled bool) error {
	if conn == nil {
		return fmt.Errorf("no TCP connection available")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	value := 0
	if enabled {
		value = 1
	}
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_CORK, value)
	}); err != nil {
		return err
	}
	return sockErr
}
