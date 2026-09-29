//go:build linux
// +build linux

package main

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// setTCPCork toggles Linux TCP_CORK on the real TCP socket. While corked,
// complete MSS-sized segments may leave normally, while the final partial
// segment is retained so the next TLS ciphertext write can fill it.
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
