//go:build !linux
// +build !linux

package main

import (
	"fmt"
	"net"
)

func setTCPCork(conn *net.TCPConn, enabled bool) error {
	return fmt.Errorf("TCP_CORK is only supported on Linux")
}
