//go:build !linux

package main

import "net"

func readTCPSocketSnapshot(conn *net.TCPConn, proxy bool) *tcpSocketSnapshot {
	s := newTCPSnapshot(conn, proxy)
	s.Unavailable["socket"] = "unsupported_platform"
	return s
}
