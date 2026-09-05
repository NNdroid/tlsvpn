//go:build !linux
// +build !linux

package main

import (
	"context"
	"fmt"
	"net"

	"github.com/songgao/water"
)

// newTapConfig 在非 Linux 平台上不支持指定 TAP 网卡名（由驱动决定）。
// 这些桩仅用于让项目在非 Linux 开发机上编译并通过可移植的单元测试，
// 实际隧道功能仍以 Linux 为准。
func newTapConfig(name string) water.Config {
	return water.Config{DeviceType: water.TAP}
}

func setTapMac(tapName, macStr string) error {
	return fmt.Errorf("setTapMac is only supported on Linux")
}

func setupPolicyRouting(tapName string, mark int, gwV4, gwV6 string) error {
	return fmt.Errorf("policy routing is only supported on Linux")
}

func cleanPolicyRouting(tapName string, mark int, gwV4, gwV6 string) {}

func applyTCPBrutal(conn *net.TCPConn, rateMbps uint64) error {
	return fmt.Errorf("TCP Brutal is only supported on Linux")
}

func getTCPRTT(conn *net.TCPConn) (uint32, error) {
	return 0, fmt.Errorf("TCP RTT probing is only supported on Linux")
}

func startRTTPoller(ctx context.Context, conn *net.TCPConn, rttCache *uint32) {}
