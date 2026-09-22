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

// 非 Linux 上隧道网卡的全部配置函数都是桩：不设置 MAC、不挂地址、不建策略路由。
func netlinkTunnelSupported() bool { return false }

func setTapMac(tapName, macStr string) error {
	return fmt.Errorf("setTapMac is only supported on Linux")
}

func setupPolicyRouting(tapName string, spec policyRoutingSpec) error {
	return fmt.Errorf("policy routing is only supported on Linux")
}

func cleanPolicyRouting(tapName string, spec policyRoutingSpec) {}

func applyTCPBrutal(conn *net.TCPConn, totalRate, legacyRate, groupID uint64) brutalApplyResult {
	return brutalApplyResult{Attempted: true, Error: "TCP Brutal is only supported on Linux"}
}

// 非 Linux 上不存在内核拥塞控制可查：面板把 brutal 状态显示为"平台不支持"，
// 而不是把它当成配置错误或生效失败。
func brutalSystemStatus() brutalStatus {
	return brutalStatus{supported: false, err: "TCP Brutal requires Linux"}
}

func getTCPRTT(conn *net.TCPConn) (uint32, error) {
	return 0, fmt.Errorf("TCP RTT probing is only supported on Linux")
}

func startRTTPoller(ctx context.Context, conn *net.TCPConn, rttCache *uint32) {}
