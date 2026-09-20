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

func setupPolicyRouting(tapName string, mark int, gwV4, gwV6 string) error {
	return fmt.Errorf("policy routing is only supported on Linux")
}

func cleanPolicyRouting(tapName string, mark int, gwV4, gwV6 string) {}

func applyTCPBrutal(conn *net.TCPConn, rateMbps uint64) error {
	return fmt.Errorf("TCP Brutal is only supported on Linux")
}

// brutalStatus 系统级 TCP Brutal 能力与状态。结构体与两个平台的实现分离：
// 字段是面板协议的一部分，定义在公共代码里避免两份拷贝漂移。
type brutalStatus struct {
	supported bool
	current   string
	available []string
	err       string
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
