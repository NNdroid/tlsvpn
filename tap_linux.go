//go:build linux
// +build linux

package main

import "github.com/songgao/water"

// newTapConfig 构造 Linux 下的 TAP 设备配置（可指定网卡名）。
func newTapConfig(name string) water.Config {
	config := water.Config{DeviceType: water.TAP}
	config.Name = name
	return config
}
