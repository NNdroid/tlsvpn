//go:build linux
// +build linux

package main

import (
	"encoding/binary"
	"os"
	"sync"
)

// atClkTck 辅助向量 AT_CLKTCK 的键值，语义同 glibc 的 sysconf(_SC_CLK_TCK)。
const atClkTck = 17

var (
	clkTckOnce sync.Once
	clkTckVal  float64
)

// hostCLKTCK 返回内核时钟节拍率（CLK_TCK），用于把 /proc/<pid>/stat 的 utime/stime
// 换算成秒。HZ≠100 的内核（CONFIG_HZ=250/1000 等）若按固定 100 折算，CPU% 会成
// 比例失真。从 /proc/self/auxv 读 AT_CLKTCK（glibc sysconf(_SC_CLK_TCK) 的同源
// 取值；本仓库依赖的 x/sys 版本未提供 unix.Sysconf）。该值进程生命周期内不变，
// 读一次缓存即可；auxv 不可读或缺项时回退到 Linux 最常见的默认值 100。
func hostCLKTCK() float64 {
	clkTckOnce.Do(func() {
		clkTckVal = 100
		if v := auxvClkTck(); v > 0 {
			clkTckVal = float64(v)
		}
	})
	return clkTckVal
}

// auxvClkTck 从 /proc/self/auxv 解析 AT_CLKTCK。auxv 是 (key, value) 两个本机
// 字节序 uint64 一组的数组；读取失败或缺项时返回 0，由调用方回退默认值。
func auxvClkTck() uint64 {
	data, err := os.ReadFile("/proc/self/auxv")
	if err != nil {
		return 0
	}
	for i := 0; i+16 <= len(data); i += 16 {
		key := binary.NativeEndian.Uint64(data[i:])
		val := binary.NativeEndian.Uint64(data[i+8:])
		if key == atClkTck {
			return val
		}
	}
	return 0
}
