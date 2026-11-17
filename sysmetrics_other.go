//go:build !linux
// +build !linux

package main

// hostCLKTCK 非 Linux 平台不读 /proc（readProcCPU 恒返 nil），该值不会被用到；
// 固定返回 100 保持调用方可移植编译。
func hostCLKTCK() float64 { return 100 }
