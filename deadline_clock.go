package main

import (
	"sync/atomic"
	"time"
)

// deadlineClockEpoch 是数据面 deadline 刷新的进程级粗时钟。
//
// client/server 的高 PPS 热路径只做一次 atomic Load + 整数比较；真正的
// time.Now 和 poll deadline syscall 仍然最多每连接每秒一次。相比每连接 ticker，
// 这里全进程只有一个 runtime timer，也不会在每帧执行 channel receive。
var deadlineClockEpoch atomic.Uint64

func init() {
	deadlineClockEpoch.Store(1)
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for range ticker.C {
			deadlineClockEpoch.Add(1)
		}
	}()
}

func currentDeadlineEpoch() uint64 {
	return deadlineClockEpoch.Load()
}
