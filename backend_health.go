package main

// 后端健康感知。
//
// stalled 标记某条物理连接已被判定为不健康。调度器（backendScore /
// pickAdaptiveBackend）跳过 stalled 后端，使其不再接收新的数据批次，避免把
// 数据持续送进已经死亡/半开的 TCP 路径——这正是"4 条连接断 3 条后网络就断"
// 的根源之一：在连接被读/写超时踢出之前，调度器只凭队列深度判断健康，会
// 继续把最多 (N-1)/N 的流量分配给死路径。
//
// 标记时机：
//   - 连接读循环 ReadFrame 返回错误（对端消失 / 读超时）。
//   - 连接写循环 Write 返回错误（对端停止读取 / 写超时）。
//   - 连续 rttFailuresStall 次 RTT 采样失败（连接正在关闭）。
//
// 连接重拨会新建 Backend（RegisterOwnedBackend），旧对象的 stalled 随对象
// 一起废弃，因此无需显式清除。

const (
	// rttFailuresStall 连续 RTT 采样失败达到该次数即置 stalled。
	// RTT 每 200ms 采样一次，3 次 ≈ 600ms，足以过滤瞬时 syscall 抖动。
	rttFailuresStall = 3
)

// markStalled 置位 stalled 标记（幂等）。
func (b *Backend) markStalled() {
	if b != nil {
		b.stalled.Store(true)
	}
}

// isStalled 返回该后端是否已被判定为不健康。
func (b *Backend) isStalled() bool {
	return b != nil && b.stalled.Load()
}

// noteRTTSuccess 记录一次成功的 RTT 采样并清零失败计数。
func (b *Backend) noteRTTSuccess() {
	if b != nil {
		b.rttFailures.Store(0)
	}
}

// noteRTTFailure 记录一次失败的 RTT 采样；连续 rttFailuresStall 次即置 stalled。
func (b *Backend) noteRTTFailure() {
	if b == nil {
		return
	}
	if b.rttFailures.Add(1) >= rttFailuresStall {
		b.markStalled()
	}
}
