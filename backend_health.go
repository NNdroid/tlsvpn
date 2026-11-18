package main

import "time"

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

	// rttSampleInterval writer 循环的 TCP_INFO/容量采样周期（ticker 与
	// noteCapacitySample 的窗口基准共用，两处必须一致）。
	rttSampleInterval = 200 * time.Millisecond

	// retransPenaltyUS 重传惩罚：最近采样窗（200ms）内每次 TCP 重传段在
	// backendScore 上加的微秒数。重传意味着路径正在丢段——时延地板（min_rtt/
	// 探针 decayed-min）对丢包不敏感，丢包路径的"真实质量"应显著差于其地板。
	// 只作用于兜底选择器 pickBackend 与 parity 目标轮转（backendScore）；
	// adaptive 排名仍由探针/min_rtt 主导，避免把丢包与时延两个维度混在一个键里。
	retransPenaltyUS = 2_000
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

// noteRetrans 吸收一次 TCP_INFO 采样的 tcpi_total_retrans 累计值，按采样窗做差
// 发布到 retransDelta（每 200ms 窗的重传段数）。writer 的采样 goroutine 独占
// retransBase/retransBaseSet（非原子，单一写者），delta 原子发布供调度器与快照
// 并发读。计数回绕/新 socket（total < base）按"重置基线"处理，本窗不产delta。
func (b *Backend) noteRetrans(total uint32) {
	if b == nil {
		return
	}
	if !b.retransBaseSet {
		b.retransBaseSet = true
		b.retransBase = total
		return // 首采样只建基线：握手期累积的重传不计入首窗
	}
	if total < b.retransBase {
		b.retransBase = total
		return
	}
	b.retransDelta.Store(total - b.retransBase)
	b.retransBase = total
}

// noteCapacitySample 结算一个采样窗的路径容量估计（writer 采样 goroutine 独占，
// 与 drainWrite/sampleRTT 同 goroutine，plain 字段无竞态）。
//
// 容量权重的反馈陷阱：writer-drain 速率是"被喂多少测多少"的量——欠估路径拿
// 不到流量就永远欠估，按它做权重会正反馈饿死慢起步路径（见
// TestAdaptiveSchedulerWriterRateCannotMonopolizePath 的钉死注释）。饱和门控
// 是防反馈的关键：conn.Write 阻塞（socket 发送缓冲打满）时 drain 速率才等于
// 路径容量。仅当窗口内写阻塞 ≥ 半窗（windowNS/2）才结算样本——饱和状态下
// 阻塞时长 ≈ 载荷/容量，bytes/busy 即容量；非饱和窗跳过，权重保留上次测量。
// EWMA α=1/2（两个饱和窗 ≈400ms 跟随）。
func (b *Backend) noteCapacitySample(windowNS int64) {
	if b == nil {
		return
	}
	busy, bytes := b.writeBusyNS, b.writeWindowBytes
	b.writeBusyNS, b.writeWindowBytes = 0, 0
	if busy <= 0 || busy*2 < windowNS || bytes == 0 {
		return // 非饱和窗：drain 速率是"被喂速率"，不是容量——保留原权重
	}
	capBytesPerSec := uint64(float64(bytes) / float64(busy) * 1e9)
	if capBytesPerSec == 0 {
		return
	}
	old := b.deliverRateBytesPerSec.Load()
	if old == 0 {
		b.deliverRateBytesPerSec.Store(capBytesPerSec)
	} else {
		b.deliverRateBytesPerSec.Store((old + capBytesPerSec) / 2)
	}
}
