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
	// 作用于兜底选择器 pickBackend 与 parity 目标轮转（backendScore）；
	// adaptive 主排名按同一信号用 retransRankPenaltyUS 施加加性罚时（不混入
	// 排名键本身，作为独立健康罚项叠加，见 buildEligibleCandidates）。
	retransPenaltyUS = 2_000

	// retransRankPenaltyUS / probeTimeoutPenaltyUS 健康罚时的默认单位值（µs）：
	// 每个 200ms 窗重传段 / 每次探针连续超时在 adaptive 排名键上加的微秒数。
	// 两者共用可配的 sched_health_penalty_us（AsyncPort.healthPenaltyUS，
	// NewAsyncPort 初始化为 schedHealthPenaltyDefaultUS，0=禁用）——同一类
	// "路径正在变坏"的健康信号，单位罚时没必要分两个字段。
	retransRankPenaltyUS  = 2_000
	probeTimeoutPenaltyUS = 2_000

	// schedHealthPenaltyDefaultUS sched_health_penalty_us 的默认值（两个单位
	// 常量同值，配置缺省与 NewAsyncPort 初始化共用）。
	schedHealthPenaltyDefaultUS = 2_000
	// schedHealthPenaltyMaxUS 罚时总量封顶：超时与重传各自封顶到该值，防大量
	// 事件叠加把排名键抬成等效禁用。
	schedHealthPenaltyMaxUS = 10_000
	// schedHealthPenaltyMaxConfigUS sched_health_penalty_us 配置上限：超过它
	// 单次事件即顶满总量封顶，等于把可调范围退化为开关，无意义。
	schedHealthPenaltyMaxConfigUS = 60_000
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
// 与 drainWrite/sampleRTT 同 goroutine，plain 字段无竞态）。cwnd/sndMss/srttUS
// 取自同 tick 的 TCP_INFO（失败时全 0，饱和窗结算不受影响）。
//
// 容量权重的反馈陷阱：writer-drain 速率是"被喂多少测多少"的量——欠估路径拿
// 不到流量就永远欠估，按它做权重会正反馈饿死慢起步路径（见
// TestAdaptiveSchedulerWriterRateCannotMonopolizePath 的钉死注释）。饱和门控
// 是防反馈的关键：conn.Write 阻塞（socket 发送缓冲打满）时 drain 速率才等于
// 路径容量。仅当窗口内写阻塞 ≥ 半窗（windowNS/2）才结算样本——饱和状态下
// 阻塞时长 ≈ 载荷/容量，bytes/busy 即容量；EWMA α=1/2（两个饱和窗 ≈400ms 跟随）。
//
// 非饱和窗补充 BDP 下界：writer-drain 速率不能当容量（被喂速率），但
// cwnd×mss/srtt 是拥塞窗口隐含的吞吐上界，与被喂速率无关。饱和门控只覆盖
// "写阻塞达半窗"的窗口——永不饱和的快路径（writer 永远追得上输入）原先生里
// 拿不到任何容量样本，权重只能落到 maxDeliver/4 防饿地板或 25MB/s 保守回退；
// BDP 估计让它进入真实量级。cwnd 仅在收到 ACK 时增长，应用受限期不会凭空
// 膨胀；srtt 是内核 EWMA。EWMA α=1/2，独立于饱和样本的 deliverRate 字段
// （面板"饱和门控容量"语义不混）。
func (b *Backend) noteCapacitySample(windowNS int64, cwnd, sndMss, srttUS uint32) {
	if b == nil {
		return
	}
	busy, bytes := b.writeBusyNS, b.writeWindowBytes
	b.writeBusyNS, b.writeWindowBytes = 0, 0
	if bytes == 0 {
		return // 空窗：无流量即无测量
	}
	if busy > 0 && busy*2 >= windowNS {
		// 饱和窗：阻塞时长 ≈ 载荷/容量，bytes/busy 即容量。
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
		return
	}
	// 非饱和窗：writer-drain 速率是"被喂速率"，不是容量——deliverRate 保留
	// 上次饱和测量；改用 BDP 下界补齐永不饱和路径的容量估计。
	if cwnd == 0 || sndMss == 0 || srttUS == 0 {
		return
	}
	bdp := uint64(cwnd) * uint64(sndMss) * 1_000_000_000 / (uint64(srttUS) * 1000)
	if bdp == 0 {
		return
	}
	old := b.bdpRateBytesPerSec.Load()
	if old == 0 {
		b.bdpRateBytesPerSec.Store(bdp)
	} else {
		b.bdpRateBytesPerSec.Store((old + bdp) / 2)
	}
}
