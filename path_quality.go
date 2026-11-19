package main

import (
	"sync/atomic"
	"time"
)

func (b *Backend) observeDelivered(n uint64) {
	if b == nil || n == 0 {
		return
	}
	b.rateSampleBytes += n
	if b.rateSampleStart.IsZero() {
		b.rateSampleStart = time.Now()
		return
	}
	if b.rateSampleBytes < adaptiveRateSampleMinBytes {
		return
	}
	now := time.Now()
	elapsed := now.Sub(b.rateSampleStart)
	if elapsed > adaptiveRateSampleMaxInterval {
		// A long idle interval is not evidence that the path became slow. Restart
		// the sample instead of poisoning the rate estimate toward zero.
		b.rateSampleStart = now
		b.rateSampleBytes = 0
		return
	}
	if elapsed < 200*time.Microsecond {
		return
	}
	inst := uint64(float64(b.rateSampleBytes) / elapsed.Seconds())
	if inst == 0 {
		return
	}
	old := b.rateBytesPerSec.Load()
	if old == 0 {
		b.rateBytesPerSec.Store(inst)
	} else {
		// 1/8 new sample, 7/8 history: stable enough for scheduling while still
		// reacting within a few successful writes when one path degrades.
		b.rateBytesPerSec.Store((old*7 + inst) / 8)
	}
	b.rateSampleBytes = 0
	b.rateSampleStart = now
}

func (b *Backend) effectiveRateBytesPerSec() uint64 {
	if b == nil {
		return adaptiveFallbackRateBytesPerSec
	}
	rate := b.rateBytesPerSec.Load()
	if rate == 0 {
		return adaptiveFallbackRateBytesPerSec
	}
	return rate
}

func serviceTimeUS(bytes, rate uint64) uint64 {
	if bytes == 0 {
		return 0
	}
	if rate == 0 {
		rate = adaptiveFallbackRateBytesPerSec
	}
	return bytes * 1_000_000 / rate
}

func serviceTimeNS(bytes, rate uint64) int64 {
	if bytes == 0 {
		return 0
	}
	if rate == 0 {
		rate = adaptiveFallbackRateBytesPerSec
	}
	return int64(bytes * 1_000_000_000 / rate)
}

// adaptiveBackendRTT returns the RTT used for ordinary telemetry plus whether
// the value is still the connection bootstrap estimate. Zero is also unknown
// for synthetic/TAP backends and proxy cases that cannot expose TCP_INFO.
func adaptiveBackendRTT(b *Backend) (uint32, bool) {
	if b == nil || b.rttCache == nil {
		return adaptiveUnknownRTTUS, true
	}
	rtt := atomic.LoadUint32(b.rttCache)
	if rtt == 0 || rtt == adaptiveUnknownRTTUS {
		return adaptiveUnknownRTTUS, true
	}
	return rtt, false
}

// adaptiveBackendMinRTT returns the connection's kernel min_rtt (无拥塞地板往返,
// µs) + unknownRTT。min_rtt 用于路径质量/排名/资格包络：SRTT 含瞬时拥塞会搅动
// 候选集，min_rtt 是稳定地板。未知时同样用 50000 哨兵纪律。
//
// 返回值约定与 adaptiveBackendRTT 完全一致：bool 为 true 表示**未知**（此时
// 第一个返回值是 50000 哨兵，不可当作真实 RTT 使用）。
func adaptiveBackendMinRTT(b *Backend) (uint32, bool) {
	if b == nil || b.minRttCache == nil {
		return adaptiveUnknownRTTUS, true
	}
	rtt := atomic.LoadUint32(b.minRttCache)
	if rtt == 0 || rtt == adaptiveUnknownRTTUS {
		// min_rtt 尚未观测到（代理/非 Linux/刚建立）：退回 SRTT 当包络参考。
		// 不能返回 50000µs 哨兵——它会让包络地板凭空抬高 2.5 万微秒，把本来
		// 合格的路径挡在候选集外；SRTT 至少是这条连接真实的观测值。
		if srtt, unknownSRTT := adaptiveBackendRTT(b); !unknownSRTT {
			return srtt, false
		}
		return adaptiveUnknownRTTUS, true
	}
	return rtt, false
}

// backendOneWayUS 返回本端 egress 方向的有效单向时延相对量（µs，有符号，可负）
// + 是否已收敛。按所属 AsyncPort 的 oneWayMode 选择 fwd/ret。
//
// 值来自 fwdRankUS/retRankUS（有效值按 raw+oneWayRankZeroUS 编码，恒 >0，故
// 字段 0=未收敛），解码回有符号 µs：负值 = 该方向快于 ref 对称基准，是真实
// 信息，选路 argmin 依赖完整序。有效值 = max(decayed-min 地板, recent-typical −
// 抖动容差)，持续劣化的路径 ~5s 内被抬升（见 recomputeAll）。显示层走另一对
// 字段（fwdOneWayUS，纯地板 + δ 抬升非负），两条路径互不污染——δ 若进选路，
// 与 min_rtt/2 回退候选混排时不抵消，会扭曲排名。
func (b *Backend) backendOneWayUS() (int64, bool) {
	if b == nil {
		return 0, false
	}
	mode := int32(0)
	if b.oneWayModePtr != nil {
		mode = b.oneWayModePtr.Load()
	}
	switch mode {
	case oneWayModeFwd:
		if v := b.fwdRankUS.Load(); v > 0 {
			return oneWayRankDecode(v), true
		}
	case oneWayModeRet:
		if v := b.retRankUS.Load(); v > 0 {
			return oneWayRankDecode(v), true
		}
	}
	return 0, false
}

// adaptiveBackendOneWayUS 返回选路用的单向时延（µs，有符号）：跨路径原始相对
// 量（已收敛）优先，否则回退 min_rtt/2（无拥塞地板），再退 SRTT/2。回退值与
// 探针原始值同尺度（绝对单程估计），无需任何公共偏移即可混排比较。估计未收敛
// 前与既有行为一致。
func adaptiveBackendOneWayUS(b *Backend) int64 {
	if v, ok := b.backendOneWayUS(); ok {
		return v
	}
	// 注意：adaptiveBackendMinRTT 的 bool 是 unknownRTT（与 adaptiveBackendRTT 一致），
	// 故这里取反；写反会让 min_rtt 恒被当成未知，回退链永远停在 SRTT/2。
	if mr, unknown := adaptiveBackendMinRTT(b); !unknown {
		return int64(mr) / 2
	}
	rtt, _ := adaptiveBackendRTT(b)
	return int64(rtt) / 2
}

// rttEffMinSamples 内核 RTT 有效地板发布前的最少采样数。首样本可能是握手期
// 离群值（TCP 慢启动/拥塞窗口未稳），与探针层 rttProbeRecentMinSamples 同纪律：
// 样本不足时调度器回退 min_rtt/SRTT 链（历史行为）。
const rttEffMinSamples = 2

// noteRTTSample 以 200ms 一次的 SRTT 采样维护内核 RTT 的有效地板
// （decayed-min：慢升 0.5ms/s、快降），writer 采样 goroutine 独占。
//
// 语义与探针层 updateDecay 平行（rttProbeDecayPerSecNS 同一常量，RTT 尺度
// 0.5ms/s）：瞬时拥塞把 SRTT 抬高只持续几个采样窗，地板不动（成员稳定性由
// TestAdaptiveSchedulerMinRTTElapsedEnvelope 钉死）；持续劣化（拥塞、路由
// 漂移，不触发重连）让地板以 0.5ms/s 慢升最终跟上；恢复时新样本低于地板，
// 快降立即自愈。这修复了 tcpi_min_rtt 是 min-ever、对连接存续期的持续劣化
// 永久钝感的问题——包络地板被一次 lucky window 钉死、健康路径长期
// envelope_out 只能靠重连解开的根因。
func (b *Backend) noteRTTSample(rttUS uint32) {
	if b == nil || rttUS == 0 {
		return
	}
	now := time.Now()
	elapsedNS := int64(0)
	if !b.rttEffLast.IsZero() {
		elapsedNS = now.Sub(b.rttEffLast).Nanoseconds()
	}
	b.rttEffLast = now
	// decayedMinUpdate 自带时钟回拨守卫（elapsed<0 不慢升，防 uint64 wrap）。
	b.rttEffFloorNS = decayedMinUpdate(b.rttEffFloorNS, elapsedNS, uint64(rttUS)*1000, rttProbeDecayPerSecNS)
	b.rttEffN++
	if b.rttEffN < rttEffMinSamples {
		return
	}
	b.effRttUS.Store(uint32(min(b.rttEffFloorNS/1000, uint64(^uint32(0)))))
}

// adaptiveBackendEffectiveRTT 返回该连接的有效内核 RTT（µs）+ 是否未知。
// effRttUS 已建立（≥rttEffMinSamples 个 SRTT 采样）时优先——decayed-min 地板
// 对持续劣化敏感、对瞬时拥塞稳定；未建立时回退 adaptiveBackendMinRTT 的
// min_rtt/SRTT 链（历史行为）。返回值约定与 adaptiveBackendMinRTT 一致：
// bool 为 true 表示未知，此时首返回值是 50000 哨兵，不可当作真实 RTT 使用。
func adaptiveBackendEffectiveRTT(b *Backend) (uint32, bool) {
	if b == nil {
		return adaptiveUnknownRTTUS, true
	}
	if v := b.effRttUS.Load(); v > 0 {
		return v, false
	}
	return adaptiveBackendMinRTT(b)
}

func (b *Backend) estimatedETAUS(incomingBytes uint64) uint64 {
	if b == nil {
		return ^uint64(0)
	}
	rtt, _ := adaptiveBackendRTT(b)
	eta := uint64(rtt)/2 + serviceTimeUS(b.queuedBytes.Load()+incomingBytes, b.effectiveRateBytesPerSec())
	if b.carryPending.Load() && eta > adaptiveCarryBonusUS {
		eta -= adaptiveCarryBonusUS
	}
	return eta
}
