package main

import (
	"math"
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

// backendOneWayUS 返回本端 egress 方向的单向时延估计（µs）+ 是否已收敛。
// 按所属 AsyncPort 的 oneWayMode 选择 fwd/ret；0=未收敛。
func (b *Backend) backendOneWayUS() (uint32, bool) {
	if b == nil {
		return 0, false
	}
	mode := int32(0)
	if b.oneWayModePtr != nil {
		mode = b.oneWayModePtr.Load()
	}
	switch mode {
	case oneWayModeFwd:
		if v := b.fwdOneWayUS.Load(); v > 0 {
			return uint32(min(v, math.MaxUint32)), true
		}
	case oneWayModeRet:
		if v := b.retOneWayUS.Load(); v > 0 {
			return uint32(min(v, math.MaxUint32)), true
		}
	}
	return 0, false
}

// adaptiveBackendOneWayUS 返回选路用的单向时延：跨路径估计（已收敛）优先，
// 否则回退 min_rtt/2（无拥塞地板），再退 SRTT/2。估计未收敛前与现状一致。
func adaptiveBackendOneWayUS(b *Backend) uint64 {
	if v, ok := b.backendOneWayUS(); ok {
		return uint64(v)
	}
	// 注意：adaptiveBackendMinRTT 的 bool 是 unknownRTT（与 adaptiveBackendRTT 一致），
	// 故这里取反；写反会让 min_rtt 恒被当成未知，回退链永远停在 SRTT/2。
	if mr, unknown := adaptiveBackendMinRTT(b); !unknown {
		return uint64(mr) / 2
	}
	rtt, _ := adaptiveBackendRTT(b)
	return uint64(rtt) / 2
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
