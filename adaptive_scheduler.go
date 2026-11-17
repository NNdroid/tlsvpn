package main

import (
	"time"
)

const (
	// One 12 KiB TLSVPN batch should stay on the latency-optimal path. Open
	// additional paths only after there is enough real queued work to keep them
	// useful; this also avoids creating one sub-MSS tail on every idle socket.
	adaptiveActive2Pressure = 24 * 1024
	adaptiveActive3Pressure = 96 * 1024
	adaptiveActive4Pressure = 256 * 1024

	// Until a path has a measured delivery rate, assume a conservative 200 Mbps.
	// The value only affects the short warm-up interval; observeDelivered replaces
	// it with a per-path EWMA after 64 KiB of successful payload delivery.
	adaptiveFallbackRateBytesPerSec = 25_000_000
	adaptiveRateSampleMinBytes      = 64 * 1024
	adaptiveRateSampleMaxInterval   = 2 * time.Second
	adaptiveDemandSampleMinInterval = 500 * time.Microsecond

	// Legacy client/server connection setup initializes every RTT cache to 50ms
	// before TCP_INFO has produced a direction-specific sample. Treat that exact
	// bootstrap value as "unknown" inside the adaptive scheduler. Otherwise one
	// socket that obtains a sub-ms RTT first can exclude the other three from the
	// near-MinRTT candidate set forever, so they never receive enough egress data
	// to warm their own measurements.
	adaptiveUnknownRTTUS uint32 = 50_000

	// Queue pressure reacts to bursts; demand rate keeps a sustained high-rate
	// stream expanded even when writers drain their channels faster than the
	// scheduler can observe a deep queue. Values are payload bytes/second.
	adaptiveActive2RateBytesPerSec = 40_000_000  // ~320 Mbps
	adaptiveActive3RateBytesPerSec = 100_000_000 // ~800 Mbps
	adaptiveActive4RateBytesPerSec = 180_000_000 // ~1.44 Gbps

	// Filling an already-corked sub-MSS tail is a useful tie-breaker, not a reason
	// to route around materially faster paths. Keep the bonus below the maximum
	// TCP_CORK carry window.
	adaptiveCarryBonusUS = 150

	adaptiveStickyMinUS = 500
	adaptiveStickyMaxUS = 5_000
)

type backendCandidate struct {
	backend   *Backend
	baseUS    int64 // unloaded path quality: oneWay probe + this batch service time; signed (probe raw may be negative)
	rttUS     uint32
	schedRate uint64 // fair-start rate used only by this scheduling decision
	wasActive bool
	virtualNS int64 // logical WFQ service debt; deliberately independent of wall clock
}

// schedulerConnJSON is embedded in the existing per-connection snapshots. The
// fields are observational only; changing the scheduler does not change the
// TLSVPN wire format.
type schedulerConnJSON struct {
	QueuedBytes        uint64  `json:"queued_bytes"`
	RateMbps           float64 `json:"rate_mbps"`
	ETAUs              uint64  `json:"eta_us"`
	Active             bool    `json:"active"`
	CarryPending       bool    `json:"carry_pending"`
	AssignedBytes      uint64  `json:"assigned_bytes"`
	AssignedBatches    uint64  `json:"assigned_batches"`
	FECAssignedBytes   uint64  `json:"fec_assigned_bytes"`
	FECAssignedBatches uint64  `json:"fec_assigned_batches"`
	// FwdOneWayUS / RetOneWayUS 跨路径探针测得的去程/回程单向时延（µs，地板）。
	// 0=未收敛（WebUI 回退显示 RTT）。仅观测，不在 TLSVPN 线上。
	FwdOneWayUS uint64 `json:"fwd_oneway_us,omitempty"`
	RetOneWayUS uint64 `json:"ret_oneway_us,omitempty"`
	// MinRttUS 该连接的内核 min_rtt 地板（µs）；0=未知。与 fwd/ret 同列供
	// WebUI 参考。仅观测，不在 TLSVPN 线上。
	MinRttUS uint64 `json:"min_rtt_us,omitempty"`
	// ProbeAtMs 最近一次发布 fwd/ret 的 unix 毫秒；0=尚未收敛。面板据此显示
	// "上次计算时间"。仅观测，不在 TLSVPN 线上。
	ProbeAtMs uint64 `json:"probe_at_ms,omitempty"`
	// ClockOffsetNS 双向时钟偏移探针解出的时钟偏移 θ（ns，客户端视角相对服务端）。
	// 非零表示 θ 已收敛，去/回程不对称度已被解出（fwd+ret=RTT 严格自洽）；
	// 0=未收敛（仍走锚定法 + δ）。仅观测，不在 TLSVPN 线上。
	ClockOffsetNS int64 `json:"clock_offset_ns,omitempty"`
	// ClockOffsetUncUS θ 的残余不确定度（µs）。越大表示两端时钟/路径抖动越大，
	// 0=尚未收敛。仅观测，不在 TLSVPN 线上。
	ClockOffsetUncUS uint64 `json:"clock_offset_unc_us,omitempty"`
	// ClockOffsetConverged θ 是否可信（样本充分且不确定度在阈内）。面板据此
	// 显示"虚拟时钟已同步"状态。仅观测，不在 TLSVPN 线上。
	ClockOffsetConverged bool `json:"clock_offset_converged,omitempty"`
}

func vpnFrameBatchBytes(batch []VPNFrame) uint64 {
	var n uint64
	for i := range batch {
		n += uint64(len(batch[i].Data))
	}
	return n
}

func atomicSubSaturating(v atomicUint64Compat, n uint64) {
	// Kept behind a tiny interface adapter below so tests can exercise the same
	// saturating accounting without ever allowing uint64 underflow to turn a
	// transient disconnect into an absurd multi-exabyte queue.
	for {
		old := v.Load()
		if old == 0 {
			return
		}
		var next uint64
		if n < old {
			next = old - n
		}
		if v.CompareAndSwap(old, next) {
			return
		}
	}
}

// atomicUint64Compat is satisfied by sync/atomic.Uint64. Using an interface here
// keeps the subtraction helper small and makes the underflow behaviour explicit.
type atomicUint64Compat interface {
	Load() uint64
	CompareAndSwap(old, new uint64) bool
}

func (b *Backend) addQueuedBytes(n uint64) {
	if b != nil && n != 0 {
		b.queuedBytes.Add(n)
	}
}

func (b *Backend) completeQueuedBytes(n uint64) {
	if b == nil || n == 0 {
		return
	}
	atomicSubSaturating(&b.queuedBytes, n)
}

// observeDelivered updates a cheap per-path payload-rate EWMA. It is called by
// that backend's sole TLS writer goroutine, so sampleBytes/sampleStart require no
// lock or atomics; only the published EWMA is atomic for the AsyncPort reader.

func (b *Backend) addVirtualServiceAtRate(incomingBytes, rate uint64) {
	if b == nil || incomingBytes == 0 {
		return
	}
	b.virtualFinishNS.Add(serviceTimeNS(incomingBytes, rate))
}

func logicalDispatchScoreNS(b *Backend, rate uint64) int64 {
	if b == nil {
		return int64(^uint64(0) >> 1)
	}
	// virtualFinishNS is a scheduler-local logical service debt, not a timestamp.
	// Use the same fair-start rate as the virtual charge: a newly activated path
	// must get enough traffic to measure itself instead of being permanently
	// penalized by the conservative 200 Mbps generic fallback.
	score := b.virtualFinishNS.Load() + serviceTimeNS(b.queuedBytes.Load(), rate)
	if b.carryPending.Load() {
		score -= int64(adaptiveCarryBonusUS) * 1_000
	}
	return score
}

func schedulerSnapshot(b *Backend) schedulerConnJSON {
	if b == nil {
		return schedulerConnJSON{}
	}
	rate := b.rateBytesPerSec.Load()
	// min_rtt 未知时 adaptiveBackendMinRTT 返回 50000 哨兵，不可当作真实值
	// 暴露；只在上报明确已知时填充，否则省略（omitempty）。
	var minRTT uint64
	if mr, unknown := adaptiveBackendMinRTT(b); !unknown {
		minRTT = uint64(mr)
	}
	snap := schedulerConnJSON{
		QueuedBytes:        b.queuedBytes.Load(),
		RateMbps:           float64(rate) * 8 / 1_000_000,
		ETAUs:              b.etaUsec.Load(),
		Active:             b.active.Load(),
		CarryPending:       b.carryPending.Load(),
		AssignedBytes:      b.assignedBytes.Load(),
		AssignedBatches:    b.assignedBatches.Load(),
		FECAssignedBytes:   b.fecAssignedBytes.Load(),
		FECAssignedBatches: b.fecAssignedBatches.Load(),
		FwdOneWayUS:        b.fwdOneWayUS.Load(),
		RetOneWayUS:        b.retOneWayUS.Load(),
		MinRttUS:           minRTT,
		ProbeAtMs:          b.probeUpdatedAt.Load(),
	}
	// 时钟偏移 θ/U：仅当注入且已收敛时暴露，面板据此显示"虚拟时钟已同步"。
	if b.clockOffsetTheta != nil {
		if th, unc, ok := b.clockOffsetTheta(); ok {
			snap.ClockOffsetNS = th
			snap.ClockOffsetUncUS = unc
			snap.ClockOffsetConverged = true
		}
	}
	return snap
}

func (p *AsyncPort) noteInputQueued(n int) {
	if p != nil && n > 0 {
		p.inputQueuedBytes.Add(uint64(n))
	}
}

func (p *AsyncPort) noteInputDequeued(n int) {
	if p == nil || n <= 0 {
		return
	}
	atomicSubSaturating(&p.inputQueuedBytes, uint64(n))
}

// observeInputDemand publishes an EWMA of payload arrival rate. Sampling lives
// on AsyncPort.run, so the hot TAP producer only increments inputTotalBytes.
// After a long idle interval the first new sample replaces (rather than blends
// with) the old bulk rate, allowing the active set to collapse immediately.
func (p *AsyncPort) observeInputDemand() (uint64, bool) {
	if p == nil {
		return 0, false
	}
	now := time.Now()
	total := p.inputTotalBytes.Load()
	if p.demandSampleAt.IsZero() {
		p.demandSampleAt = now
		p.demandSampleTotal = total
		return p.inputRateBytesPerSec.Load(), false
	}
	elapsed := now.Sub(p.demandSampleAt)
	if elapsed < adaptiveDemandSampleMinInterval {
		return p.inputRateBytesPerSec.Load(), false
	}
	delta := total - p.demandSampleTotal
	inst := uint64(0)
	if elapsed > 0 {
		inst = uint64(float64(delta) / elapsed.Seconds())
	}
	old := p.inputRateBytesPerSec.Load()
	if old == 0 || elapsed > 250*time.Millisecond {
		p.inputRateBytesPerSec.Store(inst)
	} else {
		// Demand should react faster than per-path capacity: 1/4 new, 3/4 old.
		p.inputRateBytesPerSec.Store((old*3 + inst) / 4)
	}
	p.demandSampleAt = now
	p.demandSampleTotal = total
	return p.inputRateBytesPerSec.Load(), true
}

func adaptiveActivePathTarget(pressure, demandRate uint64, eligible int) int {
	if eligible <= 0 {
		return 0
	}
	want := 1
	switch {
	case pressure >= adaptiveActive4Pressure || demandRate >= adaptiveActive4RateBytesPerSec:
		want = 4
	case pressure >= adaptiveActive3Pressure || demandRate >= adaptiveActive3RateBytesPerSec:
		want = 3
	case pressure >= adaptiveActive2Pressure || demandRate >= adaptiveActive2RateBytesPerSec:
		want = 2
	}
	if want > eligible {
		want = eligible
	}
	return want
}

func (p *AsyncPort) schedulerPressureFor(backends []*Backend, currentBatchBytes uint64) uint64 {
	if p != nil {
		if _, resampled := p.observeInputDemand(); resampled {
			// ETA 遥测与需求采样同频（≥500µs 一次，随负载自适应）：全后端
			// etaUsec 刷新从"每批 × 每后端 ~5 次原子 RMW"降到采样节奏（高
			// 负载 ~2000 次/s，低负载本来就不贵）。热数据不受影响——当批
			// 资格后端仍由 buildEligibleCandidates 每批 Store 最新 ETA。
			p.publishBaselineETA(backends, currentBatchBytes)
		}
		pressure := currentBatchBytes
		if p != nil {
			pressure += p.inputQueuedBytes.Load()
		}
		for _, b := range backends {
			if b != nil {
				pressure += b.queuedBytes.Load()
			}
		}
		if p != nil {
			p.schedulerPressure.Store(pressure)
		}
		return pressure
	}
	return currentBatchBytes
}

func adaptiveStickySlackUS(rtt uint32) uint64 {
	slack := uint64(rtt / 16)
	if slack < adaptiveStickyMinUS {
		slack = adaptiveStickyMinUS
	}
	if slack > adaptiveStickyMaxUS {
		slack = adaptiveStickyMaxUS
	}
	return slack
}

// pickAdaptiveBackend chooses the path with the earliest predicted delivery,
// not simply the lowest RTT. The active set grows from 1 -> 4 only when real
// byte pressure justifies it. Paths with measured RTT outside the near-MinRTT
// envelope remain excluded to bound receive-side reordering. A path remains in
// fair-start until it has both a usable RTT and a delivery-rate sample; this
// prevents an early/delayed TCP_INFO sample from starving a cold socket before
// it has carried the >=64 KiB needed to measure its own writer delivery rate.
// pickAdaptiveBackend 选路编排：按当前 routingPolicy 依次执行资格扫描、候选构建、
// 排名与派发。策略每批读取（热更即生效）。各阶段拆分到命名 helper，语义与历史
// 行为一致（仅结构重组）。
func (p *AsyncPort) pickAdaptiveBackend(backends []*Backend, pressure, incomingBytes uint64) *Backend {
	policy := routingPolicyForCode(p.routingAlgo.Load())
	p.feedEncoderPathCount(len(backends))
	if len(backends) == 0 {
		p.activePaths.Store(0)
		return nil
	}
	// 单后端快路径：跳过三遍全量扫描/ETA/排名（每批 ~30 次原子 RMW）。成员
	// 维护语义与全量管线一致——stalled/队满走 fallbackSinglePath（与管线
	// healthy==0 分支相同），健康路径 replicate commitSinglePath 的提交动作。
	if len(backends) == 1 {
		b := backends[0]
		if b == nil || b.queueCap() == 0 || b.queueLen() >= b.queueCap()-2 || b.isStalled() {
			return p.fallbackSinglePath(backends)
		}
		b.active.Store(true)
		b.virtualFinishNS.Store(0)
		p.activePaths.Store(1)
		p.storePreferredIfCurrent(b)
		return b
	}
	current := p.preferred.Load()

	minRTT, maxRTT, referenceRate, healthy := scanEnvelope(backends)
	if healthy == 0 {
		return p.fallbackSinglePath(backends)
	}
	cands := p.buildEligibleCandidates(policy, backends, incomingBytes, minRTT, maxRTT, referenceRate)
	p.schedulerScratch = cands
	if len(cands) == 0 {
		// 全部后端被并发排除（唯一健康者在扫描间隙被 markStalled）：pickBackend
		// 只维护 preferred，这里补齐成员维护——否则 active 集残留旧值、
		// activePaths 计数失真（面板/测试可见）。
		chosen := p.pickBackend(backends)
		for _, b := range backends {
			if b != nil {
				b.active.Store(b == chosen)
				b.virtualFinishNS.Store(0)
			}
		}
		p.activePaths.Store(1)
		return chosen
	}
	rankCandidates(cands)

	active := adaptiveActivePathTarget(pressure, p.inputRateBytesPerSec.Load(), len(cands))
	bestBase := cands[0].baseUS
	if !policy.wfq || active == 1 {
		return p.commitSinglePath(backends, cands, current, bestBase, policy)
	}
	return p.dispatchWFQ(backends, cands, active, incomingBytes)
}

// feedEncoderPathCount 把物理后端数喂给 FEC 编码器（非活跃数：低负载调度刻意
// 保持 activePaths==1 而待命 TCP 路径仍可承载有用 parity）。
func (p *AsyncPort) feedEncoderPathCount(n int) {
	if p != nil && p.encoder != nil {
		p.encoder.setPhysicalPathCount(n)
	}
}

// publishBaselineETA 为所有后端发布保守 ETA 遥测（含当前拥塞的 SRTT 估计）。
// 调用方负责节流：此函数每跑一遍要对所有后端各做 ~5 次原子 RMW，每批调用
// 是多路径高 PPS 下的主要每批固定开销之一（见 schedulerPressureFor）。
func (p *AsyncPort) publishBaselineETA(backends []*Backend, incomingBytes uint64) {
	for _, b := range backends {
		if b != nil {
			b.etaUsec.Store(b.estimatedETAUS(incomingBytes))
		}
	}
}

// scanEnvelope 单遍合并原 scanWarmedMinRTT + buildEnvelope：健康计数、热身
// 最小 RTT、资格包络与参考速率。原先两遍各自重复加载同一批原子（每后端
// minRTT/rate/cold 各算两次），高 PPS 下是每批的主要固定开销之一。语义逐
// 字段保留：healthy 只计未阻塞路径；minWarmed 只计有 RTT 且完成热身的健康
// 路径（否则测量顺序可能永久压缩候选集）；referenceRate 只计包络内（或
// fairStart）路径；包络排除明显偏离的路径以限界接收端乱序。
func scanEnvelope(backends []*Backend) (minRTT uint32, maxRTT uint64, referenceRate uint64, healthy int) {
	minWarmed := ^uint32(0)
	for _, b := range backends {
		if b == nil || b.queueCap() == 0 || b.queueLen() >= b.queueCap()-2 || b.isStalled() {
			continue
		}
		healthy++
		rtt, unknownRTT := adaptiveBackendMinRTT(b)
		cold := b.rateBytesPerSec.Load() == 0
		if !unknownRTT && !cold && rtt < minWarmed {
			minWarmed = rtt
		}
	}
	minRTT = minWarmed
	if minRTT == ^uint32(0) {
		minRTT = adaptiveUnknownRTTUS
	}
	rttSlack := max(uint32(backendRTTHysteresisMin), minRTT/4)
	maxRTT = uint64(minRTT) + uint64(rttSlack)
	referenceRate = uint64(adaptiveFallbackRateBytesPerSec)
	for _, b := range backends {
		// 与第一遍对齐：stalled/队满路径的 rate 不参与参考速率（仅冷路径 ETA
		// 回退用），死路径不应抬高它。
		if b == nil || b.queueCap() == 0 || b.queueLen() >= b.queueCap()-2 || b.isStalled() {
			continue
		}
		rtt, unknownRTT := adaptiveBackendMinRTT(b)
		cold := b.rateBytesPerSec.Load() == 0
		fairStart := unknownRTT || cold
		if fairStart {
			// Candidate ordering uses the best warmed RTT only during bootstrap.
			rtt = minRTT
		}
		if !fairStart && uint64(rtt) > maxRTT {
			continue
		}
		if rate := b.rateBytesPerSec.Load(); rate > referenceRate {
			referenceRate = rate
		}
	}
	return minRTT, maxRTT, referenceRate, healthy
}

// fallbackSinglePath 无健康路径时退化为首条后端，重置活跃/债务状态。
func (p *AsyncPort) fallbackSinglePath(backends []*Backend) *Backend {
	// 与 pickBackend 的兜底一致：优先未 stalled 的后端——4 连接断 3 条时若盲取
	// backends[0]（恰是死路径），数据会先进死通道黑洞（writer 已退、残留未满），
	// 拥塞下可持续多个 RTT；全部 stalled 时才取第一条兜底。
	b := backends[0]
	for _, x := range backends {
		if x != nil && !x.isStalled() {
			b = x
			break
		}
	}
	if b != nil {
		for _, x := range backends {
			if x != nil {
				x.active.Store(x == b)
				x.virtualFinishNS.Store(0)
			}
		}
		p.activePaths.Store(1)
		p.storePreferredIfCurrent(b)
	}
	return b
}

// buildEligibleCandidates 构建候选集：资格包络 + stall/队满排除，按策略算主排名键。
func (p *AsyncPort) buildEligibleCandidates(policy routingPolicy, backends []*Backend, incomingBytes uint64, minRTT uint32, maxRTT uint64, referenceRate uint64) []backendCandidate {
	cands := p.schedulerScratch[:0]
	for _, b := range backends {
		if b == nil || b.queueCap() == 0 || b.queueLen() >= b.queueCap()-2 || b.isStalled() {
			if b != nil {
				b.active.Store(false)
				b.virtualFinishNS.Store(0)
			}
			continue
		}
		// SRTT 用于 ETA 遥测（含当前拥塞，预测更准）；min_rtt 用于资格包络与
		// 候选排序（无拥塞地板，成员稳定）。
		srt, _ := adaptiveBackendRTT(b)
		rtt, unknownRTT := adaptiveBackendMinRTT(b)
		cold := b.rateBytesPerSec.Load() == 0
		fairStart := unknownRTT || cold
		if fairStart {
			rtt = minRTT
		}
		if !fairStart && uint64(rtt) > maxRTT {
			// 冷路径完成热身却真正落在包络外：清掉过期成员。
			b.active.Store(false)
			b.virtualFinishNS.Store(0)
			continue
		}
		// Writer-drain EWMA 只作观测 ETA，不代表端到端 TCP 投递能力。
		etaRate := b.rateBytesPerSec.Load()
		if etaRate == 0 {
			etaRate = referenceRate
		}
		eta := uint64(srt)/2 + serviceTimeUS(b.queuedBytes.Load()+incomingBytes, etaRate)
		if b.carryPending.Load() && eta > adaptiveCarryBonusUS {
			eta -= adaptiveCarryBonusUS
		}
		b.etaUsec.Store(eta)
		// 调度债务刻意字节公平：统一固定速率把虚拟服务时间变成字节计数器。
		schedRate := uint64(adaptiveFallbackRateBytesPerSec)
		// 主排名键按当前算法计算（candidateRankUS）；完全未测路径折到 minRTT/2。
		// oneWay 为有符号原始相对量（探针已收敛时，负值=快于 ref 基准），显示层
		// 的 δ 抬升不参与选路——回退候选不带 δ，混排时不抵消会扭曲排名。
		oneWay := adaptiveBackendOneWayUS(b)
		if _, ok := b.backendOneWayUS(); !ok {
			if _, mrUnknown := adaptiveBackendMinRTT(b); mrUnknown {
				if _, srttUnknown := adaptiveBackendRTT(b); srttUnknown {
					oneWay = int64(minRTT) / 2
				}
			}
		}
		cands = append(cands, backendCandidate{
			backend:   b,
			baseUS:    candidateRankUS(policy, oneWay, rtt, srt, incomingBytes, schedRate),
			rttUS:     rtt,
			schedRate: schedRate,
			wasActive: b.active.Load(),
			virtualNS: b.virtualFinishNS.Load(),
		})
	}
	return cands
}

// rankCandidates 按主排名键稳定排序（rttUS 平局裁决）。
func rankCandidates(cands []backendCandidate) {
	for i := 1; i < len(cands); i++ {
		x := cands[i]
		j := i
		// 平局裁决：baseUS 相同（rankMinRTTHalf 下 fairStart 冷路径与最优热路径
		// 恒并列）时先比 rttUS，再比 wasActive——热路径优先，消除"冷路径靠注册
		// 顺序抢槽"的顺序巧合。
		for j > 0 && (x.baseUS < cands[j-1].baseUS ||
			(x.baseUS == cands[j-1].baseUS && x.rttUS < cands[j-1].rttUS) ||
			(x.baseUS == cands[j-1].baseUS && x.rttUS == cands[j-1].rttUS && x.wasActive && !cands[j-1].wasActive)) {
			cands[j] = cands[j-1]
			j--
		}
		cands[j] = x
	}
}

// commitSinglePath 单活跃路径提交：严格模式直接取 rank[0]；sticky 模式在粘滞带内
// 保留当前路径；其余路径清为待命并重置公平债务。
func (p *AsyncPort) commitSinglePath(backends []*Backend, cands []backendCandidate, current *Backend, bestBase int64, policy routingPolicy) *Backend {
	chosen := cands[0].backend
	if policy.sticky && current != nil && current != chosen {
		for i := range cands {
			if cands[i].backend != current {
				continue
			}
			if cands[i].baseUS <= bestBase+int64(adaptiveStickySlackUS(cands[i].rttUS)) {
				chosen = current
			}
			break
		}
	}
	// 单路径交互模式无公平债务：清空以便后续扩张从同一虚拟纪元起步。
	for _, b := range backends {
		if b != nil {
			b.active.Store(b == chosen)
			b.virtualFinishNS.Store(0)
		}
	}
	p.activePaths.Store(1)
	p.storePreferredIfCurrent(chosen)
	return chosen
}

// dispatchWFQ 活跃集内按虚拟服务债务（WFQ/stride）分摊：债务不随墙钟衰减，
// 快速写者清空浅队列后仍会把连续批次条带化到不同活跃路径。
func (p *AsyncPort) dispatchWFQ(backends []*Backend, cands []backendCandidate, active int, incomingBytes uint64) *Backend {
	var epoch int64
	haveEpoch := false
	for i := 0; i < active; i++ {
		if cands[i].wasActive {
			v := cands[i].virtualNS
			if !haveEpoch || v < epoch {
				epoch = v
				haveEpoch = true
			}
		}
	}
	if !haveEpoch {
		epoch = 0
	}
	for i := range cands {
		b := cands[i].backend
		if i >= active {
			b.active.Store(false)
			b.virtualFinishNS.Store(0)
			continue
		}
		if !cands[i].wasActive {
			b.virtualFinishNS.Store(epoch)
			cands[i].virtualNS = epoch
		}
		b.active.Store(true)
	}

	// 每次派发重定基：只相对服务债务有意义，最小值归零防计数器无限增长。
	minVirtual := cands[0].backend.virtualFinishNS.Load()
	for i := 1; i < active; i++ {
		if v := cands[i].backend.virtualFinishNS.Load(); v < minVirtual {
			minVirtual = v
		}
	}
	if minVirtual != 0 {
		for i := 0; i < active; i++ {
			b := cands[i].backend
			b.virtualFinishNS.Add(-minVirtual)
		}
	}

	chosen := cands[0]
	chosenScore := logicalDispatchScoreNS(chosen.backend, chosen.schedRate)
	for i := 1; i < active; i++ {
		score := logicalDispatchScoreNS(cands[i].backend, cands[i].schedRate)
		if score < chosenScore || (score == chosenScore && cands[i].rttUS < chosen.rttUS) {
			chosen = cands[i]
			chosenScore = score
		}
	}
	chosen.backend.addVirtualServiceAtRate(incomingBytes, chosen.schedRate)
	p.activePaths.Store(int32(active))
	p.storePreferredIfCurrent(chosen.backend)
	return chosen.backend
}
