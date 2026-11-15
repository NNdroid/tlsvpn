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
	baseUS    uint64 // unloaded path quality: RTT/2 + this batch service time
	etaUS     uint64 // observational queued completion estimate for WebUI
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
	return schedulerConnJSON{
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
func (p *AsyncPort) observeInputDemand() uint64 {
	if p == nil {
		return 0
	}
	now := time.Now()
	total := p.inputTotalBytes.Load()
	if p.demandSampleAt.IsZero() {
		p.demandSampleAt = now
		p.demandSampleTotal = total
		return p.inputRateBytesPerSec.Load()
	}
	elapsed := now.Sub(p.demandSampleAt)
	if elapsed < adaptiveDemandSampleMinInterval {
		return p.inputRateBytesPerSec.Load()
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
	return p.inputRateBytesPerSec.Load()
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
		p.observeInputDemand()
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
	current := p.preferred.Load()
	p.publishBaselineETA(backends, incomingBytes)

	minMeasuredRTT, healthy := scanWarmedMinRTT(backends)
	if healthy == 0 {
		return p.fallbackSinglePath(backends)
	}
	minRTT, maxRTT, referenceRate := buildEnvelope(backends, minMeasuredRTT)
	cands := p.buildEligibleCandidates(policy, backends, incomingBytes, minRTT, maxRTT, referenceRate)
	p.schedulerScratch = cands
	if len(cands) == 0 {
		return p.pickBackend(backends)
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
func (p *AsyncPort) publishBaselineETA(backends []*Backend, incomingBytes uint64) {
	for _, b := range backends {
		if b != nil {
			b.etaUsec.Store(b.estimatedETAUS(incomingBytes))
		}
	}
}

// scanWarmedMinRTT 只从完全"热身"路径构建 RTT 参考：有 RTT 采样且已承载足够
// egress 载荷（rateBytesPerSec!=0）才计入，否则测量顺序可能永久压缩候选集。
func scanWarmedMinRTT(backends []*Backend) (minMeasuredRTT uint32, healthy int) {
	minMeasuredRTT = ^uint32(0)
	for _, b := range backends {
		if b == nil || b.queueCap() == 0 || b.queueLen() >= b.queueCap()-2 || b.isStalled() {
			continue
		}
		healthy++
		rtt, unknownRTT := adaptiveBackendMinRTT(b)
		cold := b.rateBytesPerSec.Load() == 0
		if unknownRTT || cold {
			continue
		}
		if rtt < minMeasuredRTT {
			minMeasuredRTT = rtt
		}
	}
	return minMeasuredRTT, healthy
}

// fallbackSinglePath 无健康路径时退化为首条后端，重置活跃/债务状态。
func (p *AsyncPort) fallbackSinglePath(backends []*Backend) *Backend {
	b := backends[0]
	if b != nil {
		for _, x := range backends {
			if x != nil {
				x.active.Store(x == b)
				x.virtualFinishNS.Store(0)
			}
		}
		p.activePaths.Store(1)
		p.preferred.Store(b)
	}
	return b
}

// buildEnvelope 计算近 MinRTT 资格包络（maxRTT）与参考速率。min_rtt 是无拥塞
// 地板，包络用它排除明显偏离的路径以限界接收端乱序。
func buildEnvelope(backends []*Backend, minMeasuredRTT uint32) (minRTT uint32, maxRTT uint64, referenceRate uint64) {
	minRTT = minMeasuredRTT
	if minRTT == ^uint32(0) {
		minRTT = adaptiveUnknownRTTUS
	}
	rttSlack := max(uint32(backendRTTHysteresisMin), minRTT/4)
	maxRTT = uint64(minRTT) + uint64(rttSlack)
	referenceRate = uint64(adaptiveFallbackRateBytesPerSec)
	for _, b := range backends {
		if b == nil {
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
	return minRTT, maxRTT, referenceRate
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
		oneWay := adaptiveBackendOneWayUS(b)
		if _, ok := b.backendOneWayUS(); !ok {
			if _, mrUnknown := adaptiveBackendMinRTT(b); mrUnknown {
				if _, srttUnknown := adaptiveBackendRTT(b); srttUnknown {
					oneWay = uint64(minRTT) / 2
				}
			}
		}
		cands = append(cands, backendCandidate{
			backend:   b,
			baseUS:    candidateRankUS(policy, oneWay, rtt, srt, incomingBytes, schedRate),
			etaUS:     eta,
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
		for j > 0 && (x.baseUS < cands[j-1].baseUS || (x.baseUS == cands[j-1].baseUS && x.rttUS < cands[j-1].rttUS)) {
			cands[j] = cands[j-1]
			j--
		}
		cands[j] = x
	}
}

// commitSinglePath 单活跃路径提交：严格模式直接取 rank[0]；sticky 模式在粘滞带内
// 保留当前路径；其余路径清为待命并重置公平债务。
func (p *AsyncPort) commitSinglePath(backends []*Backend, cands []backendCandidate, current *Backend, bestBase uint64, policy routingPolicy) *Backend {
	chosen := cands[0].backend
	if policy.sticky && current != nil && current != chosen {
		for i := range cands {
			if cands[i].backend != current {
				continue
			}
			if cands[i].baseUS <= bestBase+adaptiveStickySlackUS(cands[i].rttUS) {
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
	p.preferred.Store(chosen)
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
	p.preferred.Store(chosen.backend)
	return chosen.backend
}
