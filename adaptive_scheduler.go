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

// schedFlag* 是 Backend.schedFlags 的位布局。bit-pack 而非逐字段 atomic：
// buildEligibleCandidates 每批每后端只做 1 次 Store（该循环已有 etaUsec/active/
// virtualFinishNS 三次 Store），面板要的却是四项不同信息。
const (
	schedFlagNearIn      uint32 = 1 << 0 // parity near 窗口内（真实判定）
	schedFlagNearLenient uint32 = 1 << 1 // 探针未收敛的 bootstrap 宽限（宽松放行）
	schedFlagStickyHeld  uint32 = 1 << 2 // 本批因粘滞滞回保留了当前路径
	schedFlagRankKnown   uint32 = 1 << 3 // rankKeyUS 已发布（0 是合法排名值，需门控）
	schedFlagExcludeMask uint32 = 7 << 4 // 排除原因，见 schedExclude*
)

// schedExclude* 排除原因（schedFlagExcludeMask 内编码）。0 = 无排除（候选内）。
// 分列而不是笼统的 eligible=false：面板要回答的是"为什么没选它"。
const (
	schedExcludeNone        uint32 = 0 << 4
	schedExcludeStalled     uint32 = 1 << 4
	schedExcludeQueueFull   uint32 = 2 << 4
	schedExcludeCapZero     uint32 = 3 << 4
	schedExcludeEnvelopeOut uint32 = 4 << 4
)

// schedReason* 是选路管线各返回分支的决策原因。用稳定字符串而非数字码：
// 前端直接映射到 i18n 键 sched.reason.<token>，避免两套编号漂移。
const (
	schedReasonRank0         = "rank0"          // 单路径模式取 rank[0]
	schedReasonStickyHeld    = "sticky_held"    // 粘滞带内保留当前路径
	schedReasonWFQDispatch   = "wfq_dispatch"   // 活跃集内按 WFQ 服务债务分发
	schedReasonEnvelopeEmpty = "envelope_empty" // 候选集被资格门清空，退化到 pickBackend
	schedReasonNoHealthy     = "no_healthy"     // 无健康后端，退化到首条后端
	schedReasonSinglePath    = "single_path"    // 单后端快路径
)

// schedDecisionEntry 是选路决策环的一条记录。
type schedDecisionEntry struct {
	Reason string `json:"reason"`
	Path   int    `json:"path"` // 所选后端的 backends 下标；-1 = 未选出
	AtMs   uint64 `json:"at_ms"`
	Active int32  `json:"active"` // 本批活跃路径数
}

// schedDecisionRingCap 决策环容量。只记"相对末条发生变化"的决策，故 16 条足够
// 覆盖人类可读的切换历史；固定容量保证内存不随运行时长线性增长。
const schedDecisionRingCap = 16

// recordSchedDecision 追加一条选路决策。run goroutine 独占调用。
// 与末条同原因同路径时不追加——否则高 PPS 下 16 条会被瞬间轮空。
func (p *AsyncPort) recordSchedDecision(reason string, path int, active int32) {
	if p == nil {
		return
	}
	e := schedDecisionEntry{
		Reason: reason,
		Path:   path,
		AtMs:   uint64(time.Now().UnixMilli()),
		Active: active,
	}
	if e.Reason == p.decisionLast.Reason && e.Path == p.decisionLast.Path {
		return
	}
	p.decisionMu.Lock()
	p.decisionRing = append(p.decisionRing, e)
	if len(p.decisionRing) > schedDecisionRingCap {
		p.decisionRing = append(p.decisionRing[:0], p.decisionRing[len(p.decisionRing)-schedDecisionRingCap:]...)
	}
	p.decisionMu.Unlock()
	p.decisionLast = e
}

// recordChoice recordSchedDecision 的便捷包装：把所选后端解析为 backends 下标，
// 使面板能把决策映射回连接表里的某一行。
func (p *AsyncPort) recordChoice(backends []*Backend, chosen *Backend, reason string, active int32) {
	idx := -1
	for i, b := range backends {
		if b == chosen {
			idx = i
			break
		}
	}
	p.recordSchedDecision(reason, idx, active)
}

// schedDecisionSnapshot 返回决策环的只读副本（API goroutine 读）。
func (p *AsyncPort) schedDecisionSnapshot() []schedDecisionEntry {
	if p == nil {
		return nil
	}
	p.decisionMu.Lock()
	defer p.decisionMu.Unlock()
	if len(p.decisionRing) == 0 {
		return nil
	}
	out := make([]schedDecisionEntry, len(p.decisionRing))
	copy(out, p.decisionRing)
	return out
}

// schedFlagsSet 置位/清位 schedFlags 的 mask 内各 bit（其余 bit 保留）。
//
// 两个写者（buildEligibleCandidates 写排除/排名 bit、pickParityBackend 写 near
// bit）都在 run goroutine 内串行执行，故 Load-Store 的 RMW 无竞态；用原子而非
// 普通字段是因为 schedulerSnapshot 在 API goroutine 读它。
func (b *Backend) schedFlagsSet(mask, v uint32) {
	if b == nil {
		return
	}
	b.schedFlags.Store((b.schedFlags.Load() &^ mask) | (v & mask))
}

// publishExcluded 把一条被资格门排除的路径的观测状态写回该 Backend。
// 与 buildEligibleCandidates 内"进入候选集"的发布点构成同一套不变量：每批每后端
// 恰好写一次排除原因或一次候选内标志。
func (p *AsyncPort) publishExcluded(b *Backend, reason uint32, minRTT uint32, maxRTT uint64, fwdFloor int64, fwdFloorOK bool) {
	if b == nil {
		return
	}
	b.active.Store(false)
	b.virtualFinishNS.Store(0)
	if minRTT != adaptiveUnknownRTTUS {
		b.schedEnvMinRttUS.Store(uint64(minRTT))
		b.schedEnvMaxRttUS.Store(maxRTT)
	}
	p.publishEnvelopeFloor(b, fwdFloor, fwdFloorOK)
	// 未进入候选集即无排名键：清 RankKnown 并把键归零，面板显示"-"而非伪 0。
	b.rankKeyUS.Store(0)
	// 被排除的路径同样清粘滞位，否则上一批的 sticky_held 会跨批残留。
	b.schedFlagsSet(schedFlagExcludeMask|schedFlagRankKnown|schedFlagStickyHeld, reason)
}

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
	// Eligible 该路径是否落在本批资格包络内（true=进入候选集参与排名）。
	// false 表示被 buildEligibleCandidates 排除，ExcludeReason 给出原因。
	// 面板据此把"去程最快却待命"解释成包络外，而不是选路 bug。
	Eligible bool `json:"eligible"`
	// ExcludeReason 排除原因（stalled/queue_full/cap_zero/envelope_out）。
	// 候选内或尚未评估时为空串。
	ExcludeReason string `json:"exclude_reason,omitempty"`
	// RankKnown / RankKeyUS 本批实际用于排名的排名键（µs，有符号）。与显示层
	// 的 fwd_oneway_us 是两条互不污染的数（后者带 δ 抬升），并置展示才能看出
	// "调度依据"和"面板读数"的差别。
	RankKnown bool  `json:"rank_known,omitempty"`
	RankKeyUS int64 `json:"rank_key_us,omitempty"`
	// GroupMinRttUS / GroupMaxRttUS 本批资格包络的组内 min_rtt 地板与上限（µs）。
	// 组约简结果，前端无法自行推算（cold/unknownRTT 豁免状态不在 JSON 里）。
	// 0=包络尚未建立。
	GroupMinRttUS uint64 `json:"group_min_rtt_us,omitempty"`
	GroupMaxRttUS uint64 `json:"group_max_rtt_us,omitempty"`
	// GroupFwdFloorUS 本批 fwd 门的组内去程地板（µs，有符号相对量）。仅
	// sched_envelope=fwd 时有值；面板据此显示"去程地板"，并把落在地板+窗口之外
	// 的路径解释成包络外。0=尚未建立。与 GroupMinRttUS 是两条独立的门，不同时
	// 都生效——前端应按端口级 envelope_mode 选择展示哪一组。
	GroupFwdFloorUS int64 `json:"group_fwd_floor_us,omitempty"`
	// FwdRankKnown / FwdRankUS 本路径已收敛的去程读数（µs，有符号相对量），与
	// GroupFwdFloorUS 同一尺度，供 fwd 门的排除比较式使用。刻意区别于显示层的
	// fwd_oneway_us（后者带 δ 抬升非负）。未收敛时两者都缺省，前端不显示比较式。
	FwdRankKnown bool  `json:"fwd_rank_known,omitempty"`
	FwdRankUS    int64 `json:"fwd_rank_us,omitempty"`
	// NearState parity near 窗口成员资格："in"=窗口内、"lenient"=探针未收敛的
	// bootstrap 宽限放行；窗口外不发布（字段 omitempty 缺省），不会拿 parity。
	// 仅 near 策略有意义。
	NearState string `json:"near_state,omitempty"`
	// StickyHeld 本批是否因粘滞滞回保留了当前路径（而非取 rank[0]）。
	StickyHeld bool `json:"sticky_held,omitempty"`
	// PeerActive 对端调度器当前选中本槽位（0x07 active-paths 位图，2s 窗口内
	// 收到过声明）。与 Active（本端选中）并列：面板据此把"两端各自选了谁"
	// 同时呈现。由连接快照组装层填充（数据在 connInfo 而非 Backend）。
	PeerActive bool `json:"peer_active,omitempty"`
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
	// schedFlags 一次 Load 按位拆分 RankKnown/StickyHeld/排除原因/NearState：
	// 分多次 Load 会在 run goroutine 并发 RMW 时让面板读到自相矛盾的组合
	// （如 RankKnown=true 却同时 exclude_reason=envelope_out）。
	flags := b.schedFlags.Load()
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
		GroupMinRttUS:      b.schedEnvMinRttUS.Load(),
		GroupMaxRttUS:      b.schedEnvMaxRttUS.Load(),
		GroupFwdFloorUS:    b.schedEnvFwdFloorUS.Load(),
		RankKnown:          flags&schedFlagRankKnown != 0,
		RankKeyUS:          b.rankKeyUS.Load(),
		StickyHeld:         flags&schedFlagStickyHeld != 0,
	}
	// 排除原因优先于"候选内"呈现：被排除时 Eligible 必为 false，面板据此换徽章。
	reason := flags & schedFlagExcludeMask
	switch {
	case reason == schedExcludeStalled:
		snap.ExcludeReason = "stalled"
	case reason == schedExcludeQueueFull:
		snap.ExcludeReason = "queue_full"
	case reason == schedExcludeCapZero:
		snap.ExcludeReason = "cap_zero"
	case reason == schedExcludeEnvelopeOut:
		snap.ExcludeReason = "envelope_out"
	}
	snap.Eligible = reason == schedExcludeNone
	switch {
	case flags&schedFlagNearIn != 0:
		snap.NearState = "in"
	case flags&schedFlagNearLenient != 0:
		snap.NearState = "lenient"
	}
	// fwd 门的比较式需要"这条路径的去程读数 vs 组内地板"。用 backendOneWayUS 的
	// 原始有符号相对量（与门判定同源），刻意不用显示层的 fwdOneWayUS——后者带 δ
	// 抬升，与地板+窗口的判定不是同一个数，并置展示会让面板读到"其实没超窗"。
	if v, ok := b.backendOneWayUS(); ok {
		snap.FwdRankKnown = true
		snap.FwdRankUS = v
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
			fb := p.fallbackSinglePath(backends)
			p.recordChoice(backends, fb, schedReasonNoHealthy, 1)
			return fb
		}
		b.active.Store(true)
		b.virtualFinishNS.Store(0)
		// 补一次标志发布：快路径跳过全量管线（每批 0 次候选写入），而拓扑收缩
		// （如 4 连接掉 3 条）会让幸存 Backend 残留上一批管线写的排除原因/粘滞
		// 标志——面板将长期显示 active=true 却 eligible=false + envelope_out 的
		// 自相矛盾组合。清掉排除/粘滞/排名位，与"单路径被选中"的事实自洽；
		// near 位留给 parity 路径维护。
		b.schedFlagsSet(schedFlagExcludeMask|schedFlagRankKnown|schedFlagStickyHeld, schedExcludeNone)
		p.activePaths.Store(1)
		p.storePreferredIfCurrent(b)
		p.recordChoice(backends, b, schedReasonSinglePath, 1)
		return b
	}
	current := p.preferred.Load()

	obs, minRTT, maxRTT, referenceRate, healthy := p.scanEnvelope(backends)
	if healthy == 0 {
		fb := p.fallbackSinglePath(backends)
		p.recordChoice(backends, fb, schedReasonNoHealthy, 1)
		return fb
	}
	// fwd 门的组内去程地板。取不到（组内无已收敛去程读数）时整体回退 rtt 门：
	// 回退值混排会让地板变成绝对尺度伪值，把全部路径误判成包络外。
	fwdFloor, fwdFloorOK := int64(0), false
	if p.schedEnvelopeFwd.Load() {
		fwdFloor, fwdFloorOK = schedEnvelopeFloor(backends)
	}
	cands := p.buildEligibleCandidates(policy, obs, backends, incomingBytes, minRTT, maxRTT, referenceRate, fwdFloor, fwdFloorOK)
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
		p.recordChoice(backends, chosen, schedReasonEnvelopeEmpty, 1)
		return chosen
	}
	rankCandidates(cands)

	bestBase := cands[0].baseUS
	// strict/latency_sticky（!wfq）不参与字节公平：活跃目标计算（原子读+阈值）
	// 只在 wfq 分支需要，提前搬进来避免 strict 每批白付一次。
	if !policy.wfq {
		return p.commitSinglePath(backends, cands, current, bestBase, policy)
	}
	active := adaptiveActivePathTarget(pressure, p.inputRateBytesPerSec.Load(), len(cands))
	if active == 1 {
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

// schedEnvelopeFloor 健康后端的去程读数最小值：fwd 门的地板。
//
// 只计 backendOneWayUS 已收敛的路径（真实探针值），且要求与 min_rtt 同源
// 的公平启动条件（有 RTT 且完成热身）——冷/未测路径的 min_rtt/2 回退是绝对
// 内核尺度，与已收敛探针的有符号相对量混排会让参考地板被一条冷路径钉到负
// 侧，把其余路径全部判成"包络外"。因此地板取不到时返回 ok=false，调用方整体
// 回退 rtt 门（见 schedEnvelope 的文档）。
func schedEnvelopeFloor(backends []*Backend) (floor int64, ok bool) {
	var minFwd int64
	for _, b := range backends {
		if b == nil || b.queueCap() == 0 || b.queueLen() >= b.queueCap()-2 || b.isStalled() {
			continue
		}
		if b.rateBytesPerSec.Load() == 0 {
			continue
		}
		if _, unknownRTT := adaptiveBackendMinRTT(b); unknownRTT {
			continue
		}
		fwd, okFwd := b.backendOneWayUS()
		if !okFwd {
			continue
		}
		if !ok || fwd < minFwd {
			minFwd, ok = fwd, true
		}
	}
	return minFwd, ok
}

// publishEnvelopeFloor 发布本批 fwd 门的组内去程地板（µs，有符号相对量）。
// 与 rtt 门的 schedEnvMinRttUS/MaxRttUS 平行的观测字段：面板据此显示"去程地板"，
// 并把落在其 +sched_envelope_ms 之外的路径解释成包络外。未收敛时归零（=尚未建立）。
func (p *AsyncPort) publishEnvelopeFloor(b *Backend, fwdFloor int64, ok bool) {
	if b == nil || !ok {
		return
	}
	b.schedEnvFwdFloorUS.Store(fwdFloor)
}

// envelopeIn 判定一条已完成公平启动的路径是否落在当前资格门内（false=排除）。
//
// rtt 门（默认，历史行为）：内核 min_rtt 往返地板 + 滞回上限。方向盲——会顺手
// 毙掉"去程最快但往返很慢"的极不对称路径。maxRTT 由 scanEnvelope 算好传入，
// 与历史实现的比较式逐字一致。
// fwd 门：本端去程排名键，与排名键同源，使上述路径准入；它慢的那一侧是对端的
// 发送方向，由对端自己那端的门负责挡掉，两端各自按发送方向设门、无需跨端协调。
//
// 探针未收敛的路径在 fwd 门下宽松放行（与 near 窗口的 parityNearState 同契约）：
// 未收敛时 adaptiveBackendOneWayUS 回退到绝对内核尺度（min_rtt/2 或 50ms 哨兵
// 折半），与已收敛探针的有符号相对量跨尺度比较会把 bootstrap 期全部误判包络外。
//
// minRTTUS / oneWayUS / oneWayOK 由调用方传入本轮的首读结果（调用方在资格判定
// 之前就要读同一批原子做 fairStart 判定与排名键回退），此处不再重读：热路径每
// 候选的 minRTT/oneWay 加载从 2-3 次降到 1 次。调用方保证仅在 !fairStart 时进入
// （此时探针原始值缺失即宽松放行，语义与历史实现一致）。
func (p *AsyncPort) envelopeIn(fwdFloor int64, fwdFloorOK bool, maxRTT uint64, minRTTUS uint32, oneWayUS int64, oneWayOK bool) bool {
	if !p.schedEnvelopeFwd.Load() || !fwdFloorOK {
		// rtt 门，或 fwd 门因组内无已收敛读数整体回退。
		if uint64(minRTTUS) > maxRTT {
			return false
		}
		return true
	}
	if !oneWayOK {
		return true
	}
	return oneWayUS <= fwdFloor+int64(p.schedEnvelopeUS.Load())
}

// scanEnvelope 单遍合并原 scanWarmedMinRTT + buildEnvelope：健康计数、热身
// 最小 RTT、资格包络与参考速率。原先两遍各自重复加载同一批原子（每后端
// minRTT/rate/cold 各算两次），高 PPS 下是每批的主要固定开销之一。语义逐
// 字段保留：healthy 只计未阻塞路径；minWarmed 只计有 RTT 且完成热身的健康
// 路径（否则测量顺序可能永久压缩候选集）；referenceRate 只计包络内（或
// fairStart）路径；包络排除明显偏离的路径以限界接收端乱序。
//
// 两遍结构必须保留：minRTT 聚合要在包络比较之前完成，合并为单遍会把先访问
// 的路径与"半成品"地板比较。但第二遍不再重读原子，而是复用第一遍的观测
// （queueCap/queueLen/isStalled/minRTT/rate 各只读一次）——这既省一半加载，
// 也让"与第一遍对齐"的字段语义变成字面意义上的同一次观察；探针/速率在两遍
// 之间落地属极端路径，下一批自然纠正。
// envelopeObs 是单条后端在资格扫描阶段的一次性观测：第一遍聚合（健康闸、
// min_rtt/速率首读）与第二遍包络比较复用同一次观察，候选构建阶段再消费同一
// 份切片——minRTT/rate/queue 队列状态跨阶段各只读一次。切片挂在 AsyncPort 上
// 由 run goroutine 独占并按批复用（与 schedulerScratch/parityScratch 同纪律），
// 消除每批一次的固定堆分配。
type envelopeObs struct {
	alive      bool   // 通过健康闸（第一遍观察，后续阶段沿用）
	rtt        uint32 // adaptiveBackendMinRTT 首读
	unknownRTT bool
	cold       bool   // rateBytesPerSec==0（第一遍观察）
	rate       uint64 // 首读的速率值，第二遍直接参与 referenceRate
	cap        int    // queueCap 首读（候选阶段的排除子原因区分用）
	qLen       int    // queueLen 首读
	stalled    bool   // isStalled 首读
}

func (p *AsyncPort) scanEnvelope(backends []*Backend) (obs []envelopeObs, minRTT uint32, maxRTT uint64, referenceRate uint64, healthy int) {
	if cap(p.envelopeScratch) < len(backends) {
		p.envelopeScratch = make([]envelopeObs, len(backends))
	}
	obs = p.envelopeScratch[:len(backends)]
	clear(obs)
	minWarmed := ^uint32(0)
	for i, b := range backends {
		o := &obs[i]
		if b == nil {
			continue
		}
		o.cap = b.queueCap()
		o.qLen = b.queueLen()
		o.stalled = b.isStalled()
		if o.cap == 0 || o.qLen >= o.cap-2 || o.stalled {
			continue
		}
		o.alive = true
		healthy++
		o.rtt, o.unknownRTT = adaptiveBackendMinRTT(b)
		o.rate = b.rateBytesPerSec.Load()
		o.cold = o.rate == 0
		if !o.unknownRTT && !o.cold && o.rtt < minWarmed {
			minWarmed = o.rtt
		}
	}
	minRTT = minWarmed
	if minRTT == ^uint32(0) {
		minRTT = adaptiveUnknownRTTUS
	}
	rttSlack := max(uint32(backendRTTHysteresisMin), minRTT/4)
	maxRTT = uint64(minRTT) + uint64(rttSlack)
	referenceRate = uint64(adaptiveFallbackRateBytesPerSec)
	for i := range backends {
		o := &obs[i]
		// 与第一遍同一次观察：stalled/队满路径的 rate 不参与参考速率（仅冷路径
		// ETA 回退用），死路径不应抬高它。
		if !o.alive {
			continue
		}
		fairStart := o.unknownRTT || o.cold
		if !fairStart && uint64(o.rtt) > maxRTT {
			continue
		}
		if o.rate > referenceRate {
			referenceRate = o.rate
		}
	}
	return obs, minRTT, maxRTT, referenceRate, healthy
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
// 队列状态与 min_rtt/速率复用 scanEnvelope 的同一次观测（obs 与 backends 同序），
// 排除子原因按首读区分发布；只有 SRTT 尚未扫过，仍在此处单次读取。
func (p *AsyncPort) buildEligibleCandidates(policy routingPolicy, obs []envelopeObs, backends []*Backend, incomingBytes uint64, minRTT uint32, maxRTT uint64, referenceRate uint64, fwdFloor int64, fwdFloorOK bool) []backendCandidate {
	cands := p.schedulerScratch[:0]
	for i, b := range backends {
		if b == nil {
			continue
		}
		o := &obs[i]
		// 四类排除子原因分列发布：面板要回答的是"为什么没选它"，笼统的
		// eligible=false 无法区分 stalled、队满、cap 未就绪与真正落在包络外。
		switch {
		case o.cap == 0:
			p.publishExcluded(b, schedExcludeCapZero, minRTT, maxRTT, fwdFloor, fwdFloorOK)
			continue
		case o.qLen >= o.cap-2:
			p.publishExcluded(b, schedExcludeQueueFull, minRTT, maxRTT, fwdFloor, fwdFloorOK)
			continue
		case o.stalled:
			p.publishExcluded(b, schedExcludeStalled, minRTT, maxRTT, fwdFloor, fwdFloorOK)
			continue
		}
		// SRTT 用于 ETA 遥测（含当前拥塞，预测更准）；min_rtt 已在扫描阶段
		// 首读（obs）。本轮候选评估内每条原子的首读结果全部复用：资格门、ETA
		// 与排名键的判定点彼此只差几条指令，探针在这几条指令之间落地不值得
		// 多付一倍加载，下一批自然纠正。
		srt, srttUnknown := adaptiveBackendRTT(b)
		mr, unknownRTT := o.rtt, o.unknownRTT
		rate := o.rate
		cold := o.cold
		fairStart := unknownRTT || cold
		rtt := mr
		if fairStart {
			// 公平启动路径按组内热身地板参与排序（仅 bootstrap 期）。
			rtt = minRTT
		}
		oneWay, oneWayOK := b.backendOneWayUS()
		if !fairStart && !p.envelopeIn(fwdFloor, fwdFloorOK, maxRTT, mr, oneWay, oneWayOK) {
			// 冷路径完成热身却真正落在资格门外（按当前 sched_envelope 维度判定）：
			// 清掉过期成员。
			p.publishExcluded(b, schedExcludeEnvelopeOut, minRTT, maxRTT, fwdFloor, fwdFloorOK)
			continue
		}
		// Writer-drain EWMA 只作观测 ETA，不代表端到端 TCP 投递能力。
		etaRate := rate
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
		// 回退链与 adaptiveBackendOneWayUS 同型，但复用本轮首读（oneWayOK/
		// unknownRTT/srttUnknown），每候选少 2-3 次原子加载：
		//   min_rtt 已知 → min_rtt/2；SRTT 已知 → SRTT/2；
		//   两者皆未知（全未测）→ 组内 minRTT/2（哨兵折半，与历史覆盖逻辑一致）。
		if !oneWayOK {
			switch {
			case !unknownRTT:
				oneWay = int64(mr) / 2
			case srttUnknown:
				oneWay = int64(minRTT) / 2
			default:
				oneWay = int64(srt) / 2
			}
		}
		baseUS := candidateRankUS(policy, oneWay, rtt, srt, incomingBytes, schedRate)
		// 观测发布：排名键 + 资格包络 + 候选内标志，面板据此把"去程最快却待命"
		// 解释清楚。与上方排除分支写同一批原子，避免两条路径语义分叉。
		if minRTT != adaptiveUnknownRTTUS {
			b.schedEnvMinRttUS.Store(uint64(minRTT))
			b.schedEnvMaxRttUS.Store(maxRTT)
		}
		p.publishEnvelopeFloor(b, fwdFloor, fwdFloorOK)
		b.rankKeyUS.Store(baseUS)
		// StickyHeld 在此处清空：粘滞判定发生在其后的 commitSinglePath，同一批内
		// "先清后设"，故粘滞未生效的路径不会残留上一批的旧标志。
		b.schedFlagsSet(schedFlagExcludeMask|schedFlagRankKnown|schedFlagStickyHeld, schedExcludeNone|schedFlagRankKnown)
		cands = append(cands, backendCandidate{
			backend:   b,
			baseUS:    baseUS,
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
	reason := schedReasonRank0
	if policy.sticky && current != nil && current != chosen {
		// 粘滞带锚定最优候选（rank0）而非 current：滞回阈值必须与"谁是 current"
		// 无关。若用 current（较慢）的 RTT，其 slack 偏大，切换条件被放宽——一旦
		// 落到慢路径就再也回不到快路径（单向锁死，活跃路径反复横跳）。rank0 的
		// RTT 反映"值得离开的快路径有多快"，两个方向共用同一锚，进出对称：快路径
		// 领先超过它自己的粘滞带才切换。
		slack := int64(adaptiveStickySlackUS(cands[0].rttUS))
		for i := range cands {
			if cands[i].backend != current {
				continue
			}
			if cands[i].baseUS <= bestBase+slack {
				chosen = current
				reason = schedReasonStickyHeld
				// 标记"因粘滞保留"而非"排名第一当选"：面板据此解释为什么明明有
				// 更快的候选却留在当前路径。上方 buildEligibleCandidates 已清空该位。
				current.schedFlagsSet(schedFlagStickyHeld, schedFlagStickyHeld)
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
	p.recordChoice(backends, chosen, reason, 1)
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
	p.recordChoice(backends, chosen.backend, schedReasonWFQDispatch, int32(active))
	return chosen.backend
}
