package main

import (
	"sync/atomic"
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

func (b *Backend) baseQualityUS(incomingBytes uint64) uint64 {
	if b == nil {
		return ^uint64(0)
	}
	rtt, _ := adaptiveBackendRTT(b)
	return uint64(rtt)/2 + serviceTimeUS(incomingBytes, b.effectiveRateBytesPerSec())
}

// schedulingETAUS combines kernel/user-space queued work with a virtual service
// finish timestamp. The virtual debt survives a very fast writer drain, so a
// shallow high-throughput queue still stripes consecutive batches across the
// active set instead of repeatedly selecting the same socket.
func (b *Backend) schedulingETAUS(incomingBytes uint64) uint64 {
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

func schedulerSnapshot(b *Backend) schedulerConnJSON {
	if b == nil {
		return schedulerConnJSON{}
	}
	rate := b.rateBytesPerSec.Load()
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
func (p *AsyncPort) pickAdaptiveBackend(backends []*Backend, pressure, incomingBytes uint64) *Backend {
	// dispatchBatch calls the scheduler immediately before feeding the FEC encoder.
	// Feed the encoder the *physical* backend count here rather than p.activePaths:
	// low-load scheduling intentionally keeps activePaths==1 even when standby TCP
	// paths exist and can carry useful parity.
	if p != nil && p.encoder != nil {
		p.encoder.setPhysicalPathCount(len(backends))
	}

	if len(backends) == 0 {
		if p != nil {
			p.activePaths.Store(0)
		}
		return nil
	}
	current := p.preferred.Load()
	for _, b := range backends {
		if b != nil {
			b.etaUsec.Store(b.estimatedETAUS(incomingBytes))
		}
	}

	// Build the RTT reference only from fully warmed paths. A socket that has an
	// RTT sample but still has rateBytesPerSec==0 has not yet carried enough
	// egress payload to validate that sample for multipath eligibility. Counting
	// it here can let measurement order collapse the candidate set permanently.
	var minMeasuredRTT uint32 = ^uint32(0)
	healthy := 0
	for _, b := range backends {
		if b == nil || b.queueCap() == 0 || b.queueLen() >= b.queueCap()-2 {
			continue
		}
		healthy++
		rtt, unknownRTT := adaptiveBackendRTT(b)
		cold := b.rateBytesPerSec.Load() == 0
		if unknownRTT || cold {
			continue
		}
		if rtt < minMeasuredRTT {
			minMeasuredRTT = rtt
		}
	}
	if healthy == 0 {
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

	minRTT := minMeasuredRTT
	if minRTT == ^uint32(0) {
		minRTT = adaptiveUnknownRTTUS
	}
	rttSlack := max(uint32(backendRTTHysteresisMin), minRTT/4)
	maxRTT := uint64(minRTT) + uint64(rttSlack)
	referenceRate := uint64(adaptiveFallbackRateBytesPerSec)
	for _, b := range backends {
		if b == nil {
			continue
		}
		rtt, unknownRTT := adaptiveBackendRTT(b)
		cold := b.rateBytesPerSec.Load() == 0
		fairStart := unknownRTT || cold
		if fairStart {
			// Candidate ordering uses the best warmed RTT only during bootstrap.
			// WebUI ETA keeps the real/conservative value via estimatedETAUS.
			rtt = minRTT
		}
		if !fairStart && uint64(rtt) > maxRTT {
			continue
		}
		if rate := b.rateBytesPerSec.Load(); rate > referenceRate {
			referenceRate = rate
		}
	}
	cands := p.schedulerScratch[:0]
	for _, b := range backends {
		if b == nil || b.queueCap() == 0 || b.queueLen() >= b.queueCap()-2 {
			if b != nil {
				b.active.Store(false)
				b.virtualFinishNS.Store(0)
			}
			continue
		}
		rtt, unknownRTT := adaptiveBackendRTT(b)
		cold := b.rateBytesPerSec.Load() == 0
		fairStart := unknownRTT || cold
		if fairStart {
			rtt = minRTT
		}
		if !fairStart && uint64(rtt) > maxRTT {
			// Clear stale membership when a previously cold path finishes warm-up
			// and is now genuinely outside the near-MinRTT envelope.
			b.active.Store(false)
			b.virtualFinishNS.Store(0)
			continue
		}
		// Writer-drain EWMA is useful telemetry but tlsConn.Write completion only
		// means bytes entered the socket buffer; it is not a reliable estimate of
		// end-to-end TCP delivery capacity. Use it for observational ETA only.
		etaRate := b.rateBytesPerSec.Load()
		if etaRate == 0 {
			etaRate = referenceRate
		}
		eta := uint64(rtt)/2 + serviceTimeUS(b.queuedBytes.Load()+incomingBytes, etaRate)
		if b.carryPending.Load() && eta > adaptiveCarryBonusUS {
			eta -= adaptiveCarryBonusUS
		}
		b.etaUsec.Store(eta)
		// Scheduling debt is intentionally byte-fair. A common fixed rate turns
		// virtual service time into a scaled byte counter, preventing transient
		// userspace writer speed from creating a self-reinforcing path monopoly.
		schedRate := uint64(adaptiveFallbackRateBytesPerSec)
		cands = append(cands, backendCandidate{
			backend:   b,
			baseUS:    uint64(rtt)/2 + serviceTimeUS(incomingBytes, schedRate),
			etaUS:     eta,
			rttUS:     rtt,
			schedRate: schedRate,
			wasActive: b.active.Load(),
			virtualNS: b.virtualFinishNS.Load(),
		})
	}
	p.schedulerScratch = cands
	if len(cands) == 0 {
		return p.pickBackend(backends)
	}

	// Stable active membership comes from unloaded path quality. Short-lived
	// queue debt changes dispatch order inside the set, not membership itself.
	for i := 1; i < len(cands); i++ {
		x := cands[i]
		j := i
		for j > 0 && (x.baseUS < cands[j-1].baseUS || (x.baseUS == cands[j-1].baseUS && x.rttUS < cands[j-1].rttUS)) {
			cands[j] = cands[j-1]
			j--
		}
		cands[j] = x
	}

	demandRate := p.inputRateBytesPerSec.Load()
	active := adaptiveActivePathTarget(pressure, demandRate, len(cands))
	bestBase := cands[0].baseUS

	if active == 1 {
		chosen := cands[0].backend
		if current != nil && current != chosen {
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
		// Single-path interactive mode has no fairness debt. Reset it so a later
		// expansion starts all newly-active paths from the same virtual epoch.
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

	// WFQ/stride scheduling: logical debt does NOT decay with wall-clock time.
	// That is the crucial property for shallow high-rate queues: even if a TLS
	// writer drains a 12 KiB batch before the next batch arrives, the scheduler
	// remembers that the path just consumed its share and selects another active
	// path. Faster measured paths accrue debt more slowly and naturally get a
	// equal byte share; RTT/queue state still determines eligibility and immediate order.
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

	// Rebase the active set every dispatch. Only relative service debt matters;
	// keeping the minimum at zero prevents long-lived sessions from accumulating
	// huge counters and makes newly activated paths join immediately.
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
