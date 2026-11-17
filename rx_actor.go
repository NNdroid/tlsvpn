package main

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"time"
)

// NewActorReorderBuffer creates a reorder buffer whose mutable sequencing state
// is exclusively owned by rxSessionWorker. Unlike NewReorderBuffer it does not
// start timeoutWorker; the session actor owns the gap timer as well.
func NewActorReorderBuffer(outFunc func([]byte)) *ReorderBuffer {
	return newActorReorderBuffer(outFunc, false)
}

// NewOwnedActorReorderBuffer is the ownership-transfer variant used by the
// server VSwitch receive path.
func NewOwnedActorReorderBuffer(outFunc func([]byte)) *ReorderBuffer {
	return newActorReorderBuffer(outFunc, true)
}

func newActorReorderBuffer(outFunc func([]byte), outOwned bool) *ReorderBuffer {
	rb := &ReorderBuffer{
		actorOwned: true,
		ring:       make([][]byte, ReorderWindowSize),
		seqSlots:   make([]uint32, ReorderWindowSize),
		windowMask: ReorderWindowSize - 1,
		outFunc:    outFunc,
		outOwned:   outOwned,
		outChan:    make(chan *reorderBatch, reorderOutQueue),
		gapWake:    make(chan struct{}, 1),
		closed:     make(chan struct{}),
	}
	goSafe(rb.outWorker)
	return rb
}

// InsertActorBuffered records one actor-owned frame but defers handing the
// resulting ordered batch to outWorker. This lets the actor interleave original
// and FEC-recovered frames in sequence order before one delivery flush.
//
// Actor 无锁契约（本组 Actor* 方法绕过 rb.mu/fecDecoder.mu 直接改序号状态，
// 结构上无法用锁保护，只能靠调用顺序保证）：唯一合法写者是已通过
// rxSessionWorker.Close() 退出（Close 内部等待 w.done）的 RX worker goroutine，
// 以及在"发布给读者之前"完成构建期 Reset 的构造序列。因此任何重排/FEC 状态
// 的 Close 必须先于 worker 关闭之后调用——client.go/server.go 的会话清理序列
// 固定先 rxWorker.Close() 再 rxReorder.Close()，AdvanceEpochAndReset 经 epoch
// barrier 与 worker 串行。调整清理顺序前先核对这里。
func (rb *ReorderBuffer) InsertActorBuffered(seq uint32, frame []byte) {
	if seq == 0 {
		if frame != nil {
			putFrame(frame)
		}
		return
	}
	if rb.shutting {
		putFrame(frame)
		return
	}
	rb.insertLocked(seq, frame)
}

func (rb *ReorderBuffer) FlushActor() { rb.deliver(rb.takePendingLocked()) }

// InsertActor is the recovered-frame/cold caller convenience path.
func (rb *ReorderBuffer) InsertActor(seq uint32, frame []byte) {
	rb.InsertActorBuffered(seq, frame)
	rb.FlushActor()
}

// ResetActor resets sequencing state at an epoch barrier. No producer from the
// new generation is published until the barrier returns, so no mutex is needed.
func (rb *ReorderBuffer) ResetActor() {
	drain := rb.takePendingLocked()
	rb.expectedSeq = 0
	rb.releaseRingLocked()
	// epoch barrier 内单写者、缓冲区已清空：把大偏斜扩出的窗口缩回初始尺寸，
	// 与非 actor 的 Reset 行为对齐（否则 65536 级 ring 常驻到会话结束）。
	rb.shrinkWindowLocked()
	rb.gapSince = time.Time{}
	rb.freeBatch(drain)
}

func (rb *ReorderBuffer) ExpectedSeqActor() uint32 { return rb.expectedSeq }

func (rb *ReorderBuffer) GapDeadlineActor() (time.Time, bool) {
	if rb.shutting || rb.gapSince.IsZero() {
		return time.Time{}, false
	}
	return rb.gapSince.Add(reorderSkipDelay), true
}

func (rb *ReorderBuffer) ExpireGapActor(now time.Time) {
	if rb.shutting || rb.gapSince.IsZero() || now.Before(rb.gapSince.Add(reorderSkipDelay)) ||
		rb.buffered == 0 || rb.expectedSeq == 0 || rb.ring[rb.expectedSeq&rb.windowMask] != nil {
		return
	}

	skipped := uint32(0)
	for i := uint32(1); i < uint32(len(rb.ring)); i++ {
		if rb.ring[(rb.expectedSeq+i)&rb.windowMask] != nil {
			rb.expectedSeq += i
			skipped = i
			break
		}
	}
	rb.gapSince = time.Time{}
	if skipped > 0 {
		rb.timeoutFlushes.Add(1)
		rb.skippedFrames.Add(uint64(skipped))
		rb.drainLocked()
	}
	rb.FlushActor()
}

// Actor-mode FEC never calls directly back into reorder. Recovery is returned
// to rxSessionWorker so the worker can place the current original and recovered
// member in the correct order under one ownership domain.
func fecReorderHooks(rb *ReorderBuffer, worker *rxSessionWorker) (func(uint32, []byte), func() uint32) {
	if worker != nil {
		return nil, rb.ExpectedSeqActor
	}
	return rb.Insert, rb.ExpectedSeqSnapshot
}

func (d *fecDecoder) ResetActor() {
	for _, g := range d.groups {
		d.releaseLocked(g)
	}
	clear(d.groups)
	d.groupOrder = d.groupOrder[:0]
	d.groupHead = 0
	clear(d.doneRing[:])
	d.cleanupBefore.Store(0)
	d.retiredBefore.Store(0)
	d.fence.Reset()
}

func (d *fecDecoder) handleModeControlActor(ctrl fecModeControl) {
	if !d.fence.Apply(ctrl) {
		return
	}
	from, until := d.fence.Window()
	if from == 0 {
		return
	}
	atomicMaxUint32(&d.cleanupBefore, from)
	d.dropGroupsInRangeLocked(from, until)
	d.maybeRetireOldGroupsLocked()
}

// OnControlActorWithScratch returns an optional recovered member instead of
// invoking d.out. That keeps recovery and reorder mutation on rxSessionWorker.
func (d *fecDecoder) OnControlActorWithScratch(payload []byte, scratch *nonceAADScratch) (uint32, []byte, error) {
	kind, err := parseControlKind(payload)
	if err != nil {
		return 0, nil, err
	}
	switch kind {
	case controlKindFECParity:
		seq, frame, ok := d.OnParityActorWithScratch(payload, scratch)
		if !ok {
			return 0, nil, nil
		}
		return seq, frame, nil
	case controlKindFECMode:
		ctrl, ok := parseFECModeControl(payload)
		if !ok {
			return 0, nil, fmt.Errorf("malformed FEC_MODE control")
		}
		d.handleModeControlActor(ctrl)
		return 0, nil, nil
	case controlKindRttProbe, controlKindRttReply:
		// 探针/回包由读循环在 FEC 门控之前拦截；防御性 no-op。
		return 0, nil, nil
	case controlKindClockProbe, controlKindClockReply:
		// 时钟偏移探针/回包同样在 FEC 门控之前拦截；防御性 no-op。
		return 0, nil, nil
	default:
		return 0, nil, fmt.Errorf("unsupported control kind 0x%02x", kind)
	}
}

// OnDataActor mutates FEC state for one borrowed original frame and returns an
// optional reconstruction. The worker inserts both frames into reorder only
// after FEC has finished reading the original payload.
func (d *fecDecoder) OnDataActor(seq uint32, frame []byte) (uint32, []byte, bool) {
	if len(frame) == 0 || seq == 0 || d.staticSingle.Load() {
		return 0, nil, false
	}
	if d.fence.BypassData(seq) {
		if seq&0xff == 0 {
			d.maybeRetireOldGroupsLocked()
		}
		return 0, nil, false
	}
	if retired := d.retiredBefore.Load(); retired != 0 && seq < retired {
		return 0, nil, false
	}
	start := d.groupStartOf(seq)
	if d.isDoneLocked(start) {
		return 0, nil, false
	}
	g, ok := d.groups[start]
	if !ok {
		g = d.newGroupLocked(start)
	}
	bit := uint64(seq - start)
	mask := uint64(1) << bit
	if g.gotMask&mask != 0 {
		return 0, nil, false
	}
	g.gotMask |= mask
	if g.gotMask == d.fullMask {
		d.finishGroupLocked(g)
		return 0, nil, false
	}
	if len(frame) > len(g.acc) {
		g.acc = d.growAccLocked(g.acc, len(frame))
	}
	subtle.XORBytes(g.acc[:len(frame)], g.acc[:len(frame)], frame)
	return d.tryRecoverActor(g)
}

func (d *fecDecoder) tryRecoverActor(g *fecGroupState) (uint32, []byte, bool) {
	if g.k == 0 || g.parity == nil {
		return 0, nil, false
	}
	missing := -1
	missingCount := 0
	for i := 0; i < g.k; i++ {
		if g.gotMask&(uint64(1)<<uint(i)) == 0 {
			missingCount++
			if missingCount > 1 {
				return 0, nil, false
			}
			missing = i
		}
	}
	if missing < 0 {
		d.finishGroupLocked(g)
		return 0, nil, false
	}
	if missing >= len(g.lens) || g.lens[missing] > len(g.parity) {
		d.finishGroupLocked(g)
		return 0, nil, false
	}
	n := g.lens[missing]
	if n > len(g.acc) {
		g.acc = d.growAccLocked(g.acc, n)
	}
	rec := getFrameAtLeast(n)[:n]
	subtle.XORBytes(rec, g.parity[:n], g.acc[:n])
	recoveredSeq := g.start + uint32(missing)
	g.gotMask |= uint64(1) << uint(missing)
	d.finishGroupLocked(g)
	atomic.AddUint64(&d.recovered, 1)
	return recoveredSeq, rec, true
}

func (d *fecDecoder) OnParityActorWithScratch(payload []byte, scratch *nonceAADScratch) (uint32, []byte, bool) {
	if d.staticSingle.Load() || len(payload) < 7 || payload[0] != controlKindFECParity {
		return 0, nil, false
	}
	start := binary.BigEndian.Uint32(payload[1:5])
	k := int(payload[5])
	if start == 0 || k != d.k || (start-1)%uint32(d.k) != 0 {
		return 0, nil, false
	}
	d.maybeRetireOldGroupsLocked()
	// SUSPEND 后在途 parity 与 OnDataActor 的 BypassData 检查对称：bypass 窗口
	// 覆盖的组不建状态——成员已被 bypass 丢弃，parity 永远等不到它们，只会以
	// "全部成员缺失"形态占住 pending 组表直到淘汰。快路径一次 atomic load
	// （actor 模式下 fence 写者与本校验同在 worker goroutine，无需二次检查）。
	if d.fence.BypassParity(start) {
		return 0, nil, false
	}
	if retired := d.retiredBefore.Load(); retired != 0 && start < retired {
		return 0, nil, false
	}
	descLen := 6 + 4*k
	tagLen := 0
	if d.ic != nil {
		tagLen = d.ic.tagLen()
	}
	if len(payload) < descLen+tagLen {
		return 0, nil, false
	}
	lens := getFECLens(k)
	maxLen := 0
	for i := 0; i < k; i++ {
		// int64 解析防 32 位平台 uint32→int 翻负绕过校验（同 OnParityWithScratch）。
		l := int64(binary.BigEndian.Uint32(payload[6+4*i : 10+4*i]))
		if l < 0 || l+int64(tagLen) > int64(len(payload)-descLen) {
			putFECLens(lens)
			return 0, nil, false
		}
		lens[i] = int(l)
		if int(l) > maxLen {
			maxLen = int(l)
		}
	}

	retired := d.retiredBefore.Load()
	if d.staticSingle.Load() || (retired != 0 && start < retired) || d.isDoneLocked(start) {
		putFECLens(lens)
		return 0, nil, false
	}
	g, ok := d.groups[start]
	if ok && g.parity != nil {
		putFECLens(lens)
		return 0, nil, false
	}
	if !ok {
		g = d.newGroupLocked(start)
	}
	g.k = k
	g.lens = lens
	pb := getFrameAtLeast(maxLen)[:maxLen]
	if _, err := d.ic.openToWithAAD(pb, payload[descLen:descLen+maxLen+tagLen], start, payload[:descLen], scratch); err != nil {
		putFrame(pb)
		putFECLens(g.lens)
		g.lens = nil
		return 0, nil, false
	}
	g.parity = pb
	seq, rec, recovered := d.tryRecoverActor(g)
	d.maybeRetireOldGroupsLocked()
	return seq, rec, recovered
}
