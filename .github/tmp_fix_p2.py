from pathlib import Path

actor_go = r'''package main

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
	go rb.outWorker()
	return rb
}

// InsertActorBuffered records one actor-owned frame but defers handing the
// resulting ordered batch to outWorker. This lets the actor interleave original
// and FEC-recovered frames in sequence order before one delivery flush.
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

// InsertBatchActor consumes a reader-owned batch without rb.mu/deliverMu. The
// session worker is the only sequencing-state writer in actor mode.
func (rb *ReorderBuffer) InsertBatchActor(frames []VPNFrame) {
	if len(frames) == 0 {
		return
	}
	if rb.shutting {
		freeFrames(frames)
		return
	}
	for i := range frames {
		frame := frames[i].Data
		if frames[i].Seq == 0 {
			if frame != nil {
				putFrame(frame)
			}
			frames[i].Data = nil
			continue
		}
		rb.insertLocked(frames[i].Seq, frame)
		frames[i].Data = nil
	}
	rb.FlushActor()
}

// ResetActor resets sequencing state at an epoch barrier. No producer from the
// new generation is published until the barrier returns, so no mutex is needed.
func (rb *ReorderBuffer) ResetActor() {
	drain := rb.takePendingLocked()
	rb.expectedSeq = 0
	rb.releaseRingLocked()
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
		l := int(binary.BigEndian.Uint32(payload[6+4*i : 10+4*i]))
		if l+tagLen > len(payload)-descLen {
			putFECLens(lens)
			return 0, nil, false
		}
		lens[i] = l
		if l > maxLen {
			maxLen = l
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
	wireLen := uint32(maxLen + tagLen)
	if _, err := d.ic.openToWithScratch(pb, payload[descLen:descLen+maxLen+tagLen], start, wireLen, scratch); err != nil {
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
'''
Path("rx_actor.go").write_text(actor_go)

rx_batch_go = r'''package main

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	rxSessionBatchCap   = 16
	rxSessionQueueDepth = 256
)

type rxSessionBatch struct {
	frames     [rxSessionBatchCap]VPNFrame
	n          int
	fec        *fecDecoder
	generation uint64
	fail       func(error)
}

func newRXSessionBatch() any { return new(rxSessionBatch) }
var rxSessionBatchPool = sync.Pool{New: newRXSessionBatch}

func getRXSessionBatch() *rxSessionBatch {
	b := rxSessionBatchPool.Get().(*rxSessionBatch)
	b.n = 0
	b.fec = nil
	b.generation = 0
	b.fail = nil
	return b
}
func putRXSessionBatch(b *rxSessionBatch) {
	if b == nil { return }
	clear(b.frames[:b.n])
	b.n = 0
	b.fec = nil
	b.generation = 0
	b.fail = nil
	rxSessionBatchPool.Put(b)
}
func freeRXSessionBatch(b *rxSessionBatch) {
	if b == nil { return }
	freeFrames(b.frames[:b.n])
	putRXSessionBatch(b)
}

type rxSessionWork struct {
	batch    *rxSessionBatch
	barrier  chan struct{}
	reset    bool
	resetFEC *fecDecoder
}

type rxSessionWorker struct {
	reorder *ReorderBuffer
	queue chan rxSessionWork
	generation atomic.Uint64
	closing atomic.Bool
	enqueueMu sync.RWMutex
	closed chan struct{}
	done chan struct{}
	closeOnce sync.Once
}

func newRXSessionWorker(reorder *ReorderBuffer) *rxSessionWorker {
	if reorder == nil || !reorder.actorOwned { panic("rxSessionWorker requires an actor-owned ReorderBuffer") }
	w := &rxSessionWorker{reorder: reorder, queue: make(chan rxSessionWork, rxSessionQueueDepth), closed: make(chan struct{}), done: make(chan struct{})}
	w.generation.Store(1)
	go w.run()
	return w
}
func (w *rxSessionWorker) enqueue(work rxSessionWork) bool {
	if w == nil { return false }
	w.enqueueMu.RLock()
	defer w.enqueueMu.RUnlock()
	if w.closing.Load() { return false }
	select { case w.queue <- work: return true; case <-w.closed: return false }
}
func (w *rxSessionWorker) advanceEpoch(reset bool, fec *fecDecoder) {
	if w == nil || w.closing.Load() { return }
	w.generation.Add(1)
	done := make(chan struct{})
	if !w.enqueue(rxSessionWork{barrier: done, reset: reset, resetFEC: fec}) { return }
	select { case <-done: case <-w.closed: }
}
func (w *rxSessionWorker) AdvanceEpoch() { w.advanceEpoch(false, nil) }
func (w *rxSessionWorker) AdvanceEpochAndReset(fec *fecDecoder) { w.advanceEpoch(true, fec) }
func (w *rxSessionWorker) Close() {
	if w == nil { return }
	w.closeOnce.Do(func() {
		w.enqueueMu.Lock()
		w.closing.Store(true)
		close(w.closed)
		w.enqueueMu.Unlock()
		<-w.done
	})
}
func stopRXTimer(timer *time.Timer) {
	if !timer.Stop() { select { case <-timer.C: default: } }
}
func (w *rxSessionWorker) run() {
	timer := time.NewTimer(time.Hour)
	stopRXTimer(timer)
	defer func() { stopRXTimer(timer); close(w.done) }()
	var timerC <-chan time.Time
	armGapTimer := func() {
		deadline, ok := w.reorder.GapDeadlineActor()
		if !ok { stopRXTimer(timer); timerC = nil; return }
		wait := time.Until(deadline)
		if wait < 0 { wait = 0 }
		stopRXTimer(timer)
		timer.Reset(wait)
		timerC = timer.C
	}
	for {
		select {
		case work := <-w.queue:
			w.process(work)
			armGapTimer()
		case now := <-timerC:
			timerC = nil
			w.reorder.ExpireGapActor(now)
			armGapTimer()
		case <-w.closed:
			for {
				select {
				case work := <-w.queue:
					if work.batch != nil { freeRXSessionBatch(work.batch) }
					if work.barrier != nil { close(work.barrier) }
				default: return
				}
			}
		}
	}
}

func (w *rxSessionWorker) insertOriginalAndRecovery(seq uint32, frame []byte, recSeq uint32, rec []byte) {
	if rec != nil && recSeq < seq { w.reorder.InsertActorBuffered(recSeq, rec); rec = nil }
	w.reorder.InsertActorBuffered(seq, frame)
	if rec != nil && recSeq > seq { w.reorder.InsertActorBuffered(recSeq, rec); rec = nil }
	if rec != nil { putFrame(rec) }
}

func (w *rxSessionWorker) process(work rxSessionWork) {
	if work.reset {
		if work.resetFEC != nil { work.resetFEC.ResetActor() }
		w.reorder.ResetActor()
	}
	if work.barrier != nil { close(work.barrier); return }
	b := work.batch
	if b == nil { return }
	defer putRXSessionBatch(b)
	if b.generation != w.generation.Load() { freeFrames(b.frames[:b.n]); return }

	var controlScratch nonceAADScratch
	for i := 0; i < b.n; {
		if b.frames[i].Seq == 0 {
			frame := b.frames[i].Data
			b.frames[i].Data = nil
			if b.fec == nil {
				putFrame(frame)
				w.failBatch(b, i+1, errRXControlWithoutFEC)
				return
			}
			recSeq, rec, err := b.fec.OnControlActorWithScratch(frame, &controlScratch)
			putFrame(frame)
			if err != nil {
				if rec != nil { putFrame(rec) }
				w.failBatch(b, i+1, err)
				return
			}
			if rec != nil { w.reorder.InsertActorBuffered(recSeq, rec); w.reorder.FlushActor() }
			i++
			continue
		}

		j := i + 1
		for j < b.n && b.frames[j].Seq != 0 { j++ }
		for k := i; k < j; k++ {
			seq, frame := b.frames[k].Seq, b.frames[k].Data
			var recSeq uint32
			var rec []byte
			if b.fec != nil { recSeq, rec, _ = b.fec.OnDataActor(seq, frame) }
			w.insertOriginalAndRecovery(seq, frame, recSeq, rec)
			b.frames[k].Data = nil
		}
		w.reorder.FlushActor()
		i = j
	}
}
func (w *rxSessionWorker) failBatch(b *rxSessionBatch, next int, err error) {
	for i := next; i < b.n; i++ { if b.frames[i].Data != nil { putFrame(b.frames[i].Data); b.frames[i].Data = nil } }
	if b.fail != nil { b.fail(err) }
}

type rxBatchProducer struct { worker *rxSessionWorker; fec *fecDecoder; fail func(error); generation uint64; batch *rxSessionBatch }
func (w *rxSessionWorker) NewProducer(fec *fecDecoder, fail func(error)) *rxBatchProducer {
	if w == nil { return nil }
	return &rxBatchProducer{worker: w, fec: fec, fail: fail, generation: w.generation.Load()}
}
func (p *rxBatchProducer) Push(seq uint32, frame []byte) {
	if p == nil || frame == nil { return }
	if p.batch == nil { p.batch = getRXSessionBatch(); p.batch.fec = p.fec; p.batch.fail = p.fail; p.batch.generation = p.generation }
	p.batch.frames[p.batch.n] = VPNFrame{Seq: seq, Data: frame}
	p.batch.n++
	if p.batch.n == rxSessionBatchCap { p.Flush() }
}
func (p *rxBatchProducer) Flush() {
	if p == nil || p.batch == nil { return }
	b := p.batch; p.batch = nil
	if b.n == 0 { putRXSessionBatch(b); return }
	if !p.worker.enqueue(rxSessionWork{batch: b}) { freeRXSessionBatch(b) }
}
var errRXControlWithoutFEC = &rxProtocolError{"typed control without negotiated FEC"}
type rxProtocolError struct{ msg string }
func (e *rxProtocolError) Error() string { return e.msg }
'''
Path("rx_batch.go").write_text(rx_batch_go)

p = Path("rx_actor_test.go")
text = p.read_text()
old = "\t\td.OnDataBatchActor(batch[:])\n"
new = "\t\tfor i := range batch {\n\t\t\t_, rec, _ := d.OnDataActor(batch[i].Seq, batch[i].Data)\n\t\t\tif rec != nil { putFrame(rec) }\n\t\t}\n"
if old not in text:
    raise SystemExit("rx_actor_test.go benchmark call not found")
p.write_text(text.replace(old, new, 1))
