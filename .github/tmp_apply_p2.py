from pathlib import Path


def replace_once(path, old, new):
    p = Path(path)
    text = p.read_text()
    n = text.count(old)
    if n != 1:
        raise SystemExit(f"{path}: expected exactly one match, got {n}: {old[:80]!r}")
    p.write_text(text.replace(old, new, 1))


replace_once(
    "buffer.go",
    "type ReorderBuffer struct {\n\tmu          sync.Mutex\n",
    "type ReorderBuffer struct {\n\tmu          sync.Mutex\n\tactorOwned  bool // true: rxSessionWorker is the sole state-machine writer; no timeoutWorker\n",
)

actor_go = r'''package main

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
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

// InsertActor is the recovered-frame path for an actor-owned reorder buffer.
// The caller MUST be the owning rxSessionWorker goroutine.
func (rb *ReorderBuffer) InsertActor(seq uint32, frame []byte) {
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
	rb.deliver(rb.takePendingLocked())
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
	rb.deliver(rb.takePendingLocked())
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

// ExpectedSeqActor is the actor-only FEC retirement progress probe.
func (rb *ReorderBuffer) ExpectedSeqActor() uint32 { return rb.expectedSeq }

// GapDeadlineActor returns the current gap deadline. Only the session actor may
// call it; normal reorder buffers continue to use timeoutWorker.
func (rb *ReorderBuffer) GapDeadlineActor() (time.Time, bool) {
	if rb.shutting || rb.gapSince.IsZero() {
		return time.Time{}, false
	}
	return rb.gapSince.Add(reorderSkipDelay), true
}

// ExpireGapActor performs the timeout transition previously owned by
// ReorderBuffer.timeoutWorker. The session worker calls this when its timer fires.
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
	rb.deliver(rb.takePendingLocked())
}

// fecReorderHooks selects callbacks that match the ownership model. Actor FEC
// recovery must never call the lock-based Insert/ExpectedSeqSnapshot methods.
func fecReorderHooks(rb *ReorderBuffer, worker *rxSessionWorker) (func(uint32, []byte), func() uint32) {
	if worker != nil {
		return rb.InsertActor, rb.ExpectedSeqActor
	}
	return rb.Insert, rb.ExpectedSeqSnapshot
}

// ResetActor clears decoder state at an RX actor epoch barrier. All group-map
// mutation is serialized by rxSessionWorker, so d.mu/controlMu are unnecessary.
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

// OnControlActorWithScratch is the actor-owned protocol-v3 control path.
func (d *fecDecoder) OnControlActorWithScratch(payload []byte, scratch *nonceAADScratch) error {
	kind, err := parseControlKind(payload)
	if err != nil {
		return err
	}
	switch kind {
	case controlKindFECParity:
		d.OnParityActorWithScratch(payload, scratch)
		return nil
	case controlKindFECMode:
		ctrl, ok := parseFECModeControl(payload)
		if !ok {
			return fmt.Errorf("malformed FEC_MODE control")
		}
		d.handleModeControlActor(ctrl)
		return nil
	default:
		return fmt.Errorf("unsupported control kind 0x%02x", kind)
	}
}

// OnDataBatchActor is the lock-free multi-connection decoder hot path.
func (d *fecDecoder) OnDataBatchActor(frames []VPNFrame) {
	if len(frames) == 0 || d.staticSingle.Load() {
		return
	}
	for i := range frames {
		seq, frame := frames[i].Seq, frames[i].Data
		if len(frame) == 0 || seq == 0 {
			continue
		}
		if d.staticSingle.Load() {
			continue
		}
		if d.fence.BypassData(seq) {
			if seq&0xff == 0 {
				d.maybeRetireOldGroupsLocked()
			}
			continue
		}
		retired := d.retiredBefore.Load()
		if retired != 0 && seq < retired {
			continue
		}
		start := d.groupStartOf(seq)
		if d.isDoneLocked(start) {
			continue
		}
		g, ok := d.groups[start]
		if !ok {
			g = d.newGroupLocked(start)
		}
		bit := uint64(seq - start)
		mask := uint64(1) << bit
		if g.gotMask&mask != 0 {
			continue
		}
		g.gotMask |= mask
		if g.gotMask == d.fullMask {
			d.finishGroupLocked(g)
			continue
		}
		if len(frame) > len(g.acc) {
			g.acc = d.growAccLocked(g.acc, len(frame))
		}
		subtle.XORBytes(g.acc[:len(frame)], g.acc[:len(frame)], frame)
		d.tryRecoverLocked(g)
	}
}

// OnParityActorWithScratch mirrors OnParityWithScratch without d.mu. Recovery
// calls d.out, which actor-mode decoders bind to ReorderBuffer.InsertActor.
func (d *fecDecoder) OnParityActorWithScratch(payload []byte, scratch *nonceAADScratch) {
	if d.staticSingle.Load() || len(payload) < 7 || payload[0] != controlKindFECParity {
		return
	}
	start := binary.BigEndian.Uint32(payload[1:5])
	k := int(payload[5])
	if start == 0 || k != d.k || (start-1)%uint32(d.k) != 0 {
		return
	}
	d.maybeRetireOldGroupsLocked()
	if retired := d.retiredBefore.Load(); retired != 0 && start < retired {
		return
	}
	descLen := 6 + 4*k
	tagLen := 0
	if d.ic != nil {
		tagLen = d.ic.tagLen()
	}
	if len(payload) < descLen+tagLen {
		return
	}
	lens := getFECLens(k)
	maxLen := 0
	for i := 0; i < k; i++ {
		l := int(binary.BigEndian.Uint32(payload[6+4*i : 10+4*i]))
		if l+tagLen > len(payload)-descLen {
			putFECLens(lens)
			return
		}
		lens[i] = l
		if l > maxLen {
			maxLen = l
		}
	}

	retired := d.retiredBefore.Load()
	if d.staticSingle.Load() || (retired != 0 && start < retired) || d.isDoneLocked(start) {
		putFECLens(lens)
		return
	}
	g, ok := d.groups[start]
	if ok && g.parity != nil {
		putFECLens(lens)
		return
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
		return
	}
	g.parity = pb
	d.tryRecoverLocked(g)
	d.maybeRetireOldGroupsLocked()
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
	if b == nil {
		return
	}
	clear(b.frames[:b.n])
	b.n = 0
	b.fec = nil
	b.generation = 0
	b.fail = nil
	rxSessionBatchPool.Put(b)
}

func freeRXSessionBatch(b *rxSessionBatch) {
	if b == nil {
		return
	}
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
	queue   chan rxSessionWork

	generation atomic.Uint64
	closing    atomic.Bool
	enqueueMu  sync.RWMutex
	closed     chan struct{}
	done       chan struct{}
	closeOnce  sync.Once
}

func newRXSessionWorker(reorder *ReorderBuffer) *rxSessionWorker {
	if reorder == nil || !reorder.actorOwned {
		panic("rxSessionWorker requires an actor-owned ReorderBuffer")
	}
	w := &rxSessionWorker{
		reorder: reorder,
		queue:   make(chan rxSessionWork, rxSessionQueueDepth),
		closed:  make(chan struct{}),
		done:    make(chan struct{}),
	}
	w.generation.Store(1)
	go w.run()
	return w
}

func (w *rxSessionWorker) enqueue(work rxSessionWork) bool {
	if w == nil {
		return false
	}
	w.enqueueMu.RLock()
	defer w.enqueueMu.RUnlock()
	if w.closing.Load() {
		return false
	}
	select {
	case w.queue <- work:
		return true
	case <-w.closed:
		return false
	}
}

func (w *rxSessionWorker) advanceEpoch(reset bool, fec *fecDecoder) {
	if w == nil || w.closing.Load() {
		return
	}
	w.generation.Add(1)
	done := make(chan struct{})
	if !w.enqueue(rxSessionWork{barrier: done, reset: reset, resetFEC: fec}) {
		return
	}
	select {
	case <-done:
	case <-w.closed:
	}
}

func (w *rxSessionWorker) AdvanceEpoch() { w.advanceEpoch(false, nil) }
func (w *rxSessionWorker) AdvanceEpochAndReset(fec *fecDecoder) { w.advanceEpoch(true, fec) }

func (w *rxSessionWorker) Close() {
	if w == nil {
		return
	}
	w.closeOnce.Do(func() {
		w.enqueueMu.Lock()
		w.closing.Store(true)
		close(w.closed)
		w.enqueueMu.Unlock()
		<-w.done
	})
}

func stopRXTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func (w *rxSessionWorker) run() {
	timer := time.NewTimer(time.Hour)
	stopRXTimer(timer)
	defer func() {
		stopRXTimer(timer)
		close(w.done)
	}()
	var timerC <-chan time.Time
	armGapTimer := func() {
		deadline, ok := w.reorder.GapDeadlineActor()
		if !ok {
			stopRXTimer(timer)
			timerC = nil
			return
		}
		wait := time.Until(deadline)
		if wait < 0 {
			wait = 0
		}
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
					if work.batch != nil {
						freeRXSessionBatch(work.batch)
					}
					if work.barrier != nil {
						close(work.barrier)
					}
				default:
					return
				}
			}
		}
	}
}

func (w *rxSessionWorker) process(work rxSessionWork) {
	if work.reset {
		if work.resetFEC != nil {
			work.resetFEC.ResetActor()
		}
		w.reorder.ResetActor()
	}
	if work.barrier != nil {
		close(work.barrier)
		return
	}
	b := work.batch
	if b == nil {
		return
	}
	defer putRXSessionBatch(b)
	if b.generation != w.generation.Load() {
		freeFrames(b.frames[:b.n])
		return
	}

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
			err := b.fec.OnControlActorWithScratch(frame, &controlScratch)
			putFrame(frame)
			if err != nil {
				w.failBatch(b, i+1, err)
				return
			}
			i++
			continue
		}
		j := i + 1
		for j < b.n && b.frames[j].Seq != 0 {
			j++
		}
		segment := b.frames[i:j]
		if b.fec != nil {
			b.fec.OnDataBatchActor(segment)
		}
		w.reorder.InsertBatchActor(segment)
		i = j
	}
}

func (w *rxSessionWorker) failBatch(b *rxSessionBatch, next int, err error) {
	for i := next; i < b.n; i++ {
		if b.frames[i].Data != nil {
			putFrame(b.frames[i].Data)
			b.frames[i].Data = nil
		}
	}
	if b.fail != nil {
		b.fail(err)
	}
}

type rxBatchProducer struct {
	worker     *rxSessionWorker
	fec        *fecDecoder
	fail       func(error)
	generation uint64
	batch      *rxSessionBatch
}

func (w *rxSessionWorker) NewProducer(fec *fecDecoder, fail func(error)) *rxBatchProducer {
	if w == nil {
		return nil
	}
	return &rxBatchProducer{worker: w, fec: fec, fail: fail, generation: w.generation.Load()}
}

func (p *rxBatchProducer) Push(seq uint32, frame []byte) {
	if p == nil || frame == nil {
		return
	}
	if p.batch == nil {
		p.batch = getRXSessionBatch()
		p.batch.fec = p.fec
		p.batch.fail = p.fail
		p.batch.generation = p.generation
	}
	p.batch.frames[p.batch.n] = VPNFrame{Seq: seq, Data: frame}
	p.batch.n++
	if p.batch.n == rxSessionBatchCap {
		p.Flush()
	}
}

func (p *rxBatchProducer) Flush() {
	if p == nil || p.batch == nil {
		return
	}
	b := p.batch
	p.batch = nil
	if b.n == 0 {
		putRXSessionBatch(b)
		return
	}
	if !p.worker.enqueue(rxSessionWork{batch: b}) {
		freeRXSessionBatch(b)
	}
}

var errRXControlWithoutFEC = &rxProtocolError{"typed control without negotiated FEC"}
type rxProtocolError struct{ msg string }
func (e *rxProtocolError) Error() string { return e.msg }
'''
Path("rx_batch.go").write_text(rx_batch_go)

replace_once("client.go", "c.rxReorder = NewReorderBuffer(func(orderedFrame []byte) {", "c.rxReorder = NewActorReorderBuffer(func(orderedFrame []byte) {")
replace_once("client.go", "c.rxWorker.AdvanceEpoch()\n", "c.rxWorker.AdvanceEpochAndReset(c.fecDec)\n")
replace_once(
    "client.go",
    "\t\t\tif c.fecDec != nil {\n\t\t\t\tc.fecDec.Reset()\n\t\t\t}\n\t\t\tfecRebuild = true\n",
    "\t\t\tif c.fecDec != nil && c.rxWorker == nil {\n\t\t\t\tc.fecDec.Reset()\n\t\t\t}\n\t\t\tfecRebuild = true\n",
)
replace_once(
    "client.go",
    "\t\t\tc.fecDec = NewFECDecoder(c.fecNegotiated, fecRx, c.rxReorder.Insert)\n\t\t\tc.fecDec.SetReorderProgress(c.rxReorder.ExpectedSeqSnapshot)\n",
    "\t\t\trxFECOut, rxReorderProgress := fecReorderHooks(c.rxReorder, c.rxWorker)\n\t\t\tc.fecDec = NewFECDecoder(c.fecNegotiated, fecRx, rxFECOut)\n\t\t\tc.fecDec.SetReorderProgress(rxReorderProgress)\n",
)
replace_once(
    "client.go",
    "\t\tc.rxReorder.Reset()\n\t}\n\n\t// 会话身份落盘",
    "\t\tif c.rxWorker == nil {\n\t\t\tc.rxReorder.Reset()\n\t\t}\n\t}\n\n\t// 会话身份落盘",
)

replace_once(
    "server.go",
    "\t\tsession.RxReorder = NewOwnedReorderBuffer(func(orderedFrame []byte) {\n",
    "\t\tnewRXReorder := NewOwnedReorderBuffer\n\t\tif !isStaticSinglePathTopology(req.BrutalConns) {\n\t\t\tnewRXReorder = NewOwnedActorReorderBuffer\n\t\t}\n\t\tsession.RxReorder = newRXReorder(func(orderedFrame []byte) {\n",
)
replace_once("server.go", "session.RxWorker.AdvanceEpoch()\n", "session.RxWorker.AdvanceEpochAndReset(session.FecDec)\n")
replace_once(
    "server.go",
    "\tsession.RxReorder.Reset()\n\tif session.FecDec != nil {\n\t\tsession.FecDec.Reset()\n\t}\n\tif session.FecEncK > 0 {\n",
    "\tif session.RxWorker == nil {\n\t\tsession.RxReorder.Reset()\n\t\tif session.FecDec != nil {\n\t\t\tsession.FecDec.Reset()\n\t\t}\n\t}\n\tif session.FecEncK > 0 {\n",
)
replace_once(
    "server.go",
    "\t\tsession.FecDec = NewFECDecoder(session.FecEncK, fecRx, session.RxReorder.Insert)\n\t\tsession.FecDec.SetReorderProgress(session.RxReorder.ExpectedSeqSnapshot)\n",
    "\t\trxFECOut, rxReorderProgress := fecReorderHooks(session.RxReorder, session.RxWorker)\n\t\tsession.FecDec = NewFECDecoder(session.FecEncK, fecRx, rxFECOut)\n\t\tsession.FecDec.SetReorderProgress(rxReorderProgress)\n",
)
replace_once(
    "server.go",
    "\t\t\tsession.FecDec = NewFECDecoder(fecEncK, fecRx, session.RxReorder.Insert)\n\t\t\tsession.FecDec.SetReorderProgress(session.RxReorder.ExpectedSeqSnapshot)\n",
    "\t\t\trxFECOut, rxReorderProgress := fecReorderHooks(session.RxReorder, session.RxWorker)\n\t\t\tsession.FecDec = NewFECDecoder(fecEncK, fecRx, rxFECOut)\n\t\t\tsession.FecDec.SetReorderProgress(rxReorderProgress)\n",
)

p = Path("rx_batch_test.go")
text = p.read_text()
if text.count("NewReorderBuffer(") != 2:
    raise SystemExit(f"rx_batch_test.go: expected 2 worker reorder constructors, got {text.count('NewReorderBuffer(')}")
p.write_text(text.replace("NewReorderBuffer(", "NewActorReorderBuffer("))

actor_test = r'''package main

import (
	"sync"
	"testing"
	"time"
)

func TestRXActorOwnsGapTimeout(t *testing.T) {
	got := make(chan byte, 4)
	rb := NewActorReorderBuffer(func(frame []byte) { got <- frame[0] })
	w := newRXSessionWorker(rb)
	defer func() { w.Close(); rb.Close() }()
	p := w.NewProducer(nil, func(err error) { t.Errorf("unexpected RX error: %v", err) })
	p.Push(1, pooledTestFrame(1))
	p.Push(3, pooledTestFrame(3))
	p.Flush()
	for _, want := range []byte{1, 3} {
		select {
		case v := <-got:
			if v != want { t.Fatalf("got byte=%d want=%d", v, want) }
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for byte=%d", want)
		}
	}
	stats := rb.Stats()
	if stats.TimeoutFlushes != 1 || stats.SkippedFrames != 1 {
		t.Fatalf("actor timeout stats=%+v, want one flush skipping one frame", stats)
	}
}

func TestRXActorEpochResetCancelsOldGap(t *testing.T) {
	got := make(chan byte, 8)
	rb := NewActorReorderBuffer(func(frame []byte) { got <- frame[0] })
	w := newRXSessionWorker(rb)
	defer func() { w.Close(); rb.Close() }()
	stale := w.NewProducer(nil, nil)
	stale.Push(1, pooledTestFrame(1))
	stale.Push(3, pooledTestFrame(3))
	stale.Flush()
	select {
	case v := <-got:
		if v != 1 { t.Fatalf("pre-reset byte=%d want=1", v) }
	case <-time.After(time.Second):
		t.Fatal("pre-reset seq=1 not delivered")
	}
	w.AdvanceEpochAndReset(nil)
	fresh := w.NewProducer(nil, nil)
	fresh.Push(1, pooledTestFrame(7))
	fresh.Push(2, pooledTestFrame(8))
	fresh.Flush()
	for _, want := range []byte{7, 8} {
		select {
		case v := <-got:
			if v != want { t.Fatalf("post-reset byte=%d want=%d", v, want) }
		case <-time.After(time.Second):
			t.Fatalf("post-reset byte=%d not delivered", want)
		}
	}
	time.Sleep(2 * reorderSkipDelay)
	select {
	case v := <-got:
		t.Fatalf("stale pre-reset frame leaked after actor reset: %d", v)
	default:
	}
}

func TestRXActorFECRecoveryStaysOnOwner(t *testing.T) {
	var mu sync.Mutex
	got := make([]byte, 0, 4)
	done := make(chan struct{})
	rb := NewActorReorderBuffer(func(frame []byte) {
		mu.Lock()
		got = append(got, frame[0])
		if len(got) == 4 {
			select { case <-done: default: close(done) }
		}
		mu.Unlock()
	})
	w := newRXSessionWorker(rb)
	defer func() { w.Close(); rb.Close() }()
	parts := [][]byte{pooledTestFrame(1), pooledTestFrame(2), pooledTestFrame(3), pooledTestFrame(4)}
	parity := encodeGroup(4, nil, 1, parts)
	putFrame(parts[1])
	fec := NewFECDecoder(4, nil, rb.InsertActor)
	fec.SetReorderProgress(rb.ExpectedSeqActor)
	p := w.NewProducer(fec, func(err error) { t.Errorf("unexpected FEC control error: %v", err) })
	p.Push(1, parts[0])
	p.Push(3, parts[2])
	p.Push(4, parts[3])
	p.Push(0, parity)
	p.Flush()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for actor-owned FEC recovery")
	}
	mu.Lock()
	defer mu.Unlock()
	want := []byte{1, 2, 3, 4}
	if len(got) != len(want) { t.Fatalf("delivered=%v want=%v", got, want) }
	for i := range want {
		if got[i] != want[i] { t.Fatalf("delivered[%d]=%d want=%d (all=%v)", i, got[i], want[i], got) }
	}
	recovered, _ := fec.FECStats()
	if recovered != 1 { t.Fatalf("recovered=%d want=1", recovered) }
}

func BenchmarkFECDecoderDataActor16(b *testing.B) {
	d := NewFECDecoder(4, nil, nil)
	frame := make([]byte, 256)
	var batch [16]VPNFrame
	seq := uint32(1)
	b.ReportAllocs()
	b.SetBytes(16 * int64(len(frame)))
	for n := 0; n < b.N; n++ {
		for i := range batch {
			batch[i] = VPNFrame{Seq: seq, Data: frame}
			seq++
		}
		d.OnDataBatchActor(batch[:])
	}
}
'''
Path("rx_actor_test.go").write_text(actor_test)
