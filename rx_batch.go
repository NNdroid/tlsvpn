package main

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
	reorder    *ReorderBuffer
	queue      chan rxSessionWork
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
	w := &rxSessionWorker{reorder: reorder, queue: make(chan rxSessionWork, rxSessionQueueDepth), closed: make(chan struct{}), done: make(chan struct{})}
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
func (w *rxSessionWorker) AdvanceEpoch()                        { w.advanceEpoch(false, nil) }
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
	defer func() { stopRXTimer(timer); close(w.done) }()
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

func (w *rxSessionWorker) insertOriginalAndRecovery(seq uint32, frame []byte, recSeq uint32, rec []byte) {
	if rec != nil && recSeq < seq {
		w.reorder.InsertActorBuffered(recSeq, rec)
		rec = nil
	}
	w.reorder.InsertActorBuffered(seq, frame)
	if rec != nil && recSeq > seq {
		w.reorder.InsertActorBuffered(recSeq, rec)
		rec = nil
	}
	if rec != nil {
		putFrame(rec)
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
			recSeq, rec, err := b.fec.OnControlActorWithScratch(frame, &controlScratch)
			putFrame(frame)
			if err != nil {
				if rec != nil {
					putFrame(rec)
				}
				w.failBatch(b, i+1, err)
				return
			}
			if rec != nil {
				w.reorder.InsertActorBuffered(recSeq, rec)
				w.reorder.FlushActor()
			}
			i++
			continue
		}

		j := i + 1
		for j < b.n && b.frames[j].Seq != 0 {
			j++
		}
		for k := i; k < j; k++ {
			seq, frame := b.frames[k].Seq, b.frames[k].Data
			var recSeq uint32
			var rec []byte
			if b.fec != nil {
				recSeq, rec, _ = b.fec.OnDataActor(seq, frame)
			}
			w.insertOriginalAndRecovery(seq, frame, recSeq, rec)
			b.frames[k].Data = nil
		}
		w.reorder.FlushActor()
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
