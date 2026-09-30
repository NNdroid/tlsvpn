package main

import (
	"sync"
	"sync/atomic"
)

const (
	// A 16-frame producer batch is large enough to amortize queue + FEC/reorder
	// synchronization while still fitting the common ~16 KiB scanner read burst.
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
	batch   *rxSessionBatch
	barrier chan struct{}
}

// rxSessionWorker is the single mutation owner for a multi-connection RX
// session. Physical TCP readers only decrypt and enqueue owned batches;
// FEC, reorder and ordered delivery are serialized here at batch granularity.
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

// AdvanceEpoch invalidates all existing producers and establishes a queue
// barrier. After it returns, no batch queued before the barrier can still
// mutate FEC/reorder state, so callers may safely Reset/rekey them.
func (w *rxSessionWorker) AdvanceEpoch() {
	if w == nil || w.closing.Load() {
		return
	}
	w.generation.Add(1)
	done := make(chan struct{})
	if !w.enqueue(rxSessionWork{barrier: done}) {
		return
	}
	select {
	case <-done:
	case <-w.closed:
	}
}

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

func (w *rxSessionWorker) run() {
	defer close(w.done)
	for {
		select {
		case work := <-w.queue:
			w.process(work)
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
			err := b.fec.OnControlWithScratch(frame, &controlScratch)
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
			b.fec.OnDataBatch(segment)
		}
		w.reorder.InsertBatch(segment)
		// InsertBatch consumes ownership even when a frame is duplicate/stale.
		for k := range segment {
			segment[k].Data = nil
		}
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
	if p == nil {
		return
	}
	if frame == nil {
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
