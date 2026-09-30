#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path: str) -> str:
    return (ROOT / path).read_text()


def write(path: str, text: str) -> None:
    (ROOT / path).write_text(text)


def replace_once(text: str, old: str, new: str, label: str) -> str:
    n = text.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {n}")
    return text.replace(old, new, 1)


def replace_between(text: str, start: str, end: str, new: str, label: str) -> str:
    i = text.find(start)
    if i < 0:
        raise SystemExit(f"{label}: start marker not found")
    j = text.find(end, i)
    if j < 0:
        raise SystemExit(f"{label}: end marker not found")
    return text[:i] + new + text[j:]


# frame.go: keep the legacy descriptor-slice pool for cold/tests, but add the
# production ownership object whose Bytes field is authoritative from AsyncPort.
path = "frame.go"
t = read(path)
marker = "// framePoolSizes 帧缓冲尺寸分档。保留该表供测试/文档核对；真正池对象使用\n"
owned = r'''// VPNFrameBatch is the production ownership unit between AsyncPort and a
// backend consumer. Frames and Bytes move together: AsyncPort computes Bytes
// while building the batch, the scheduler transfers the pointer, and the TLS/TAP
// consumer returns the object to the pool after consuming every payload.
type VPNFrameBatch struct {
	Frames []VPNFrame
	Bytes  uint64
}

func newOwnedVPNFrameBatch() any {
	return &VPNFrameBatch{Frames: make([]VPNFrame, 0, hotVPNBatchCap)}
}

var ownedVPNFrameBatchPool = sync.Pool{New: newOwnedVPNFrameBatch}

func getOwnedVPNFrameBatch() *VPNFrameBatch {
	b := ownedVPNFrameBatchPool.Get().(*VPNFrameBatch)
	b.Frames = b.Frames[:0]
	b.Bytes = 0
	return b
}

func putOwnedVPNFrameBatch(b *VPNFrameBatch) {
	if b == nil {
		return
	}
	clear(b.Frames) // release payload references before the descriptor storage is pooled
	b.Frames = b.Frames[:0]
	b.Bytes = 0
	ownedVPNFrameBatchPool.Put(b)
}

func freeOwnedVPNFrameBatch(b *VPNFrameBatch) {
	if b == nil {
		return
	}
	freeFrames(b.Frames)
	putOwnedVPNFrameBatch(b)
}

func appendOwnedVPNFrame(b *VPNFrameBatch, vf VPNFrame) {
	b.Frames = append(b.Frames, vf)
	b.Bytes += uint64(len(vf.Data))
}

'''
if "type VPNFrameBatch struct" not in t:
    t = replace_once(t, marker, owned + marker, "frame.go ownership insert")
write(path, t)


# client.go: add a production owned channel while retaining the legacy []VPNFrame
# channel solely for unit-test/cold compatibility paths.
path = "client.go"
t = read(path)
t = replace_once(
    t,
    "type Backend struct {\n\tch       chan []VPNFrame\n\trttCache *uint32\n",
    "type Backend struct {\n\tch       chan []VPNFrame // legacy/cold compatibility path; production uses ownedCh\n\townedCh  chan *VPNFrameBatch\n\trttCache *uint32\n",
    "Backend owned channel",
)

register_block = r'''func (p *AsyncPort) ID() string { return p.id }
func (p *AsyncPort) RegisterBackend(ch chan []VPNFrame, rttCache *uint32) *Backend {
	p.backendsMu.Lock()
	defer p.backendsMu.Unlock()
	b := &Backend{ch: ch, rttCache: rttCache}
	p.backends = append(p.backends, b)
	return b
}
func (p *AsyncPort) UnregisterBackend(ch chan []VPNFrame) {
	p.backendsMu.Lock()
	defer p.backendsMu.Unlock()
	for i, b := range p.backends {
		if b.ch == ch {
			p.preferred.CompareAndSwap(b, nil)
			p.backends = append(p.backends[:i], p.backends[i+1:]...)
			break
		}
	}
}

// RegisterOwnedBackend is the production data path. The channel carries the
// batch object itself, so descriptor storage and its byte count have one owner.
func (p *AsyncPort) RegisterOwnedBackend(ch chan *VPNFrameBatch, rttCache *uint32) *Backend {
	p.backendsMu.Lock()
	defer p.backendsMu.Unlock()
	b := &Backend{ownedCh: ch, rttCache: rttCache}
	p.backends = append(p.backends, b)
	return b
}

func (p *AsyncPort) UnregisterOwnedBackend(ch chan *VPNFrameBatch) {
	p.backendsMu.Lock()
	defer p.backendsMu.Unlock()
	for i, b := range p.backends {
		if b.ownedCh == ch {
			p.preferred.CompareAndSwap(b, nil)
			p.backends = append(p.backends[:i], p.backends[i+1:]...)
			break
		}
	}
}

func (b *Backend) queueLen() int {
	if b == nil {
		return 0
	}
	if b.ownedCh != nil {
		return len(b.ownedCh)
	}
	return len(b.ch)
}

func (b *Backend) queueCap() int {
	if b == nil {
		return 0
	}
	if b.ownedCh != nil {
		return cap(b.ownedCh)
	}
	return cap(b.ch)
}

func (b *Backend) queueHasRoom() bool {
	capacity := b.queueCap()
	return capacity > 0 && b.queueLen() < capacity
}

'''
t = replace_between(t, "func (p *AsyncPort) ID() string", "func (p *AsyncPort) WriteFrame", register_block, "backend registration block")

t = t.replace("cap(b.ch) > 0 && len(b.ch) < cap(b.ch)", "b.queueHasRoom()")

run_new = r'''func (p *AsyncPort) run() {
	const MaxBatchBytes = streamTLSBatchSoftLimit
	batch := getOwnedVPNFrameBatch()
	defer func() { freeOwnedVPNFrameBatch(batch) }()

	for {
		select {
		case <-p.ctx.Done():
			return
		case reset := <-p.resetEpoch:
			p.txSeq = 0
			p.parityNext = 0
			p.dataNext = 0
			p.exhausted.Store(false)
			if reset.k >= fecMinGroup {
				p.encoder = newFECEncoder(reset.k, reset.ic)
			} else {
				p.encoder = nil
			}
			// Fence generations are scoped to the sequence/key epoch because a new
			// encoder starts generation numbering from one. Backends can survive an
			// epoch reset, so clear their remembered generation or the first new
			// SUSPEND/RESUME could be mistaken for an already-queued old fence.
			p.backendsMu.RLock()
			for _, b := range p.backends {
				if b != nil {
					b.fecFenceGen.Store(0)
				}
			}
			p.backendsMu.RUnlock()
			close(reset.done)
		case frame := <-p.ch:
			p.noteInputDequeued(len(frame))
			if len(frame) == 0 {
				putFrame(frame)
				continue
			}
			if !p.waitForBackendSlot() {
				p.dropN(1)
				putFrame(frame)
				continue
			}
			seq, ok := p.nextSeq()
			if !ok {
				p.dropN(1)
				putFrame(frame)
				continue
			}
			appendOwnedVPNFrame(batch, VPNFrame{Seq: seq, Data: frame})

			// Interactive bursts get one very short coalescing opportunity. Under
			// sustained load p.ch is already non-empty, so the hot bulk path never sleeps.
			if len(p.ch) == 0 && batch.Bytes < MaxBatchBytes {
				time.Sleep(150 * time.Microsecond)
			}

			queueLen := len(p.ch)
			for i := 0; i < queueLen && batch.Bytes < MaxBatchBytes; i++ {
				f := <-p.ch
				p.noteInputDequeued(len(f))
				if len(f) == 0 {
					putFrame(f)
					continue
				}
				s, ok := p.nextSeq()
				if !ok {
					p.dropN(1)
					putFrame(f)
					continue
				}
				appendOwnedVPNFrame(batch, VPNFrame{Seq: s, Data: f})
			}

			// Ownership moves as one object: scheduler/TLS writer consume both the
			// descriptors and the authoritative payload-byte count.
			p.dispatchBatch(batch)
			batch = getOwnedVPNFrameBatch()
		}
	}
}

'''
t = replace_between(t, "func (p *AsyncPort) run()", "// dispatchBatch", run_new, "AsyncPort.run")

dispatch_new = r'''// dispatchBatch 把一个 owned batch 分发给后端，并接管其中全部 payload。
// 成功时 batch 指针本身转交给唯一后端；失败时本函数负责释放并归池。
func (p *AsyncPort) dispatchBatch(batch *VPNFrameBatch) {
	if batch == nil {
		return
	}
	p.backendsMu.RLock()
	defer p.backendsMu.RUnlock()
	backends := p.backends
	if len(backends) == 0 {
		p.dropN(len(batch.Frames))
		freeOwnedVPNFrameBatch(batch)
		return
	}
	pressure := p.schedulerPressureFor(backends, batch.Bytes)
	dataBest := p.pickAdaptiveBackend(backends, pressure, batch.Bytes)

	if p.encoder != nil {
		parities := p.parityScratch[:0]
		for _, vf := range batch.Frames {
			if par := p.encoder.add(vf); par != nil {
				parities = append(parities, par)
			}
		}
		best := dataBest
		p.dropN(sendOwnedBatchToAnyFenced(p, backends, best, batch))
		for _, par := range parities {
			if len(backends) < 2 {
				putFrame(par)
				continue
			}
			p.paritySent.Add(1)
			target := p.pickParityBackend(backends, best)
			p.dropN(sendOwnedFrameTo(target, VPNFrame{Seq: 0, Data: par}))
		}
		clear(parities)
		p.parityScratch = parities[:0]
		return
	}

	p.dropN(sendOwnedBatchToAnyFenced(p, backends, dataBest, batch))
}

'''
t = replace_between(t, "// dispatchBatch", "const backendRTTHysteresisMin", dispatch_new, "dispatchBatch")

old_backend_score_start = "func backendScore(b *Backend) (uint32, bool) {"
old_backend_score_end = "// pickBackend 使用 MinRTT"
backend_score_new = r'''func backendScore(b *Backend) (uint32, bool) {
	qLen := b.queueLen()
	qCap := b.queueCap()
	if qCap == 0 || qLen >= qCap-2 {
		return math.MaxUint32, false
	}
	rtt := atomic.LoadUint32(b.rttCache)
	penalty := uint64(0)
	if qLen > 10 {
		penalty = uint64(qLen-10) * 1000
	}
	score := uint64(rtt) + penalty
	if score > math.MaxUint32 {
		score = math.MaxUint32
	}
	return uint32(score), true
}

'''
t = replace_between(t, old_backend_score_start, old_backend_score_end, backend_score_new, "backendScore")

send_new = r'''// tryQueueOwnedBatch transfers batch ownership on success and leaves ownership
// with the caller on failure. Production backends use ownedCh and therefore do
// not copy descriptors. The legacy []VPNFrame channel exists only for cold/unit
// compatibility and snapshots descriptors before taking payload ownership.
func tryQueueOwnedBatch(b *Backend, batch *VPNFrameBatch) bool {
	if b == nil || batch == nil {
		return false
	}
	if b.ownedCh != nil {
		select {
		case b.ownedCh <- batch:
			return true
		default:
			return false
		}
	}
	if b.ch == nil {
		return false
	}
	legacy := getVPNFrameBatch(len(batch.Frames))
	copy(legacy, batch.Frames)
	select {
	case b.ch <- legacy:
		// payload ownership moved into the copied legacy descriptors; only the
		// ownership-object descriptor storage is returned here.
		putOwnedVPNFrameBatch(batch)
		return true
	default:
		putVPNFrameBatch(legacy)
		return false
	}
}

// sendOwnedBatchToAnyFenced is the production scheduler transfer. AsyncPort has
// already computed batch.Bytes while ingesting TAP frames, so neither scheduler
// nor TLS writer needs a frame-length scan.
func sendOwnedBatchToAnyFenced(p *AsyncPort, backends []*Backend, preferred *Backend, batch *VPNFrameBatch) int {
	out := batch
	if out == nil {
		return 0
	}
	outBytes := out.Bytes

	trySend := func(b *Backend) bool {
		if b == nil {
			return false
		}

		sendBatch := out
		var ctrl fecModeControl
		fenced := false
		if p != nil && p.encoder != nil {
			if current, ok := p.encoder.currentModeControl(); ok && b.fecFenceGen.Load() < current.Generation {
				ctrl = current
				payload := getFrameAtLeast(fecControlWireLen)[:0]
				payload = appendFECModeControl(payload, current)
				withFence := getOwnedVPNFrameBatch()
				appendOwnedVPNFrame(withFence, VPNFrame{Seq: 0, Data: payload})
				withFence.Frames = append(withFence.Frames, out.Frames...)
				withFence.Bytes += out.Bytes
				sendBatch = withFence
				fenced = true
			}
		}

		b.addQueuedBytes(sendBatch.Bytes)
		if tryQueueOwnedBatch(b, sendBatch) {
			if fenced {
				b.fecFenceGen.Store(ctrl.Generation)
				// sendBatch owns copied data descriptors now; return only out's
				// descriptor container, never the payloads.
				putOwnedVPNFrameBatch(out)
			}
			out = nil
			b.assignedBytes.Add(outBytes)
			b.assignedBatches.Add(1)
			return true
		}

		b.completeQueuedBytes(sendBatch.Bytes)
		if fenced {
			// The data payloads still belong to out. Only the temporary fence has
			// unique payload ownership on a failed attempt.
			putFrame(sendBatch.Frames[0].Data)
			sendBatch.Frames[0].Data = nil
			putOwnedVPNFrameBatch(sendBatch)
		}
		return false
	}

	tryAll := func() bool {
		if trySend(preferred) {
			return true
		}
		for _, b := range backends {
			if b != preferred && trySend(b) {
				return true
			}
		}
		return false
	}

	if tryAll() {
		return 0
	}

	deadline := time.Now().Add(5 * time.Millisecond)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Microsecond)
		if tryAll() {
			return 0
		}
	}

	dropped := len(out.Frames)
	freeOwnedVPNFrameBatch(out)
	return dropped
}

// sendBatchToAnyFenced is retained for cold/tests that still construct a raw
// []VPNFrame. It converts once into the ownership object; production AsyncPort
// never enters this compatibility path.
func sendBatchToAnyFenced(p *AsyncPort, backends []*Backend, preferred *Backend, batch []VPNFrame) int {
	owned := getOwnedVPNFrameBatch()
	owned.Frames = append(owned.Frames, batch...)
	owned.Bytes = vpnFrameBatchBytes(batch)
	for i := range batch {
		batch[i].Data = nil
	}
	return sendOwnedBatchToAnyFenced(p, backends, preferred, owned)
}

func sendBatchToAny(backends []*Backend, preferred *Backend, batch []VPNFrame) int {
	return sendBatchToAnyFenced(nil, backends, preferred, batch)
}

func sendBatchTo(b *Backend, batch []VPNFrame) int {
	return sendBatchToAny([]*Backend{b}, b, batch)
}

// sendOwnedFrameTo transfers one already-owned payload as a one-frame batch.
func sendOwnedFrameTo(b *Backend, vf VPNFrame) int {
	if b == nil {
		if vf.Data != nil {
			putFrame(vf.Data)
		}
		return 1
	}
	out := getOwnedVPNFrameBatch()
	appendOwnedVPNFrame(out, vf)
	n := out.Bytes
	b.addQueuedBytes(n)
	if tryQueueOwnedBatch(b, out) {
		b.fecAssignedBytes.Add(n)
		b.fecAssignedBatches.Add(1)
		return 0
	}
	b.completeQueuedBytes(n)
	freeOwnedVPNFrameBatch(out)
	return 1
}

// sendFrameTo retains copy semantics for callers that do not transfer payload ownership.
func sendFrameTo(b *Backend, vf VPNFrame) int {
	if b == nil {
		return 1
	}
	out := getOwnedVPNFrameBatch()
	appendOwnedVPNFrame(out, VPNFrame{Seq: vf.Seq, Data: cloneFrame(vf.Data)})
	n := out.Bytes
	b.addQueuedBytes(n)
	if tryQueueOwnedBatch(b, out) {
		return 0
	}
	b.completeQueuedBytes(n)
	freeOwnedVPNFrameBatch(out)
	return 1
}

'''
t = replace_between(t, "// sendBatchToAnyFenced", "// FECRecovered", send_new, "owned scheduler send block")

# Client physical TLS backends use only the owned channel.
t = replace_once(t, "connTxChan := make(chan []VPNFrame, 32)", "connTxChan := make(chan *VPNFrameBatch, 32)", "client conn channel")
t = replace_once(t, "backend := c.txPort.RegisterBackend(connTxChan, rttCache)", "backend := c.txPort.RegisterOwnedBackend(connTxChan, rttCache)", "client register owned")
t = replace_once(t, "c.txPort.UnregisterBackend(connTxChan)", "c.txPort.UnregisterOwnedBackend(connTxChan)", "client unregister owned")
t = replace_once(t, "case frames := <-connTxChan:", "case batch := <-connTxChan:", "client writer receive")
t = replace_once(t, "queuedPayload += vpnFrameBatchBytes(frames)", "queuedPayload += batch.Bytes", "client writer bytes")
t = replace_once(t, "appendOwnedFrameBatchStreamWithScratch(sendBuffer, frames, icTx, &txAEADScratch)", "appendOwnedVPNFrameBatchStreamWithScratch(sendBuffer, batch, icTx, &txAEADScratch)", "client writer consume")
t = replace_once(t, "case frames = <-connTxChan:", "case batch = <-connTxChan:", "client writer drain")
write(path, t)


# stream_padding.go: production writer consumes and returns the ownership object.
path = "stream_padding.go"
t = read(path)
needle = r'''func appendOwnedFrameBatchStreamWithScratch(buf []byte, frames []VPNFrame, ic *innerCipher, scratch *nonceAADScratch) ([]byte, int, int) {
	n := len(frames)
	last := -1
	for _, vf := range frames {
		var start int
		buf, start = appendUnpaddedFrameWithScratch(buf, vf, ic, scratch)
		last = start
	}
	freeFrames(frames)
	putVPNFrameBatch(frames)
	return buf, n, last
}

'''
add = needle + r'''func appendOwnedVPNFrameBatchStreamWithScratch(buf []byte, batch *VPNFrameBatch, ic *innerCipher, scratch *nonceAADScratch) ([]byte, int, int) {
	if batch == nil {
		return buf, 0, -1
	}
	n := len(batch.Frames)
	last := -1
	for _, vf := range batch.Frames {
		var start int
		buf, start = appendUnpaddedFrameWithScratch(buf, vf, ic, scratch)
		last = start
	}
	freeFrames(batch.Frames)
	putOwnedVPNFrameBatch(batch)
	return buf, n, last
}

'''
t = replace_once(t, needle, add, "stream owned batch helper")
write(path, t)


# server.go: TAP consumer and TLS physical backends both use ownership channels.
path = "server.go"
t = read(path)
t = replace_once(t, "tapBackend := make(chan []VPNFrame, 32)", "tapBackend := make(chan *VPNFrameBatch, 32)", "server TAP channel")
t = replace_once(t, "tapPort.RegisterBackend(tapBackend, new(uint32))", "tapPort.RegisterOwnedBackend(tapBackend, new(uint32))", "server TAP register")
old_tap_loop = r'''	go func() {
		for frames := range tapBackend {
			for _, vf := range frames {
				if len(vf.Data) > 0 {
					if _, werr := srv.tap.Write(vf.Data); werr != nil {
						// 旧实现把这里的错误直接丢掉，TAP 故障表现为"隧道在线但
						// 客户端不通"。计数 + 限频日志让故障可观测。
						n := srv.tapWriteErrs.Add(1)
						if n == 1 || n%1000 == 0 {
							log.Warnf("TAP write failed #%d: %v", n, werr)
						}
					}
					putFrame(vf.Data)
				}
			}
			putVPNFrameBatch(frames)
		}
	}()
'''
new_tap_loop = r'''	go func() {
		for batch := range tapBackend {
			for _, vf := range batch.Frames {
				if len(vf.Data) > 0 {
					if _, werr := srv.tap.Write(vf.Data); werr != nil {
						n := srv.tapWriteErrs.Add(1)
						if n == 1 || n%1000 == 0 {
							log.Warnf("TAP write failed #%d: %v", n, werr)
						}
					}
					putFrame(vf.Data)
				}
			}
			putOwnedVPNFrameBatch(batch)
		}
	}()
'''
t = replace_once(t, old_tap_loop, new_tap_loop, "server TAP consumer")
t = replace_once(t, "connTxChan := make(chan []VPNFrame, 32)", "connTxChan := make(chan *VPNFrameBatch, 32)", "server conn channel")
t = replace_once(t, "backend := port.RegisterBackend(connTxChan, rttCache)", "backend := port.RegisterOwnedBackend(connTxChan, rttCache)", "server register owned")
t = replace_once(t, "port.UnregisterBackend(connTxChan)", "port.UnregisterOwnedBackend(connTxChan)", "server unregister owned")
t = replace_once(t, "case frames := <-connTxChan:", "case batch := <-connTxChan:", "server writer receive")
t = replace_once(t, "queuedPayload += vpnFrameBatchBytes(frames)", "queuedPayload += batch.Bytes", "server writer bytes")
t = replace_once(t, "appendOwnedFrameBatchStreamWithScratch(sendBuffer, frames, icTx, &txAEADScratch)", "appendOwnedVPNFrameBatchStreamWithScratch(sendBuffer, batch, icTx, &txAEADScratch)", "server writer consume")
t = replace_once(t, "case frames = <-connTxChan:", "case batch = <-connTxChan:", "server writer drain")
write(path, t)


# Add focused ownership tests + accounting benchmark.
test = r'''package main

import (
	"context"
	"testing"
	"time"
)

var vpnBatchBenchSink uint64

func TestOwnedVPNFrameBatchTransferPreservesIdentityAndBytes(t *testing.T) {
	rtt := uint32(1)
	ch := make(chan *VPNFrameBatch, 1)
	b := &Backend{ownedCh: ch, rttCache: &rtt}
	batch := getOwnedVPNFrameBatch()
	payload := getFrameAtLeast(1400)[:1400]
	ptr := &payload[0]
	appendOwnedVPNFrame(batch, VPNFrame{Seq: 7, Data: payload})
	wantBatch := batch

	if !tryQueueOwnedBatch(b, batch) {
		freeOwnedVPNFrameBatch(batch)
		t.Fatal("owned batch queue unexpectedly full")
	}
	got := <-ch
	if got != wantBatch {
		t.Fatal("production owned channel copied/replaced the batch object")
	}
	if got.Bytes != 1400 || len(got.Frames) != 1 || got.Frames[0].Seq != 7 {
		t.Fatalf("unexpected owned batch: bytes=%d frames=%d", got.Bytes, len(got.Frames))
	}
	if &got.Frames[0].Data[0] != ptr {
		t.Fatal("payload backing buffer changed across ownership transfer")
	}
	freeOwnedVPNFrameBatch(got)
}

func TestAsyncPortOwnedBackendCarriesAuthoritativeBytes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := NewAsyncPort(ctx, "owned-batch-bytes")
	rtt := uint32(1)
	ch := make(chan *VPNFrameBatch, 4)
	p.RegisterOwnedBackend(ch, &rtt)
	defer p.UnregisterOwnedBackend(ch)

	payload := getFrameAtLeast(1379)[:1379]
	if err := p.WriteOwnedFrame(payload); err != nil {
		t.Fatal(err)
	}
	select {
	case batch := <-ch:
		if batch.Bytes != 1379 {
			t.Fatalf("batch.Bytes=%d, want 1379", batch.Bytes)
		}
		if vpnFrameBatchBytes(batch.Frames) != batch.Bytes {
			t.Fatal("authoritative batch byte count diverged from frame contents")
		}
		freeOwnedVPNFrameBatch(batch)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for owned batch")
	}
}

func BenchmarkVPNFrameBatchAccounting(b *testing.B) {
	frames := make([]VPNFrame, 64)
	payload := make([]byte, 1400)
	var total uint64
	for i := range frames {
		frames[i] = VPNFrame{Seq: uint32(i + 1), Data: payload}
		total += uint64(len(payload))
	}
	batch := &VPNFrameBatch{Frames: frames, Bytes: total}

	b.Run("Scan64", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			vpnBatchBenchSink = vpnFrameBatchBytes(frames)
		}
	})
	b.Run("Metadata", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			vpnBatchBenchSink = batch.Bytes
		}
	})
}
'''
write("vpn_batch_ownership_test.go", test)

print("VPNFrameBatch ownership P0 patch applied")
