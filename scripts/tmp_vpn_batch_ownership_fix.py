#!/usr/bin/env python3
from pathlib import Path

p = Path("client.go")
t = p.read_text()

old = "func (p *AsyncPort) dispatchBatch(batch *VPNFrameBatch) {"
new = "func (p *AsyncPort) dispatchOwnedBatch(batch *VPNFrameBatch) {"
if t.count(old) != 1:
    raise SystemExit(f"owned dispatch signature: expected 1 match, got {t.count(old)}")
t = t.replace(old, new, 1)

old_call = "\t\t\tp.dispatchBatch(batch)\n\t\t\tbatch = getOwnedVPNFrameBatch()"
new_call = "\t\t\tp.dispatchOwnedBatch(batch)\n\t\t\tbatch = getOwnedVPNFrameBatch()"
if t.count(old_call) != 1:
    raise SystemExit(f"owned dispatch call: expected 1 match, got {t.count(old_call)}")
t = t.replace(old_call, new_call, 1)

marker = "const backendRTTHysteresisMin = 5_000"
wrapper = '''// dispatchBatch retains the historical raw-slice API for tests/cold callers.\n// It converts once into the ownership object, transfers payload ownership, and\n// never participates in the production AsyncPort.run hot path.\nfunc (p *AsyncPort) dispatchBatch(batch []VPNFrame, batchBytes int) {\n\towned := getOwnedVPNFrameBatch()\n\towned.Frames = append(owned.Frames, batch...)\n\towned.Bytes = uint64(batchBytes)\n\tfor i := range batch {\n\t\tbatch[i].Data = nil\n\t}\n\tp.dispatchOwnedBatch(owned)\n}\n\n'''
if t.count(marker) != 1:
    raise SystemExit(f"compat wrapper marker: expected 1 match, got {t.count(marker)}")
t = t.replace(marker, wrapper + marker, 1)
p.write_text(t)

# Adaptive scheduling must inspect whichever queue the backend actually owns.
p = Path("adaptive_multipath.go")
t = p.read_text()
old = "b == nil || cap(b.ch) == 0 || len(b.ch) >= cap(b.ch)-2"
count = t.count(old)
if count != 2:
    raise SystemExit(f"adaptive queue checks: expected 2 matches, got {count}")
t = t.replace(old, "b == nil || b.queueCap() == 0 || b.queueLen() >= b.queueCap()-2")
p.write_text(t)

# Add a focused regression test proving the adaptive scheduler sees production
# owned queues; use warmed paths so this test is independent of existing RTT
# fair-start policy tests.
p = Path("vpn_batch_ownership_test.go")
t = p.read_text()
extra = r'''
func TestAdaptiveSchedulerOwnedBackendQueues(t *testing.T) {
	p := &AsyncPort{}
	fastRTT := uint32(800)
	slowRTT := uint32(900)
	fast := &Backend{ownedCh: make(chan *VPNFrameBatch, 32), rttCache: &fastRTT}
	slow := &Backend{ownedCh: make(chan *VPNFrameBatch, 32), rttCache: &slowRTT}
	fast.rateBytesPerSec.Store(25_000_000)
	slow.rateBytesPerSec.Store(25_000_000)

	got := p.pickAdaptiveBackend([]*Backend{fast, slow}, 0, 12*1024)
	if got != fast {
		t.Fatalf("owned backend scheduler picked %p, want fast %p", got, fast)
	}
	if !fast.active.Load() || p.activePaths.Load() != 1 {
		t.Fatalf("owned backend was not admitted to active set: active=%v paths=%d", fast.active.Load(), p.activePaths.Load())
	}
}
'''
if "func TestAdaptiveSchedulerOwnedBackendQueues" not in t:
    t += extra
p.write_text(t)

print("dispatch compatibility and owned-queue scheduler fixes applied")
