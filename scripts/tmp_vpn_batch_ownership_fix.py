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
print("dispatchBatch compatibility wrapper applied")
