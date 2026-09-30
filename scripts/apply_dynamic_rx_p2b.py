#!/usr/bin/env python3
from pathlib import Path

p = Path("client.go")
text = p.read_text()
old = '''\t\tcase reset := <-p.resetEpoch:
\t\t\tp.txSeq = 0
\t\t\tp.parityNext = 0
\t\t\tp.dataNext = 0
\t\t\tp.exhausted.Store(false)
\t\t\tif reset.k >= fecMinGroup {
\t\t\t\tp.encoder = newFECEncoder(reset.k, reset.ic)
\t\t\t} else {
\t\t\t\tp.encoder = nil
\t\t\t}
\t\t\tclose(reset.done)
'''
new = '''\t\tcase reset := <-p.resetEpoch:
\t\t\tp.txSeq = 0
\t\t\tp.parityNext = 0
\t\t\tp.dataNext = 0
\t\t\tp.exhausted.Store(false)
\t\t\tif reset.k >= fecMinGroup {
\t\t\t\tp.encoder = newFECEncoder(reset.k, reset.ic)
\t\t\t} else {
\t\t\t\tp.encoder = nil
\t\t\t}
\t\t\t// Fence generations are scoped to the sequence/key epoch because a new
\t\t\t// encoder starts generation numbering from one. Backends can survive an
\t\t\t// epoch reset, so clear their remembered generation or the first new
\t\t\t// SUSPEND/RESUME could be mistaken for an already-queued old fence.
\t\t\tp.backendsMu.RLock()
\t\t\tfor _, b := range p.backends {
\t\t\t\tif b != nil {
\t\t\t\t\tb.fecFenceGen.Store(0)
\t\t\t\t}
\t\t\t}
\t\t\tp.backendsMu.RUnlock()
\t\t\tclose(reset.done)
'''
count = text.count(old)
if count != 1:
    raise SystemExit(f"client.go: expected resetEpoch block exactly once, got {count}")
p.write_text(text.replace(old, new, 1))
print("epoch-scoped backend FEC fence generation reset applied")
