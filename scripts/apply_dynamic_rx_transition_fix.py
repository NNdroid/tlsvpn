#!/usr/bin/env python3
from pathlib import Path

p = Path("fec.go")
text = p.read_text()
old = '''\tif !multipath {
\t\t// 2 -> 1: a partially accumulated group is abandoned. The RX bypass fence
\t\t// must rewind to that group's arithmetic start, not merely firstSeq.
\t\tboundary := fecGroupStart(firstSeq, e.k)
\t\tif len(e.seqs) != 0 {
\t\t\tboundary = e.seqs[0]
\t\t}
\t\te.multipath = false
\t\tif len(e.seqs) != 0 || e.activeLen != 0 {
\t\t\te.reset()
\t\t}
\t\te.armed = false
\t\te.publishModeControl(fecControlSuspend, boundary)
\t\treturn
\t}

\t// 1 -> 2: sequence numbers advanced while XOR work was suppressed. Resume
\t// only at the next complete arithmetic group. A zero boundary means sequence
\t// exhaustion leaves no complete group in this epoch, so no RESUME is sent.
\te.multipath = true
\te.armed = false
\tif boundary := fecNextGroupStart(firstSeq, e.k); boundary != 0 {
\t\te.publishModeControl(fecControlResume, boundary)
\t}
'''
new = '''\tif !multipath {
\t\t// The constructor defaults to multipath=true so direct encoder tests keep
\t\t// their historical immediate-encoding semantics. If the very first real
\t\t// dispatch has only one backend, however, no multipath traffic has existed
\t\t// yet and RX has no dynamic state to suspend. Enter suppressed mode without
\t\t// emitting a synthetic startup SUSPEND.
\t\thadTraffic := e.lastSeq != 0 || len(e.seqs) != 0
\t\tboundary := fecGroupStart(firstSeq, e.k)
\t\tif len(e.seqs) != 0 {
\t\t\tboundary = e.seqs[0]
\t\t}
\t\te.multipath = false
\t\tif len(e.seqs) != 0 || e.activeLen != 0 {
\t\t\te.reset()
\t\t}
\t\te.armed = false
\t\tif hadTraffic {
\t\t\te.publishModeControl(fecControlSuspend, boundary)
\t\t}
\t\treturn
\t}

\t// A startup 1 -> 2 transition does not require RESUME if no SUSPEND was ever
\t// published: RX stayed conservatively active the whole time. Once a genuine
\t// multipath -> single-path SUSPEND exists, later 1 -> 2 transitions must close
\t// that bypass window at the next complete arithmetic group boundary.
\te.multipath = true
\te.armed = false
\tif e.controlGeneration == 0 {
\t\treturn
\t}
\tif boundary := fecNextGroupStart(firstSeq, e.k); boundary != 0 {
\t\te.publishModeControl(fecControlResume, boundary)
\t}
'''
count = text.count(old)
if count != 1:
    raise SystemExit(f"fec.go: expected transition block exactly once, got {count}")
p.write_text(text.replace(old, new, 1))
print("dynamic transition fencing fix applied")
