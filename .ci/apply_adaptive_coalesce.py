from pathlib import Path

p = Path("client.go")
s = p.read_text()
old = '''\t\t\t// Interactive bursts get one very short coalescing opportunity. Under
\t\t\t// sustained load p.ch is already non-empty, so the hot bulk path never sleeps.
\t\t\tif len(p.ch) == 0 && batchBytes < MaxBatchBytes {
\t\t\t\ttime.Sleep(150 * time.Microsecond)
\t\t\t}
'''
new = '''\t\t\t// Sparse bursts get an adaptive coalescing opportunity before we snapshot
\t\t\t// and drain p.ch. Tiny one-frame bursts may wait up to 500us so later TAP
\t\t\t// frames can fill the batch naturally; medium batches wait less, while
\t\t\t// sustained traffic (queue already non-empty) never sleeps here.
\t\t\tif len(p.ch) == 0 && batchBytes < MaxBatchBytes {
\t\t\t\tif delay := streamCoalesceDelay(batchBytes); delay > 0 {
\t\t\t\t\ttime.Sleep(delay)
\t\t\t\t}
\t\t\t}
'''
if old not in s:
    raise SystemExit("client.go coalescing anchor not found")
s = s.replace(old, new, 1)
p.write_text(s)
