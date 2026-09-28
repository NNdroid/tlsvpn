#!/usr/bin/env python3
from pathlib import Path
import re


def replace_once(s, old, new, label):
    n = s.count(old)
    if n != 1:
        raise SystemExit(f'{label}: expected 1, got {n}')
    return s.replace(old, new, 1)


def regex_once(s, pat, repl, label):
    out, n = re.subn(pat, repl, s, count=1, flags=re.S)
    if n != 1:
        raise SystemExit(f'{label}: expected 1 regex match, got {n}')
    return out

# Restore the proven AsyncPort aggregation cadence. Persistent packing belongs
# above it and should carry only the small remainder between those batches.
p = Path('client.go')
s = p.read_text()
anchor = '''\t\t\tbatch = append(batch, VPNFrame{Seq: seq, Data: frame})
\t\t\tbatchBytes += len(frame)

\t\t\tqueueLen := len(p.ch)
'''
repl = '''\t\t\tbatch = append(batch, VPNFrame{Seq: seq, Data: frame})
\t\t\tbatchBytes += len(frame)

\t\t\t// Keep the proven aggregation cadence from main. The connection-level
\t\t\t// stream packer carries only the sub-MSS tail across these batches.
\t\t\tif len(p.ch) == 0 && batchBytes < MaxBatchBytes {
\t\t\t\ttime.Sleep(150 * time.Microsecond)
\t\t\t}

\t\t\tqueueLen := len(p.ch)
'''
s = replace_once(s, anchor, repl, 'restore AsyncPort coalescing')
p.write_text(s)

# Add a downward-aligned prefix helper. It keeps one application TLS write in
# the same <=16KiB size class as main but leaves only a sub-MSS carry tail.
p = Path('stream_padding.go')
s = p.read_text()
old = '''func (p *tunnelStreamPacker) fullChunkSize() int {
\treturn streamMaxAlignedTLSPlaintext(p.mss)
}
'''
new = '''func (p *tunnelStreamPacker) fullChunkSize() int {
\treturn streamMaxAlignedTLSPlaintext(p.mss)
}

// alignedPrefixSize returns the largest MSS-aligned plaintext prefix already
// present in the stream. It deliberately requires at least two outer segments:
// a lone ~1500B inner frame must not be split into one full record plus a tiny
// immediate tail. The unsent remainder is <1 MSS and naturally joins the next
// producer batch.
func (p *tunnelStreamPacker) alignedPrefixSize() int {
\tavail := p.available()
\tif avail <= 0 {
\t\treturn 0
\t}
\tmaxTarget := streamMaxAlignedTLSPlaintext(p.mss)
\tif avail >= maxTarget {
\t\treturn maxTarget
\t}
\tsegs := (avail + tlsRecordOverheadReserve) / p.mss
\tif segs < 2 {
\t\treturn 0
\t}
\ttarget := segs*p.mss - tlsRecordOverheadReserve
\tif target <= 0 || target > avail {
\t\treturn 0
\t}
\treturn target
}
'''
s = replace_once(s, old, new, 'alignedPrefixSize')
p.write_text(s)

# Replace both client/server fixed-max loops with downward aligned prefix loops.
for name in ('client.go', 'server.go'):
    p = Path(name)
    s = p.read_text()
    s = s.replace('''\t\t\t\t\tchunkSize := streamPacker.fullChunkSize()
\t\t\t\t\tfor streamPacker.available() >= chunkSize {
''', '''\t\t\t\t\tchunkSize := streamPacker.alignedPrefixSize()
\t\t\t\t\tfor chunkSize > 0 {
''')
    # Recompute after each consumption, because a >16KiB backlog may yield
    # several efficient TLS writes while a normal ~12KiB batch yields one.
    needle = '''\t\t\t\t\t\tdailyTraffic.Add(uint64(chunkSize), 0)
\t\t\t\t\t}
'''
    if name == 'client.go':
        replacement = '''\t\t\t\t\t\tdailyTraffic.Add(uint64(chunkSize), 0)
\t\t\t\t\t\tchunkSize = streamPacker.alignedPrefixSize()
\t\t\t\t\t}
'''
    else:
        needle = '''\t\t\t\t\t\tdailyTraffic.Add(0, uint64(chunkSize))
\t\t\t\t\t}
'''
        replacement = '''\t\t\t\t\t\tdailyTraffic.Add(0, uint64(chunkSize))
\t\t\t\t\t\tchunkSize = streamPacker.alignedPrefixSize()
\t\t\t\t\t}
'''
    s = replace_once(s, needle, replacement, f'{name} recompute aligned prefix')
    p.write_text(s)

# Update focused regression: two 1500B frames should emit a 2-MSS prefix and
# leave the remainder of frame 2 for the next batch.
p = Path('persistent_stream_test.go')
s = p.read_text()
pat = r'''func TestPersistentStreamChunkMaySplitVPNFrame\(t \*testing\.T\) \{.*?\n\}\n\nfunc TestSparseMTUFrameDoesNotPayLargeCoverGap'''
repl = '''func TestPersistentStreamChunkMaySplitVPNFrame(t *testing.T) {
\told := setPadMode(padModeBucket)
\tdefer setPadMode(old)

\tp := newTunnelStreamPacker(paddingRecordLimitForMSS(1440))
\tframes := getVPNFrameBatch(2)
\tfor i := range frames {
\t\tframes[i] = VPNFrame{Seq: uint32(i + 1), Data: cloneFrame(make([]byte, 1500))}
\t}
\tp.appendOwnedFrames(frames, nil)

\ttarget := p.alignedPrefixSize()
\tif want := 2*1440 - tlsRecordOverheadReserve; target != want {
\t\tt.Fatalf("downward MSS target=%d want=%d", target, want)
\t}
\tif got := (target + tlsRecordOverheadReserve) % 1440; got != 0 {
\t\tt.Fatalf("aligned prefix remainder=%d", got)
\t}
\t// Each frame is 1510B. A 2848B prefix contains all of frame 1 and 1338B
\t// of frame 2, proving the transport boundary cuts through a logical frame.
\tcompleted := p.consume(target)
\tif completed != 1 {
\t\tt.Fatalf("aligned prefix should finish exactly one frame: completed=%d", completed)
\t}
\tif p.available() != 2*1510-target {
\t\tt.Fatalf("unexpected carry tail: got=%d want=%d", p.available(), 2*1510-target)
\t}
}

func TestSparseMTUFrameDoesNotPayLargeCoverGap'''
s = regex_once(s, pat, repl, 'persistent stream focused test')
p.write_text(s)
