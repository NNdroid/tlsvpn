#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one match, got {count}\n--- needle ---\n{old}")
    p.write_text(text.replace(old, new, 1))


def replace_n(path: str, old: str, new: str, expected: int) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != expected:
        raise SystemExit(f"{path}: expected {expected} matches, got {count}\n--- needle ---\n{old}")
    p.write_text(text.replace(old, new))


# Cold reorder progress snapshot. No atomic write is added to Insert/drain hot paths.
replace_once(
    "buffer.go",
    '''func (rb *ReorderBuffer) Stats() ReorderBufferStats {
\treturn ReorderBufferStats{
\t\tGapEvents:      rb.gapEvents.Load(),
\t\tTimeoutFlushes: rb.timeoutFlushes.Load(),
\t\tSkippedFrames:  rb.skippedFrames.Load(),
\t\tDroppedFrames:  rb.droppedFrames.Load(),
\t}
}

// Insert 将收到的包推入缓冲区
''',
    '''func (rb *ReorderBuffer) Stats() ReorderBufferStats {
\treturn ReorderBufferStats{
\t\tGapEvents:      rb.gapEvents.Load(),
\t\tTimeoutFlushes: rb.timeoutFlushes.Load(),
\t\tSkippedFrames:  rb.skippedFrames.Load(),
\t\tDroppedFrames:  rb.droppedFrames.Load(),
\t}
}

// ExpectedSeqSnapshot is a cold-path progress probe for FEC cleanup. Keep the
// existing mutex as the source of truth rather than publishing expectedSeq on
// every Insert/drain: dynamic topology transitions and parity are sparse, while
// normal RX data must not pay another atomic store per packet.
func (rb *ReorderBuffer) ExpectedSeqSnapshot() uint32 {
\trb.mu.Lock()
\tseq := rb.expectedSeq
\trb.mu.Unlock()
\treturn seq
}

// Insert 将收到的包推入缓冲区
''',
)

# Decoder cleanup state. controlMu serializes apply+cleanup across physical RX
# goroutines; cleanup/retired boundaries are monotonic within one sequence epoch.
replace_once(
    "fec.go",
    '''type fecDecoder struct {
\tmu           sync.Mutex
\tk            int
\tfullMask     uint64
\tstaticSingle atomic.Bool // configured topology is exactly one physical path: RX FEC has no recovery value
\tfence        fecRXFenceState
\tic           *innerCipher
''',
    '''type fecDecoder struct {
\tmu            sync.Mutex
\tcontrolMu     sync.Mutex
\tk             int
\tfullMask      uint64
\tstaticSingle  atomic.Bool // configured topology is exactly one physical path: RX FEC has no recovery value
\tfence         fecRXFenceState
\tcleanupBefore atomic.Uint32 // highest SUSPEND boundary whose older groups may retire after reorder crosses it
\tretiredBefore atomic.Uint32 // groups below this boundary can no longer affect ordered output
\treorderProgress func() uint32 // write-once before decoder publication; cold-path callback
\tic            *innerCipher
''',
)

replace_once(
    "fec.go",
    '''func NewFECDecoder(k int, ic *innerCipher, out func(seq uint32, frame []byte)) *fecDecoder {
\tk = clampFecGroup(k)
\tfullMask := ^uint64(0)
\tif k < 64 {
\t\tfullMask = (uint64(1) << uint(k)) - 1
\t}
\treturn &fecDecoder{
\t\tk:          k,
\t\tfullMask:   fullMask,
\t\tic:         ic,
\t\tout:        out,
\t\tgroups:     make(map[uint32]*fecGroupState, 64),
\t\tgroupOrder: make([]uint32, 0, fecMaxPendingGroups+64),
\t\tspares:     make([]*fecGroupState, 0, fecMaxPendingGroups),
\t}
}
''',
    '''func NewFECDecoder(k int, ic *innerCipher, out func(seq uint32, frame []byte)) *fecDecoder {
\tk = clampFecGroup(k)
\tfullMask := ^uint64(0)
\tif k < 64 {
\t\tfullMask = (uint64(1) << uint(k)) - 1
\t}
\treturn &fecDecoder{
\t\tk:          k,
\t\tfullMask:   fullMask,
\t\tic:         ic,
\t\tout:        out,
\t\tgroups:     make(map[uint32]*fecGroupState, 64),
\t\tgroupOrder: make([]uint32, 0, fecMaxPendingGroups+64),
\t\tspares:     make([]*fecGroupState, 0, fecMaxPendingGroups),
\t}
}

// SetReorderProgress installs a cold-path ordered-delivery progress probe. Call
// this before publishing the decoder to connection RX goroutines.
func (d *fecDecoder) SetReorderProgress(fn func() uint32) { d.reorderProgress = fn }
''',
)

replace_once(
    "fec.go",
    '''// Reset 清空全部组状态（服务端会话重置/客户端换会话时调用）
func (d *fecDecoder) Reset() {
\td.mu.Lock()
\tfor _, g := range d.groups {
\t\td.releaseLocked(g)
\t}
\tclear(d.groups)
\td.groupOrder = d.groupOrder[:0]
\td.groupHead = 0
\tfor i := range d.doneRing { // 数组不能用 clear()，显式归零
\t\td.doneRing[i] = 0
\t}
\td.mu.Unlock()
\t// Epoch changes restart sender fence generations from one. Keep the old
\t// window until decoder groups are cleared, then atomically return to active.
\td.fence.Reset()
}
''',
    '''// Reset 清空全部组状态（服务端会话重置/客户端换会话时调用）
func (d *fecDecoder) Reset() {
\td.controlMu.Lock()
\td.mu.Lock()
\tfor _, g := range d.groups {
\t\td.releaseLocked(g)
\t}
\tclear(d.groups)
\td.groupOrder = d.groupOrder[:0]
\td.groupHead = 0
\tfor i := range d.doneRing { // 数组不能用 clear()，显式归零
\t\td.doneRing[i] = 0
\t}
\td.cleanupBefore.Store(0)
\td.retiredBefore.Store(0)
\td.mu.Unlock()
\t// Epoch changes restart sender fence generations from one. Serialize reset
\t// with control apply so an old cleanup cannot run after the fresh epoch.
\td.fence.Reset()
\td.controlMu.Unlock()
}

func atomicMaxUint32(v *atomic.Uint32, next uint32) {
\tfor next != 0 {
\t\told := v.Load()
\t\tif next <= old || v.CompareAndSwap(old, next) {
\t\t\treturn
\t\t}
\t}
}

// handleModeControl serializes accepted generation changes with their group-map
// cleanup. This prevents a slower old control goroutine from deleting groups
// after a newer generation has already resumed FEC on another TCP stream.
func (d *fecDecoder) handleModeControl(ctrl fecModeControl) {
\td.controlMu.Lock()
\tdefer d.controlMu.Unlock()
\tif !d.fence.Apply(ctrl) {
\t\treturn
\t}
\tfrom, until := d.fence.Window()
\tif from == 0 {
\t\treturn
\t}
\tatomicMaxUint32(&d.cleanupBefore, from)
\td.mu.Lock()
\td.dropGroupsInRangeLocked(from, until)
\td.maybeRetireOldGroupsLocked()
\td.mu.Unlock()
}

// dropGroupsInRangeLocked releases decoder bookkeeping only. These groups are
// abandoned by sender topology, not confirmed packet loss: do not mark done and
// do not increment the FEC lost counter.
func (d *fecDecoder) dropGroupsInRangeLocked(from, until uint32) {
\tif from == 0 {
\t\treturn
\t}
\tchanged := false
\tfor start, g := range d.groups {
\t\tif start < from || (until != 0 && start >= until) {
\t\t\tcontinue
\t\t}
\t\td.releaseLocked(g)
\t\tdelete(d.groups, start)
\t\tchanged = true
\t}
\tif changed {
\t\td.pruneGroupOrderLocked()
\t}
}

func (d *fecDecoder) maybeRetireOldGroupsLocked() {
\tboundary := d.cleanupBefore.Load()
\tif boundary == 0 || d.retiredBefore.Load() >= boundary || d.reorderProgress == nil {
\t\treturn
\t}
\texpected := d.reorderProgress()
\tif expected == 0 || expected < boundary {
\t\treturn
\t}
\t// Publish retirement while holding d.mu. OnData re-checks retiredBefore after
\t// taking the same mutex, so late old traffic cannot recreate removed state.
\td.retiredBefore.Store(boundary)
\tchanged := false
\tfor start, g := range d.groups {
\t\tif start >= boundary {
\t\t\tcontinue
\t\t}
\t\td.releaseLocked(g)
\t\tdelete(d.groups, start)
\t\tchanged = true
\t}
\tif changed {
\t\td.pruneGroupOrderLocked()
\t}
}

// cleanupByReorderProgress is intentionally sparse. Normal active data never
// calls the reorder callback; bypassed data probes only once per 256 sequence
// numbers, while controls/parity may probe on their already-cold paths.
func (d *fecDecoder) cleanupByReorderProgress() {
\tboundary := d.cleanupBefore.Load()
\tif boundary == 0 || d.retiredBefore.Load() >= boundary || d.reorderProgress == nil {
\t\treturn
\t}
\td.mu.Lock()
\td.maybeRetireOldGroupsLocked()
\td.mu.Unlock()
}
''',
)

replace_once(
    "fec.go",
    '''\tif seq == 0 {
\t\t// Unknown seq=0 controls remain backward-compatible: old peers drop them
\t\t// in reorder, while new peers consume only the strict 0xFD/versioned form.
\t\tif ctrl, ok := parseFECModeControl(frame); ok {
\t\t\td.fence.Apply(ctrl)
\t\t}
\t\treturn
\t}
\tif d.staticSingle.Load() || d.fence.BypassData(seq) {
\t\treturn
\t}
\tstart := d.groupStartOf(seq)
\td.mu.Lock()
\tdefer d.mu.Unlock()
\t// Re-check the atomic window after acquiring d.mu. A SUSPEND may have raced
\t// the first check; without this guard that frame could still allocate/XOR a
\t// group after the sender declared it permanently parity-less.
\tif d.staticSingle.Load() || d.fence.BypassData(seq) || d.isDoneLocked(start) {
\t\treturn
\t}
''',
    '''\tif seq == 0 {
\t\t// Unknown seq=0 controls remain backward-compatible: old peers drop them
\t\t// in reorder, while new peers consume only the strict 0xFD/versioned form.
\t\tif ctrl, ok := parseFECModeControl(frame); ok {
\t\t\td.handleModeControl(ctrl)
\t\t}
\t\treturn
\t}
\tif d.staticSingle.Load() {
\t\treturn
\t}
\tif d.fence.BypassData(seq) {
\t\tif seq&0xff == 0 {
\t\t\td.cleanupByReorderProgress()
\t\t}
\t\treturn
\t}
\tif retired := d.retiredBefore.Load(); retired != 0 && seq < retired {
\t\treturn
\t}
\tstart := d.groupStartOf(seq)
\td.mu.Lock()
\tdefer d.mu.Unlock()
\t// Re-check the atomic window/retirement boundary after acquiring d.mu. A
\t// SUSPEND cleanup may have raced the first fast-path check.
\tretired := d.retiredBefore.Load()
\tif d.staticSingle.Load() || d.fence.BypassData(seq) || (retired != 0 && seq < retired) || d.isDoneLocked(start) {
\t\treturn
\t}
''',
)

# Parity is still conservative, but it is a useful sparse cleanup trigger and
# must refuse groups whose ordered-output horizon has already passed.
replace_once(
    "fec.go",
    '''\tif start == 0 || k != d.k || (start-1)%uint32(d.k) != 0 {
\t\treturn
\t}
\tdescLen := 6 + 4*k
''',
    '''\tif start == 0 || k != d.k || (start-1)%uint32(d.k) != 0 {
\t\treturn
\t}
\td.cleanupByReorderProgress()
\tif retired := d.retiredBefore.Load(); retired != 0 && start < retired {
\t\treturn
\t}
\tdescLen := 6 + 4*k
''',
)

replace_once(
    "fec.go",
    '''\td.mu.Lock()
\tdefer d.mu.Unlock()
\tif d.staticSingle.Load() || d.isDoneLocked(start) {
\t\tputFECLens(lens)
\t\treturn
\t}
''',
    '''\td.mu.Lock()
\tdefer d.mu.Unlock()
\tretired := d.retiredBefore.Load()
\tif d.staticSingle.Load() || (retired != 0 && start < retired) || d.isDoneLocked(start) {
\t\tputFECLens(lens)
\t\treturn
\t}
''',
)

replace_once(
    "fec.go",
    '''\tg.parity = pb
\td.tryRecoverLocked(g)
}
''',
    '''\tg.parity = pb
\td.tryRecoverLocked(g)
\t// Recovery inserts into ReorderBuffer while d.mu is held and may advance the
\t// ordered horizon across cleanupBefore, so retire old groups immediately on
\t// this already-cold parity path when that happens.
\td.maybeRetireOldGroupsLocked()
}
''',
)

# Wire the cold reorder progress callback before each decoder is published.
replace_once(
    "client.go",
    '''\t\t\tc.fecDec = NewFECDecoder(c.fecNegotiated, fecRx, c.rxReorder.Insert)
\t\t\tc.fecDec.SetStaticSinglePath(isStaticSinglePathTopology(lv.connsCount))
\t\t\tc.txPort.AttachFEC(c.fecNegotiated, fecTx)
''',
    '''\t\t\tc.fecDec = NewFECDecoder(c.fecNegotiated, fecRx, c.rxReorder.Insert)
\t\t\tc.fecDec.SetReorderProgress(c.rxReorder.ExpectedSeqSnapshot)
\t\t\tc.fecDec.SetStaticSinglePath(isStaticSinglePathTopology(lv.connsCount))
\t\t\tc.txPort.AttachFEC(c.fecNegotiated, fecTx)
''',
)

replace_once(
    "server.go",
    '''\tif session.FecEncK > 0 {
\t\tsession.FecDec = NewFECDecoder(session.FecEncK, fecRx, session.RxReorder.Insert)
\t\tsession.Port.ResetEpoch(session.FecEncK, fecTx)
''',
    '''\tif session.FecEncK > 0 {
\t\tsession.FecDec = NewFECDecoder(session.FecEncK, fecRx, session.RxReorder.Insert)
\t\tsession.FecDec.SetReorderProgress(session.RxReorder.ExpectedSeqSnapshot)
\t\tsession.Port.ResetEpoch(session.FecEncK, fecTx)
''',
)

replace_once(
    "server.go",
    '''\t\tif fecEncK > 0 {
\t\t\tsession.FecDec = NewFECDecoder(fecEncK, fecRx, session.RxReorder.Insert)
\t\t\t// Current Go clients always advertise BrutalGroups/BrutalConns as the
''',
    '''\t\tif fecEncK > 0 {
\t\t\tsession.FecDec = NewFECDecoder(fecEncK, fecRx, session.RxReorder.Insert)
\t\t\tsession.FecDec.SetReorderProgress(session.RxReorder.ExpectedSeqSnapshot)
\t\t\t// Current Go clients always advertise BrutalGroups/BrutalConns as the
''',
)

print("dynamic RX FEC P2c cleanup patch applied")
