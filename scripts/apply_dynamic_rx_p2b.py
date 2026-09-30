#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one match, got {count}\n--- needle ---\n{old}")
    p.write_text(text.replace(old, new, 1))


# Receiver fence state can be reused across session epochs, so Reset must clear
# both the hot atomic window and the generation ordering state.
replace_once(
    "fec_control.go",
    '''func (s *fecRXFenceState) Generation() uint64 {
\ts.mu.Lock()
\tdefer s.mu.Unlock()
\treturn s.generation
}

func (s *fecRXFenceState) BypassData(seq uint32) bool {
''',
    '''func (s *fecRXFenceState) Generation() uint64 {
\ts.mu.Lock()
\tdefer s.mu.Unlock()
\treturn s.generation
}

func (s *fecRXFenceState) Reset() {
\ts.mu.Lock()
\ts.generation = 0
\ts.window.Store(0)
\ts.mu.Unlock()
}

func (s *fecRXFenceState) BypassData(seq uint32) bool {
''',
)

# Encoder: remember the last data seq, publish topology-transition controls, and
# keep the latest control available for per-backend prepend at dispatch time.
replace_once(
    "fec.go",
    '''\t// multipath/armed 只由 AsyncPort.run goroutine 修改。直接构造 encoder 的
\t// 单元测试/benchmark 默认保持旧语义（立即编码）；数据面在只有一个物理
\t// backend 时显式切到 suppressed，恢复多路径后再等待下一个完整 K 组边界。
\tmultipath bool
\tarmed     bool
}
''',
    '''\t// multipath/armed/lastSeq/control* 只由 AsyncPort.run goroutine 修改。
\t// 直接构造 encoder 的单元测试/benchmark 默认保持旧语义（立即编码）；
\t// 数据面在只有一个物理 backend 时显式切到 suppressed，恢复多路径后再
\t// 等待下一个完整 K 组边界。control 是最新 sender-authoritative RX fence。
\tmultipath        bool
\tarmed            bool
\tlastSeq          uint32
\tcontrolGeneration uint64
\tcontrol          fecModeControl
}
''',
)

replace_once(
    "fec.go",
    '''// ParitySent 已生成的校验帧总数
func (e *fecEncoder) ParitySent() uint64 { return atomic.LoadUint64(&e.paritySent) }

// setPhysicalPathCount 根据实际注册的物理 backend 数量启停 FEC 热路径。
''',
    '''// ParitySent 已生成的校验帧总数
func (e *fecEncoder) ParitySent() uint64 { return atomic.LoadUint64(&e.paritySent) }

func (e *fecEncoder) publishModeControl(op byte, boundary uint32) {
\tif boundary == 0 || (op != fecControlSuspend && op != fecControlResume) {
\t\treturn
\t}
\te.controlGeneration++
\tif e.controlGeneration == 0 { // practically unreachable uint64 wrap guard
\t\te.controlGeneration = 1
\t}
\te.control = fecModeControl{Generation: e.controlGeneration, Op: op, Boundary: boundary}
}

func (e *fecEncoder) currentModeControl() (fecModeControl, bool) {
\tif e.control.Generation == 0 || e.control.Boundary == 0 {
\t\treturn fecModeControl{}, false
\t}
\treturn e.control, true
}

// setPhysicalPathCount 根据实际注册的物理 backend 数量启停 FEC 热路径。
''',
)

replace_once(
    "fec.go",
    '''func (e *fecEncoder) setPhysicalPathCount(paths int) {
\tmultipath := paths >= 2
\tif multipath == e.multipath {
\t\treturn
\t}
\te.multipath = multipath
\tif !multipath {
\t\t// 2 -> 1：任何未完成组都不能跨过 single-path 区间继续累计。
\t\tif len(e.seqs) != 0 || e.activeLen != 0 {
\t\t\te.reset()
\t\t}
\t\te.armed = false
\t\treturn
\t}

\t// 1 -> 2：全局数据 seq 已经继续前进；只在下一个固定 K 边界恢复。
\te.armed = false
}
''',
    '''func (e *fecEncoder) setPhysicalPathCount(paths int) {
\tmultipath := paths >= 2
\tif multipath == e.multipath {
\t\treturn
\t}

\t// The scheduler calls this before feeding the current dispatch into add(), so
\t// lastSeq is the previous dispatch's final data sequence. Therefore lastSeq+1
\t// is the exact first sequence governed by this topology transition.
\tfirstSeq := uint32(0)
\tif e.lastSeq != ^uint32(0) {
\t\tfirstSeq = e.lastSeq + 1
\t}

\tif !multipath {
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
}
''',
)

replace_once(
    "fec.go",
    '''func (e *fecEncoder) add(vf VPNFrame) []byte {
\tif len(vf.Data) == 0 {
\t\treturn nil
\t}
\tif !e.multipath {
''',
    '''func (e *fecEncoder) add(vf VPNFrame) []byte {
\tif len(vf.Data) == 0 {
\t\treturn nil
\t}
\tif vf.Seq != 0 {
\t\te.lastSeq = vf.Seq
\t}
\tif !e.multipath {
''',
)

# Decoder: seq=0 non-parity control frames already reach OnData on both client
# and server. Parse them there so no receive-loop changes are necessary. Dynamic
# bypass is intentionally data-only in P2b; parity remains conservative so it
# may arrive before RESUME on another TCP stream and wait for fenced data.
replace_once(
    "fec.go",
    '''\tfullMask     uint64
\tstaticSingle atomic.Bool // configured topology is exactly one physical path: RX FEC has no recovery value
\tic           *innerCipher
''',
    '''\tfullMask     uint64
\tstaticSingle atomic.Bool // configured topology is exactly one physical path: RX FEC has no recovery value
\tfence        fecRXFenceState
\tic           *innerCipher
''',
)

replace_once(
    "fec.go",
    '''func (d *fecDecoder) Reset() {
\td.mu.Lock()
\tdefer d.mu.Unlock()
\tfor _, g := range d.groups {
\t\td.releaseLocked(g)
\t}
\tclear(d.groups)
\td.groupOrder = d.groupOrder[:0]
\td.groupHead = 0
\tfor i := range d.doneRing { // 数组不能用 clear()，显式归零
\t\td.doneRing[i] = 0
\t}
}
''',
    '''func (d *fecDecoder) Reset() {
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
)

replace_once(
    "fec.go",
    '''// OnData 记录一个已解密的数据帧。frame 只读借用，不转移所有权。
func (d *fecDecoder) OnData(seq uint32, frame []byte) {
\tif len(frame) == 0 || seq == 0 || d.staticSingle.Load() {
\t\treturn
\t}
\tstart := d.groupStartOf(seq)
\td.mu.Lock()
\tdefer d.mu.Unlock()
\tif d.staticSingle.Load() || d.isDoneLocked(start) {
\t\treturn
\t}
''',
    '''// OnData 记录一个已解密的数据帧。frame 只读借用，不转移所有权。
func (d *fecDecoder) OnData(seq uint32, frame []byte) {
\tif len(frame) == 0 {
\t\treturn
\t}
\tif seq == 0 {
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
)

# Backend remembers which sender control generation is already queued ahead of
# its data. The atomic keeps tests/telemetry race-safe even though AsyncPort is
# the sole producer in production.
replace_once(
    "client.go",
    '''\tfecAssignedBytes   atomic.Uint64 // FEC parity payload bytes accepted by this backend
\tfecAssignedBatches atomic.Uint64 // FEC parity batches accepted by this backend
\tvirtualFinishNS    atomic.Int64  // scheduler-only service debt, published atomically for race safety
''',
    '''\tfecAssignedBytes   atomic.Uint64 // FEC parity payload bytes accepted by this backend
\tfecAssignedBatches atomic.Uint64 // FEC parity batches accepted by this backend
\tfecFenceGen        atomic.Uint64 // latest dynamic RX fence generation queued before data on this backend
\tvirtualFinishNS    atomic.Int64  // scheduler-only service debt, published atomically for race safety
''',
)

replace_once(
    "client.go",
    '''\t\tp.dropN(sendBatchToAny(backends, best, batch))
''',
    '''\t\tp.dropN(sendBatchToAnyFenced(p, backends, best, batch))
''',
)

replace_once(
    "client.go",
    '''\tp.dropN(sendBatchToAny(backends, dataBest, batch))
''',
    '''\tp.dropN(sendBatchToAnyFenced(p, backends, dataBest, batch))
''',
)

replace_once(
    "client.go",
    '''// sendBatchToAny 把数据 batch 的 payload 所有权转移给某个可写后端。
// 热路径先无阻塞尝试 preferred/其它连接；只有所有连接都满时才进入最多 5ms
// 的短退让。这样可以显著减少“分配 seq 后再丢 batch”造成的重排序号洞。
// 成功或最终失败后，调用方 batch 中的 Data 都会被置 nil。
func sendBatchToAny(backends []*Backend, preferred *Backend, batch []VPNFrame) int {
\tout := getVPNFrameBatch(len(batch))
\tcopy(out, batch)
\tfor i := range batch {
\t\tbatch[i].Data = nil
\t}
\toutBytes := vpnFrameBatchBytes(out)

\ttrySend := func(b *Backend) bool {
\t\tif b == nil {
\t\t\treturn false
\t\t}
\t\tb.addQueuedBytes(outBytes)
\t\tselect {
\t\tcase b.ch <- out:
\t\t\tb.assignedBytes.Add(outBytes)
\t\t\tb.assignedBatches.Add(1)
\t\t\treturn true
\t\tdefault:
\t\t\tb.completeQueuedBytes(outBytes)
\t\t\treturn false
\t\t}
\t}

\ttryAll := func() bool {
\t\tif trySend(preferred) {
\t\t\treturn true
\t\t}
\t\tfor _, b := range backends {
\t\t\tif b != preferred && trySend(b) {
\t\t\t\treturn true
\t\t\t}
\t\t}
\t\treturn false
\t}

\tif tryAll() {
\t\treturn 0
\t}

\t// 仅拥塞慢路径进入这里。5ms 远低于 50ms reorder skip deadline，
\t// 同时给 TLS writer 足够机会腾出一个 batch slot。
\tdeadline := time.Now().Add(5 * time.Millisecond)
\tfor time.Now().Before(deadline) {
\t\ttime.Sleep(50 * time.Microsecond)
\t\tif tryAll() {
\t\t\treturn 0
\t\t}
\t}

\tfreeFrames(out)
\tputVPNFrameBatch(out)
\treturn len(out)
}
''',
    '''// sendBatchToAnyFenced 把数据 batch 的 payload 所有权转移给实际可写后端。
// 当动态 FEC 模式刚发生切换时，目标 backend 的第一批 data 会在同一个 channel
// batch 前部 prepend 一个 seq=0 fence。这样 preferred 满后回退到其它 backend 时
// fence 会跟随真正承载数据的 TCP 流，且 channel FIFO 保证 fence 严格先于 data。
func sendBatchToAnyFenced(p *AsyncPort, backends []*Backend, preferred *Backend, batch []VPNFrame) int {
\tout := getVPNFrameBatch(len(batch))
\tcopy(out, batch)
\tfor i := range batch {
\t\tbatch[i].Data = nil
\t}
\toutBytes := vpnFrameBatchBytes(out)

\ttrySend := func(b *Backend) bool {
\t\tif b == nil {
\t\t\treturn false
\t\t}

\t\tsendBatch := out
\t\tqueuedBytes := outBytes
\t\tvar ctrl fecModeControl
\t\tfenced := false
\t\tif p != nil && p.encoder != nil {
\t\t\tif current, ok := p.encoder.currentModeControl(); ok && b.fecFenceGen.Load() < current.Generation {
\t\t\t\tctrl = current
\t\t\t\tpayload := getFrameAtLeast(fecControlWireLen)[:0]
\t\t\t\tpayload = appendFECModeControl(payload, current)
\t\t\t\twithFence := getVPNFrameBatch(len(out) + 1)
\t\t\t\twithFence[0] = VPNFrame{Seq: 0, Data: payload}
\t\t\t\tcopy(withFence[1:], out)
\t\t\t\tsendBatch = withFence
\t\t\t\tqueuedBytes += uint64(len(payload))
\t\t\t\tfenced = true
\t\t\t}
\t\t}

\t\tb.addQueuedBytes(queuedBytes)
\t\tselect {
\t\tcase b.ch <- sendBatch:
\t\t\tif fenced {
\t\t\t\tb.fecFenceGen.Store(ctrl.Generation)
\t\t\t\t// Descriptors were copied into sendBatch; payload ownership moved with
\t\t\t\t// those descriptors. Return only the original descriptor container.
\t\t\t\tputVPNFrameBatch(out)
\t\t\t\tout = nil
\t\t\t}
\t\t\tb.assignedBytes.Add(outBytes)
\t\t\tb.assignedBatches.Add(1)
\t\t\treturn true
\t\tdefault:
\t\t\tb.completeQueuedBytes(queuedBytes)
\t\t\tif fenced {
\t\t\t\t// sendBatch copied data descriptors from out, so only the fence owns
\t\t\t\t// a unique payload here. Clear descriptors without freeing data twice.
\t\t\t\tputFrame(sendBatch[0].Data)
\t\t\t\tsendBatch[0].Data = nil
\t\t\t\tputVPNFrameBatch(sendBatch)
\t\t\t}
\t\t\treturn false
\t\t}
\t}

\ttryAll := func() bool {
\t\tif trySend(preferred) {
\t\t\treturn true
\t\t}
\t\tfor _, b := range backends {
\t\t\tif b != preferred && trySend(b) {
\t\t\t\treturn true
\t\t\t}
\t\t}
\t\treturn false
\t}

\tif tryAll() {
\t\treturn 0
\t}

\t// 仅拥塞慢路径进入这里。5ms 远低于 50ms reorder skip deadline，
\t// 同时给 TLS writer 足够机会腾出一个 batch slot。
\tdeadline := time.Now().Add(5 * time.Millisecond)
\tfor time.Now().Before(deadline) {
\t\ttime.Sleep(50 * time.Microsecond)
\t\tif tryAll() {
\t\t\treturn 0
\t\t}
\t}

\tfreeFrames(out)
\tputVPNFrameBatch(out)
\treturn len(out)
}

// sendBatchToAny 保留旧的无 fence helper 供单元测试/兼容调用；生产 AsyncPort
// dispatch 走 sendBatchToAnyFenced，因此只有真实协商 FEC 的数据面会携带控制帧。
func sendBatchToAny(backends []*Backend, preferred *Backend, batch []VPNFrame) int {
\treturn sendBatchToAnyFenced(nil, backends, preferred, batch)
}
''',
)

print("dynamic RX FEC P2b source patch applied")
