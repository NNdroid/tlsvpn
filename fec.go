package main

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
)

// ======================= XOR 奇偶校验 FEC =======================
//
// 相比传统"逐帧向所有连接复制"（N 倍开销），XOR 模式每 K 个数据帧只多发
// 1 个校验帧（开销约 1/K）：校验帧负载 = K 个成员帧负载的逐字节异或，
// 接收端在组内恰好丢 1 帧时用其余帧与校验帧异或即可恢复。
//
// 协商：协议 v3 中客户端 -fec -fec-group K 时握手请求带 fec_group=K，
// 服务端必须明确接受并回带同一 K；不支持/不匹配时拒绝握手，不做旧协议回退。
//
// 编码（端口级，按全局 seq 分组，跨所有物理连接）：数据帧按调度器
// 单路发送；组满时只生成一份 parity，并优先投递到与当前数据路径不同的健康
// backend。会话级 decoder 汇聚所有物理连接，因此任意健康连接收到该 parity
// 即可用于恢复。会话内数据帧 seq 从 1 起连续编号；0 专用于握手/控制平面。
// 分组起点固定 ≡ 1 (mod K)，两端独立按算术规则确定组边界。
//
// 协议 v3 校验帧是 seq=0 的 typed control：
//
//	[1B kind=0x01][4B groupStart(大端)][1B K][K×4B 长度(大端)][异或载荷]
//
// 异或载荷为组内成员【明文】负载的异或，-encrypt 开启时以 groupStart 为
// seq 用独立 AEAD key domain 加密（见 newInnerCipherDomainForAlgo）。
//
// 分组大小恒等于 K：解码端用 seq 的算术对齐（start ≡ 1 mod K）把数据帧归组，
// 因此分组边界必须由两端独立算出、无法随帧协商。若允许"不满 K 的分组"，
// 下一组的数据帧会被算进上一组而被整组丢弃，所以编码器从不冲刷未凑满的
// 分组。代价是流量彻底停止后未凑满的尾组没有校验保护（XOR 奇偶校验的固有
// 局限），此时丢包由 TCP 层重传兜底。
//
// 解码（会话级，跨所有物理连接汇聚）：数据帧到达即按对齐规则计入所属组
// 的异或累加器，校验帧到达且组内恰好缺 1 帧时恢复并按原 seq 注入重排缓冲；
// 同组丢 ≥2 帧不可恢复（退化为容忍丢失，由重排缓冲超时兜底）。组状态在
// 恢复、全员到齐或数量超限（淘汰起点最老者）时释放，广播产生的重复校验
// 帧按组 start 去重。

const (
	fecMinGroup         = 2
	fecMaxGroup         = 64
	fecMaxPendingGroups = 512 // 解码器在途分组上限（≈ 重排窗口量级）
	// fecDoneRing 已终结分组 start 的环形记录数（去重多连接广播的重复校验帧）。
	// 必须为 2 的幂；取 256 使"相隔 256 组的 start 撞槽"在实践中不可达。
	fecDoneRing = 256
	fecDoneMask = fecDoneRing - 1
)

func newFECLens() any { return new([fecMaxGroup]int) }

var fecLensPool = sync.Pool{New: newFECLens}

func getFECLens(k int) []int {
	return fecLensPool.Get().(*[fecMaxGroup]int)[:k]
}

func putFECLens(lens []int) {
	if cap(lens) != fecMaxGroup {
		return
	}
	full := lens[:fecMaxGroup]
	clear(full)
	fecLensPool.Put((*[fecMaxGroup]int)(full))
}

// clampFecGroup 把用户配置的组大小约束到协议允许范围
func clampFecGroup(k int) int {
	if k < fecMinGroup {
		return fecMinGroup
	}
	if k > fecMaxGroup {
		return fecMaxGroup
	}
	return k
}

// ---------- 编码器（挂在 AsyncPort 上，端口级串行调用，无需加锁） ----------

type fecEncoder struct {
	k           int
	seqs        []uint32 // 当前组成员的 seq
	lens        []int    // 当前组成员的负载长度
	acc         []byte   // 成员负载的异或累加（按历史最大长度复用）
	activeLen   int      // 当前组实际触碰的最大长度；reset 只清这一段
	ic          *innerCipher
	aeadScratch nonceAADScratch
	paritySent  uint64 // 已生成校验帧计数（面板/metrics）

	// multipath/armed/lastSeq/control* 只由 AsyncPort.run goroutine 修改。
	// 独立构造 encoder 的单元测试/benchmark 默认立即编码；
	// 数据面在只有一个物理 backend 时显式切到 suppressed，恢复多路径后再
	// 等待下一个完整 K 组边界。control 是最新 sender-authoritative RX fence。
	multipath         bool
	armed             bool
	lastSeq           uint32
	controlGeneration uint64
	control           fecModeControl
}

func newFECEncoder(k int, ic *innerCipher) *fecEncoder {
	k = clampFecGroup(k)
	return &fecEncoder{
		k:         k,
		ic:        ic,
		seqs:      make([]uint32, 0, k),
		lens:      make([]int, 0, k),
		acc:       make([]byte, 0, 2048),
		multipath: true,
		armed:     true,
	}
}

// ParitySent 已生成的校验帧总数
func (e *fecEncoder) ParitySent() uint64 { return atomic.LoadUint64(&e.paritySent) }

func (e *fecEncoder) publishModeControl(op byte, boundary uint32) {
	if boundary == 0 || (op != fecControlSuspend && op != fecControlResume) {
		return
	}
	e.controlGeneration++
	if e.controlGeneration == 0 { // practically unreachable uint64 wrap guard
		e.controlGeneration = 1
	}
	e.control = fecModeControl{Generation: e.controlGeneration, Op: op, Boundary: boundary}
}

func (e *fecEncoder) currentModeControl() (fecModeControl, bool) {
	if e.control.Generation == 0 || e.control.Boundary == 0 {
		return fecModeControl{}, false
	}
	return e.control, true
}

// setPhysicalPathCount 根据实际注册的物理 backend 数量启停 FEC 热路径。
// 单 TCP 是严格有序流：同一路径后面的 parity 不可能越过前面丢失/阻塞的数据，
// 因此计算 XOR/parity 没有恢复价值。切回多路径时不能从半组继续，必须等到
// seq ≡ 1 (mod K) 的下一个完整算术分组边界重新 armed。
func (e *fecEncoder) setPhysicalPathCount(paths int) {
	multipath := paths >= 2
	if multipath == e.multipath {
		return
	}

	// The scheduler calls this before feeding the current dispatch into add(), so
	// lastSeq is the previous dispatch's final data sequence. Therefore lastSeq+1
	// is the exact first sequence governed by this topology transition.
	firstSeq := uint32(0)
	if e.lastSeq != ^uint32(0) {
		firstSeq = e.lastSeq + 1
	}

	if !multipath {
		// The constructor defaults to multipath=true so direct encoder tests keep
		// their historical immediate-encoding semantics. If the very first real
		// dispatch has only one backend, however, no multipath traffic has existed
		// yet and RX has no dynamic state to suspend. Enter suppressed mode without
		// emitting a synthetic startup SUSPEND.
		hadTraffic := e.lastSeq != 0 || len(e.seqs) != 0
		boundary := fecGroupStart(firstSeq, e.k)
		if len(e.seqs) != 0 {
			boundary = e.seqs[0]
		}
		e.multipath = false
		if len(e.seqs) != 0 || e.activeLen != 0 {
			e.reset()
		}
		e.armed = false
		if hadTraffic {
			e.publishModeControl(fecControlSuspend, boundary)
		}
		return
	}

	// A startup 1 -> 2 transition does not require RESUME if no SUSPEND was ever
	// published: RX stayed conservatively active the whole time. Once a genuine
	// multipath -> single-path SUSPEND exists, later 1 -> 2 transitions must close
	// that bypass window at the next complete arithmetic group boundary.
	e.multipath = true
	e.armed = false
	if e.controlGeneration == 0 {
		return
	}
	if boundary := fecNextGroupStart(firstSeq, e.k); boundary != 0 {
		e.publishModeControl(fecControlResume, boundary)
	}
}

// add 把一个数据帧计入当前分组；凑满 K 帧时生成校验帧并立即开启新分组。
// 返回非 nil 表示校验帧就绪：缓冲取自内存池，所有权归调用方（广播后释放）。
// 零长帧不参与分组（线路本身不会传输其负载）。
func (e *fecEncoder) add(vf VPNFrame) []byte {
	if len(vf.Data) == 0 {
		return nil
	}
	if vf.Seq != 0 {
		e.lastSeq = vf.Seq
	}
	if !e.multipath {
		return nil
	}
	if !e.armed {
		if vf.Seq == 0 || (vf.Seq-1)%uint32(e.k) != 0 {
			return nil
		}
		e.armed = true
	}
	e.seqs = append(e.seqs, vf.Seq)
	e.lens = append(e.lens, len(vf.Data))
	if len(vf.Data) > len(e.acc) {
		oldLen := len(e.acc)
		if cap(e.acc) >= len(vf.Data) {
			e.acc = e.acc[:len(vf.Data)]
			clear(e.acc[oldLen:])
		} else {
			grown := make([]byte, len(vf.Data))
			copy(grown, e.acc)
			e.acc = grown
		}
	}
	if len(vf.Data) > e.activeLen {
		e.activeLen = len(vf.Data)
	}
	subtle.XORBytes(e.acc[:len(vf.Data)], e.acc[:len(vf.Data)], vf.Data)
	if len(e.seqs) < e.k {
		return nil
	}
	return e.flushLocked()
}

// flushLocked 生成当前在途分组的校验帧并重置分组（调用方保证已凑满 K 帧）
func (e *fecEncoder) flushLocked() []byte {
	parity := e.buildParity()
	atomic.AddUint64(&e.paritySent, 1)
	e.reset()
	return parity
}

func (e *fecEncoder) reset() {
	e.seqs = e.seqs[:0]
	e.lens = e.lens[:0]
	clear(e.acc[:e.activeLen])
	e.activeLen = 0
}

func (e *fecEncoder) buildParity() []byte {
	maxLen := e.activeLen
	tagLen := 0
	if e.ic != nil {
		tagLen = e.ic.tagLen()
	}
	total := 6 + 4*len(e.lens) + maxLen + tagLen
	buf := getFrameAtLeast(total)[:total]
	buf[0] = controlKindFECParity
	binary.BigEndian.PutUint32(buf[1:5], e.seqs[0])
	buf[5] = byte(len(e.lens))
	off := 6
	for _, l := range e.lens {
		binary.BigEndian.PutUint32(buf[off:off+4], uint32(l))
		off += 4
	}
	copy(buf[off:off+maxLen], e.acc[:maxLen])
	if e.ic != nil {
		// 校验帧线路负载 = 描述符 + 加密后的异或载荷（AEAD 附标签），
		// 以 groupStart 为 AEAD 的 seq。接收端解码时用同方向盐。
		e.ic.sealInPlaceWithScratch(buf[off:off+maxLen+tagLen], maxLen, e.seqs[0], uint32(maxLen+tagLen), &e.aeadScratch)
	}
	return buf
}

// ---------- 解码器（会话级，多个物理连接的读协程并发调用） ----------

type fecGroupState struct {
	start   uint32
	k       int    // 组大小（与解码器配置一致，校验帧到达时确认）
	lens    []int  // 各成员负载长度（校验帧到达时填充）
	gotMask uint64 // 已到达成员的位图（相对 start 的偏移）
	acc     []byte // 已到达成员的异或累加
	parity  []byte // 解密后的异或载荷（decoder 持有，池缓冲）
}

type fecDecoder struct {
	mu              sync.Mutex
	controlMu       sync.Mutex
	k               int
	fullMask        uint64
	staticSingle    atomic.Bool // configured topology is exactly one physical path: RX FEC has no recovery value
	fence           fecRXFenceState
	cleanupBefore   atomic.Uint32 // highest SUSPEND boundary whose older groups may retire after reorder crosses it
	retiredBefore   atomic.Uint32 // groups below this boundary can no longer affect ordered output
	reorderProgress func() uint32 // write-once before decoder publication; cold-path callback
	ic              *innerCipher
	out             func(seq uint32, frame []byte)
	groups          map[uint32]*fecGroupState // 组起点 → 组状态
	groupOrder      []uint32                  // group 创建顺序；已完成项 lazy skip
	groupHead       int                       // groupOrder 首个可能仍活跃的位置
	doneRing        [fecDoneRing]uint32       // 已终结分组 start 的环形表（O(1) 去重）
	spares          []*fecGroupState          // decoder 内部 free-list，最多复用 pending 上限数量
	lifetime        *fecLifetimeCounters      // immutable once published
	recovered       uint64                    // 异或恢复帧计数
	lost            uint64                    // 确认丢失帧计数
}

// NewFECDecoder 创建解码器。k 必须与对端编码分组大小一致（来自握手协商）；
// ic 为对端→本端方向的解密器（校验帧用 groupStart 作 seq 解密校验载荷）。
func NewFECDecoder(k int, ic *innerCipher, out func(seq uint32, frame []byte)) *fecDecoder {
	k = clampFecGroup(k)
	fullMask := ^uint64(0)
	if k < 64 {
		fullMask = (uint64(1) << uint(k)) - 1
	}
	return &fecDecoder{
		k:          k,
		fullMask:   fullMask,
		ic:         ic,
		out:        out,
		groups:     make(map[uint32]*fecGroupState, 64),
		groupOrder: make([]uint32, 0, fecMaxPendingGroups+64),
		spares:     make([]*fecGroupState, 0, fecMaxPendingGroups),
	}
}

// SetReorderProgress installs a cold-path ordered-delivery progress probe. Call
// this before publishing the decoder to connection RX goroutines.
func (d *fecDecoder) SetReorderProgress(fn func() uint32) { d.reorderProgress = fn }

// isStaticSinglePathTopology is deliberately strict: zero means "unknown", not
// single-path. The client has an authoritative configured count; the server only
// uses this when the authenticated peer also advertised group/topology semantics.
func isStaticSinglePathTopology(configuredConns int) bool { return configuredConns == 1 }

// SetStaticSinglePath enables the RX fast bypass only for a topology configured
// to have exactly one physical connection. This is intentionally NOT driven by
// the current live connection count: a temporary 2->1 failover is precisely when
// already-in-flight parity from the surviving path can still recover lost data.
func (d *fecDecoder) SetStaticSinglePath(single bool) {
	if !single {
		d.staticSingle.Store(false)
		return
	}
	if d.staticSingle.Swap(true) {
		return
	}
	// Publish bypass before clearing state so new readers stop creating groups;
	// OnData/OnParity re-check under d.mu to close the in-flight race window.
	d.Reset()
}

// groupStartOf 计算数据帧所属分组的起点（起点 ≡ 1 mod k）
func (d *fecDecoder) groupStartOf(seq uint32) uint32 {
	return seq - ((seq - 1) % uint32(d.k))
}

// Reset 清空全部组状态（服务端会话重置/客户端换会话时调用）
func (d *fecDecoder) Reset() {
	d.controlMu.Lock()
	d.mu.Lock()
	for _, g := range d.groups {
		d.releaseLocked(g)
	}
	clear(d.groups)
	d.groupOrder = d.groupOrder[:0]
	d.groupHead = 0
	for i := range d.doneRing { // 数组不能用 clear()，显式归零
		d.doneRing[i] = 0
	}
	d.cleanupBefore.Store(0)
	d.retiredBefore.Store(0)
	d.mu.Unlock()
	// Epoch changes restart sender fence generations from one. Serialize reset
	// with control apply so an old cleanup cannot run after the fresh epoch.
	d.fence.Reset()
	d.controlMu.Unlock()
}

func atomicMaxUint32(v *atomic.Uint32, next uint32) {
	for next != 0 {
		old := v.Load()
		if next <= old || v.CompareAndSwap(old, next) {
			return
		}
	}
}

// handleModeControl serializes accepted generation changes with their group-map
// cleanup. This prevents a slower old control goroutine from deleting groups
// after a newer generation has already resumed FEC on another TCP stream.
func (d *fecDecoder) handleModeControl(ctrl fecModeControl) {
	d.controlMu.Lock()
	defer d.controlMu.Unlock()
	if !d.fence.Apply(ctrl) {
		return
	}
	from, until := d.fence.Window()
	if from == 0 {
		return
	}
	atomicMaxUint32(&d.cleanupBefore, from)
	d.mu.Lock()
	d.dropGroupsInRangeLocked(from, until)
	d.maybeRetireOldGroupsLocked()
	d.mu.Unlock()
}

// dropGroupsInRangeLocked releases decoder bookkeeping only. These groups are
// abandoned by sender topology, not confirmed packet loss: do not mark done and
// do not increment the FEC lost counter.
func (d *fecDecoder) dropGroupsInRangeLocked(from, until uint32) {
	if from == 0 {
		return
	}
	changed := false
	for start, g := range d.groups {
		if start < from || (until != 0 && start >= until) {
			continue
		}
		d.releaseLocked(g)
		delete(d.groups, start)
		changed = true
	}
	if changed {
		d.pruneGroupOrderLocked()
	}
}

func (d *fecDecoder) maybeRetireOldGroupsLocked() {
	boundary := d.cleanupBefore.Load()
	if boundary == 0 || d.retiredBefore.Load() >= boundary || d.reorderProgress == nil {
		return
	}
	expected := d.reorderProgress()
	if expected == 0 || expected < boundary {
		return
	}
	// Publish retirement while holding d.mu. OnData re-checks retiredBefore after
	// taking the same mutex, so late old traffic cannot recreate removed state.
	d.retiredBefore.Store(boundary)
	changed := false
	for start, g := range d.groups {
		if start >= boundary {
			continue
		}
		d.releaseLocked(g)
		delete(d.groups, start)
		changed = true
	}
	if changed {
		d.pruneGroupOrderLocked()
	}
}

// cleanupByReorderProgress is intentionally sparse. Normal active data never
// calls the reorder callback; bypassed data probes only once per 256 sequence
// numbers, while controls/parity may probe on their already-cold paths.
func (d *fecDecoder) cleanupByReorderProgress() {
	boundary := d.cleanupBefore.Load()
	if boundary == 0 || d.retiredBefore.Load() >= boundary || d.reorderProgress == nil {
		return
	}
	d.mu.Lock()
	d.maybeRetireOldGroupsLocked()
	d.mu.Unlock()
}

// OnControl handles a non-empty post-handshake protocol-v3 seq=0 control.
// Unknown kinds and malformed FEC_MODE payloads are protocol errors; callers
// terminate the affected physical connection rather than reinterpret unsupported control payloads.
func (d *fecDecoder) OnControl(payload []byte) error {
	var scratch nonceAADScratch
	return d.OnControlWithScratch(payload, &scratch)
}

func (d *fecDecoder) OnControlWithScratch(payload []byte, scratch *nonceAADScratch) error {
	kind, err := parseControlKind(payload)
	if err != nil {
		return err
	}
	switch kind {
	case controlKindFECParity:
		d.OnParityWithScratch(payload, scratch)
		return nil
	case controlKindFECMode:
		ctrl, ok := parseFECModeControl(payload)
		if !ok {
			return fmt.Errorf("malformed FEC_MODE control")
		}
		d.handleModeControl(ctrl)
		return nil
	default:
		return fmt.Errorf("unsupported control kind 0x%02x", kind)
	}
}

// OnData records one decrypted VPN data frame. seq=0 is control-plane only and
// must be dispatched through OnControl by the post-handshake receive loop.
func (d *fecDecoder) OnData(seq uint32, frame []byte) {
	if len(frame) == 0 || seq == 0 {
		return
	}
	if d.staticSingle.Load() {
		return
	}
	if d.fence.BypassData(seq) {
		if seq&0xff == 0 {
			d.cleanupByReorderProgress()
		}
		return
	}
	if retired := d.retiredBefore.Load(); retired != 0 && seq < retired {
		return
	}
	start := d.groupStartOf(seq)
	d.mu.Lock()
	defer d.mu.Unlock()
	// Re-check the atomic window/retirement boundary after acquiring d.mu. A
	// SUSPEND cleanup may have raced the first fast-path check.
	retired := d.retiredBefore.Load()
	if d.staticSingle.Load() || d.fence.BypassData(seq) || (retired != 0 && seq < retired) || d.isDoneLocked(start) {
		return
	}
	g, ok := d.groups[start]
	if !ok {
		g = d.newGroupLocked(start)
	}
	bit := uint64(seq - start)
	mask := uint64(1) << bit
	if g.gotMask&mask != 0 {
		return // 重复到达
	}
	g.gotMask |= mask
	// P0: once all K original members arrived, parity can no longer add value.
	// Finish immediately even if parity has not arrived yet. Besides bounding the
	// pending-group map, checking before XOR means the Kth frame avoids the final
	// accumulator pass entirely. fullMask is precomputed and handles K=64 without
	// an invalid 1<<64 shift.
	if g.gotMask == d.fullMask {
		d.finishGroupLocked(g)
		return
	}
	if len(frame) > len(g.acc) {
		g.acc = d.growAccLocked(g.acc, len(frame))
	}
	subtle.XORBytes(g.acc[:len(frame)], g.acc[:len(frame)], frame)
	d.tryRecoverLocked(g)
}

// OnDataBatch records a contiguous run of decrypted data frames while taking
// the shared decoder mutex once. Multi-connection readers never call this directly;
// the session RX worker is the sole hot-path caller.
func (d *fecDecoder) OnDataBatch(frames []VPNFrame) {
	if len(frames) == 0 || d.staticSingle.Load() {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range frames {
		seq, frame := frames[i].Seq, frames[i].Data
		if len(frame) == 0 || seq == 0 {
			continue
		}
		if d.staticSingle.Load() {
			continue
		}
		if d.fence.BypassData(seq) {
			if seq&0xff == 0 {
				d.maybeRetireOldGroupsLocked()
			}
			continue
		}
		retired := d.retiredBefore.Load()
		if retired != 0 && seq < retired {
			continue
		}
		start := d.groupStartOf(seq)
		if d.isDoneLocked(start) {
			continue
		}
		g, ok := d.groups[start]
		if !ok {
			g = d.newGroupLocked(start)
		}
		bit := uint64(seq - start)
		mask := uint64(1) << bit
		if g.gotMask&mask != 0 {
			continue
		}
		g.gotMask |= mask
		if g.gotMask == d.fullMask {
			d.finishGroupLocked(g)
			continue
		}
		if len(frame) > len(g.acc) {
			g.acc = d.growAccLocked(g.acc, len(frame))
		}
		subtle.XORBytes(g.acc[:len(frame)], g.acc[:len(frame)], frame)
		d.tryRecoverLocked(g)
	}
}

// OnParity 处理一个校验帧负载。payload 只读借用，不转移所有权。
func (d *fecDecoder) OnParity(payload []byte) {
	var scratch nonceAADScratch
	d.OnParityWithScratch(payload, &scratch)
}

func (d *fecDecoder) OnParityWithScratch(payload []byte, scratch *nonceAADScratch) {
	if d.staticSingle.Load() || len(payload) < 7 || payload[0] != controlKindFECParity {
		return
	}
	start := binary.BigEndian.Uint32(payload[1:5])
	k := int(payload[5])
	// 成员数必须恰好等于 K。解码端按 seq 的算术对齐把数据帧归组，一旦接受
	// 成员数不足 K 的分组，该 start 被标记 done 后，紧随其后的帧会全部被算进
	// 这个已终结的组而直接丢弃。这里宁可整帧忽略（退化为容忍丢失），
	// 也不能容忍归组错位。
	if start == 0 || k != d.k || (start-1)%uint32(d.k) != 0 {
		return
	}
	d.cleanupByReorderProgress()
	if retired := d.retiredBefore.Load(); retired != 0 && start < retired {
		return
	}
	descLen := 6 + 4*k
	tagLen := 0
	if d.ic != nil {
		tagLen = d.ic.tagLen()
	}
	if len(payload) < descLen+tagLen {
		return
	}
	lens := getFECLens(k)
	maxLen := 0
	for i := 0; i < k; i++ {
		l := int(binary.BigEndian.Uint32(payload[6+4*i : 10+4*i]))
		if l+tagLen > len(payload)-descLen {
			putFECLens(lens)
			return // 描述符与负载长度自洽性校验失败
		}
		lens[i] = l
		if l > maxLen {
			maxLen = l
		}
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	retired := d.retiredBefore.Load()
	if d.staticSingle.Load() || (retired != 0 && start < retired) || d.isDoneLocked(start) {
		putFECLens(lens)
		return
	}
	g, ok := d.groups[start]
	if ok && g.parity != nil {
		putFECLens(lens)
		return // 同组重复校验帧（多连接广播副本）
	}
	if !ok {
		g = d.newGroupLocked(start)
	}
	g.k = k
	g.lens = lens
	// 截断到 maxLen：后续恢复循环按 len(g.parity) 判断可用性，不能依赖池缓冲
	// 恰好返回了什么长度（openTo 按 dst[:0] 追加，以这里截断后的长度为界）。
	pb := getFrameAtLeast(maxLen)[:maxLen]
	// 解密校验载荷（GCM 模式解密同时校验完整性，失败即整组放弃）；
	// AAD 与编码端一致：[加密区域长度(4BE) || groupStart(4BE)]。
	wireLen := uint32(maxLen + tagLen)
	if _, err := d.ic.openToWithScratch(pb, payload[descLen:descLen+maxLen+tagLen], start, wireLen, scratch); err != nil {
		putFrame(pb)
		putFECLens(g.lens)
		g.lens = nil
		return
	}
	g.parity = pb
	d.tryRecoverLocked(g)
	// Recovery inserts into ReorderBuffer while d.mu is held and may advance the
	// ordered horizon across cleanupBefore, so retire old groups immediately on
	// this already-cold parity path when that happens.
	d.maybeRetireOldGroupsLocked()
}

func (d *fecDecoder) newGroupLocked(start uint32) *fecGroupState {
	// 先跳过已经正常完成/恢复的 stale order 项。每个 start 最多被检查一次，
	// 所以长期摊销 O(1)，避免旧实现 groups 满时 O(512) 遍历 map 找最小 key。
	d.pruneGroupOrderLocked()

	if len(d.groups) >= fecMaxPendingGroups {
		// 淘汰最早创建且仍活跃的组。不标记 done：若其校验帧/成员后来迟到，
		// 重建的组不会满足"恰好缺 1 帧"的恢复条件，只会自然过期。
		for d.groupHead < len(d.groupOrder) {
			oldestStart := d.groupOrder[d.groupHead]
			d.groupHead++
			if oldest := d.groups[oldestStart]; oldest != nil {
				d.releaseLocked(oldest)
				delete(d.groups, oldestStart)
				break
			}
		}
		d.pruneGroupOrderLocked()
	}

	var g *fecGroupState
	if n := len(d.spares); n > 0 {
		g = d.spares[n-1]
		d.spares = d.spares[:n-1]
	} else {
		g = &fecGroupState{}
	}
	g.start = start
	g.k = 0
	g.lens = nil
	g.gotMask = 0
	g.acc = nil
	g.parity = nil
	d.groups[start] = g
	d.groupOrder = append(d.groupOrder, start)
	return g
}

// pruneGroupOrderLocked 丢掉队头已不在 groups 的完成项，并周期压缩切片。
// 完成路径只 delete(map)，不需要从队列中间删除，因此无 O(n) 搬移热路径。
func (d *fecDecoder) pruneGroupOrderLocked() {
	for d.groupHead < len(d.groupOrder) {
		if _, ok := d.groups[d.groupOrder[d.groupHead]]; ok {
			break
		}
		d.groupHead++
	}
	if d.groupHead == 0 {
		return
	}
	if d.groupHead == len(d.groupOrder) {
		d.groupOrder = d.groupOrder[:0]
		d.groupHead = 0
		return
	}
	if d.groupHead >= 1024 || d.groupHead*2 >= len(d.groupOrder) {
		copy(d.groupOrder, d.groupOrder[d.groupHead:])
		d.groupOrder = d.groupOrder[:len(d.groupOrder)-d.groupHead]
		d.groupHead = 0
	}
}

// isDoneLocked O(1) 判定：环形表槽位存的恰好等于 start 才算命中。
// 旧实现对最多 64 项切片做线性扫描，每帧一次，在持锁状态下执行。
func (d *fecDecoder) isDoneLocked(start uint32) bool {
	return d.doneRing[start&fecDoneMask] == start
}

func (d *fecDecoder) markDoneLocked(start uint32) {
	d.doneRing[start&fecDoneMask] = start
}

// tryRecoverLocked 组内恰好缺 1 帧且校验帧已到 → 异或恢复并输出
func (d *fecDecoder) tryRecoverLocked(g *fecGroupState) {
	if g.k == 0 || g.parity == nil {
		return
	}
	missing := -1
	missingCount := 0
	for i := 0; i < g.k; i++ {
		if g.gotMask&(uint64(1)<<uint(i)) == 0 {
			missingCount++
			if missingCount > 1 {
				return // 同组丢多帧，等待剩余成员（也可能永远等不到）
			}
			missing = i
		}
	}
	if missing < 0 {
		// 全员到齐，校验帧没有存在的意义了
		d.finishGroupLocked(g)
		return
	}
	// 描述符声明的成员长度超过解密后的异或载荷：载荷与描述符不自洽。
	// 只能来自上游缓冲被截断（历史上的池长度 bug）或线路损坏，这里静默丢弃
	// 整组并计入丢失——错误帧一律不 panic、不断连。
	if missing >= len(g.lens) || g.lens[missing] > len(g.parity) {
		d.finishGroupLocked(g)
		return
	}
	// 丢失帧可能比所有已到达帧都长（正是它把校验载荷撑到 maxLen）：
	// 先把累加器零扩展到该长度，超出已到达帧长度的部分等价于"无贡献"
	n := g.lens[missing]
	if n > len(g.acc) {
		g.acc = d.growAccLocked(g.acc, n)
	}
	rec := getFrameAtLeast(n)[:n]
	subtle.XORBytes(rec, g.parity[:n], g.acc[:n])

	// finishGroupLocked 会把 group state 放回复用池，并把 g.start 清零。
	// 必须在回收前保存恢复帧序号，否则回调会收到纯 missing 下标（0..K-1），
	// 表现为所有恢复 seq 都比正确值少 groupStart。
	recoveredSeq := g.start + uint32(missing)

	// 标记已恢复成员，避免 finishGroup 把它计入丢失
	g.gotMask |= uint64(1) << uint(missing)
	d.finishGroupLocked(g)
	atomic.AddUint64(&d.recovered, 1)
	if d.lifetime != nil {
		d.lifetime.recovered.Add(1)
	}
	if d.out != nil {
		d.out(recoveredSeq, rec)
	} else {
		putFrame(rec)
	}
}

// missingCount 组内仍未到达的成员数（调用方须持锁）
func (g *fecGroupState) missingCountLocked() int {
	n := 0
	for i := 0; i < g.k; i++ {
		if g.gotMask&(uint64(1)<<uint(i)) == 0 {
			n++
		}
	}
	return n
}

// FECStats 恢复/丢失帧计数（面板/metrics）。lost 统计持有校验帧仍放弃的
// 组内缺失帧：编码端确认发过校验帧，缺失即真丢。
func (d *fecDecoder) FECStats() (recovered, lost uint64) {
	return atomic.LoadUint64(&d.recovered), atomic.LoadUint64(&d.lost)
}

// finishGroupLocked 终结一个组：释放资源、记录 start 供去重，
// 并把组内仍未到达的成员计为确认丢失
func (d *fecDecoder) finishGroupLocked(g *fecGroupState) {
	if g.k > 0 && g.parity != nil {
		n := uint64(g.missingCountLocked())
		atomic.AddUint64(&d.lost, n)
		if d.lifetime != nil {
			d.lifetime.lost.Add(n)
		}
	}
	d.markDoneLocked(g.start)
	delete(d.groups, g.start)
	d.releaseLocked(g)
}

func (d *fecDecoder) releaseLocked(g *fecGroupState) {
	if g.parity != nil {
		putFrame(g.parity)
		g.parity = nil
	}
	if g.lens != nil {
		putFECLens(g.lens)
		g.lens = nil
	}
	if g.acc != nil {
		putFrame(g.acc)
		g.acc = nil
	}
	g.start = 0
	g.k = 0
	g.gotMask = 0
	if len(d.spares) < fecMaxPendingGroups {
		d.spares = append(d.spares, g)
	}
}

// growAccLocked 使用通用 size-class frame pool 扩展 FEC accumulator。
// profile 显示旧单 spareAc 设计在多 pending group 场景下无法复用，
// growAccLocked 独占约 38% alloc_space。每个 group 释放时直接归还分档池，
// 后续任意 group 都可复用，不再受“一次只能留一个 spare”限制。
func (d *fecDecoder) growAccLocked(old []byte, need int) []byte {
	if cap(old) >= need {
		oldLen := len(old)
		buf := old[:need]
		clear(buf[oldLen:])
		return buf
	}

	pooled := getFrameAtLeast(need)
	buf := pooled[:need]
	copy(buf, old)
	clear(buf[len(old):])
	if old != nil {
		putFrame(old)
	}
	return buf
}
