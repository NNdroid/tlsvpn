package main

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
)

// ======================= XOR 奇偶校验 FEC =======================
//
// 相比传统"逐帧向所有连接复制"（N 倍开销），XOR 模式每 K 个数据帧只多发
// 1 个校验帧（开销约 1/K）：校验帧负载 = K 个成员帧负载的逐字节异或，
// 接收端在组内恰好丢 1 帧时用其余帧与校验帧异或即可恢复。
//
// 协商：客户端 -fec -fec-group K 时握手请求带 fec_group=K。支持 XOR 的
// 服务端在响应中回带 fec_group 并对两个方向启用该模式；旧实现（Rust 或
// 旧版 Go）忽略未知字段、响应中不带 fec_group，双方自动回退到传统复制
// 模式，互通性不受影响。
//
// 编码（端口级，按全局 seq 分组，跨所有物理连接）：数据帧仍按 MinRTT
// 单路分发，组满时生成校验帧并向所有连接各广播一份副本——任何单条连接
// 失效，只要其余连接存活就能收到校验帧完成恢复。会话内数据帧 seq 从 1
// 起连续编号（0 保留给心跳），分组起点固定 ≡ 1 (mod K)，两端无需额外
// 同步即可算出任一帧所属的组。
//
// 校验帧线路格式（沿用 10 字节头，seq=0、padLen 随机，加密与否不影响帧头）：
//
//	[1B 0xFE][4B groupStart(大端)][1B K][K×4B 成员长度(大端)][异或载荷]
//
// 异或载荷为 K 个成员【明文】负载的异或，-encrypt 开启时以 groupStart 为
// seq 用既有 AES-CTR 加密。seq=0 + 负载首字节 0xFE 即为识别标志；握手帧
// 同为 seq=0 但以 '{' 开头，且仅出现在数据循环建立之前，不会混淆。
//
// 解码（会话级，跨所有物理连接汇聚）：数据帧到达即按对齐规则计入所属组
// 的异或累加器，校验帧到达且组内恰好缺 1 帧时恢复并按原 seq 注入重排缓冲；
// 同组丢 ≥2 帧不可恢复（退化为容忍丢失，由重排缓冲超时兜底）。组状态在
// 恢复、全员到齐或数量超限（淘汰起点最老者）时释放，广播产生的重复校验
// 帧按组 start 去重。

const (
	fecMagic            byte = 0xFE
	fecMinGroup              = 2
	fecMaxGroup              = 64
	fecMaxPendingGroups      = 512 // 解码器在途分组上限（≈ 重排窗口量级）
	fecDoneCache             = 64  // 已终结分组的 start 记录数（去重广播副本）
)

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
	k          int
	seqs       []uint32 // 当前组成员的 seq
	lens       []int    // 当前组成员的负载长度
	acc        []byte   // 成员负载的异或累加（按最大长度对齐）
	ic         *innerCipher
	paritySent uint64 // 已生成校验帧计数（面板/metrics）
}

func newFECEncoder(k int, ic *innerCipher) *fecEncoder {
	return &fecEncoder{k: clampFecGroup(k), ic: ic}
}

// ParitySent 已生成的校验帧总数
func (e *fecEncoder) ParitySent() uint64 { return atomic.LoadUint64(&e.paritySent) }

// add 把一个数据帧计入当前分组；凑满 K 帧时生成校验帧并立即开启新分组。
// 返回非 nil 表示校验帧就绪：缓冲取自内存池，所有权归调用方（广播后释放）。
// 零长帧不参与分组（线路本身不会传输其负载）。
func (e *fecEncoder) add(vf VPNFrame) []byte {
	if len(vf.Data) == 0 {
		return nil
	}
	e.seqs = append(e.seqs, vf.Seq)
	e.lens = append(e.lens, len(vf.Data))
	if len(vf.Data) > len(e.acc) {
		grown := make([]byte, len(vf.Data))
		copy(grown, e.acc)
		e.acc = grown
	}
	for i, b := range vf.Data {
		e.acc[i] ^= b
	}
	if len(e.seqs) < e.k {
		return nil
	}
	parity := e.buildParity()
	atomic.AddUint64(&e.paritySent, 1)
	e.reset()
	return parity
}

func (e *fecEncoder) reset() {
	e.seqs = e.seqs[:0]
	e.lens = e.lens[:0]
	clear(e.acc)
}

func (e *fecEncoder) buildParity() []byte {
	maxLen := len(e.acc)
	tagLen := 0
	if e.ic != nil && e.ic.isGCM() {
		tagLen = gcmTagSize
	}
	total := 6 + 4*len(e.lens) + maxLen + tagLen
	buf := getFrame()[:total]
	buf[0] = fecMagic
	binary.BigEndian.PutUint32(buf[1:5], e.seqs[0])
	buf[5] = byte(len(e.lens))
	off := 6
	for _, l := range e.lens {
		binary.BigEndian.PutUint32(buf[off:off+4], uint32(l))
		off += 4
	}
	copy(buf[off:], e.acc)
	if e.ic != nil {
		// 校验帧线路负载 = 描述符 + 加密后的异或载荷（GCM 时附标签），
		// 以 groupStart 为 CTR/GCM 的 seq。接收端解码时用同方向盐。
		e.ic.sealInPlace(buf[off:off+maxLen+tagLen], maxLen, e.seqs[0], uint32(maxLen+tagLen))
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
	mu        sync.Mutex
	k         int
	ic        *innerCipher
	out       func(seq uint32, frame []byte)
	groups    map[uint32]*fecGroupState // 组起点 → 组状态
	done      []uint32                  // 已终结分组的 start，用于吸收多连接广播的重复帧
	spare     *fecGroupState
	spareAc   []byte
	recovered uint64 // 异或恢复帧计数
	lost      uint64 // 确认丢失帧计数（终结组内的缺失成员）
}

// NewFECDecoder 创建解码器。k 必须与对端编码分组大小一致（来自握手协商）；
// ic 为对端→本端方向的解密器（校验帧用 groupStart 作 seq 解密校验载荷）。
func NewFECDecoder(k int, ic *innerCipher, out func(seq uint32, frame []byte)) *fecDecoder {
	return &fecDecoder{
		k:      clampFecGroup(k),
		ic:     ic,
		out:    out,
		groups: make(map[uint32]*fecGroupState),
	}
}

// groupStartOf 计算数据帧所属分组的起点（起点 ≡ 1 mod k）
func (d *fecDecoder) groupStartOf(seq uint32) uint32 {
	return seq - ((seq - 1) % uint32(d.k))
}

// Reset 清空全部组状态（服务端会话重置/客户端换会话时调用）
func (d *fecDecoder) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, g := range d.groups {
		d.releaseLocked(g)
	}
	d.groups = make(map[uint32]*fecGroupState)
	d.done = nil
}

// OnData 记录一个已解密的数据帧。frame 只读借用，不转移所有权。
func (d *fecDecoder) OnData(seq uint32, frame []byte) {
	if len(frame) == 0 || seq == 0 {
		return
	}
	start := d.groupStartOf(seq)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.isDoneLocked(start) {
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
	if len(frame) > len(g.acc) {
		g.acc = d.growAccLocked(g.acc, len(frame))
	}
	for i, b := range frame {
		g.acc[i] ^= b
	}
	d.tryRecoverLocked(g)
}

// OnParity 处理一个校验帧负载。payload 只读借用，不转移所有权。
func (d *fecDecoder) OnParity(payload []byte) {
	if len(payload) < 7 || payload[0] != fecMagic {
		return
	}
	start := binary.BigEndian.Uint32(payload[1:5])
	k := int(payload[5])
	if start == 0 || k < fecMinGroup || k > fecMaxGroup || k != d.k {
		return
	}
	if (start-1)%uint32(k) != 0 {
		return // 起点与对齐规则不符
	}
	descLen := 6 + 4*k
	tagLen := 0
	if d.ic != nil && d.ic.isGCM() {
		tagLen = gcmTagSize
	}
	if len(payload) < descLen+tagLen {
		return
	}
	lens := make([]int, k)
	maxLen := 0
	for i := 0; i < k; i++ {
		l := int(binary.BigEndian.Uint32(payload[6+4*i : 10+4*i]))
		if l < 0 || l+tagLen > len(payload)-descLen {
			return // 描述符与负载长度自洽性校验失败
		}
		lens[i] = l
		if l > maxLen {
			maxLen = l
		}
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.isDoneLocked(start) {
		return
	}
	g, ok := d.groups[start]
	if ok && g.parity != nil {
		return // 同组重复校验帧（多连接广播副本）
	}
	if !ok {
		g = d.newGroupLocked(start)
	}
	g.k = k
	g.lens = lens
	pb := getFrame()[:maxLen]
	// 解密校验载荷（GCM 模式解密同时校验完整性，失败即整组放弃）；
	// AAD 与编码端一致：[加密区域长度(4BE) || groupStart(4BE)]
	aad := gcmAAD(uint32(maxLen+tagLen), start)
	if _, err := d.ic.openTo(pb, payload[descLen:descLen+maxLen+tagLen], start, aad); err != nil {
		putFrame(pb)
		return
	}
	g.parity = pb
	d.tryRecoverLocked(g)
}

func (d *fecDecoder) newGroupLocked(start uint32) *fecGroupState {
	if len(d.groups) >= fecMaxPendingGroups {
		// 淘汰起点最老的组。不标记 done：若其校验帧/成员后来迟到，
		// 重建的组不会满足"恰好缺 1 帧"的恢复条件，只会自然过期。
		var oldestStart uint32
		var oldest *fecGroupState
		for s, g := range d.groups {
			if oldest == nil || s < oldestStart {
				oldestStart, oldest = s, g
			}
		}
		if oldest != nil {
			d.releaseLocked(oldest)
			delete(d.groups, oldestStart)
		}
	}
	g := d.spare
	if g != nil {
		d.spare = nil
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
	return g
}

func (d *fecDecoder) isDoneLocked(start uint32) bool {
	for _, s := range d.done {
		if s == start {
			return true
		}
	}
	return false
}

func (d *fecDecoder) markDoneLocked(start uint32) {
	d.done = append(d.done, start)
	if len(d.done) > fecDoneCache {
		d.done = d.done[len(d.done)-fecDoneCache:]
	}
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
	// 丢失帧可能比所有已到达帧都长（正是它把校验载荷撑到 maxLen）：
	// 先把累加器零扩展到该长度，超出已到达帧长度的部分等价于"无贡献"
	n := g.lens[missing]
	if n > len(g.acc) {
		g.acc = d.growAccLocked(g.acc, n)
	}
	rec := getFrame()[:n]
	for i := 0; i < n; i++ {
		rec[i] = g.parity[i] ^ g.acc[i]
	}
	// 标记已恢复成员，避免 finishGroup 把它计入丢失
	g.gotMask |= uint64(1) << uint(missing)
	d.finishGroupLocked(g)
	atomic.AddUint64(&d.recovered, 1)
	if d.out != nil {
		d.out(g.start+uint32(missing), rec)
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
		atomic.AddUint64(&d.lost, uint64(g.missingCountLocked()))
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
	g.lens = nil
	if cap(g.acc) > cap(d.spareAc) {
		d.spareAc = g.acc
	}
	g.acc = nil
	if d.spare == nil {
		d.spare = g
	}
}

// growAccLocked 复用回收的累加缓冲，不足时新分配；扩容区域必须清零
// （异或累加器语义要求新区域等价于"尚无成员贡献"）。
func (d *fecDecoder) growAccLocked(old []byte, need int) []byte {
	var buf []byte
	if cap(d.spareAc) >= need {
		buf = d.spareAc[:need]
		d.spareAc = nil
	} else {
		buf = make([]byte, need)
	}
	copy(buf, old)
	clear(buf[len(old):])
	return buf
}
