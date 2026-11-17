package main

import (
	"crypto/subtle"
	"encoding/binary"
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
		// dispatch has only one backend, enter suppressed mode and publish a
		// startup SUSPEND at the first arithmetic group boundary: conns≥2 的会话
		// RX 侧 staticSingle=false，若第二条连接迟迟拨不上，没有 bypass 窗口的话
		// RX 会对整个被抑制区间空转建组（每帧 XOR + d.mu + pending 组表占用，
		// 512 组满舱靠淘汰链空转）。fence 随数据批到达后 RX 从 seq=1 起全 bypass；
		// 之后的 1→2 恢复由 controlGeneration!=0 分支发 RESUME 闭合窗口。
		boundary := fecGroupStart(firstSeq, e.k)
		if len(e.seqs) != 0 {
			boundary = e.seqs[0]
		}
		e.multipath = false
		if len(e.seqs) != 0 || e.activeLen != 0 {
			e.reset()
		}
		e.armed = false
		e.publishModeControl(fecControlSuspend, boundary)
		return
	}

	// A startup 1 -> 2 transition does not require RESUME only when no SUSPEND
	// was ever published (RX stayed conservatively active the whole time)——since
	// the startup single-path path now always publishes SUSPEND, every later
	// 1 -> 2 transition closes that bypass window at the next complete arithmetic
	// group boundary.
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
		// AAD 整体绑定描述符（kind+groupStart+K+成员长度表）：描述符此前是
		// parity 路径唯一的未认证字段，成员长度被篡改只能靠下游自洽性检查兜底。
		e.ic.sealInPlaceWithAAD(buf[off:off+maxLen+tagLen], maxLen, e.seqs[0], buf[:off], &e.aeadScratch)
	}
	return buf
}
