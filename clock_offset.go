package main

import (
	"context"
	"encoding/binary"
	"errors"
	mathrand "math/rand/v2"
	"sort"
	"sync/atomic"
	"time"
)

// ======================= 双向时钟偏移探针（虚拟时钟同步） =======================
//
// 目的：为参考连接 ref 解出其自身的去程/回程不对称度，从而去掉跨路径探针分解
// 里被迫引入的公共偏移 δ，恢复 fwd+ret=RTT 严格自洽。
//
// 原理：跨路径探针（rtt_probe.go）假设 ref 对称，F_ref==B_ref==halfRef。真实
// 链路常不对称，于是 decay 矩阵不变而 F_ref≠B_ref，单解无法区分——这是分解加
// δ 的根源。这里用一个"两端各留两枚时间戳"的往返探针补上缺失的那半个方程：
//
//	A 发送 t1，B 接收 t2；B 回包发送 t3，A 接收 t4。
//	  去程 RTT 分量：t2-t1 = F + θ
//	  回程 RTT 分量：t4-t3 = B - θ
//	  其中 θ = A 时钟相对 B 的偏移（B = A + θ）。
//
// t3 的精确性：t3 是"回包端决定发送"的时刻，即回包帧被注入 probeCh 的瞬间
// （respond 内 time.Now()），而非"实际写出到 TCP"的时刻。两者之差是 probeCh
// 队列 + 发送 goroutine 批处理的排队延迟。低负载下为微秒级，被 MAD·1.4826 的
// 不确定度噪声吸收；高负载下该延迟会系统性偏小 θ。故 off_ts 字段把 t3 由对端
// 显式填回，本端不靠 issued 时刻近似。
//
// 两次测量内路径准静态时，θ 由对称差解出：
//
//	θ ≈ ((t2-t1) - (t4-t3)) / 2 = (B - F)/2
//
// 这正是 ref 的不对称度。样本集上取中位数 + MAD·1.4826 的线性最小化
// （L∞ 最优、对离群值鲁棒），样本不足或残余不确定度过大时判 θ 不可信，调用方
// 回退到现有锚定法 + δ。
//
// 抗指纹：与 RTT 探针同纪律——seq==0 控制帧，由发送 goroutine 用
// appendPaddedFrame 写出，探测节奏抖动，帧尺寸与正常记录/keepalive 同分布。
//
// 载荷固定 30B（镜像 rttProbeWireLen 的固定长度纪律）：
//
//	[0]       kind    0x05 时钟偏移探针 / 0x06 回包
//	[1]       flags  必须为 0
//	[2:6]     nonce  uint32 BE，发起端关联 id
//	[6:10]    conn   uint32 BE，目标连接 index
//	[10:18]   send_ts uint64 BE，发起端发送时间戳（发送 goroutine 写入）
//	[18:26]   recv_ts uint64 BE，回包端接收时刻；探针=0，回包=填充
//	[26:30]   off_ts  uint32 BE，回包端注入时刻（UnixMilli 低 32 位）。即 t3 的
//	                  权威来源：回包端在 respond 内取 time.Now().UnixMilli() 写入，
//	                  本端据此精确解出 t3，不用 issued 时刻近似。uint32 存 UnixMilli
//	                  低 32 位，32 位纳秒溢出前可覆盖 ~136 年，无回绕风险；毫秒粒度
//	                  对 θ 估计足够（θ 精度受 U 上限 2000µs 约束，1ms 量化误差在
//	                  MAD 噪声容差内）。0=对端未填（本端跳过该样本）。
const (
	controlKindClockProbe byte = 0x05
	controlKindClockReply byte = 0x06

	clockOffsetWireLen = 30

	// 字段偏移
	clockOffOffKind   = 0
	clockOffOffFlags  = 1
	clockOffOffNonce  = 2
	clockOffOffConn   = 6
	clockOffOffSendTS = 10
	clockOffOffRecvTS = 18
	clockOffOffTSTx   = 26 // off_ts：回包端注入时刻（UnixMilli 低 32 位）
)

// 估计器参数。
const (
	// clockOffsetBaseInterval 探测基准周期；实际间隔均匀抖动 ±clockOffsetJitter。
	clockOffsetBaseInterval = 500 * time.Millisecond
	clockOffsetJitter       = 250 * time.Millisecond

	// clockOffsetMinSamples 判 θ 可信所需最少样本数。少于它时中位数/MAD 的统计
	// 意义不足，θ 视为不可信，回退锚定法。
	clockOffsetMinSamples = 8

	// clockOffsetSampleCap 样本环形缓冲容量上限（防泄漏）。
	clockOffsetSampleCap = 256

	// clockOffsetMADScale MAD→标准差的正态一致性常数（1/0.6745）。
	clockOffsetMADScale = 1.4826

	// clockOffsetUncertaintyMaxUS 判 θ 可用的残余不确定度上限（µs）。超过则视为
	// 路径抖动过大、样本不自洽，θ 不可信。
	clockOffsetUncertaintyMaxUS = 2000
)

var errClockOffsetMalformed = errors.New("malformed clock offset frame")

// appendClockOffsetProbeFrame 构建探针帧载荷（send_ts/recv_ts/off_ts 初始 0）。
func appendClockOffsetProbeFrame(dst []byte, nonce, conn uint32) []byte {
	start := len(dst)
	dst = append(dst, make([]byte, clockOffsetWireLen)...)
	dst[start+clockOffOffKind] = controlKindClockProbe
	dst[start+clockOffOffFlags] = 0 // 必须保持 0
	binary.BigEndian.PutUint32(dst[start+clockOffOffNonce:start+clockOffOffNonce+4], nonce)
	binary.BigEndian.PutUint32(dst[start+clockOffOffConn:start+clockOffOffConn+4], conn)
	binary.BigEndian.PutUint64(dst[start+clockOffOffSendTS:start+clockOffOffSendTS+8], 0)
	binary.BigEndian.PutUint64(dst[start+clockOffOffRecvTS:start+clockOffOffRecvTS+8], 0)
	binary.BigEndian.PutUint32(dst[start+clockOffOffTSTx:start+clockOffOffTSTx+4], 0)
	return dst
}

// appendClockOffsetReplyFrame 构建回包帧载荷，回显 nonce/send_ts，填 recv_ts（t2）
// 与 off_ts（t3=注入时刻）。
func appendClockOffsetReplyFrame(dst []byte, nonce uint32, sendTS, recvTS uint64, txTS uint32) []byte {
	start := len(dst)
	dst = append(dst, make([]byte, clockOffsetWireLen)...)
	dst[start+clockOffOffKind] = controlKindClockReply
	dst[start+clockOffOffFlags] = 0 // 必须保持 0
	binary.BigEndian.PutUint32(dst[start+clockOffOffNonce:start+clockOffOffNonce+4], nonce)
	binary.BigEndian.PutUint32(dst[start+clockOffOffConn:start+clockOffOffConn+4], 0)
	binary.BigEndian.PutUint64(dst[start+clockOffOffSendTS:start+clockOffOffSendTS+8], sendTS)
	binary.BigEndian.PutUint64(dst[start+clockOffOffRecvTS:start+clockOffOffRecvTS+8], recvTS)
	binary.BigEndian.PutUint32(dst[start+clockOffOffTSTx:start+clockOffOffTSTx+4], txTS)
	return dst
}

// parseClockOffsetFrame 解析探针/回包帧；严格校验长度、kind 与 flags==0。
func parseClockOffsetFrame(payload []byte) (kind byte, nonce uint32, conn uint32, sendTS, recvTS uint64, txTS uint32, err error) {
	if len(payload) != clockOffsetWireLen {
		return 0, 0, 0, 0, 0, 0, errClockOffsetMalformed
	}
	kind = payload[clockOffOffKind]
	if kind != controlKindClockProbe && kind != controlKindClockReply {
		return 0, 0, 0, 0, 0, 0, errClockOffsetMalformed
	}
	if payload[clockOffOffFlags] != 0 {
		return 0, 0, 0, 0, 0, 0, errClockOffsetMalformed
	}
	nonce = binary.BigEndian.Uint32(payload[clockOffOffNonce : clockOffOffNonce+4])
	conn = binary.BigEndian.Uint32(payload[clockOffOffConn : clockOffOffConn+4])
	sendTS = binary.BigEndian.Uint64(payload[clockOffOffSendTS : clockOffOffSendTS+8])
	recvTS = binary.BigEndian.Uint64(payload[clockOffOffRecvTS : clockOffOffRecvTS+8])
	txTS = binary.BigEndian.Uint32(payload[clockOffOffTSTx : clockOffOffTSTx+4])
	return kind, nonce, conn, sendTS, recvTS, txTS, nil
}

// isClockOffsetFrame 读循环前置分流用：payload 是合法时钟偏移帧即返回 true。
func isClockOffsetFrame(payload []byte) bool {
	if len(payload) != clockOffsetWireLen {
		return false
	}
	k := payload[clockOffOffKind]
	return k == controlKindClockProbe || k == controlKindClockReply
}

// patchClockOffsetSendTS 发送 goroutine 在 Write 前写入发送时间戳（固定偏移）。
// 仅探针（0x05）需要；回包（0x06）保留回显值。探针载荷起点 = 10（帧头）。
func patchClockOffsetSendTS(sendBuffer []byte, now time.Time) {
	off := 10 + clockOffOffSendTS
	if off+8 > len(sendBuffer) {
		return
	}
	binary.BigEndian.PutUint64(sendBuffer[off:off+8], uint64(now.UnixNano()))
}

// offsetSample 一次完整往返的四个时间戳 + 目标连接 + 本地采集时刻。
type offsetSample struct {
	t1, t2, t3, t4 uint64 // A 发送 / B 接收 / B 发送 / A 接收（ns）
	conn           int
	at             time.Time // 本端收到回包（采集）时刻，solve 按它做样本老化
}

// clockOffsetSampleMaxAge 样本最大年龄。256 样本 ≈2 分钟，网络切换后旧 regime
// 会拖住 θ 中位数；超龄样本直接从估计集剔除，θ 在 ~1 分钟内完成向新状态的收敛
// （其余寿命由 ref 切换时的整体重置兜底）。
const clockOffsetSampleMaxAge = 120 * time.Second

// clockOffsetEstimator 维护样本缓冲，线性最小化估计 θ（ns，A 相对 B）+ 不确定度 U（µs）。
//
// θ 不可信（样本不足或 U 超阈）时 thetaNS 返回 ok=false，调用方回退现有锚定法。
//
// 并发纪律：samples/head/full/dirty/converged/est* 由调度 goroutine 独占写；
// 结果经 atomic 发布给快照读取方（schedulerSnapshot 在 API goroutine 调）。
type clockOffsetEstimator struct {
	samples []offsetSample
	head    int // 环形游标
	full    bool
	// 最近一次 solve 的缓存结果（samples 变才重算）。
	estThetaNS int64
	estUncUS   uint64
	converged  bool
	dirty      bool

	// 原子发布通道：快照读取不抢调度 goroutine 的锁。
	pubThetaNS   atomic.Int64
	pubUncUS     atomic.Uint64
	pubConverged atomic.Bool
}

// newClockOffsetEstimator 创建空估计器。
func newClockOffsetEstimator() *clockOffsetEstimator {
	return &clockOffsetEstimator{dirty: true}
}

// add 追加一次往返样本，按环形缓冲保留最近 clockOffsetSampleCap 个。
func (e *clockOffsetEstimator) add(s offsetSample) {
	if s.at.IsZero() {
		s.at = time.Now()
	}
	if len(e.samples) < clockOffsetSampleCap {
		e.samples = append(e.samples, s)
		e.head = 0
		e.dirty = true
		return
	}
	// 已满：覆盖最旧槽位并前移游标。
	e.samples[e.head] = s
	e.head = (e.head + 1) % clockOffsetSampleCap
	e.full = true
	e.dirty = true
}

// count 当前样本数。
func (e *clockOffsetEstimator) count() int {
	if e.full {
		return clockOffsetSampleCap
	}
	return len(e.samples)
}

// thetaNS 返回估计的时钟偏移（ns，A 相对 B）；不可信时返回 0 且 ok=false。
// 读原子发布值，供快照 goroutine 安全调用。
func (e *clockOffsetEstimator) thetaNS() (int64, bool) {
	if !e.pubConverged.Load() {
		return 0, false
	}
	return e.pubThetaNS.Load(), true
}

// uncertaintyUS 返回残余不确定度（µs），未收敛时为 0。
func (e *clockOffsetEstimator) uncertaintyUS() uint64 {
	return e.pubUncUS.Load()
}

// solve 重算 θ 与不确定度 U，并记录收敛态。调度 goroutine 独占。
func (e *clockOffsetEstimator) solve() {
	e.dirty = false
	e.converged = false
	e.estThetaNS = 0
	e.estUncUS = 0

	n := e.count()
	if n < clockOffsetMinSamples {
		return
	}

	// 每个往返给出一个 θ 约束：θ_i = ((t2-t1) - (t4-t3))/2 = (B-F)/2。
	// 用 uint64 差值转 int64（ns 量级远小于 int64 上限，无溢出）。
	est := make([]int64, 0, n)
	for _, s := range e.samples {
		// 样本老化：超龄样本属于旧网络状态（路由切换、路径迁移），留在集合里
		// 会让 θ 中位数在新旧 regime 之间拖 ~2 分钟。
		if !s.at.IsZero() && time.Since(s.at) > clockOffsetSampleMaxAge {
			continue
		}
		// 只过滤缺时间戳的哨兵样本；t2<t1 / t4<t3 是跨钟（A↔B）比较，B 慢于
		// A 属合法状态（θ<0），据此丢弃会让估计器对负偏移系统性失明。
		if s.t1 == 0 || s.t2 == 0 || s.t3 == 0 || s.t4 == 0 {
			continue
		}
		f := int64(s.t2 - s.t1) // 去程分量 F + θ
		b := int64(s.t4 - s.t3) // 回程分量 B - θ
		est = append(est, (f-b)/2)
	}
	if len(est) < clockOffsetMinSamples {
		return
	}
	sort.Slice(est, func(i, j int) bool { return est[i] < est[j] })

	// 中位数 = L∞ 最小化的最优解（最小化最大绝对偏差）。
	med := median(est)

	// MAD：到中位数绝对偏差的中位数，×1.4826 得一致性标准差估计。
	dev := make([]int64, 0, len(est))
	for _, v := range est {
		d := v - med
		if d < 0 {
			d = -d
		}
		dev = append(dev, d)
	}
	mad := median(dev)
	uncNS := int64(float64(mad) * clockOffsetMADScale)
	if uncNS < 0 {
		uncNS = 0
	}
	uncUS := uint64(uncNS / 1000)

	e.estThetaNS = med
	e.estUncUS = uncUS
	if uncUS <= clockOffsetUncertaintyMaxUS {
		e.converged = true
	}
	// 发布到原子通道，供快照 goroutine 无锁读取。
	e.pubThetaNS.Store(e.estThetaNS)
	e.pubUncUS.Store(e.estUncUS)
	e.pubConverged.Store(e.converged)
}

// refresh 在样本可能变化后重算并发布。调度 goroutine 在每次 absorb 后调用。
func (e *clockOffsetEstimator) refresh() {
	if e.dirty {
		e.solve()
	}
}

// median 返回切片的中位数（调用方保证非空且已排序）。偶数个取中间两值平均。
func median(sorted []int64) int64 {
	n := len(sorted)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

// ======================= 调度器 =======================
//
// clockOffsetScheduler 每侧一个，与 rttProbeScheduler 对称：既发起探针也响应回包。
// 与 rttProbe 共享 probeCh 投递通道（seq==0 控制帧同路径），独立定时。

// clockOffsetFrame 读循环 → 调度 goroutine 的投递结构。
type clockOffsetFrame struct {
	kind    byte
	nonce   uint32
	conn    uint32
	sendTS  uint64
	recvTS  uint64
	txTS    uint32 // off_ts：回包端注入时刻（UnixMilli 低 32 位）；0=对端未填
	srcConn int
	recvAt  time.Time
}

type pendingClockProbe struct {
	srcConn    int
	targetConn int
	issued     time.Time
}

// clockOffsetScheduler 每侧一个（客户端挂 client、服务端每会话挂 session）。
type clockOffsetScheduler struct {
	resolveConn func(connIndex int) *Backend
	activeConns func() []int

	ctx    context.Context
	cancel context.CancelFunc

	enabled atomic.Bool

	// 以下均为调度 goroutine 独占。
	pending map[uint32]pendingClockProbe
	est     *clockOffsetEstimator
	nonce   uint32
	target  int // 用于偏移估计的目标连接（ref，index 最小者）
	replies chan clockOffsetFrame
	kickCh  chan struct{}
	timer   *time.Timer
	timerCh <-chan time.Time
}

// newClockOffsetScheduler 创建调度器（不启动探测；enabled 由握手协商后置 true）。
func newClockOffsetScheduler(ctx context.Context, resolveConn func(int) *Backend, activeConns func() []int) *clockOffsetScheduler {
	sctx, scancel := context.WithCancel(ctx)
	s := &clockOffsetScheduler{
		resolveConn: resolveConn,
		activeConns: activeConns,
		ctx:         sctx,
		cancel:      scancel,
		est:         newClockOffsetEstimator(),
		pending:     make(map[uint32]pendingClockProbe, 16),
		replies:     make(chan clockOffsetFrame, 64),
		kickCh:      make(chan struct{}, 1),
	}
	s.timer = time.NewTimer(clockOffsetBaseInterval)
	s.timerCh = s.timer.C
	return s
}

// enable 握手协商成功后开启探测（幂等）。
func (s *clockOffsetScheduler) enable() { s.enabled.Store(true) }

// kick 事件驱动：后端注册/stall 恢复时立即发起一轮。
func (s *clockOffsetScheduler) kick() {
	select {
	case s.kickCh <- struct{}{}:
	default:
	}
}

// start 启动调度 goroutine。
func (s *clockOffsetScheduler) start() { goSafe(s.run) }

// stop 终止调度 goroutine。
func (s *clockOffsetScheduler) stop() { s.cancel() }

// thetaNS 供快照读取当前估计：θ(ns)、不确定度 U(µs)、是否可信。
// 不可信（样本不足/U 超阈）返回 0,0,false。读原子发布值，无锁。
func (s *clockOffsetScheduler) thetaNS() (thetaNS int64, uncUS uint64, ok bool) {
	if s == nil {
		return 0, 0, false
	}
	th, ok := s.est.thetaNS()
	if !ok {
		return 0, 0, false
	}
	return th, s.est.uncertaintyUS(), true
}

// onFrame 读循环回调（在物理连接读 goroutine 内调用，必须非阻塞）。
func (s *clockOffsetScheduler) onFrame(payload []byte, srcConn int) {
	if !isClockOffsetFrame(payload) {
		return
	}
	kind, nonce, conn, sendTS, recvTS, txTS, err := parseClockOffsetFrame(payload)
	if err != nil {
		return
	}
	select {
	case s.replies <- clockOffsetFrame{kind: kind, nonce: nonce, conn: conn, sendTS: sendTS,
		recvTS: recvTS, txTS: txTS, srcConn: srcConn, recvAt: time.Now()}:
	default:
		// 通道满则丢弃该帧；探针可容忍偶发丢失（下一轮补测）。
	}
}

// run 调度主循环：抖动定时发起探针 + 处理回包/请求。
func (s *clockOffsetScheduler) run() {
	defer s.timer.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-s.kickCh:
			if s.enabled.Load() {
				s.issueRound()
			}
			s.resetTimer()
		case <-s.timerCh:
			if s.enabled.Load() {
				s.issueRound()
			}
			s.resetTimer()
		case fr := <-s.replies:
			if fr.kind == controlKindClockProbe {
				s.respond(fr)
			} else {
				s.absorb(fr)
			}
		}
	}
}

// resetTimer 以抖动后的间隔重置定时器。
func (s *clockOffsetScheduler) resetTimer() {
	d := clockOffsetBaseInterval + time.Duration(mathrand.Int64N(int64(2*clockOffsetJitter+1))) - clockOffsetJitter
	if d < 50*time.Millisecond {
		d = 50 * time.Millisecond
	}
	// 排空可能已到期的旧值：不排空的话 Reset 后下一轮 select 会立刻收到
	// 旧到期值，多打一轮探针（有 pending 上限兜底，但属无谓抖动）。
	select {
	case <-s.timer.C:
	default:
	}
	s.timer.Reset(d)
	s.timerCh = s.timer.C
}

// issueRound 向当前目标连接（ref，index 最小者）发起一次偏移探针。
func (s *clockOffsetScheduler) issueRound() {
	active := s.activeConns()
	if len(active) == 0 {
		return
	}
	// 偏移估计针对 ref 连接（index 最小者），与 rttProbe 的 ref 选法一致。
	ref := active[0]
	if ref != s.target {
		// ref 变化 = 被测链路换了：θ 是"该条链路的去/回程不对称度"，旧 ref 的
		// 样本对新 ref 毫无意义——整体重置估计器，θ 从不可信态重新收敛（面板
		// 显示同步丢失，~8 个样本 ≈4s 恢复），而不是让新旧链路的 θ 混合出
		// 无人持有的伪值。
		s.est = newClockOffsetEstimator()
		s.target = ref
	}
	s.emitProbe(ref)
}

// emitProbe 在目标连接上发起一个偏移探针。
func (s *clockOffsetScheduler) emitProbe(connIndex int) {
	b := s.resolveConn(connIndex)
	if b == nil || b.probeCh == nil {
		return
	}
	s.nonce++
	if s.nonce == 0 {
		s.nonce++
	}
	nonce := s.nonce
	s.pending[nonce] = pendingClockProbe{srcConn: connIndex, targetConn: connIndex, issued: time.Now()}
	s.sweepPending()
	payload := appendClockOffsetProbeFrame(nil, nonce, uint32(connIndex))
	select {
	case b.probeCh <- payload:
	default:
		delete(s.pending, nonce)
	}
}

// sweepPending 清理过期/超量 pending。
func (s *clockOffsetScheduler) sweepPending() {
	now := time.Now()
	for nonce, p := range s.pending {
		if now.Sub(p.issued) > rttProbePendingTimeout {
			delete(s.pending, nonce)
		}
	}
	if len(s.pending) > rttProbePendingMax {
		for nonce := range s.pending {
			if len(s.pending) <= rttProbePendingMax {
				break
			}
			delete(s.pending, nonce)
		}
	}
}

// respond 收到对端探针请求：记接收时刻 t2（recv_ts），并把回包注入时刻 t3
// （off_ts）显式写入帧，供对端精确解出回程分量，不用 issued 时刻近似。
func (s *clockOffsetScheduler) respond(fr clockOffsetFrame) {
	b := s.resolveConn(int(fr.conn))
	if b == nil || b.probeCh == nil {
		return
	}
	// t2 必须取读循环的到达时刻（fr.recvAt，与 absorb 的 t4 同一打点位置），
	// 而非本 goroutine 的 time.Now()：后者混入 replies 通道（cap 64）+ goroutine
	// 唤醒延迟 d——负载下 d 系统性偏大且方差小，会让 θ 估计带 +d/2 的固定偏置
	// 却"低不确定度收敛"到错值。t3 依旧取注入时刻（writer 队列延迟属于回程
	// 链路，本来就该计入 B−θ 分量，off_ts 显式回填的意义所在）。
	recvTS := uint64(fr.recvAt.UnixNano())
	txTS := uint32(time.Now().UnixMilli())
	payload := appendClockOffsetReplyFrame(nil, fr.nonce, fr.sendTS, recvTS, txTS)
	select {
	case b.probeCh <- payload:
	default:
	}
}

// absorb 收到回包：查 nonce、凑齐四时间戳、喂估计器。
func (s *clockOffsetScheduler) absorb(fr clockOffsetFrame) {
	p, ok := s.pending[fr.nonce]
	if !ok {
		return
	}
	delete(s.pending, fr.nonce)
	if fr.sendTS == 0 || fr.recvTS == 0 || fr.txTS == 0 {
		return // 缺时间戳（含对端未填 off_ts）：丢弃该样本
	}
	recvNS := uint64(fr.recvAt.UnixNano()) // t4（A 钟）
	// t3 重建：off_ts 是 UnixMilli 的低 32 位（不能当绝对毫秒用——直接乘 1e6
	// 会得到比 t4 小三个数量级的垃圾 t3，θ 恒为荒谬负值却"收敛"）。以 t2
	// （B 钟完整纳秒）的毫秒为基准，按 uint32 环回差值还原：
	// t3 = t2 + (off_ms − floor(t2/1e6)) × 1e6，误差 ≤1ms（off_ts 毫秒截断）。
	// int32 环回差值要求 |t3−t2| < 2^31 ms，恒成立。
	deltaMS := int32(fr.txTS - uint32(fr.recvTS/1_000_000))
	if deltaMS < 0 || deltaMS > 1000 {
		return // off_ts 垃圾或 B 侧异常延迟：丢弃该样本
	}
	t3NS := fr.recvTS + uint64(deltaMS)*1_000_000
	if fr.sendTS > recvNS {
		return // t1 > t4（A 钟内回包早于请求发出）：时钟异常
	}
	// 注意 t2/t3 是 B 钟值，不与 t1/t4（A 钟）跨钟比较大小——B 慢于 A 是合法
	// 状态，正是本估计器要测量的 θ。
	s.est.add(offsetSample{
		t1:   fr.sendTS, // A 发送
		t2:   fr.recvTS, // B 接收
		t3:   t3NS,      // B 发送（由 off_ts 环回重建）
		t4:   recvNS,    // A 接收
		conn: p.targetConn,
		at:   fr.recvAt, // 本端采集时刻（solve 按它做样本老化）
	})
	s.est.refresh()
}
