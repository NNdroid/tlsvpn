package main

import (
	"context"
	"encoding/binary"
	"errors"
	mathrand "math/rand/v2"
	"sync/atomic"
	"time"
)

// ======================= 跨路径 RTT 探针（方案A） =======================
//
// 目的：测量每条物理连接的去程/回程单向时延，供去程按 min(fwd)、回程按
// min(ret) 独立选路。核心思想是跨路径探针：发起端在连接 i 发探针，对端在
// 连接 j 回包，测得 RTT_{i,j} = fwd_i + ret_j。以参考连接 ref 为锚，生成集
// {RTT_{i,ref}} ∪ {RTT_{ref,j}} 即可分解相对单向时延，且公共常数在 argmin
// 中抵消——无需时钟同步。
//
// 抗指纹：探针/回包是 seq==0 控制帧，由发送 goroutine 用 appendPaddedFrame
// 写出（逐帧随机桶尺寸 + randomPool 覆盖字节），与正常记录/keepalive 同尺寸
// 分布，不可区分。探测节奏抖动（[250,750]ms），生成集轮转，避免固定周期。
//
// 载荷固定 18B（镜像 fecControlWireLen 的固定长度纪律）：
//
//	[0]      kind    0x03 探针 / 0x04 回包
//	[1]      flags   必须为 0
//	[2:6]    nonce   uint32 BE，发起端关联 id
//	[6:10]   reply_on uint32 BE，探针=目标回包连接 index；回包=0
//	[10:18]  send_ts uint64 BE，探针=发起端发送时间戳（发送 goroutine 在
//	                  Write 前写入固定偏移）；回包=从探针回显
const (
	controlKindRttProbe byte = 0x03
	controlKindRttReply byte = 0x04

	rttProbeWireLen = 18

	// 字段偏移
	rttProbeOffKind    = 0
	rttProbeOffFlags   = 1
	rttProbeOffNonce   = 2
	rttProbeOffReplyOn = 6
	rttProbeOffSendTS  = 10
)

// 探测节奏与估算参数。
const (
	// rttProbeBaseInterval 探测基准周期；实际间隔均匀抖动 ±rttProbeJitter。
	rttProbeBaseInterval = 500 * time.Millisecond
	rttProbeJitter       = 250 * time.Millisecond

	// rttProbeDecayPerSec decayed-min 的慢升速率：每秒钟最小值允许抬升的纳秒数
	//（0.5ms/s）。快降（新样本更小立即采纳）保证路径改善立即反映，慢升防止
	// 一次幸运采样永久锁死地板，与内核 tcpi_min_rtt 语义平行。
	rttProbeDecayPerSecNS = 500_000

	// rttProbePendingTimeout 未回包探针的过期时间。
	rttProbePendingTimeout = 2 * time.Second

	// rttProbePendingMax 未回包探针上限（防泄漏）。
	rttProbePendingMax = 256

	// rttProbeFastModeAll 每周期发全生成集（更快收敛、更多填充帧）；
	// false=每周期 2 个探针轮转（低开销、时序平滑）。
	rttProbeFastModeAll = false
)

var errRttProbeMalformed = errors.New("malformed rtt probe frame")

// appendRttProbeFrame 构建探针帧载荷（send_ts 初始 0，由发送 goroutine 写入）。
func appendRttProbeFrame(dst []byte, nonce, replyOn uint32) []byte {
	start := len(dst)
	dst = append(dst, make([]byte, rttProbeWireLen)...)
	dst[start+rttProbeOffKind] = controlKindRttProbe
	dst[start+rttProbeOffFlags] = 0 // 必须保持 0
	binary.BigEndian.PutUint32(dst[start+rttProbeOffNonce:start+rttProbeOffNonce+4], nonce)
	binary.BigEndian.PutUint32(dst[start+rttProbeOffReplyOn:start+rttProbeOffReplyOn+4], replyOn)
	binary.BigEndian.PutUint64(dst[start+rttProbeOffSendTS:start+rttProbeOffSendTS+8], 0)
	return dst
}

// appendRttReplyFrame 构建回包帧载荷，回显探针的 nonce 与 send_ts。
func appendRttReplyFrame(dst []byte, nonce, sendTS uint64) []byte {
	start := len(dst)
	dst = append(dst, make([]byte, rttProbeWireLen)...)
	dst[start+rttProbeOffKind] = controlKindRttReply
	dst[start+rttProbeOffFlags] = 0 // 必须保持 0
	binary.BigEndian.PutUint32(dst[start+rttProbeOffNonce:start+rttProbeOffNonce+4], uint32(nonce))
	binary.BigEndian.PutUint32(dst[start+rttProbeOffReplyOn:start+rttProbeOffReplyOn+4], 0)
	binary.BigEndian.PutUint64(dst[start+rttProbeOffSendTS:start+rttProbeOffSendTS+8], sendTS)
	return dst
}

// parseRttProbeFrame 解析探针/回包帧；严格校验长度、kind 与 flags==0。
func parseRttProbeFrame(payload []byte) (kind byte, nonce uint32, replyOn uint32, sendTS uint64, err error) {
	if len(payload) != rttProbeWireLen {
		return 0, 0, 0, 0, errRttProbeMalformed
	}
	kind = payload[rttProbeOffKind]
	if kind != controlKindRttProbe && kind != controlKindRttReply {
		return 0, 0, 0, 0, errRttProbeMalformed
	}
	if payload[rttProbeOffFlags] != 0 {
		return 0, 0, 0, 0, errRttProbeMalformed
	}
	nonce = binary.BigEndian.Uint32(payload[rttProbeOffNonce : rttProbeOffNonce+4])
	replyOn = binary.BigEndian.Uint32(payload[rttProbeOffReplyOn : rttProbeOffReplyOn+4])
	sendTS = binary.BigEndian.Uint64(payload[rttProbeOffSendTS : rttProbeOffSendTS+8])
	return kind, nonce, replyOn, sendTS, nil
}

// isRttProbeFrame 读循环前置拦截用：payload 是合法探针/回包帧即返回 true。
// 不校验 flags/长度之外的字段，失败一律当作非探针帧（走原有 FEC 控制路径）。
func isRttProbeFrame(payload []byte) bool {
	if len(payload) != rttProbeWireLen {
		return false
	}
	k := payload[rttProbeOffKind]
	return k == controlKindRttProbe || k == controlKindRttReply
}

// patchRttProbeSendTS 发送 goroutine 在 Write 前写入发送时间戳（固定偏移）。
// 仅探针（0x03）需要；回包（0x04）保留回显值。sendBuffer 为 appendPaddedFrame
// 输出，探针载荷起点 = 10（帧头）。
func patchRttProbeSendTS(sendBuffer []byte, now time.Time) {
	off := 10 + rttProbeOffSendTS
	if off+8 > len(sendBuffer) {
		return
	}
	binary.BigEndian.PutUint64(sendBuffer[off:off+8], uint64(now.UnixNano()))
}

// rttProbeFrame 读循环 → 调度 goroutine 的投递结构。
type rttProbeFrame struct {
	kind    byte
	nonce   uint32
	replyOn uint32
	sendTS  uint64
	srcConn int       // 该帧到达的连接 index（读循环已知）
	recvAt  time.Time // 读循环接收时刻（精确 RTT 测量）
}

type pendingProbe struct {
	srcConn int // 探针发出的连接 i
	replyOn int // 目标回包连接 j
	issued  time.Time
}

// rttProbeScheduler 每侧一个（客户端挂 client、服务端每会话挂 session）。
// 同一结构既发起探针（initiator）也响应回包（responder），两侧对称。
type rttProbeScheduler struct {
	// 连接访问器（调用方注入）。resolveConn 返回某 index 当前的 Backend；
	// activeConns 返回按 index 升序的存活连接列表。
	resolveConn func(connIndex int) *Backend
	activeConns func() []int

	ctx    context.Context
	cancel context.CancelFunc

	// enabled 握手协商 RTTProbe 双方支持后才置 true，此前不发起探针。
	enabled atomic.Bool

	// 以下均为调度 goroutine 独占。
	pending   map[uint32]pendingProbe
	decay     map[[2]uint32]uint64 // decayed-min per (src,dst)，ns
	lastDecay time.Time
	nonce     uint32
	rotate    int // 生成集轮转游标
	refConn   int
	active    []int
	replies   chan rttProbeFrame
	kickCh    chan struct{}
	timer     *time.Timer
	timerCh   <-chan time.Time
}

// newRttProbeScheduler 创建调度器（不启动探测；enabled 由握手协商后置 true）。
func newRttProbeScheduler(ctx context.Context, resolveConn func(int) *Backend, activeConns func() []int) *rttProbeScheduler {
	sctx, scancel := context.WithCancel(ctx)
	s := &rttProbeScheduler{
		resolveConn: resolveConn,
		activeConns: activeConns,
		ctx:         sctx,
		cancel:      scancel,
		pending:     make(map[uint32]pendingProbe, 16),
		decay:       make(map[[2]uint32]uint64, 32),
		lastDecay:   time.Now(),
		nonce:       0,
		replies:     make(chan rttProbeFrame, 64),
		kickCh:      make(chan struct{}, 1),
	}
	s.timer = time.NewTimer(rttProbeBaseInterval)
	s.timerCh = s.timer.C
	return s
}

// enable 握手协商成功后开启探测（幂等）。
func (s *rttProbeScheduler) enable() { s.enabled.Store(true) }

// kick 事件驱动：后端注册/stall 恢复时立即发起一轮。
func (s *rttProbeScheduler) kick() {
	select {
	case s.kickCh <- struct{}{}:
	default:
	}
}

// start 启动调度 goroutine。
func (s *rttProbeScheduler) start() { go s.run() }

// stop 终止调度 goroutine。
func (s *rttProbeScheduler) stop() { s.cancel() }

// onFrame 读循环回调（在物理连接读 goroutine 内调用，必须非阻塞）。
func (s *rttProbeScheduler) onFrame(payload []byte, srcConn int) {
	if !isRttProbeFrame(payload) {
		return
	}
	kind, nonce, replyOn, sendTS, err := parseRttProbeFrame(payload)
	if err != nil {
		return
	}
	select {
	case s.replies <- rttProbeFrame{kind: kind, nonce: nonce, replyOn: replyOn, sendTS: sendTS, srcConn: srcConn, recvAt: time.Now()}:
	default:
		// 通道满则丢弃该帧；探针可容忍偶发丢失（下一轮补测）。
	}
}

// run 调度主循环：抖动定时发起探针 + 处理回包/请求。
func (s *rttProbeScheduler) run() {
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
			if fr.kind == controlKindRttProbe {
				s.respond(fr)
			} else {
				s.absorb(fr)
			}
		}
	}
}

// resetTimer 以抖动后的间隔重置定时器。
func (s *rttProbeScheduler) resetTimer() {
	d := rttProbeBaseInterval + time.Duration(mathrand.Int64N(int64(2*rttProbeJitter+1))) - rttProbeJitter
	if d < 50*time.Millisecond {
		d = 50 * time.Millisecond
	}
	s.timer.Reset(d)
	s.timerCh = s.timer.C
}

// issueRound 发起当前轮次的探针（生成集轮转）。
func (s *rttProbeScheduler) issueRound() {
	active := s.activeConns()
	if len(active) < 2 {
		// 少于 2 条连接时无跨路径可言，仅需 ref 基线（若存在）以维持锚定。
		if len(active) == 1 {
			s.emitProbe(active[0], active[0])
		}
		s.active = active
		return
	}
	ref := active[0]
	s.refConn = ref
	s.active = active

	// 生成集：row = {(i,ref) | i≠ref}，col = {(ref,j) | j≠ref}。
	row := make([]int, 0, len(active)-1)
	col := make([]int, 0, len(active)-1)
	for _, idx := range active {
		if idx == ref {
			continue
		}
		row = append(row, idx)
		col = append(col, idx)
	}

	if rttProbeFastModeAll {
		for _, i := range row {
			s.emitProbe(i, ref)
		}
		for _, j := range col {
			s.emitProbe(ref, j)
		}
		s.emitProbe(ref, ref)
		return
	}

	// 轮转：每周期一对 (row[k], col[k])；k==0 时附加 ref 基线。
	n := len(row)
	if n == 0 {
		return
	}
	k := s.rotate % n
	s.rotate = (k + 1) % n
	s.emitProbe(row[k], ref)
	s.emitProbe(ref, col[k])
	if k == 0 {
		s.emitProbe(ref, ref)
	}
}

// emitProbe 在 src 连接上发起一个“对端回包到 replyOn”的探针。
func (s *rttProbeScheduler) emitProbe(srcConn, replyOn int) {
	b := s.resolveConn(srcConn)
	if b == nil || b.probeCh == nil {
		return
	}
	s.nonce++
	if s.nonce == 0 {
		s.nonce++
	}
	nonce := s.nonce
	s.pending[nonce] = pendingProbe{srcConn: srcConn, replyOn: replyOn, issued: time.Now()}
	s.sweepPending()
	payload := appendRttProbeFrame(nil, nonce, uint32(replyOn))
	select {
	case b.probeCh <- payload:
	default:
		// 通道满：放弃本次探针，移除 pending。
		delete(s.pending, nonce)
	}
}

// sweepPending 清理过期/超量 pending。
func (s *rttProbeScheduler) sweepPending() {
	now := time.Now()
	for nonce, p := range s.pending {
		if now.Sub(p.issued) > rttProbePendingTimeout {
			delete(s.pending, nonce)
		}
	}
	if len(s.pending) > rttProbePendingMax {
		// 保守裁剪：先删最旧的若干。
		for nonce := range s.pending {
			if len(s.pending) <= rttProbePendingMax {
				break
			}
			delete(s.pending, nonce)
		}
	}
}

// respond 收到对端探针请求：按 reply_on 把回包注入目标连接。
func (s *rttProbeScheduler) respond(fr rttProbeFrame) {
	b := s.resolveConn(int(fr.replyOn))
	if b == nil || b.probeCh == nil {
		return
	}
	payload := appendRttReplyFrame(nil, uint64(fr.nonce), fr.sendTS)
	select {
	case b.probeCh <- payload:
	default:
	}
}

// absorb 收到回包：查 nonce、算 RTT、更新 decayed-min、重算 fwd/ret。
func (s *rttProbeScheduler) absorb(fr rttProbeFrame) {
	p, ok := s.pending[fr.nonce]
	if !ok {
		return
	}
	delete(s.pending, fr.nonce)
	recvNS := uint64(fr.recvAt.UnixNano())
	if fr.sendTS == 0 || fr.sendTS > recvNS {
		return // 无有效 send_ts 或时钟异常，丢弃
	}
	rtt := recvNS - fr.sendTS
	s.updateDecay(uint32(p.srcConn), uint32(p.replyOn), rtt)
	s.recomputeAll()
}

// updateDecay 慢升快降的 decayed-min。
func (s *rttProbeScheduler) updateDecay(src, dst uint32, sampleNS uint64) {
	key := [2]uint32{src, dst}
	now := time.Now()
	elapsed := now.Sub(s.lastDecay)
	s.lastDecay = now
	cur := s.decay[key]
	if cur == 0 {
		s.decay[key] = sampleNS
		return
	}
	cur += uint64(float64(elapsed.Nanoseconds()) / 1e9 * float64(rttProbeDecayPerSecNS))
	if sampleNS < cur {
		cur = sampleNS
	}
	s.decay[key] = cur
}

// recomputeAll 用当前锚定重算各连接 fwd/ret 并发布到 Backend 原子。
func (s *rttProbeScheduler) recomputeAll() {
	if len(s.active) == 0 {
		return
	}
	ref := s.refConn
	halfRef := s.anchorHalfRef(ref)
	if halfRef == 0 {
		return // 锚定尚未建立
	}
	for _, i := range s.active {
		b := s.resolveConn(i)
		if b == nil {
			continue
		}
		if i == ref {
			b.fwdOneWayUS.Store(halfRef)
			b.retOneWayUS.Store(halfRef)
			continue
		}
		if v, ok := s.decay[[2]uint32{uint32(i), uint32(ref)}]; ok {
			b.fwdOneWayUS.Store(subClamp(v, halfRef))
		}
		if v, ok := s.decay[[2]uint32{uint32(ref), uint32(i)}]; ok {
			b.retOneWayUS.Store(subClamp(v, halfRef))
		}
	}
}

// anchorHalfRef 锚定：参考连接 min_rtt/2；不可用时退 (ref,ref) 基线/2。
func (s *rttProbeScheduler) anchorHalfRef(ref int) uint64 {
	if b := s.resolveConn(ref); b != nil && b.minRttCache != nil {
		mr := atomic.LoadUint32(b.minRttCache)
		if mr > 0 && mr != adaptiveUnknownRTTUS {
			return uint64(mr) / 2
		}
	}
	if v := s.decay[[2]uint32{uint32(ref), uint32(ref)}]; v > 0 {
		return v / 2
	}
	return 0
}

// subClamp 计算 a-b 且保证非零：0 是“未收敛”哨兵，不能被一个合法的
// 零差值占用。仅当矩阵反转（锚定被低估/瞬时乱序采样）时才落到 1µs 地板，
// 正常样本保留真实量级，否则所有方向都被压成 1µs、argmin 退化。
func subClamp(a, b uint64) uint64 {
	if b > a {
		return 1
	}
	d := a - b
	if d == 0 {
		d = 1
	}
	return d
}

// decayedMinUpdate 纯函数：decayed-min 更新（供测试）。
func decayedMinUpdate(cur uint64, elapsedNS int64, sample uint64, decayPerSecNS uint64) uint64 {
	if cur == 0 {
		return sample
	}
	cur += uint64(float64(elapsedNS) / 1e9 * float64(decayPerSecNS))
	if sample < cur {
		cur = sample
	}
	return cur
}

// recomputeOneWay 纯函数：由 decay 矩阵 + 锚定计算 fwd/ret（供测试）。
// 返回每 index 的 fwd/ret；ref 本身 = halfRef。
func recomputeOneWay(decay map[[2]uint32]uint64, active []int, ref int, halfRef uint64) (fwd, ret map[int]uint64) {
	fwd = make(map[int]uint64, len(active))
	ret = make(map[int]uint64, len(active))
	for _, i := range active {
		if i == ref {
			fwd[i] = halfRef
			ret[i] = halfRef
			continue
		}
		if v, ok := decay[[2]uint32{uint32(i), uint32(ref)}]; ok {
			fwd[i] = subClamp(v, halfRef)
		}
		if v, ok := decay[[2]uint32{uint32(ref), uint32(i)}]; ok {
			ret[i] = subClamp(v, halfRef)
		}
	}
	return fwd, ret
}
