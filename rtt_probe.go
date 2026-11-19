package main

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
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
	// false=每周期 2 个探针轮转（低开销、时序平滑）。稳态轮转不受影响——
	// 拓扑变化后的收敛爆发（rttProbeBurstRounds）与其独立叠加。
	rttProbeFastModeAll = false

	// rttProbeBurstRounds 拓扑变化（kick / 连接重拨）后的收敛爆发轮数。轮转
	// 模式每轮只测一对 (row[k],ref)+(ref,col[k])，n 条连接要 n 轮（~2.5s）才
	// 覆盖全生成集，期间 fwd 门宽松放行、near 窗口 lenient、排名走 min_rtt/2
	// 回退。爆发期每轮发全生成集，bootstrap 从 ~2.5s 缩到 ~500ms；爆发结束
	// 回到轮转稳态。每轮 2n+1 ≤ 33 个探针（16 槽上限），probeCh 容量按此上限。
	rttProbeBurstRounds = 6

	// recent-typical 伴随指标的参数。decayed-min 是地板（慢升 0.5ms/s），
	// "同连接内持续劣化"（拥塞、路由漂移，不触发重连）最长 ~90s 才被排名
	// 反映；recent 是样本 EWMA（α=1/2，约 2 个采样窗 ≈5s 跟随 75%），用于
	// 把排名键抬到"当前典型时延"。
	rttProbeRecentMinSamples = 2 // typical 参与排名前的最少样本数（防首样本离群）
	rttProbeJitterAllowMinUS = 200
	rttProbeJitterAllowMaxUS = 5000
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

// isRttProbeFrame 读循环前置分流用：payload 是合法探针/回包帧即返回 true。
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

	// minHalfRefUS 物理锚定下界的当前值（µs）。recomputeAll 每次读取，热更后
	// 下一次重算即生效。nil 表示未注入（回落默认 0=不抬升，仅测试构造）。
	minHalfRefUS func() uint64

	ctx    context.Context
	cancel context.CancelFunc

	// enabled 握手协商 RTTProbe 双方支持后才置 true，此前不发起探针。
	enabled atomic.Bool

	// 以下均为调度 goroutine 独占。
	pending   map[uint32]pendingProbe
	decay     map[[2]uint32]uint64    // decayed-min per (src,dst)，ns
	lastDecay map[[2]uint32]time.Time // 每 key 独立的慢升计时（ns 地板按 key 累积）
	// recent / recentDev / recentN per (src,dst) 的 recent-typical 伴随指标：
	// 样本 EWMA（α=1/2）、|样本−EWMA| 的 EWMA（≈MAD）、样本计数。recent 参与
	// 排名前须 ≥ rttProbeRecentMinSamples 个样本（防首样本离群钉死典型值）。
	// 与 decay 同 key 同生命周期（重连一并清除）。单位 ns，0=未建立。
	recent    map[[2]uint32]uint64
	recentDev map[[2]uint32]uint64
	recentN   map[[2]uint32]int
	// lastBackend 上轮 resolveConn 的 connIndex→Backend 指针。槽位换新 Backend
	// （断线重拨/网络切换）时清 decay 键，防止新连接继承旧连接的时延地板。
	lastBackend map[int]*Backend
	nonce       uint32
	rotate      int // 生成集轮转游标
	burst       int // 剩余收敛爆发轮数（kick/重拨时置满，每轮递减）
	refConn     int
	active      []int
	replies     chan rttProbeFrame
	kickCh      chan struct{}
	timer       *time.Timer
	timerCh     <-chan time.Time
}

// newRttProbeScheduler 创建调度器（不启动探测；enabled 由握手协商后置 true）。
// minHalfRefUS 提供物理锚定下界的当前值（µs），每次重算读取；nil 时不抬升。
func newRttProbeScheduler(ctx context.Context, resolveConn func(int) *Backend, activeConns func() []int, minHalfRefUS func() uint64) *rttProbeScheduler {
	sctx, scancel := context.WithCancel(ctx)
	s := &rttProbeScheduler{
		resolveConn:  resolveConn,
		activeConns:  activeConns,
		minHalfRefUS: minHalfRefUS,
		ctx:          sctx,
		cancel:       scancel,
		pending:      make(map[uint32]pendingProbe, 16),
		decay:        make(map[[2]uint32]uint64, 32),
		lastDecay:    make(map[[2]uint32]time.Time, 32),
		recent:       make(map[[2]uint32]uint64, 32),
		recentDev:    make(map[[2]uint32]uint64, 32),
		recentN:      make(map[[2]uint32]int, 32),
		lastBackend:  make(map[int]*Backend, 8),
		nonce:        0,
		replies:      make(chan rttProbeFrame, 64),
		kickCh:       make(chan struct{}, 1),
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
func (s *rttProbeScheduler) start() { goSafe(s.run) }

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
				// kick 语义=拓扑可能变了（后端注册/stall 恢复）：置满收敛爆发，
				// 让新路径的全生成集在数百毫秒内覆盖，而不是等轮转 ~2.5s。
				s.burst = rttProbeBurstRounds
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
	// 排空可能已到期的旧值：kick 分支在定时器未触发时到来，若 issueRound 处理
	// 期间定时器已到期，旧到期值滞留 channel buffer，Reset 不会移除它——下一轮
	// select 会立刻收到并多打一轮探针（与 clockOffsetScheduler.resetTimer 同纪律）。
	select {
	case <-s.timer.C:
	default:
	}
	s.timer.Reset(d)
	s.timerCh = s.timer.C
}

// issueRound 发起当前轮次的探针（生成集轮转）。
// detectReconnectedConns 检测 connIndex 槽位的 Backend 指针变化并清理 decay
// 状态。槽位重连（断线重拨、WiFi→蜂窝切换）后，旧连接的 decayed-min 地板
// 不再代表新连接：快降只接受更小样本，路径劣化只能靠 0.5ms/s 慢升追赶
// （50ms 劣化需 ~100s），期间 rankOneWay 把劣化路径当快路径。删除该槽位
// 参与的全部 decay 键（含作为 ref 的锚），新连接从无偏估计重新收敛。
// 调度 goroutine 独占（与 pending/decay 同纪律）。
func (s *rttProbeScheduler) detectReconnectedConns(active []int) {
	for _, idx := range active {
		b := s.resolveConn(idx)
		if b == nil {
			continue
		}
		if prev, seen := s.lastBackend[idx]; seen && prev == b {
			continue
		}
		s.lastBackend[idx] = b
		// 重拨即拓扑变化：清该槽位全部探针状态并置满收敛爆发，新连接从无偏
		// 估计快速重新收敛（full-set 覆盖 ~1 轮而非轮转 n 轮）。
		s.burst = rttProbeBurstRounds
		for key := range s.decay {
			if key[0] == uint32(idx) || key[1] == uint32(idx) {
				delete(s.decay, key)
				delete(s.lastDecay, key)
				delete(s.recent, key)
				delete(s.recentDev, key)
				delete(s.recentN, key)
			}
		}
	}
}

func (s *rttProbeScheduler) issueRound() {
	active := s.activeConns()
	s.detectReconnectedConns(active)
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

	// 收敛爆发期（或稳态 fast 模式）：每轮发全生成集。爆发轮数随轮递减，
	// 结束后回到低开销轮转。
	if s.burst > 0 || rttProbeFastModeAll {
		if s.burst > 0 {
			s.burst--
		}
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
			// 探针超时=路径疑似黑洞：对发出槽位累计连续超时（任一回包到达即
			// 清零，见 absorb），选路层按 probeTimeoutPenaltyUS 施加递增罚时。
			// 此前超时只被静默丢弃——黑洞路径的 decayed-min 地板保持陈旧低值、
			// min_rtt 不变，会持续赢得排名。槽位换新 Backend 时计数随旧对象
			// 废弃，无需显式清除（与 decay 键的 lastBackend 清理独立）。
			if b := s.resolveConn(p.srcConn); b != nil {
				b.probeTimeoutStreak.Add(1)
			}
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
	// 回包到达即清零发出槽位的超时连击：即使时间戳无效（下方 return）也代表
	// 往返可达——黑洞不带白，时间戳只影响样本质量不影响健康判定。
	if b := s.resolveConn(p.srcConn); b != nil {
		b.probeTimeoutStreak.Store(0)
	}
	recvNS := uint64(fr.recvAt.UnixNano())
	if fr.sendTS == 0 || fr.sendTS > recvNS {
		return // 无有效 send_ts 或时钟异常，丢弃
	}
	rtt := recvNS - fr.sendTS
	if rtt == 0 {
		rtt = 1 // 同机回环/同纳秒收发：clamp 到 1ns，防止 decay 存 0 与"未测量"哨兵混淆
	}
	s.updateDecay(uint32(p.srcConn), uint32(p.replyOn), rtt)
	s.updateRecent(uint32(p.srcConn), uint32(p.replyOn), rtt)
	s.recomputeAll()
}

// updateRecent recent-typical 伴随指标：样本 EWMA（α=1/2）+ |样本−EWMA| 的
// EWMA（≈MAD）。decayed-min 是"历史最优地板"，对同连接内持续劣化（拥塞、
// 路由漂移——不触发重连）只能靠 0.5ms/s 慢升追赶（45ms 劣化 ≈90s）；EWMA 约
// 2 个采样窗（~5s）即可跟随 75%，供 recomputeAll 把排名键抬到当前典型时延。
// 与 updateDecay 同 key 生命周期（重连一并清除，见 detectReconnectedConns）。
func (s *rttProbeScheduler) updateRecent(src, dst uint32, sampleNS uint64) {
	if sampleNS == 0 {
		sampleNS = 1
	}
	key := [2]uint32{src, dst}
	n := s.recentN[key] + 1
	s.recentN[key] = n
	prev := s.recent[key]
	if n == 1 || prev == 0 {
		// 首样本只建立基线不产出 typical：单个样本可能是离群值，等第二个样本
		// 校准后才让 recent 参与排名（与 clockOffsetMinSamples 同思路）。
		s.recent[key] = sampleNS
		s.recentDev[key] = 0
		return
	}
	dev := sampleNS - prev
	if sampleNS < prev {
		dev = prev - sampleNS
	}
	s.recent[key] = (prev + sampleNS) / 2
	s.recentDev[key] = (s.recentDev[key] + dev) / 2
}

// recentJitterAllowUS 由 recentDev（≈MAD，ns）换算排名用的抖动容差（µs）：
// 排名键抬升量为 typical − 2·MAD，容差内的抖动不惩罚（稳定路径不受 EWMA 噪声
// 影响），容差外（持续劣化）才抬升。钳制防 MAD 极端值（无线链路 mad 可达数十
// ms）把排名键抬成等效"禁用该路径"。
func recentJitterAllowUS(devNS uint64) int64 {
	allow := int64(oneWayUS(devNS)) * 2
	if allow < rttProbeJitterAllowMinUS {
		allow = rttProbeJitterAllowMinUS
	}
	if allow > rttProbeJitterAllowMaxUS {
		allow = rttProbeJitterAllowMaxUS
	}
	return allow
}

// updateDecay 慢升快降的 decayed-min。慢升量按 (src,dst) 独立累积：用全局
// 时钟会让多个 key 轮转更新时互相吞掉对方的慢升增量（A 在 t1、B 在 t2 更新，
// A 下次在 t3 更新却只拿到 t2→t3，丢失 t1→t2）。每 key 记自己的上次更新时刻。
func (s *rttProbeScheduler) updateDecay(src, dst uint32, sampleNS uint64) {
	if sampleNS == 0 {
		sampleNS = 1 // 防御：0 与"未测量"哨兵（decay[key]==0）混淆
	}
	key := [2]uint32{src, dst}
	now := time.Now()
	elapsed := now.Sub(s.lastDecay[key])
	s.lastDecay[key] = now
	cur := s.decay[key]
	if cur == 0 {
		s.decay[key] = sampleNS
		return
	}
	// 时钟回拨（elapsed<0）时不做慢升：decayed-min 的慢升是"允许最小值随物理
	// 时间缓慢抬升"，时钟回拨不是路径变慢，不应触发抬升，更不可让 uint64(负)
	// wrap 成接近 2^64 的污染值——曾致 decay 爆炸、halfRef 巨大、δ 被抬到 1.7e13
	// 这类 fwd/ret 伪值。快降（sample<cur）仍生效，新样本一到即自愈。
	if elapsed > 0 {
		cur += uint64(float64(elapsed.Nanoseconds()) / 1e9 * float64(rttProbeDecayPerSecNS))
	}
	if sampleNS < cur {
		cur = sampleNS
	}
	s.decay[key] = cur
}

// recomputeAll 用当前锚定重算各连接 fwd/ret 并发布到 Backend 原子。
// 单位契约：decay 样本为 ns（updateDecay 存 sampleNS），这里统一换算成 µs
// 再与 µs 的 halfRef 相减。同一原始值双路发布：fwdOneWayUS/retOneWayUS 为
// δ 抬升非负的显示值；fwdRankUS/retRankUS 为 raw+oneWayRankZeroUS 编码的
// 选路值（backendOneWayUS 解码使用）。
func (s *rttProbeScheduler) recomputeAll() {
	if len(s.active) == 0 {
		return
	}
	ref := s.refConn
	halfRef := s.anchorHalfRef(ref)
	if halfRef == 0 {
		return // 锚定尚未建立
	}
	// 本次重算的发布时刻：面板据此显示"上次计算时间"。同一次重算内所有连接
	// 视为同一时刻，无需逐连接取钟。
	nowMs := uint64(time.Now().UnixMilli())

	// 相对时延分解：decay[(i,ref)]=F_i+B_ref 中 B_ref 是公共常数，在去程选路的
	// argmin 里抵消；decay[(ref,i)]=F_ref+B_i 中 F_ref 同理。不假设任何连接对称
	// 或相互相等，绝对单程不对称（去直回绕）免疫。θ 探针（0x05/0x06）仅作两端
	// 时钟偏移的观测展示，不参与分解——绝对分解欠定（2N 方程对 2N+1 未知数），
	// 强行代入会产生 259/5 这类物理不可能的伪值。
	//
	// 双路发布：原始有符号相对量（可负）供选路，δ 抬升非负副本供面板显示。
	// δ 只进显示——选路回退链（min_rtt/2、SRTT/2）不带 δ，混排时不抵消会
	// 扭曲排名（见 decomposeOneWay/displayDeltaUS 注释）。
	//
	// 选路值不是纯地板而是"有效去程"：max(decayed-min 地板, recent-typical −
	// 抖动容差)。地板慢升 0.5ms/s，对同连接内持续劣化（拥塞/路由漂移，不触发
	// 重连）最长 ~90s 才反映；EWMA typical ~5s 跟随，把这样的路径及时从排名
	// 上压下去（near 窗口与 fwd 门消费同一有效值，慢路径同样拿不到 parity）。
	// 显示层保持地板值：面板的 fwd_oneway_us 与 rank_key_us 本就是"面板读数 vs
	// 调度依据"两条刻意分开的数。
	fwdRaw, retRaw := decomposeOneWay(s.decay, s.active, ref, halfRef)
	delta := displayDeltaUS(fwdRaw, retRaw)
	fwdTyp, retTyp := decomposeRecent(s.recent, s.recentN, s.active, ref, halfRef)
	for _, i := range s.active {
		b := s.resolveConn(i)
		if b == nil {
			continue
		}
		if f, ok := fwdRaw[i]; ok {
			typ, hasTyp := fwdTyp[i]
			eff := s.effectiveOneWay(f, typ, hasTyp, s.recentDev[[2]uint32{uint32(i), uint32(ref)}])
			b.fwdOneWayUS.Store(uint64(f + delta))   // 显示层：地板，≥1µs
			b.fwdRankUS.Store(oneWayRankEncode(eff)) // 选路层：有效值编码
		}
		if r, ok := retRaw[i]; ok {
			typ, hasTyp := retTyp[i]
			eff := s.effectiveOneWay(r, typ, hasTyp, s.recentDev[[2]uint32{uint32(ref), uint32(i)}])
			b.retOneWayUS.Store(uint64(r + delta))   // 显示层：地板，≥1µs
			b.retRankUS.Store(oneWayRankEncode(eff)) // 选路层：有效值编码
			// 回程拥塞抬升 = 有效值 − 地板 = 探针回程的排队深度。探针回包从
			// 对端的 writer 注入本连接（reply_on=i），与对端下行数据共用发送
			// 队列——该抬升即"本端 ACK 在对端下行数据后面排了多深"，是双向
			// 吞吐区间回程拥塞门（schedExcludeRetCongested）的直接输入。
			// typ 缺席时 eff=r ⇒ 抬升 0（无拥塞证据，不制造伪信号）。
			b.retCongestUS.Store(eff - r)
		}
		b.probeUpdatedAt.Store(nowMs)
	}
}

// effectiveOneWay 选路用的有效单向值：地板与 recent-typical − 抖动容差取大。
// typical 缺席（样本 < rttProbeRecentMinSamples）时退纯地板——与历史行为一致，
// 单样本可能是离群值。map 取值零值 = 无 typical，m[key] 对 nil map 安全。
func (s *rttProbeScheduler) effectiveOneWay(floor int64, typ int64, hasTyp bool, devNS uint64) int64 {
	if !hasTyp {
		return floor
	}
	if cand := typ - recentJitterAllowUS(devNS); cand > floor {
		return cand
	}
	return floor
}

// anchorHalfRef 锚定：只用参考连接的探针自回包基线 (ref,ref)/2。
//
// 不能用内核 min_rtt/2 锚定：min_rtt 是物理无拥塞地板（不含应用层处理/队列/
// TLS 批处理/调度延迟），而 fwd/ret 全部由探针 decay（recvAt-sendTS，含完整
// 写/读/回包路径延迟）导出。用不同尺度的量相减会让 fwd/ret 系统性偏高，且
// 破坏自洽性 fwd[i]+ret[i]=RTT_i。锚定必须与探针同尺度，即 (ref,ref) 基线。
//
// 物理下界：(ref,ref) decayed-min 可能采到亚毫秒极值（同机回环、批处理对齐、
// 亚毫秒幸运采样），使 halfRef 地板成伪值，ref 自身去/回程被钉成"去程 1ms"这类
// 物理上不可能的读数。故 halfRef 抬升到配置化下界 minHalfRefUS（默认 1ms）。
// 下界仍是探针同尺度的量（不是 min_rtt/2），不重新引入跨尺度混用。
func (s *rttProbeScheduler) anchorHalfRef(ref int) uint64 {
	if v := s.decay[[2]uint32{uint32(ref), uint32(ref)}]; v > 0 {
		h := oneWayUS(v) / 2
		if h < 1 {
			h = 1 // 亚 2µs 基线：地板 1µs，避免 halfRef=0 使 recomputeAll 提前返回
		}
		if s.minHalfRefUS != nil {
			if mn := s.minHalfRefUS(); h < mn {
				h = mn
			}
		}
		return h
	}
	return 0
}

// subClamp 计算 a-b，返回该方向相对锚定的单向时延（µs）。
//
// 注意：已不再用于探针分解——decomposeOneWay 用独立有符号相对解替代，使
// 100% 方向可探测（不再把"比锚定快"的方向压成 0）。此函数保留供通用
// saturating 减法用途（b>=a 返回 0），测试仍覆盖其行为。
//
// 返回 0 表示“低于锚定精度/不可测”，而不是 1µs 伪值：当 b>=a（矩阵反转，
// 该方向时延不比参考连接大，即它比 ref 更快或与之持平）时，我们无法给出
// 一个有物理意义的下界——真实差值≤0，任何正值都是编造。0 同时是调用方的
// “未收敛/不可测”哨兵（前端 r.ret>0 判 '-'），
// 使显示层显示 '-' 而非伪造的 1ms。选路侧已改用 decomposeOneWay 的有符号
// 相对量（负值保留真实序），不再经由此函数。
//
// 注意：旧实现把反转压成 1µs，前端 max(1,·) 会把它显示成“回程 1ms”，
// 且 adaptiveBackendOneWayUS 会把 1µs 当真实值用于回程选路（超快路径抢槽位），
// 两处都是失真。改为 0 后由调用方统一按“不可测”处理。
func subClamp(a, b uint64) uint64 {
	if b >= a {
		return 0
	}
	return a - b
}

// oneWayUS 把 ns 量级的探测样本换算成 µs：探针采样（recvNS-sendTS）与
// decay 矩阵均为 ns，而对外发布的 fwdOneWayUS/retOneWayUS 为 µs。
func oneWayUS(sampleNS uint64) uint64 { return sampleNS / 1000 }

// oneWayRankZeroUS 选路层编码零点（µs）。原始相对量可为负（快于 ref 基准），
// 而 Backend 的原子字段以 0 表示"未收敛"，故选路值按 raw+oneWayRankZeroUS
// 编码存储、读取时解码回有符号值。零点必须大于 |raw| 的可能上界：halfRef 受
// ProbeMinHalfRTTUs 配置上限 3_600_000µs 约束，探针样本受 pending 超时 2s
// （→2e6µs）约束，故 raw ∈ [-3.6e6, +3.6e6]，取 4e6 保证编码值恒 >0，与
// 未收敛哨兵（0）永不冲突。
const oneWayRankZeroUS = 4_000_000

// oneWayRankEncode / oneWayRankDecode 选路层编码与解码（见 oneWayRankZeroUS）。
func oneWayRankEncode(rawUS int64) uint64 { return uint64(rawUS + oneWayRankZeroUS) }
func oneWayRankDecode(enc uint64) int64   { return int64(enc) - oneWayRankZeroUS }

// displayDeltaUS 显示层 δ 抬升量：所有有测量方向（fwd/ret 联合，与分解同轮
// 同基准）的最小值抬到 1µs 所需的公共偏移。仅用于 fwdOneWayUS/retOneWayUS
// 显示发布，选路层不得使用——回退链不带 δ，混排时不抵消会扭曲排名。
func displayDeltaUS(fwdRaw, retRaw map[int]int64) int64 {
	min := int64(math.MaxInt64)
	for _, v := range fwdRaw {
		if v < min {
			min = v
		}
	}
	for _, v := range retRaw {
		if v < min {
			min = v
		}
	}
	if min == math.MaxInt64 || min >= 1 {
		return 0
	}
	return 1 - min
}

// decayedMinUpdate 纯函数：decayed-min 更新（供测试）。
func decayedMinUpdate(cur uint64, elapsedNS int64, sample uint64, decayPerSecNS uint64) uint64 {
	if cur == 0 {
		return sample
	}
	// 时钟回拨（elapsedNS<0）不做慢升，与 updateDecay 一致；uint64(负) wrap 会
	// 把 cur 污染到接近 2^64，故必须 clamp。
	if elapsedNS > 0 {
		cur += uint64(float64(elapsedNS) / 1e9 * float64(decayPerSecNS))
	}
	if sample < cur {
		cur = sample
	}
	return cur
}

// decomposeOneWay 核心分解：由 decay 矩阵 + 锚定计算每条连接有测量方向的
// 原始有符号相对量（µs，可负）。返回两个 map，仅包含"该方向已有探针测量"的
// 连接。
//
// 以 ref 对称基准（halfRef）锚定，独立解出每条连接的去/回程相对量：
//
//	fwd_i = decay[(i,ref)] - halfRef  （= F_i + (B_ref-F_ref)/2，即绝对去程
//	                                   在 ref 不对称度 θ 下的最优估计）
//	ret_i = decay[(ref,i)] - halfRef  （= B_i - θ，同理）
//
// ref 自身 = halfRef。相对量可为负（该方向比 ref 对称基准更快），保留真实
// 完整序（选路 argmin 依赖；压非负会毁掉快路径之间的排序，旧 subClamp 教训）。
//
// 返回值直接供两路消费，本函数不做任何非负化：
//   - 选路层（fwdRankUS/retRankUS）：直接用原始有符号值，负值是真实信息。
//   - 显示层（fwdOneWayUS/retOneWayUS）：由调用方加 displayDeltaUS 抬到 ≥1µs，
//     面板不出现负值，也不与 0=未收敛哨兵混淆。
//
// δ 只进显示，绝不进选路：选路回退链（min_rtt/2、SRTT/2）不带 δ，"已收敛
// (带δ)"与"未收敛"候选混排时 δ 不抵消——δ 可达 halfRef 量级（快路径部署下
// halfRef 常被 minHalfRefUS 地板抬高），足以系统性扭曲排名。
func decomposeOneWay(decay map[[2]uint32]uint64, active []int, ref int, halfRef uint64) (fwdX, retX map[int]int64) {
	fwdX = make(map[int]int64, len(active))
	retX = make(map[int]int64, len(active))
	for _, i := range active {
		if i == ref {
			fwdX[i] = int64(halfRef)
			retX[i] = int64(halfRef)
			continue
		}
		if v, ok := decay[[2]uint32{uint32(i), uint32(ref)}]; ok {
			fwdX[i] = int64(oneWayUS(v)) - int64(halfRef)
		}
		if v, ok := decay[[2]uint32{uint32(ref), uint32(i)}]; ok {
			retX[i] = int64(oneWayUS(v)) - int64(halfRef)
		}
	}
	return fwdX, retX
}

// decomposeRecent recent-typical 的同锚分解：与 decomposeOneWay 同一 halfRef
// 锚（地板尺度），把每对 (i,ref)/(ref,i) 的样本 EWMA 换算成有符号相对量。
// 仅包含样本数 ≥ rttProbeRecentMinSamples 的方向；ref 自身用 (ref,ref) 的
// typical 半值（当前自回包 RTT 的一半相对地板锚）。EWMA 是"当前典型"而地板是
// "历史最优"，二者相减保留同一相对序——持续劣化的路径 typical 抬升、稳定路径
// typical ≈ 地板，argmin/near 窗口差值中的公共项（B_ref 等）同样抵消。
func decomposeRecent(recent map[[2]uint32]uint64, recentN map[[2]uint32]int, active []int, ref int, halfRef uint64) (fwdX, retX map[int]int64) {
	fwdX = make(map[int]int64, len(active))
	retX = make(map[int]int64, len(active))
	for _, i := range active {
		if i == ref {
			if v, ok := recent[[2]uint32{uint32(ref), uint32(ref)}]; ok && recentN[[2]uint32{uint32(ref), uint32(ref)}] >= rttProbeRecentMinSamples {
				t := int64(oneWayUS(v))/2 - int64(halfRef)
				fwdX[i] = t
				retX[i] = t
			}
			continue
		}
		if v, ok := recent[[2]uint32{uint32(i), uint32(ref)}]; ok && recentN[[2]uint32{uint32(i), uint32(ref)}] >= rttProbeRecentMinSamples {
			fwdX[i] = int64(oneWayUS(v)) - int64(halfRef)
		}
		if v, ok := recent[[2]uint32{uint32(ref), uint32(i)}]; ok && recentN[[2]uint32{uint32(ref), uint32(i)}] >= rttProbeRecentMinSamples {
			retX[i] = int64(oneWayUS(v)) - int64(halfRef)
		}
	}
	return fwdX, retX
}

// (decomposeOneWayWithTheta 已移除：绝对单程分解欠定——跨路径探针测的是
// F_i+B_ref 这类和，2N 个方程对 2N+1 个未知数（N 条连接的 F_i、B_i 加唯一时钟
// 偏移 θ），无法唯一解出绝对单程。强行代入 θ 会把 ref 的不对称度双重污染，
// 产生"去程 259ms/回程 5ms"这类物理不可能伪值。相对分解 decomposeOneWay 才是
// 正确路径：公共常数 B_ref/F_ref 在选路 argmin 中抵消，无需假设对称或连接相等，
// 对绝对单程不对称（去直回绕）免疫。)
