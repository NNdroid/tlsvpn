package main

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	mathrand "math/rand/v2"
	"net"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	utls "github.com/refraction-networking/utls"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

// ======================= 异步聚合端口 (支持 MinRTT) =======================

// queuePriorityPref 决定数据面写 goroutine 优先服务哪类帧。数值高者先：
// controlPriority > dataPriority → 控制帧优先；反之数据帧优先；相等两者皆
// false（写循环保持原 select 随机竞争，零行为变化）。控制帧含心跳/RTT 探针/
// FEC 控制（Seq==0），数据帧为 TAP 负载（Seq!=0）打包批。
func queuePriorityPref(controlPriority, dataPriority int) (controlFirst, dataFirst bool) {
	switch {
	case controlPriority > dataPriority:
		return true, false
	case dataPriority > controlPriority:
		return false, true
	default:
		return false, false
	}
}

type Backend struct {
	ch       chan []VPNFrame // legacy/cold compatibility path; production uses ownedCh
	ownedCh  chan *VPNFrameBatch
	rttCache *uint32
	// minRttCache 该连接的内核 tcpi_min_rtt（µs，无拥塞地板），用于路径质量/
	// 资格包络与单向回退链（adaptiveBackendMinRTT）。探针分解的锚定**不用**它：
	// 锚定必须是探针尺度（见 rtt_probe.go anchorHalfRef），min_rtt 是物理地板，
	// 与含处理延迟的探针 RTT 尺度错配，会破坏 fwd/ret 自洽性。
	minRttCache *uint32
	// probeCh 跨路径 RTT 探针/回包的专用投递通道（发送 goroutine 独立 select
	// case 处理，用 appendPaddedFrame 桶填充写出以消除流量特征）。0x07
	// active-paths 帧同路投递。
	probeCh chan []byte
	// connIndex 双端同步的握手槽位编号（RegisterOwnedBackend 传入）；-1=无槽位
	// 语义（本机 TAP），不参与对端活跃位图。
	connIndex int

	// Adaptive scheduler observability. queuedBytes includes channel-resident
	// batches plus the batch currently owned by the TLS writer until Write
	// succeeds. The writer publishes delivery-rate EWMA; AsyncPort only reads it.
	queuedBytes        atomic.Uint64
	rateBytesPerSec    atomic.Uint64
	etaUsec            atomic.Uint64
	active             atomic.Bool
	carryPending       atomic.Bool
	assignedBytes      atomic.Uint64 // actual data bytes accepted by this backend (after fallback)
	assignedBatches    atomic.Uint64 // actual data batches accepted by this backend
	fecAssignedBytes   atomic.Uint64 // FEC parity payload bytes accepted by this backend
	fecAssignedBatches atomic.Uint64 // FEC parity batches accepted by this backend
	fecFenceGen        atomic.Uint64 // latest dynamic RX fence generation queued before data on this backend
	virtualFinishNS    atomic.Int64  // scheduler-only service debt, published atomically for race safety
	// fwdOneWayUS / retOneWayUS 跨路径探针测得的去程/回程单向时延（µs，decayed-min
	// 地板，δ 抬升非负）——仅供面板/快照显示。0=未收敛。由 rttProbeScheduler 发布。
	fwdOneWayUS atomic.Uint64
	retOneWayUS atomic.Uint64
	// fwdRankUS / retRankUS 选路专用：原始有符号相对量按 raw+oneWayRankZeroUS
	// 编码（恒 >0，故 0=未收敛）。刻意不带显示层的 δ——δ 进选路会在与 min_rtt/2
	// 回退候选混排时不抵消，扭曲排名。与显示字段同轮发布（见 recomputeAll）。
	fwdRankUS atomic.Uint64
	retRankUS atomic.Uint64
	// probeUpdatedAt 最近一次发布 fwd/ret 的 unix 毫秒（0=尚未收敛）。面板用它
	// 显示"上次计算时间"，判断跨路径 RTT 探针是否仍在刷新。
	probeUpdatedAt atomic.Uint64
	// schedFlags 调度决策观测标志（见 adaptive_scheduler.go 的 schedFlag* 常量）。
	// bit-pack 成单个 atomic：buildEligibleCandidates 每批每后端只做 1 次 Store，
	// 与该循环既有的 etaUsec/active/virtualFinishNS 三次 Store 同量级。
	// run goroutine 写、API goroutine 快照读。
	schedFlags atomic.Uint32
	// rankKeyUS 本批选路实际使用的排名键（µs，有符号，candidateRankUS 的产出）。
	// 与显示层的 fwdOneWayUS 刻意分开：后者带 δ 抬升非负，前者是有符号原始相对量。
	// 是否有效由 schedFlagRankKnown 门控（0 是合法排名值，不能当哨兵）。
	rankKeyUS atomic.Int64
	// schedEnvMinRttUS / schedEnvMaxRttUS 本批资格包络的组内 min_rtt 地板与上限
	// （µs，见 scanEnvelope）。0=包络尚未建立。
	//
	// 组级量刻意冗余存到每条 Backend（而非只存 AsyncPort）：schedulerSnapshot
	// 只接收 *Backend，两条快照调用点（客户端/服务端）都不在选路锁内，走
	// per-Backend 通道可保持该函数签名不变、两条链路零分改。
	schedEnvMinRttUS atomic.Uint64
	schedEnvMaxRttUS atomic.Uint64
	// schedEnvFwdFloorUS 本批 fwd 门的组内去程地板（µs，有符号相对量，见
	// schedEnvelopeFloor）。与 schedEnvMinRttUS 同一套冗余到 per-Backend 的理由。
	// 用 Int64：该值是 raw+oneWayRankZeroUS 解码后的有符号量，可为负（快于 ref
	// 基准）。0 = 尚未收敛/未建立。
	schedEnvFwdFloorUS atomic.Int64
	oneWayModePtr      *atomic.Int32 // 指向所属 AsyncPort 的 oneWayMode
	// clockOffsetTheta 提供所属会话的双向时钟偏移 θ（ns）+ 不确定度 U（µs）+
	// 是否收敛。由 Client/ServerSession 在初始化 Backend 时注入，使快照可暴露
	// θ/U 收敛状态。nil=未注入（快照省略这些字段）。
	clockOffsetTheta func() (thetaNS int64, uncUS uint64, ok bool)
	rateSampleBytes  uint64
	rateSampleStart  time.Time

	// stalled 标记该后端对应的物理连接已被判定为不健康（写/读失败、或连续多次
	// RTT 采样失败）。调度器跳过 stalled 后端，使其不再接收新的数据，避免把
	// 数据送进死路径。连接恢复/重建时由新一轮握手清除。
	stalled atomic.Bool
	// orphaned 标记该后端已从端口注销（连接关闭）：writer 已退出、channel 残留
	// 无人排空。与 stalled 的区别——stalled 后端的 writer 仍活着并继续 drain
	// （RTT 采样失败等软信号，恢复握手会清除），仍可承载流量；orphaned 后端的
	// 任何入队都是静默丢数据（已分配线路 seq → 序号洞），派发必须跳过。
	orphaned atomic.Bool
	// rttFailures 连续 RTT 采样失败计数；超过阈值即视为连接异常并置 stalled。
	rttFailures atomic.Uint32
}

// AsyncPort 单向时延模式：决定调度器用 fwd 还是 ret 作为本端 egress 的单向
// 估计（去程=本端 egress 方向：客户端→服务端 或 服务端→客户端，两端都用 fwd；
// 0=roundtrip 兼容模式，等价于现有 rtt/2）。
const (
	oneWayModeRoundtrip int32 = 0
	oneWayModeFwd       int32 = 1
	oneWayModeRet       int32 = 2
)

type AsyncPort struct {
	id              string
	ch              chan []byte
	ctx             context.Context
	cancel          context.CancelFunc
	backendsMu      sync.RWMutex
	backends        []*Backend
	preferred       atomic.Pointer[Backend]
	encoder         *fecEncoder
	txSeq           uint32
	resetEpoch      chan portEpochReset
	exhausted       atomic.Bool
	onExhaust       func()
	dropped         atomic.Uint64 // 各环节丢弃帧计数（面板/metrics）；atomic 类型保证 32 位平台 8 字节对齐
	fecTXArmed      atomic.Bool
	written         txFrameCounters
	paritySent      atomic.Uint64
	parityScratch   [][]byte      // run goroutine 独占，复用 FEC parity 描述符切片
	parityNext      uint32        // run goroutine 独占：单份 parity 在健康后端间轮转
	dataNext        uint32        // legacy/compatibility picker cursor
	spinCount       int           // run goroutine 独占：waitForBackendSlot 对 preferred 的连续自旋计数（超限触发全后端扫描）
	envelopeScratch []envelopeObs // run goroutine 独占：资格扫描观测切片，按批复用避免每批堆分配
	lastFecStrategy int32         // run goroutine 独占：上一批的 fecStrategy 码，用于检测热更切换并清理 near 位

	// oneWayMode 本端 egress 的单向时延选择（见 oneWayMode* 常量）。
	// 设置后由所有 Backend 经 oneWayModePtr 读取；run() 每批读取。
	oneWayMode atomic.Int32

	// routingAlgo 当前选路算法码（见 routingAlgoCode）。调度器每批读取并映射为
	// routingPolicy；热更后新一批即生效，无需重建连接。
	routingAlgo atomic.Int32

	// fecStrategy 当前 parity 分发策略码（见 fecStrategyCode）。pickParityBackend
	// 每批读取；热更后新一批即生效。
	fecStrategy atomic.Int32
	// fecNearWindowUS near 策略的去程时延窗口（µs）。热更生效。
	fecNearWindowUS atomic.Uint64

	// schedEnvelopeFwd 候选资格门是否改用本端去程排名键（true=fwd，false=内核
	// min_rtt 往返地板，默认）。见 SchedEnvelope。调度器每批读取，热更后新一批即
	// 生效。
	schedEnvelopeFwd atomic.Bool
	// schedEnvelopeUS fwd 模式的去程准入窗口（µs）。热更生效。
	schedEnvelopeUS atomic.Uint64

	// probeMinHalfRTTUS 单向时延分解的物理锚定下界（µs）。跨路径探针的参考
	// 连接 ref 自回包 decayed-min 可能采到亚毫秒极值，使锚点 halfRef 地板成伪值
	// （ref 自身去/回程被钉成"去程 1ms"这类物理上不可能的读数）。调度器每次重算
	// 读取该下界抬升 halfRef。热更生效。
	probeMinHalfRTTUS atomic.Uint64

	// decisionMu 保护 decisionRing：run goroutine 在选路管线各返回分支追加，
	// API goroutine 快照读。decisionLast 是 run goroutine 独占的变化检测快路径
	// （原因或所选路径相对末条无变化就不追加，天然把每批数千次的写入压到低频）。
	decisionMu   sync.Mutex
	decisionRing []schedDecisionEntry
	decisionLast schedDecisionEntry

	// clockOffsetTheta 提供本端会话的双向时钟偏移 θ（ns）+ 不确定度 U（µs）+
	// 是否收敛。由 Client/ServerSession 注入所属 clockOffsetScheduler 的读取器；
	// Register*Backend 复制到每个 Backend，使快照可暴露 θ/U 收敛状态。nil=未注入。
	clockOffsetTheta func() (thetaNS int64, uncUS uint64, ok bool)

	// Adaptive multipath state. Input bytes are accounted independently from
	// frame count so 64 tiny packets no longer look like 64 full-MTU packets.
	inputQueuedBytes     atomic.Uint64
	inputTotalBytes      atomic.Uint64
	inputRateBytesPerSec atomic.Uint64
	activePaths          atomic.Int32
	schedulerPressure    atomic.Uint64
	schedulerScratch     []backendCandidate // run goroutine owned; reused per batch
	demandSampleTotal    uint64             // run goroutine owned
	demandSampleAt       time.Time          // run goroutine owned
}

type portEpochReset struct {
	k    int
	ic   *innerCipher
	done chan struct{}
}

// Dropped 累计丢弃帧数（队列满、后端投递失败、无后端）
func (p *AsyncPort) Dropped() uint64 { return p.dropped.Load() }

// ParitySent is the legacy parity-attempt counter. Web stats use written counters.
func (p *AsyncPort) ParitySent() uint64 {
	return p.paritySent.Load()
}

func (p *AsyncPort) dropN(n int) {
	if n > 0 {
		p.dropped.Add(uint64(n))
	}
}

func NewAsyncPort(ctx context.Context, id string) *AsyncPort {
	pCtx, pCancel := context.WithCancel(ctx)
	p := &AsyncPort{
		id: id, ch: make(chan []byte, 4096), ctx: pCtx, cancel: pCancel,
		resetEpoch:    make(chan portEpochReset),
		parityScratch: make([][]byte, 0, 32),
	}
	// near 窗口默认 10ms，防止未配置时策略读到 0 而把 parity 限制到恰好同速。
	p.fecNearWindowUS.Store(uint64(fecNearWindowDefaultMs) * 1000)
	// fwd 模式准入窗口默认 20ms。未配置时不能让 0 窗口把所有路径挡在门外。
	p.schedEnvelopeUS.Store(uint64(schedEnvelopeDefaultMs) * 1000)
	goSafe(p.run)
	return p
}

// SetOneWayMode 设定本端 egress 使用的单向时延（fwd=本端发送方向=去程；ret=对端
// 发送方向=回程）。两端 egress（客户端上行 / 服务端下行）均用 oneWayModeFwd，使
// "去程"在两端都是各自发送方向、语义对称。须在端口开始承载流量前调用一次；
// 调度器每批读取，未设=roundtrip 兼容模式。
func (p *AsyncPort) SetOneWayMode(mode int32) {
	p.oneWayMode.Store(mode)
}

// SetRoutingAlgo 设定本端 egress 的选路算法（见 RoutingAlgo 常量）。
// 可随时热更；调度器每批读取，新一批即生效，无需重建连接。
func (p *AsyncPort) SetRoutingAlgo(algo string) {
	p.routingAlgo.Store(routingAlgoCode(algo))
}

// SetFecStrategy 设定本端 egress 的 parity 分发策略（见 FecStrategy 常量）。
// 可随时热更；pickParityBackend 每批读取，新一批即生效。
func (p *AsyncPort) SetFecStrategy(strategy string) {
	p.fecStrategy.Store(fecStrategyCode(strategy))
}

// SetFecNearWindowMs 设定 near 策略的去程时延窗口（毫秒）。可随时热更。
func (p *AsyncPort) SetFecNearWindowMs(ms int) {
	// 0 = 显式重置到最小窗口（TestSetFecNearWindowMsClamp 钉住的契约）；常规
	// 热更路径的 0 会在 applyDefaults 归一为默认 10ms 后才到这里。
	if ms < fecNearWindowMinMs {
		ms = fecNearWindowMinMs
	}
	if ms > fecNearWindowMaxMs {
		ms = fecNearWindowMaxMs
	}
	p.fecNearWindowUS.Store(uint64(ms) * 1000)
}

// SetSchedEnvelope 设定候选资格门的度量维度（见 SchedEnvelope 常量）。可热更，
// 调度器每批读取，新一批即生效。未知值按 rtt（默认）处理。
func (p *AsyncPort) SetSchedEnvelope(v string) {
	p.schedEnvelopeFwd.Store(schedEnvelopeFor(v) == SchedEnvelopeFwd)
}

// SetSchedEnvelopeMs 设定 fwd 模式的去程准入窗口（毫秒）。可热更。
func (p *AsyncPort) SetSchedEnvelopeMs(ms int) {
	if ms < schedEnvelopeMinMs {
		ms = schedEnvelopeMinMs
	}
	if ms > schedEnvelopeMaxMs {
		ms = schedEnvelopeMaxMs
	}
	p.schedEnvelopeUS.Store(uint64(ms) * 1000)
}

// SchedEnvelope 返回当前资格门维度（供快照/面板展示）。热路径零分配读取。
func (p *AsyncPort) SchedEnvelope() SchedEnvelope {
	if p.schedEnvelopeFwd.Load() {
		return SchedEnvelopeFwd
	}
	return SchedEnvelopeRTT
}

// SchedEnvelopeMs 返回 fwd 模式的去程准入窗口（毫秒）。供快照/面板展示。
func (p *AsyncPort) SchedEnvelopeMs() int {
	return int(p.schedEnvelopeUS.Load() / 1000)
}

// SetProbeMinHalfRTTUs 设定单向时延分解的物理锚定下界（µs）。可随时热更。
// 传负值按 0（禁用下界）处理；调用方应在配置校验层拦住负值。
func (p *AsyncPort) SetProbeMinHalfRTTUs(us int) {
	if us < 0 {
		us = 0
	}
	// 运行期与配置校验层（config 上限 3_600_000µs）双保险：锚定下界超过
	// oneWayRankZeroUS 的安全余量会让 raw+偏移的编码撞上 0=未收敛哨兵。
	if us > 3_600_000 {
		us = 3_600_000
	}
	p.probeMinHalfRTTUS.Store(uint64(us))
}

// SetClockOffsetTheta 注入双向时钟偏移 θ 的读取器（供快照暴露收敛状态）。
// 在端口承载 Backend 前调用；后续注册的 Backend 即带上该读取器。
func (p *AsyncPort) SetClockOffsetTheta(f func() (int64, uint64, bool)) {
	p.clockOffsetTheta = f
}

// FecStrategy 返回当前 parity 分发策略（供快照/面板展示）。热路径零分配读取。
func (p *AsyncPort) FecStrategy() FecStrategy {
	return fecStrategyForCode(p.fecStrategy.Load())
}

// FecNearWindowMs 返回 near 策略的去程时延窗口（毫秒）。供快照/面板展示。
func (p *AsyncPort) FecNearWindowMs() int {
	return int(p.fecNearWindowUS.Load() / 1000)
}

// AttachFEC 在端口上启用 XOR 奇偶校验 FEC：每 K 个数据帧发送 1 个校验帧。
// parity 只需由会话级 decoder 收到一份，因此在健康物理连接间轮转，而不是
// 向 N 条连接复制 N 份；线路开销从约 N/K 降回约 1/K。
// ic 为本端发送方向的内层加密器（-encrypt 关闭时为 nil，校验帧明文）。
func (p *AsyncPort) AttachFEC(k int, ic *innerCipher) {
	p.ResetEpoch(k, ic)
}

// ResetEpoch 原子切换发送密钥代际：序号从 1 重新开始前必须先安装新密钥。
func (p *AsyncPort) ResetEpoch(k int, ic *innerCipher) {
	done := make(chan struct{})
	select {
	case <-p.ctx.Done():
		return
	case p.resetEpoch <- portEpochReset{k: k, ic: ic, done: done}:
	}
	select {
	case <-p.ctx.Done():
	case <-done:
	}
}

func (p *AsyncPort) SetSequenceExhaustedHandler(fn func()) { p.onExhaust = fn }

func (p *AsyncPort) nextSeq() (uint32, bool) {
	// txSeq 只在 AsyncPort.run goroutine 中递增；ResetEpoch 也通过 resetEpoch
	// channel 在同一 goroutine 串行执行，因此无需每个数据帧做原子 CAS。
	if p.txSeq == ^uint32(0) {
		if p.exhausted.CompareAndSwap(false, true) && p.onExhaust != nil {
			goSafe(p.onExhaust)
		}
		return 0, false
	}
	p.txSeq++
	return p.txSeq, true
}

func (p *AsyncPort) ID() string { return p.id }
func (p *AsyncPort) RegisterBackend(ch chan []VPNFrame, rttCache *uint32) *Backend {
	p.backendsMu.Lock()
	defer p.backendsMu.Unlock()
	b := &Backend{ch: ch, rttCache: rttCache}
	b.oneWayModePtr = &p.oneWayMode
	b.clockOffsetTheta = p.clockOffsetTheta
	p.backends = append(p.backends, b)
	return b
}
func (p *AsyncPort) UnregisterBackend(ch chan []VPNFrame) {
	p.backendsMu.Lock()
	defer p.backendsMu.Unlock()
	for i, b := range p.backends {
		if b.ch == ch {
			b.orphaned.Store(true)
			p.preferred.CompareAndSwap(b, nil)
			p.backends = append(p.backends[:i], p.backends[i+1:]...)
			break
		}
	}
}

// RegisterOwnedBackend is the production data path. The channel carries the
// batch object itself, so descriptor storage and its byte count have one owner.
// connIndex 是握手 BrutalConnIndex 同步的双端槽位编号（0..conns-1）；本机 TAP
// 等无槽位语义的端口传 -1（不参与 0x07 活跃位图）。
func (p *AsyncPort) RegisterOwnedBackend(ch chan *VPNFrameBatch, rttCache *uint32, connIndex int) *Backend {
	p.backendsMu.Lock()
	defer p.backendsMu.Unlock()
	b := &Backend{ownedCh: ch, rttCache: rttCache, connIndex: connIndex}
	b.oneWayModePtr = &p.oneWayMode
	b.clockOffsetTheta = p.clockOffsetTheta
	p.backends = append(p.backends, b)
	return b
}

func (p *AsyncPort) UnregisterOwnedBackend(ch chan *VPNFrameBatch) {
	p.backendsMu.Lock()
	for i, b := range p.backends {
		if b.ownedCh == ch {
			b.orphaned.Store(true)
			p.preferred.CompareAndSwap(b, nil)
			p.backends = append(p.backends[:i], p.backends[i+1:]...)
			break
		}
	}
	p.backendsMu.Unlock()
	// 排空注销通道里未被 writer 消费的批次并归还内存池：writer 退出后通道
	// （容量 32）里残留的 batch 无人 free，频繁重连时池命中率下降、GC 压力
	// 上升。非阻塞 best-effort：与已退出 writer 的残留发送者并发时漏掉的
	// 批次仍由 GC 兜底（与旧行为一致）。
	for {
		select {
		case batch := <-ch:
			freeOwnedVPNFrameBatch(batch)
		default:
			return
		}
	}
}

// peerActiveInterval 0x07 活跃位图广播周期；peerActiveWindow 快照过期窗口
// （容忍连续 4 轮丢失）。
const (
	peerActiveInterval = 500 * time.Millisecond
	peerActiveWindow   = 2 * time.Second
)

// startPeerActiveBroadcaster 每 500ms 把本端调度器的活跃槽位位图以 0x07
// active-paths 控制帧投给轮转后端的 probeCh（writer 的控制帧优先通道，与
// RTT 探针同路）。位图 bit i = 本端调度器当前选中 connIndex i；对端 RX 按自己
// 的握手槽位编号判定"我这条在对端是否活跃"。probeCh 满则跳过本轮（writer 忙，
// 下轮再试）；轮转游标仅本 goroutine 独占。ctx 派生自 port ctx，Close 即停。
func (p *AsyncPort) startPeerActiveBroadcaster() {
	goSafe(func() {
		t := time.NewTicker(peerActiveInterval)
		defer t.Stop()
		rotate := 0
		for {
			select {
			case <-p.ctx.Done():
				return
			case <-t.C:
			}
			var cands []*Backend
			p.backendsMu.RLock()
			bitmap := buildActivePathsBitmap(p.backends)
			for _, b := range p.backends {
				if b != nil && b.connIndex >= 0 && b.connIndex < 16 && b.probeCh != nil {
					cands = append(cands, b)
				}
			}
			p.backendsMu.RUnlock()
			if len(cands) == 0 {
				continue
			}
			// 空闲隧道没有数据批，b.active 不会被本轮刷新——两级回落让对端
			// 徽章在无流量时保持稳定而不是闪断：先 preferred（调度器的"上次
			// 选择"），仍无则单后端拓扑直接取唯一路径（单路径没有选择问题，
			// 它就是事实数据路径）。多路径空闲且从未 dispatch 时位图为空，对端
			// 按窗口过期自然熄灭；有流量时下一批立即覆盖。
			if bitmap == 0 {
				if pb := p.preferred.Load(); pb != nil && pb.connIndex >= 0 && pb.connIndex < 16 {
					bitmap = 1 << uint(pb.connIndex)
				} else if len(p.backends) == 1 && p.backends[0] != nil &&
					p.backends[0].connIndex >= 0 && p.backends[0].connIndex < 16 {
					bitmap = 1 << uint(p.backends[0].connIndex)
				}
			}
			b := cands[rotate%len(cands)]
			rotate = (rotate + 1) % len(cands)
			select {
			case b.probeCh <- appendActivePathsFrame(nil, bitmap):
			default:
			}
		}
	})
}

// buildActivePathsBitmap 汇总本端调度器活跃槽位：bit i = connIndex i 的
// Backend 本批 active。负槽位（本机 TAP）与 ≥16 越界不参与。
func buildActivePathsBitmap(backends []*Backend) uint16 {
	var bitmap uint16
	for _, b := range backends {
		if b == nil || b.connIndex < 0 || b.connIndex >= 16 {
			continue
		}
		if b.active.Load() {
			bitmap |= 1 << uint(b.connIndex)
		}
	}
	return bitmap
}

// peerActiveRecently 报告对端活跃标志是否仍在过期窗口内。
func peerActiveRecently(at int64) bool {
	return at > 0 && time.Since(time.Unix(0, at)) < peerActiveWindow
}

// storePreferredIfCurrent 把 b 写回 preferred，但仅当它仍在当前后端表中。
//
// 派发路径已改为"快照 + 锁外运行"：快照里的后端可能在 pick 过程中被
// UnregisterOwnedBackend（连接死亡的 goroutine）摘除并 CAS 清掉 preferred。
// 若这里无条件 Store，死后端会"复活"进 preferred——waitForBackendSlot 的
// 拥塞分支对非 nil 的 preferred 永不重扫，writer 已退的通道排空后队列恒满、
// 生产者 50µs 自旋、run 阻塞在空 p.ch 上，整个端口永久断流。持读锁校验
// 成员资格期间完成 Store，Unregister 的写锁无法插入，竞态窗口关闭。
func (p *AsyncPort) storePreferredIfCurrent(b *Backend) {
	if b == nil {
		return
	}
	p.backendsMu.RLock()
	for _, x := range p.backends {
		if x == b {
			p.preferred.Store(b)
			break
		}
	}
	p.backendsMu.RUnlock()
}

func (b *Backend) queueLen() int {
	if b == nil {
		return 0
	}
	if b.ownedCh != nil {
		return len(b.ownedCh)
	}
	return len(b.ch)
}

func (b *Backend) queueCap() int {
	if b == nil {
		return 0
	}
	if b.ownedCh != nil {
		return cap(b.ownedCh)
	}
	return cap(b.ch)
}

func (b *Backend) queueHasRoom() bool {
	capacity := b.queueCap()
	return capacity > 0 && b.queueLen() < capacity
}

func (p *AsyncPort) WriteFrame(frame []byte) error {
	select {
	case <-p.ctx.Done():
		return fmt.Errorf("port closed")
	default:
	}
	var buf []byte
	if frame != nil {
		buf = getFrameAtLeast(len(frame))[:len(frame)]
		copy(buf, frame)
	}
	return p.WriteOwnedFrame(buf)
}

// WriteOwnedFrame 接管 frame 的所有权。调用后无论成功入队、端口关闭还是背压
// 丢弃，调用方都不得再访问 frame。真实 TAP 热路径直接把池缓冲交进 AsyncPort，
// 消除一次 payload memcpy；普通 WriteFrame 仍保留 copy 语义供共享/外部调用使用。
func (p *AsyncPort) WriteOwnedFrame(frame []byte) error {
	select {
	case <-p.ctx.Done():
		if frame != nil {
			putFrame(frame)
		}
		return fmt.Errorf("port closed")
	default:
	}
	queuedInput := len(frame)
	p.noteInputQueued(queuedInput)
	if queuedInput > 0 {
		p.inputTotalBytes.Add(uint64(queuedInput))
	}
	select {
	case p.ch <- frame:
	default:
		p.noteInputDequeued(queuedInput)
		log.Debugf("[AsyncPort %s] BACKPRESSURE! Queue full, dropping frame.", p.id)
		p.dropN(1)
		if frame != nil {
			putFrame(frame)
		}
	}
	return nil
}

// waitForBackendSlot 在分配线路 seq 之前等待至少一个物理后端拥有 batch
// channel 空位。AsyncPort.run 是这些 backend channel 唯一的数据生产者，因此
// 一旦观察到空位，在本 goroutine 随后的 dispatch 前不会被其它 producer 抢走。
//
// 这样拥塞时优先让 p.ch 在 WriteFrame 入口丢帧（尚未分配 seq），而不是
// 先递增 txSeq、最后因后端满而丢 batch。后者会人为制造线路序号洞，触发
// reorder/FEC timeout，严重过载时甚至把整个 reorder window 打穿。
func (p *AsyncPort) waitForBackendSlot() bool {
	for {
		select {
		case <-p.ctx.Done():
			return false
		default:
		}

		// Fast path: dispatchBatch keeps the preferred backend in an atomic
		// pointer. When that queue has room, no backend-list lock/scan is needed.
		if b := p.preferred.Load(); b != nil {
			if b.queueHasRoom() {
				return true
			}
			// 拥塞：preferred（最近一次 dispatch 选中的最佳后端）已满。先退避重试，
			// 不扫描全部 backends 也不持 backendsMu——其余后端在拥塞下大概率同样
			// 已满，扫描徒增锁竞争。但下一次 dispatch 正被本函数阻塞，preferred
			// 不会因 pickAdaptiveBackend 而更新：自旋若干轮仍满时必须主动回退一次
			// 全后端扫描，否则 preferred 的 writer 卡在长写（最坏 3s）时，即使另一
			// 条连接空闲，入口也持续自旋并在 p.ch 满后丢帧，人为制造线路序号洞。
			p.spinCount++
			if p.spinCount < 20 {
				time.Sleep(50 * time.Microsecond)
				continue
			}
			p.spinCount = 0
			p.backendsMu.RLock()
			ready := false
			for _, alt := range p.backends {
				if alt.queueHasRoom() {
					ready = true
					break
				}
			}
			p.backendsMu.RUnlock()
			if ready {
				return true
			}
			time.Sleep(50 * time.Microsecond)
			continue
		}

		// preferred 为 nil（尚未 dispatch 过，或全部后端已注销）：需要扫描
		// backends 确认是否一个都没有。此刻不忙等，仅做一次发现。
		p.backendsMu.RLock()
		n := len(p.backends)
		ready := false
		for _, b := range p.backends {
			if b.queueHasRoom() {
				ready = true
				break
			}
		}
		p.backendsMu.RUnlock()

		if n == 0 {
			return false
		}
		if ready {
			return true
		}
		// 只走拥塞慢路径。50us 足够让 TLS writer drain 一个 batch，同时
		// 不用忙等抢占连接读写 goroutine。
		time.Sleep(50 * time.Microsecond)
	}
}

func (p *AsyncPort) run() {
	const MaxBatchBytes = streamTLSBatchSoftLimit
	batch := getOwnedVPNFrameBatch()
	defer func() { freeOwnedVPNFrameBatch(batch) }()

	for {
		select {
		case <-p.ctx.Done():
			return
		case reset := <-p.resetEpoch:
			p.fecTXArmed.Store(false)
			p.txSeq = 0
			p.parityNext = 0
			p.dataNext = 0
			p.exhausted.Store(false)
			if reset.k >= fecMinGroup {
				p.encoder = newFECEncoder(reset.k, reset.ic)
			} else {
				p.encoder = nil
			}
			// Fence generations are scoped to the sequence/key epoch because a new
			// encoder starts generation numbering from one. Backends can survive an
			// epoch reset, so clear their remembered generation or the first new
			// SUSPEND/RESUME could be mistaken for an already-queued old fence.
			p.backendsMu.RLock()
			for _, b := range p.backends {
				if b != nil {
					b.fecFenceGen.Store(0)
				}
			}
			p.backendsMu.RUnlock()
			close(reset.done)
		case frame := <-p.ch:
			p.noteInputDequeued(len(frame))
			if len(frame) == 0 {
				putFrame(frame)
				continue
			}
			if !p.waitForBackendSlot() {
				p.dropN(1)
				putFrame(frame)
				continue
			}
			seq, ok := p.nextSeq()
			if !ok {
				p.dropN(1)
				putFrame(frame)
				continue
			}
			appendOwnedVPNFrame(batch, VPNFrame{Seq: seq, Data: frame})

			// Interactive bursts get one very short coalescing opportunity. Under
			// sustained load p.ch is already non-empty, so the hot bulk path never sleeps.
			if len(p.ch) == 0 && batch.Bytes < MaxBatchBytes {
				time.Sleep(150 * time.Microsecond)
			}

			queueLen := len(p.ch)
			for i := 0; i < queueLen && batch.Bytes < MaxBatchBytes; i++ {
				f := <-p.ch
				p.noteInputDequeued(len(f))
				if len(f) == 0 {
					putFrame(f)
					continue
				}
				s, ok := p.nextSeq()
				if !ok {
					p.dropN(1)
					putFrame(f)
					continue
				}
				appendOwnedVPNFrame(batch, VPNFrame{Seq: s, Data: f})
			}

			// Ownership moves as one object: scheduler/TLS writer consume both the
			// descriptors and the authoritative payload-byte count.
			batch.RateBytes = batch.Bytes // 本批全是数据帧：投递速率按全部 payload 记账
			p.dispatchOwnedBatch(batch)
			batch = getOwnedVPNFrameBatch()
		}
	}
}

// dispatchBatch 把一个 owned batch 分发给后端，并接管其中全部 payload。
// 成功时 batch 指针本身转交给唯一后端；失败时本函数负责释放并归池。
func (p *AsyncPort) dispatchOwnedBatch(batch *VPNFrameBatch) {
	if batch == nil {
		return
	}
	// 只在快照读取时持读锁；派发、FEC parity 与拥塞退避全部使用快照。
	// ownedCh 从不关闭（UnregisterOwnedBackend 只摘表项，Backend 对象由快照
	// 持有引用），锁外发送安全。此前整个派发——含最长 5ms 的拥塞自旋——都压
	// 在 backendsMu 之下：UnregisterOwnedBackend 的写锁被阻塞，且 Go RWMutex
	// 写者等待期间新读者也排队，重连风暴会反压入口队列（结构性放大器）。
	p.backendsMu.RLock()
	backends := p.backends
	p.backendsMu.RUnlock()
	if len(backends) == 0 {
		p.dropN(len(batch.Frames))
		freeOwnedVPNFrameBatch(batch)
		return
	}
	pressure := p.schedulerPressureFor(backends, batch.Bytes)
	dataBest := p.pickAdaptiveBackend(backends, pressure, batch.Bytes)

	if p.encoder != nil {
		// near 三态观测维护：数据路径契约上恒在窗口内（或未收敛宽松），但
		// pickParityBackend 的首轮循环跳过 dataBest 不发布，热切 auto 后旧 near
		// 位也会永久残留——这里每批补一次 dataBest 发布，并在策略码切换后的
		// 第一批清掉全部后端的 near 位（run goroutine 独占，无锁）。
		curStrategy := p.fecStrategy.Load()
		if curStrategy != p.lastFecStrategy {
			p.lastFecStrategy = curStrategy
			for _, b := range backends {
				if b != nil {
					b.schedFlagsSet(schedFlagNearIn|schedFlagNearLenient, 0)
				}
			}
		}
		if dataBest != nil {
			p.publishNearState(dataBest, dataBest)
		}
		parities := p.parityScratch[:0]
		for _, vf := range batch.Frames {
			if par := p.encoder.add(vf); par != nil {
				parities = append(parities, par)
			}
		}
		p.fecTXArmed.Store(p.encoder.multipath && p.encoder.armed)
		best := dataBest
		p.dropN(sendOwnedBatchToAnyFenced(p, backends, best, batch))
		if len(backends) < 2 {
			// 单路径：encoder 已旁路，parities 恒空；防御性释放。
			for _, par := range parities {
				putFrame(par)
			}
		} else if len(parities) > 0 {
			// 同一次 flush 的 parity 合并为单个 owned batch：此前每份 parity
			// 各自走"取批次对象→入队→记账"，K=4 时每 4 个数据帧多一整套批次
			// 开销。目标仍由 pickParityBackend 轮转选择（每次 dispatch 旋转
			// 一步，跨批均匀分布）。
			target := p.pickParityBackend(backends, best)
			if target == nil {
				// near 模式下连数据路径都不健康：抑制本次 parity（near 的意图
				// 就是宁可不发也不发到慢链路/死链路）。与单路径防御分支一致，
				// 不计 paritySent。
				for _, par := range parities {
					putFrame(par)
				}
			} else {
				p.paritySent.Add(uint64(len(parities)))
				pbatch := getOwnedVPNFrameBatch()
				for _, par := range parities {
					appendOwnedVPNFrame(pbatch, VPNFrame{Seq: 0, Data: par})
				}
				n := pbatch.Bytes
				target.addQueuedBytes(n)
				if !tryQueueOwnedBatch(target, pbatch) {
					// 二分调试：逐份回退禁用，改回直接丢弃（昨日合批语义）
					target.completeQueuedBytes(n)
					p.dropN(len(pbatch.Frames))
					freeOwnedVPNFrameBatch(pbatch)
				} else {
					target.fecAssignedBytes.Add(n)
					target.fecAssignedBatches.Add(1)
				}
			}
		}
		clear(parities)
		p.parityScratch = parities[:0]
		return
	}

	p.dropN(sendOwnedBatchToAnyFenced(p, backends, dataBest, batch))
}

// dispatchBatch retains the historical raw-slice API for tests/cold callers.
// It converts once into the ownership object, transfers payload ownership, and
// never participates in the production AsyncPort.run hot path.
func (p *AsyncPort) dispatchBatch(batch []VPNFrame, batchBytes int) {
	owned := getOwnedVPNFrameBatch()
	owned.Frames = append(owned.Frames, batch...)
	owned.Bytes = uint64(batchBytes)
	for i := range batch {
		batch[i].Data = nil
	}
	p.dispatchOwnedBatch(owned)
}

const backendRTTHysteresisMin = 5_000 // 微秒

func backendScore(b *Backend) (uint32, bool) {
	qLen := b.queueLen()
	qCap := b.queueCap()
	if qCap == 0 || qLen >= qCap-2 || b.isStalled() || b.orphaned.Load() {
		return math.MaxUint32, false
	}
	rtt := atomic.LoadUint32(b.rttCache)
	penalty := uint64(0)
	if qLen > 10 {
		penalty = uint64(qLen-10) * 1000
	}
	score := uint64(rtt) + penalty
	if score > math.MaxUint32 {
		score = math.MaxUint32
	}
	return uint32(score), true
}

// pickBackend 使用 MinRTT + 积压评分，但为当前连接保留至少 12.5% RTT（最低
// 5ms）的切换滞回。相近 WAN 路径的轻微 RTT 抖动不会让相邻批次跨 TCP 流
// 来回切换；当前连接接近满队列时仍会立即转移。
func (p *AsyncPort) pickBackend(backends []*Backend) *Backend {
	var bestBackend *Backend
	var minScore uint32 = math.MaxUint32
	for _, b := range backends {
		score, ok := backendScore(b)
		if !ok {
			continue
		}
		if score < minScore {
			minScore = score
			bestBackend = b
		}
	}
	if bestBackend == nil {
		// 所有后端均不可用（stalled/满队列）。优先选一条未 stalled 的后端，
		// 避免回退到死路径；全部 stalled 时才取第一条兜底。
		bestBackend = backends[0]
		for _, b := range backends {
			if b != nil && !b.isStalled() {
				bestBackend = b
				break
			}
		}
		p.storePreferredIfCurrent(bestBackend)
		return bestBackend
	}
	current := p.preferred.Load()
	if current != nil && current != bestBackend {
		present := false
		for _, b := range backends {
			if b == current {
				present = true
				break
			}
		}
		if present {
			if currentScore, ok := backendScore(current); ok {
				// 滞回带锚定最优候选（bestBackend）的 RTT，而非 current：阈值必须与
				// "谁是 current"无关。若用 current（较慢）的 RTT，其 hysteresis 偏大，
				// 切换条件被放宽——一旦落到慢路径就再也回不到快路径（单向锁死）。
				// bestBackend 的 RTT 反映"值得离开的快路径有多快"，进出共用同一锚，
				// 两个方向对称（与 commitSinglePath 的粘滞带锚定 rank0 同理）。
				hysteresis := max(uint32(backendRTTHysteresisMin), atomic.LoadUint32(bestBackend.rttCache)/8)
				if uint64(currentScore) <= uint64(minScore)+uint64(hysteresis) {
					bestBackend = current
				}
			}
		}
	}
	p.storePreferredIfCurrent(bestBackend)
	return bestBackend
}

const (
	multipathStripeBacklog     = 64
	multipathStripeBatchFrames = 32
)

// pickDataBackend 保留低负载 MinRTT 行为；只有 AsyncPort 输入出现持续 backlog 时，
// 才在 RTT 接近最佳路径的健康后端中轮转。这样 bulk 流量可以真正并行使用多条
// TCP 连接，而交互式小流量仍保持最低延迟并避免不必要的跨流乱序。
func (p *AsyncPort) pickDataBackend(backends []*Backend) *Backend {
	return p.pickDataBackendFor(backends, len(p.ch) >= multipathStripeBacklog)
}

// pickDataBackendFor 接收 run goroutine 捕获的 bulk 快照。这样一次大批量已经
// drain 掉 p.ch 后仍能 striping；直接调用 pickDataBackend 的交互/测试语义不变。
func (p *AsyncPort) pickDataBackendFor(backends []*Backend, bulk bool) *Backend {
	best := p.pickBackend(backends)
	if len(backends) < 2 || !bulk || best == nil {
		return best
	}

	bestRTT := atomic.LoadUint32(best.rttCache)
	slack := max(uint32(backendRTTHysteresisMin), bestRTT/4)
	maxRTT := uint64(bestRTT) + uint64(slack)
	bestScore, _ := backendScore(best)
	maxScore := uint64(bestScore) + uint64(slack)

	start := int(p.dataNext % uint32(len(backends)))
	p.dataNext++
	for i := 0; i < len(backends); i++ {
		b := backends[(start+i)%len(backends)]
		score, ok := backendScore(b)
		if !ok {
			continue
		}
		if uint64(atomic.LoadUint32(b.rttCache)) <= maxRTT && uint64(score) <= maxScore {
			return b
		}
	}
	return best
}

// pickParityBackend 选择一条健康连接承载单份 parity。多连接时优先避开
// 当前 data path，并从轮转游标开始扫描，避免所有 parity 固定压在同一 TCP 流。
//
// near 策略（见 FecStrategy）额外要求候选的去程单程时延 ≤ 数据路径 fwd + 窗口，
// 使 parity 只落在与数据路径相近的连接上，抑制慢备链路的 parity 泄漏。
func (p *AsyncPort) pickParityBackend(backends []*Backend, dataBest *Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}
	nearOnly := fecStrategyForCode(p.fecStrategy.Load()) == FecStrategyNear
	start := int(p.parityNext % uint32(len(backends)))
	p.parityNext++
	if len(backends) > 1 {
		for i := 0; i < len(backends); i++ {
			b := backends[(start+i)%len(backends)]
			if b == dataBest {
				continue
			}
			if nearOnly {
				if st := p.publishNearState(b, dataBest); st == 0 {
					continue
				}
			}
			if _, ok := backendScore(b); ok {
				return b
			}
		}
	}
	if dataBest != nil {
		if _, ok := backendScore(dataBest); ok {
			if nearOnly {
				// 数据路径自身天然在窗口内（差值 0）；仍走同一发布通道，面板
				// 才能看出它拿到 parity 是"窗口内"而非"bootstrap 宽限"。
				p.publishNearState(dataBest, dataBest)
			}
			return dataBest
		}
	}
	for i := 0; i < len(backends); i++ {
		b := backends[(start+i)%len(backends)]
		if nearOnly {
			if st := p.publishNearState(b, dataBest); st == 0 {
				continue
			}
		}
		if _, ok := backendScore(b); ok {
			return b
		}
	}
	// 全部后端都不合格（stalled/队满，或 near 下全部窗口外）：返回 nil，由
	// 调用方抑制本次 parity——原实现无视 near 过滤与健康度直接取
	// backends[start]，是 near 语义的违例出口，且大概率入队失败丢帧。
	return nil
}

// parityNearEligible 报告候选后端是否落在 near 窗口内：其去程单程时延 ≤ 数据路径
// fwd + 窗口。用与选路同一估计的原始有符号相对量——同一轮 recompute 共享锚点，
// 差值中公共项抵消，两侧符号无关。任一侧探针未收敛时宽松返回 true：未收敛的
// 回退值是绝对内核尺度（min_rtt/2，双未知时是 50ms 哨兵折半），而已收敛的 ref
// 常为负，跨尺度比较会把未收敛候选系统性排除在窗口外（bootstrap 期 parity 全部
// 退化到数据路径），与"此时两者近等，本就无慢链之分"的文档承诺直接矛盾。
// publishNearState 计算 near 三态并发布到候选后端，返回该三态（0=窗口外）。
// pickParityBackend 的过滤条件即"三态 != 0"，与 parityNearEligible 语义一致；
// 发布让面板能区分"窗口内拿到 parity"与"探针未收敛的 bootstrap 宽限"。
func (p *AsyncPort) publishNearState(b, dataBest *Backend) uint32 {
	st := p.parityNearState(b, dataBest)
	if b != nil {
		b.schedFlagsSet(schedFlagNearIn|schedFlagNearLenient, st)
	}
	return st
}

// parityNearState near 窗口的三态：schedFlagNearIn=窗口内、schedFlagNearLenient=
// 探针未收敛的宽松放行、0=窗口外。ok 判定拿到的原始 oneWay 直接复用比较：
// adaptiveBackendOneWayUS 在已收敛时返回同一原始值（回退链只服务未测路径，
// 而未测已被 Lenient 分支提前认领），不必经 adaptive 再读一轮原子。
func (p *AsyncPort) parityNearState(b, dataBest *Backend) uint32 {
	if b == nil || dataBest == nil {
		return 0
	}
	refUS, okRef := dataBest.backendOneWayUS()
	if !okRef {
		return schedFlagNearLenient
	}
	fwdUS, okFwd := b.backendOneWayUS()
	if !okFwd {
		return schedFlagNearLenient
	}
	if fwdUS <= refUS+int64(p.fecNearWindowUS.Load()) {
		return schedFlagNearIn
	}
	return 0
}

// tryQueueOwnedBatch transfers batch ownership on success and leaves ownership
// with the caller on failure. Production backends use ownedCh and therefore do
// not copy descriptors. The legacy []VPNFrame channel exists only for cold/unit
// compatibility and snapshots descriptors before taking payload ownership.
func tryQueueOwnedBatch(b *Backend, batch *VPNFrameBatch) bool {
	if b == nil || batch == nil {
		return false
	}
	if b.ownedCh != nil {
		select {
		case b.ownedCh <- batch:
			return true
		default:
			return false
		}
	}
	if b.ch == nil {
		return false
	}
	legacy := getVPNFrameBatch(len(batch.Frames))
	copy(legacy, batch.Frames)
	select {
	case b.ch <- legacy:
		// payload ownership moved into the copied legacy descriptors; only the
		// ownership-object descriptor storage is returned here.
		putOwnedVPNFrameBatch(batch)
		return true
	default:
		putVPNFrameBatch(legacy)
		return false
	}
}

// sendOwnedBatchToAnyFenced is the production scheduler transfer. AsyncPort has
// already computed batch.Bytes while ingesting TAP frames, so neither scheduler
// nor TLS writer needs a frame-length scan.
func sendOwnedBatchToAnyFenced(p *AsyncPort, backends []*Backend, preferred *Backend, batch *VPNFrameBatch) int {
	out := batch
	if out == nil {
		return 0
	}
	outBytes := out.Bytes

	trySend := func(b *Backend) bool {
		if b == nil {
			return false
		}
		// orphaned（已注销、writer 已退）的后端绝不尝试：残留未满的死通道会
		// 静默吞掉整批（已分配线路 seq → 序号洞）。注意不能用 isStalled 判——
		// stalled 后端的 writer 仍活着并继续 drain，仍可承载流量（本机 Windows
		// 下 RTT 采样不可用会把健康后端打成 stalled，误跳过曾致 87% 丢包）。
		if b.orphaned.Load() {
			return false
		}

		sendBatch := out
		var ctrl fecModeControl
		fenced := false
		if p != nil && p.encoder != nil {
			if current, ok := p.encoder.currentModeControl(); ok && b.fecFenceGen.Load() < current.Generation {
				ctrl = current
				payload := getFrameAtLeast(fecControlWireLen)[:0]
				payload = appendFECModeControl(payload, current)
				withFence := getOwnedVPNFrameBatch()
				appendOwnedVPNFrame(withFence, VPNFrame{Seq: 0, Data: payload})
				withFence.Frames = append(withFence.Frames, out.Frames...)
				withFence.Bytes += out.Bytes
				withFence.RateBytes = out.RateBytes // fence 控制帧不计投递速率
				sendBatch = withFence
				fenced = true
			}
		}

		b.addQueuedBytes(sendBatch.Bytes)
		if tryQueueOwnedBatch(b, sendBatch) {
			if fenced {
				b.fecFenceGen.Store(ctrl.Generation)
				// sendBatch owns copied data descriptors now; return only out's
				// descriptor container, never the payloads.
				putOwnedVPNFrameBatch(out)
			}
			out = nil
			b.assignedBytes.Add(outBytes)
			b.assignedBatches.Add(1)
			return true
		}

		b.completeQueuedBytes(sendBatch.Bytes)
		if fenced {
			// The data payloads still belong to out. Only the temporary fence has
			// unique payload ownership on a failed attempt.
			putFrame(sendBatch.Frames[0].Data)
			sendBatch.Frames[0].Data = nil
			putOwnedVPNFrameBatch(sendBatch)
		}
		return false
	}

	tryAll := func() bool {
		if trySend(preferred) {
			return true
		}
		for _, b := range backends {
			if b != preferred && trySend(b) {
				return true
			}
		}
		return false
	}

	if tryAll() {
		return 0
	}

	deadline := time.Now().Add(5 * time.Millisecond)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Microsecond)
		if tryAll() {
			return 0
		}
	}

	dropped := len(out.Frames)
	freeOwnedVPNFrameBatch(out)
	return dropped
}

// sendBatchToAnyFenced is retained for cold/tests that still construct a raw
// []VPNFrame. It converts once into the ownership object; production AsyncPort
// never enters this compatibility path.
func sendBatchToAnyFenced(p *AsyncPort, backends []*Backend, preferred *Backend, batch []VPNFrame) int {
	owned := getOwnedVPNFrameBatch()
	owned.Frames = append(owned.Frames, batch...)
	owned.Bytes = vpnFrameBatchBytes(batch)
	for i := range batch {
		batch[i].Data = nil
	}
	return sendOwnedBatchToAnyFenced(p, backends, preferred, owned)
}

func sendBatchToAny(backends []*Backend, preferred *Backend, batch []VPNFrame) int {
	return sendBatchToAnyFenced(nil, backends, preferred, batch)
}

func sendBatchTo(b *Backend, batch []VPNFrame) int {
	return sendBatchToAny([]*Backend{b}, b, batch)
}

// sendOwnedFrameTo transfers one already-owned payload as a one-frame batch.
func sendOwnedFrameTo(b *Backend, vf VPNFrame) int {
	if b == nil {
		if vf.Data != nil {
			putFrame(vf.Data)
		}
		return 1
	}
	out := getOwnedVPNFrameBatch()
	appendOwnedVPNFrame(out, vf)
	n := out.Bytes
	b.addQueuedBytes(n)
	if tryQueueOwnedBatch(b, out) {
		b.fecAssignedBytes.Add(n)
		b.fecAssignedBatches.Add(1)
		return 0
	}
	b.completeQueuedBytes(n)
	freeOwnedVPNFrameBatch(out)
	return 1
}

// sendFrameTo retains copy semantics for callers that do not transfer payload ownership.
func sendFrameTo(b *Backend, vf VPNFrame) int {
	if b == nil {
		return 1
	}
	out := getOwnedVPNFrameBatch()
	appendOwnedVPNFrame(out, VPNFrame{Seq: vf.Seq, Data: cloneFrame(vf.Data)})
	n := out.Bytes
	b.addQueuedBytes(n)
	if tryQueueOwnedBatch(b, out) {
		return 0
	}
	b.completeQueuedBytes(n)
	freeOwnedVPNFrameBatch(out)
	return 1
}

// Lifetime recovery counters survive receive decoder/key-epoch replacement.
func (c *Client) FECRecovered() uint64       { return c.fecLifetime.recovered.Load() }
func (c *Client) FECLost() uint64            { return c.fecLifetime.lost.Load() }
func (c *Client) FECStats() (uint64, uint64) { return c.FECRecovered(), c.FECLost() }

// ReconnectAttempts 累计重连尝试次数
func (c *Client) ReconnectAttempts() uint64 { return atomic.LoadUint64(&c.reconnects) }

// ForceReconnect 触发所有物理连接断开并由重连循环重建（面板控制用）。
// 世代计数保证多次触发都能重置退避，且不会造成热循环。
func (c *Client) ForceReconnect() {
	atomic.AddUint64(&c.forceGen, 1)
	c.connsMu.Lock()
	for _, ci := range c.conns {
		if v := ci.conn.Load(); v != nil {
			v.(connHolder).CloseIfOpen()
		}
	}
	c.connsMu.Unlock()
	c.wakeAll()
}
func (p *AsyncPort) Close() { p.cancel() }

// rebalanceBrutalRates 在物理连接数变化后重新分配 Brutal 整形份额。
//
// 初始握手时每条连接按 config 声明的 connsCount 均分总预算；当其余连接断开
// 后，幸存连接应拿到更大的份额（例如 4 条中的 3 条断开后，幸存者应拿回全部
// 预算而不是停在 1/4）。v2 group 语义由内核在组内自动重分配，本方法只是用
// 新的逐连接份额重新 apply 一次（对 v2 等价于设置相同的组总速率，无害）。
//
// 调用方在连接 up/down 计数变化后触发；本方法自行加锁遍历。
// skipConnIndex >= 0 表示跳过该连接（正在断开、socket 已关闭，无需也不应再
// 重新整形），-1 表示遍历全部。
func (c *Client) rebalanceBrutalRates(skipConnIndex int) {
	live := int(atomic.LoadInt32(&c.liveConns))
	if live <= 0 {
		return
	}
	c.connsMu.Lock()
	defer c.connsMu.Unlock()
	for connIndex, ci := range c.conns {
		if ci == nil || connIndex == skipConnIndex {
			continue
		}
		if state, _ := ci.state.Load().(string); state != "up" {
			continue
		}
		cfg := ci.brutalCfg.Load()
		if cfg == nil || !cfg.enabled {
			continue
		}
		tcpConn := ci.observedTCP.Load()
		if tcpConn == nil {
			continue
		}
		// 按当前实际存活连接数重新计算逐连接份额（v1 逐连接 ABI）。
		newLegacy := splitLegacyBrutalRateBps(cfg.totalRateMbps, live, cfg.connIndex)
		br := applyTCPBrutal(tcpConn, cfg.totalRateMbps, newLegacy, cfg.groupID)
		ci.brutal.Store(br.clone())
		if !br.Applied {
			log.Warnf("[Conn %d] TCP Brutal rebalance skipped: %s", cfg.connIndex, br.Error)
		} else if br.Error != "" {
			log.Debugf("[Conn %d] TCP Brutal rebalance limited observability: %s", cfg.connIndex, br.Error)
		}
	}
}

// ======================= 客户端实现 =======================

// parseServerAddresses 解析逗号分隔的服务器地址字符串，并清理空格
func parseServerAddresses(addrStr string) []string {
	var addrs []string
	rawList := strings.Split(addrStr, ",")

	for _, raw := range rawList {
		cleanAddr := strings.TrimSpace(raw)
		if cleanAddr != "" {
			addrs = append(addrs, cleanAddr)
		}
	}

	// 如果由于某种原因解析后为空，提供一个安全的降级处理
	if len(addrs) == 0 {
		return []string{}
	}
	return addrs
}

type Client struct {
	fecLifetime     fecLifetimeCounters
	clientID        string
	serverSessionID string // 记录服务端的会话ID
	sessionToken    string // 服务端下发的会话令牌；重连握手时回带，用于
	// 防止持密者冒充一个已在线的会话
	gwV4      string     // 记录网关以便退出时清理
	gwV6      string     // 记录网关以便退出时清理
	sessionMu sync.Mutex // 保护状态防止并发写
	stateMu   sync.Mutex // 保护 state（多条物理连接的握手协程会并发落盘）
	stateFile string     // 身份状态文件路径；""=不持久化
	state     *clientState
	// 策略路由的安装记录：配置意图在 cfg 快照里，这里回答"现在到底生效
	// 没有"。prMark/prGw* 是已实际写进内核的那一份参数，退出或热更时按它
	// 清理，而不是按当前生效配置——配置改了之后旧规则还在内核里。
	prMu        sync.Mutex
	prMark      int
	prGwV4      string
	prGwV6      string
	prExtra     []string
	prSrc       []SourceRule
	prInstalled []policyRoutingSpec
	prOK        bool
	prErr       string
	// live 指向当前生效配置；面板热更时整体替换该指针，
	// dialAndServe 每轮重拨前取最新值
	live             atomic.Pointer[liveConfig]
	interfaceManager string
	netifdInterface  string
	netifdMu         sync.Mutex
	netifdState      netifdLinkState
	tapName          string
	macAddr          string
	tap              io.ReadWriteCloser
	connsCount       int32  // 与 live.conns 一致的只读影子（连接注册表按此建）
	fecNegotiated    int    // 0=未协商, >0=XOR 分组大小
	fecStatus        string // 面板展示用
	fecAlgo          int    // fecDec 绑定的加密算法（会话重建判据）
	fecSaltKey       string // fecDec 绑定的盐（会话重建判据）
	txPort           *AsyncPort
	rttProbe         *rttProbeScheduler    // 跨路径 RTT 探针（握手协商后启用）
	clockOffset      *clockOffsetScheduler // 双向时钟偏移探针（握手协商后启用）
	rxReorder        *ReorderBuffer
	rxWorker         *rxSessionWorker
	fecDec           *fecDecoder
	TxBytes          atomic.Uint64
	RxBytes          atomic.Uint64
	TxPackets        atomic.Uint64
	RxPackets        atomic.Uint64
	icTx             *innerCipher           // 当前会话发送方向（GCM）
	icRx             *innerCipher           // 当前会话接收方向（GCM）
	encAlgo          int                    // 当前会话协商结果（encAlgoNone / encAlgoGCM）
	assignedV4       string                 // 服务端分配的 IPv4（面板展示）
	assignedV6       string                 // 服务端分配的 IPv6（面板展示）
	liveConns        int32                  // 当前已建立的物理连接数（面板展示）
	tapWriteErrs     atomic.Uint64          // TAP 交付失败帧数（旧实现被静默吞掉）
	reconnects       uint64                 // 累计重连尝试次数（面板展示）
	forceGen         uint64                 // 强制重连世代：递增即要求重连循环跳过退避
	wake             chan struct{}          // 重连唤醒：强制重连/热更配置时广播（缓冲 1，非阻塞）
	instanceID       atomic.Value           // string：本进程实例；变化即要求服务端换密钥代际
	sessionEpoch     uint64                 // 服务端确认的密钥代际
	peerInfo         PeerInfo               // 服务端自报诊断元数据；sessionMu 保护
	negInfo          *sessionNeg            // 上次成功握手的协商快照（面板展示用）
	cfgSnap          atomic.Pointer[Config] // 数据面实际生效完整配置（hook/up 启动数据源）
	// desiredCfg 用户已保存、期望达到的配置（设置页/状态卡回显与 PendingRestart
	// 数据源）。与 cfgSnap 分离：仅保存（不热应用）时 desiredCfg 更新为磁盘目标态，
	// cfgSnap 保持数据面真实生效值。ApplyConfig（save_apply）时两者同步。
	desiredCfg       atomic.Pointer[Config]
	bootCfg          atomic.Pointer[Config] // 启动时配置（NeedsRestart 差异基准）
	connsMu          sync.Mutex
	conns            map[int]*clientConnInfo // 每物理连接明细（connIndex → 状态）
	startedAt        time.Time
	hooks            *LifecycleHooks
	runCancel        context.CancelFunc
	fatalOnce        sync.Once
	fatalErr         chan error
	networkSetup     sync.Mutex
}

// sessionNeg 最近一次握手成功的端到端协商结果快照。面板"状态"页展示的是
// 它而不是本地配置值：配置写 brutal 不代表内核真做了 shaping，写 GCM 不
// 代表服务端真的回了 GCM——两者必须分开看。
type sessionNeg struct {
	ProtocolVersion int
	FEC             bool
	FecGroup        int
	EncAlgo         int
	PadMode         string
	SessionToken    bool
	SessionEpoch    uint64
	TxRateMbps      uint64 // 服务端为本端上行分配的整形速率
	RxRateMbps      uint64 // 服务端为本端下行分配的整形速率
	TLS             *TLSHandshakeInfo
}

// liveConfig 客户端热更生效的连接相关参数快照（不含 TAP/MAC 等需重启项）
type liveConfig struct {
	psk            string
	targetAddrs    []string
	reqV4          string
	reqV6          string
	sni            string
	insecure       bool
	certHash       string
	fwmark         int
	fwmarkPriority int
	extraRoutes    []string
	sourceRules    []SourceRule
	brutal         bool
	brutalUp       uint64
	brutalDown     uint64
	connsCount     int
	fecMode        bool
	fecGroup       int
	encrypt        bool
	encAlgo        int // encAlgoGCM(AES-256) / encAlgoGCM128(AES-128)
	minEnc         int // 内层加密强度下限（minEncRank 值，0=不限）
	// 数据面写队列优先级：控制帧 vs 数据帧谁先写（数值高者先）。写 goroutine
	// 每次拨号快照一次，热更后新连接生效。
	priorityControl int
	priorityData    int
}

// liveFromCfg 从完整配置提取热更子集
func liveFromCfg(cfg *Config) *liveConfig {
	return &liveConfig{
		psk: cfg.PSK, targetAddrs: parseServerAddresses(cfg.Addr),
		reqV4: cfg.Client.ReqV4, reqV6: cfg.Client.ReqV6,
		sni: cfg.Client.SNI, insecure: cfg.Client.Insecure, certHash: cfg.Client.CertSHA256,
		fwmark: cfg.Client.Fwmark, fwmarkPriority: cfg.Client.FwmarkPriority, extraRoutes: cfg.Client.ExtraRoutes,
		sourceRules: cfg.Client.SourceRules,
		brutal:      cfg.Brutal, brutalUp: cfg.BrutalUp, brutalDown: cfg.BrutalDown,
		connsCount: cfg.Client.Conns, fecMode: cfg.Client.FEC, fecGroup: cfg.Client.FecGroup,
		encrypt: cfg.Encrypt, encAlgo: encAlgoFromConfig(cfg.EncAlgo), minEnc: minEncRank(cfg.MinEnc),
		priorityControl: intValue(cfg.PriorityControl), priorityData: intValue(cfg.PriorityData),
	}
}

// policyRoutingSpec 一次策略路由安装或清理所需的全部参数。拆成结构体是因为
// 安装和清理必须拿到同一份：清理时按错表号或错优先级会把规则留在内核里。
type policyRoutingSpec struct {
	mark        int    // 0 = 关闭 fwmark 规则
	priority    uint32 // 0 = 交给内核分配
	gwV4        string // 空串 = 服务端未下发该族的网关，跳过
	gwV6        string
	extra       []string     // fwmark 表的额外路由，iproute2 序列化语法
	sourceRules []SourceRule // 按源地址前缀的规则，与 fwmark 相互独立
}

// policyRoutingSpecFor 组合生效配置与服务端下发的网关。网关来自握手响应而非
// 本地配置，因为前缀随服务器变化，写死在客户端配置里迟早过期。
func policyRoutingSpecFor(lv *liveConfig, gwV4, gwV6 string) policyRoutingSpec {
	return policyRoutingSpec{
		mark: lv.fwmark, priority: uint32(lv.fwmarkPriority),
		gwV4: gwV4, gwV6: gwV6, extra: lv.extraRoutes, sourceRules: lv.sourceRules,
	}
}

// specEmpty 判断这份 spec 是否需要装任何东西。两类规则任一非空即需安装。
func specEmpty(s policyRoutingSpec) bool {
	return s.mark <= 0 && len(s.sourceRules) == 0
}

// sameStringSlice 判断两个字符串切片是否逐元素相等。
func sameStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// samePolicySpec 判断两份 spec 是否描述了同一组内核对象。
// 网关不参与比较：它来自握手响应，每次可能不同，而"同一组规则"只由 mark 和
// source_rules 决定。
func samePolicySpec(a, b policyRoutingSpec) bool {
	if a.mark != b.mark || !sameStringSlice(a.extra, b.extra) {
		return false
	}
	if len(a.sourceRules) != len(b.sourceRules) {
		return false
	}
	for i := range a.sourceRules {
		x, y := a.sourceRules[i], b.sourceRules[i]
		if x.From != y.From || x.Table != y.Table || x.Priority != y.Priority {
			return false
		}
		if !sameStringSlice(x.Routes, y.Routes) {
			return false
		}
	}
	return true
}

// containsPolicySpec 判断已安装清单里是否已有同一组规则。
func containsPolicySpec(specs []policyRoutingSpec, spec policyRoutingSpec) bool {
	for _, s := range specs {
		if samePolicySpec(s, spec) {
			return true
		}
	}
	return false
}

// mergePolicySpecs 合并两份安装清单，已存在的条目保留原条目
// （原条目带有当时真实写入内核的参数，覆盖会丢掉旧的优先级或额外路由）。
func mergePolicySpecs(dst, src []policyRoutingSpec) []policyRoutingSpec {
	for _, s := range src {
		if specEmpty(s) || containsPolicySpec(dst, s) {
			continue
		}
		dst = append(dst, s)
	}
	return dst
}

// policyRoutingResult 最近一次策略路由安装的结果快照。
func (c *Client) policyRoutingResult() (ok bool, err string) {
	c.prMu.Lock()
	defer c.prMu.Unlock()
	return c.prOK, c.prErr
}

// notePolicyRouting 记录本次安装结果，供面板的"策略路由是否生效"一栏读取。
func (c *Client) notePolicyRouting(err error) {
	c.prMu.Lock()
	c.prOK = err == nil
	if err == nil {
		c.prErr = ""
	} else {
		c.prErr = err.Error()
	}
	c.prMu.Unlock()
}

// installedSpecFor 取出当前已写入内核的那一份 spec（调用方持有 prMu）。
// 从未安装成功过返回 nil。
func (c *Client) installedSpecFor() *policyRoutingSpec {
	if c.prMark <= 0 && len(c.prSrc) == 0 {
		return nil
	}
	s := policyRoutingSpec{mark: c.prMark, gwV4: c.prGwV4, gwV6: c.prGwV6,
		extra: c.prExtra, sourceRules: c.prSrc}
	return &s
}

// takePolicyRoutingInstalled 取出已安装清单并清空，进程退出时调用一次。
func (c *Client) takePolicyRoutingInstalled() []policyRoutingSpec {
	c.prMu.Lock()
	defer c.prMu.Unlock()
	out := c.prInstalled
	c.prInstalled = nil
	return out
}

// installPolicyRouting 安装当前生效配置的策略路由，并保证幂等：
// 先清掉上一轮写进内核的东西，再装新的。清理必须用当时真实写入的参数
// （优先级、额外路由都可能是旧值），所以不能拿当前配置去删。
func (c *Client) installPolicyRouting(spec policyRoutingSpec) error {
	c.prMu.Lock()
	snap := c.installedSpecFor()
	if snap != nil && samePolicySpec(*snap, spec) {
		// 同一组规则的重复安装：旧规则会撞 "File exists"，先按旧参数清干净。
		// 网关来自握手响应可能变化（前缀按请求下发），所以用本轮的下发值
		// 覆盖 snap 的网关，只保留它独有的旧优先级和旧额外路由。
		snap.gwV4, snap.gwV6 = spec.gwV4, spec.gwV6
		s := *snap
		// 覆盖末条而非追加：fwmark 客户端按 1-3s 退避持续重连，追加会让
		// prInstalled 随运行时长线性增长，退出清理对同组规则重复执行。
		if n := len(c.prInstalled); n > 0 {
			c.prInstalled[n-1] = s
		} else {
			c.prInstalled = append(c.prInstalled, s)
		}
	}
	c.prMark = spec.mark
	c.prGwV4, c.prGwV6 = spec.gwV4, spec.gwV6
	c.prExtra = spec.extra
	c.prSrc = spec.sourceRules
	if !containsPolicySpec(c.prInstalled, spec) {
		c.prInstalled = append(c.prInstalled, spec)
	}
	c.prMu.Unlock()

	if snap != nil && samePolicySpec(*snap, spec) {
		cleanPolicyRouting(c.tapName, *snap)
	}
	err := setupPolicyRouting(c.tapName, spec)
	if err != nil {
		log.Warnf("policy routing configuration failed: %v", err)
	}
	c.notePolicyRouting(err)
	return err
}

// ApplyConfig 面板热更入口：原子替换生效配置并唤醒所有重连监督器。
// conns 数量变化时重建连接注册表（新数量生效于下一次重拨）。
func (c *Client) ApplyConfig(cfg *Config) {
	lv := liveFromCfg(cfg)
	// 空目标列表会让 dialAndServe 的 connIndex%len(...) 除零 panic（Validate
	// 已拒绝，这里再挡一层纵深防御）：拒绝本次热更，保留旧 live 继续运行。
	if len(lv.targetAddrs) == 0 {
		log.Errorf("[Client] hot-apply rejected: client.addr parses to zero target addresses, keeping current config")
		return
	}
	// 捕获旧 live 必须早于 Store：比较要拿「本次热更之前」的生效值，否则
	// Store 之后 Load 读到的已是新值，DeepEqual 恒真而永远不触发重连。
	oldLive := c.live.Load()
	c.live.Store(lv)
	c.cfgSnap.Store(cfg)
	c.desiredCfg.Store(cfg) // save_apply：数据面与目标态同步
	// 内层加密器不在此处重建：GCM 实例由每次握手的会话盐派生，直接取自
	// 刚更新的 lv.psk，无需额外的共享回退加密器。

	// 填充策略全局生效于发送路径
	if actual := setPadMode(cfg.PadMode); actual != cfg.PadMode {
		log.Warnf("[Client] Invalid pad_mode %q, using %s", cfg.PadMode, actual)
	}
	// 选路算法热更：调度器每批读取，新一批即生效。
	c.txPort.SetRoutingAlgo(cfg.RoutingAlgo)
	// 候选资格门维度与 fwd 窗口热更：buildEligibleCandidates 每批读取。
	c.txPort.SetSchedEnvelope(cfg.SchedEnvelope)
	c.txPort.SetSchedEnvelopeMs(cfg.SchedEnvelopeMs)
	// FEC parity 分发策略与 near 窗口热更：pickParityBackend 每批读取。
	c.txPort.SetFecStrategy(cfg.FecStrategy)
	c.txPort.SetFecNearWindowMs(cfg.FecNearWindowMs)
	// 单向时延物理锚定下界热更：recomputeAll 每次读取，下一次探针收敛即生效。
	c.txPort.SetProbeMinHalfRTTUs(intValue(cfg.ProbeMinHalfRTTUs))
	if int32(lv.connsCount) != c.connsCount {
		// 监督器数量属于进程拓扑，当前实现不在运行中增删 goroutine。保留启动
		// 值并由 NeedsRestart 明确报告，避免面板声称已热更但实际没有生效。
		lv.connsCount = int(c.connsCount)
		log.Warnf("[Client] client.conns change requires restart (effective=%d requested=%d)", c.connsCount, cfg.Client.Conns)
	}
	// 只对「新连接才生效」的握手消费字段变化才重连。liveConfig 不含四个纯原子
	// 热更字段（routing_algo/fec_strategy/fec_near_window_ms/pad_mode，它们已在
	// 上方 setter 立即生效），因此仅当这些调度字段变化时新旧 live 相等，无需
	// 撕裂并重拨所有连接——否则每次保存调度设置都会触发一次全量重连风暴。
	if oldLive == nil || !reflect.DeepEqual(oldLive, lv) {
		c.ForceReconnect()
	}
	log.Infof("[Client] Configuration hot-applied (conns=%d fec=%v fecGroup=%d encrypt=%v brutal=%v)",
		lv.connsCount, lv.fecMode, lv.fecGroup, lv.encrypt, lv.brutal)
}

// wakeAll 非阻塞唤醒所有等待中的重连监督器
func (c *Client) wakeAll() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// brutalRebalanceCfg 保存 Brutal 整形参数，供连接数变化时重新分配每连接份额。
// 连接建立后存活数变化（其余物理连接断开/重连）时，幸存连接应重新获得更大
// 的整形份额（v1 逐连接 ABI），而不是永远停在握手时按 connsCount 均分的份额。
type brutalRebalanceCfg struct {
	totalRateMbps uint64 // 会话整形总预算（Mbps），v2 group 语义下由内核在组内重分配
	groupID       uint64 // 内核 group id（v2 有效）
	connIndex     int    // 本连接在配置中的下标，用于重新计算逐连接份额
	enabled       bool   // 是否已成功应用 Brutal（false 则无需重协商）
}

// clientConnInfo 单条物理连接的运行明细（面板展示 + 强制重连句柄）
type clientConnInfo struct {
	observedTCP    atomic.Pointer[net.TCPConn]
	observedProxy  atomic.Bool
	tcpObservation atomic.Pointer[tcpSocketSnapshot]
	target         string
	connID         atomic.Value // string：本次物理连接握手 ID；每次重拨都会更新
	remote         atomic.Value // string：对端地址（握手后可得）
	state          atomic.Value // string：connecting / up / retrying
	lastError      atomic.Value // string：最近一次失败原因
	rttMeasured    atomic.Bool
	rttCache       *uint32 // 微秒（200ms 刷新）
	minRttCache    *uint32 // tcpi_min_rtt（微秒，无拥塞地板）
	backend        atomic.Pointer[Backend]
	conn           atomic.Value // connHolder：强制重连时关闭（统一包装类型避免 Value 类型不一致 panic）
	txBytes        atomic.Uint64
	rxBytes        atomic.Uint64
	retries        atomic.Uint64
	// peerActiveAt 最近一次收到对端 0x07 active-paths 帧且本槽位在对端活跃
	// 位图中的时刻（unix ns；0=从未）。快照按 2s 窗口判过期。
	peerActiveAt atomic.Int64
	brutal       atomic.Pointer[brutalApplyResult]  // 本连接的内核实际状态；nil=尚未尝试
	brutalCfg    atomic.Pointer[brutalRebalanceCfg] // Brutal 重协商参数（连接数变化时用）
	negotiated   atomic.Pointer[sessionNeg]
	linkedAt     int64 // 最近一次握手成功时间（unix 秒，0=未连接过）
}

// startClient 以 JSON 配置启动客户端（cfg 已经过 applyDefaults + Validate）
func startClient(ctx context.Context, cfg *Config) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	c := NewClient(runCtx, cfg)
	defer c.tap.Close()
	c.hooks = NewLifecycleHooks(cfg.Up, cfg.Down)
	c.runCancel = cancel
	c.fatalErr = make(chan error, 1)
	c.Run(runCtx)
	downErr := c.hooks.Down()
	select {
	case err := <-c.fatalErr:
		if downErr != nil {
			return fmt.Errorf("%v; cleanup failed: %w", err, downErr)
		}
		return err
	default:
		return downErr
	}
}

func (c *Client) failProcess(err error) {
	c.fatalOnce.Do(func() {
		if c.fatalErr != nil {
			c.fatalErr <- err
		}
		if c.runCancel != nil {
			c.runCancel()
		}
	})
}

// applyTapMac 决定并应用客户端的 TAP MAC。MAC 是 clientID 的输入，进而决定
// 服务端会话与分配的隧道 IP；Linux 上 water 每次创建 TAP 都发随机 MAC，
// 因此未显式配置时必须生成并落盘，否则每次重启都是一次全新会话——换新 IP，
// 而旧会话还要占用旧 IP 满 120 秒。非 Linux 平台设置 MAC 是编译桩，此时不
// 生成也不落盘：clientID 退化为仅由 PSK 派生，本身已跨进程稳定。
func applyTapMac(tapName, configuredMac, statePath string, st *clientState) {
	if !netlinkTunnelSupported() {
		log.Warnf("Client: TAP MAC configuration is not available on this platform (tunnels target Linux); clientID is derived from PSK only")
		return
	}
	mac := configuredMac
	if mac == "" && st.MAC != "" {
		mac = st.MAC
		log.Infof("Restored persistent TAP MAC: %s", mac)
	}
	if mac == "" {
		gen, err := generateTapMAC()
		if err != nil {
			log.Fatalf("Client failed to generate tap MAC: %v", err)
		}
		mac = gen
	}
	if err := setTapMac(tapName, mac); err != nil {
		log.Warnf("Client failed to set tap MAC: %v", err)
		return
	}
	if configuredMac == "" && st.MAC != mac {
		st.MAC = mac
		if err := saveClientState(statePath, st); err != nil {
			log.Warnf("Client failed to persist TAP MAC: %v", err)
		} else {
			log.Infof("Generated and persisted TAP MAC: %s", mac)
		}
	}
}

// NewClient 构造客户端运行体（TAP、密钥、面板、连接注册表），供进程启动
// 与测试进程内使用。
func NewClient(ctx context.Context, cfg *Config) *Client {
	cl := cfg.Client
	log.Infof("Starting TCP TLS client process...")

	statePath := clientStatePath(cfg)
	var st *clientState
	st, loadErr := loadClientState(statePath)
	if loadErr != nil {
		log.Warnf("Client failed to read identity state %s: %v", statePath, loadErr)
	}
	if st == nil {
		st = &clientState{}
	}

	var iface io.ReadWriteCloser
	if cfg.Tap == "mem" {
		iface = newMemTap(ctx)
		log.Infof("Using in-memory TAP backend (no real device)")
	} else {
		t, err := water.New(newTapConfig(cfg.Tap))
		if err != nil {
			log.Fatalf("Client TAP creation error: %v", err)
		}
		iface = t
		applyTapMac(cfg.Tap, cfg.Mac, statePath, st)
	}
	actualMac := cfg.Mac
	if actualMac == "" && cfg.Tap != "mem" {
		if link, err := netlink.LinkByName(cfg.Tap); err == nil {
			actualMac = link.Attrs().HardwareAddr.String()
		}
	}
	if actualMac == "" {
		actualMac = st.MAC
	}
	if actualMac == "" {
		var genErr error
		actualMac, genErr = generateTapMAC()
		if genErr != nil {
			log.Fatalf("Client failed to generate stable identity MAC: %v", genErr)
		}
		st.MAC = actualMac
		if err := saveClientState(statePath, st); err != nil {
			log.Fatalf("Client failed to persist stable identity MAC: %v", err)
		}
	}
	if parsed, ok := parseMACKey(actualMac); ok {
		actualMac = fmtMAC(parsed)
	}

	ns := uuid.NewMD5(uuid.NameSpaceURL, []byte("my_vpn_tunnel"))
	clientID := uuid.NewSHA1(ns, []byte(actualMac+cfg.PSK)).String()
	log.Infof("Assigned UUID v5 ClientID: %s", clientID)

	netifdInterface := ""
	if cl.InterfaceManager == "netifd" {
		if cfg.Tap == "mem" {
			log.Fatalf("client.interface_manager=netifd requires a real TAP device")
		}
		netifdInterface = strings.TrimSpace(os.Getenv("TLSVPN_NETIFD_INTERFACE"))
		if netifdInterface == "" {
			log.Fatalf("client.interface_manager=netifd requires TLSVPN_NETIFD_INTERFACE from the netifd protocol handler")
		}
	}

	c := &Client{
		clientID: clientID, tapName: cfg.Tap,
		interfaceManager: cl.InterfaceManager, netifdInterface: netifdInterface,
		tap: iface, macAddr: actualMac, connsCount: int32(cl.Conns),
		txPort:    NewAsyncPort(ctx, "client_tx_port"),
		stateFile: statePath, state: st,
		startedAt: time.Now(),
	}
	// 去程调度使用 fwd（client→server）单向估计。
	c.txPort.SetOneWayMode(oneWayModeFwd)
	// 本端调度器活跃槽位周期广播（0x07 active-paths）：让对端面板标注
	// "客户端上行调度正活跃在哪条连接"。随 port ctx 停止，无泄漏。
	c.txPort.startPeerActiveBroadcaster()
	// 启动即应用配置里的选路算法；空值归一化为 auto。
	c.txPort.SetRoutingAlgo(cfg.RoutingAlgo)
	// 候选资格门维度与 fwd 窗口：buildEligibleCandidates 每批读取。
	c.txPort.SetSchedEnvelope(cfg.SchedEnvelope)
	c.txPort.SetSchedEnvelopeMs(cfg.SchedEnvelopeMs)
	// FEC parity 分发策略与 near 窗口热更：pickParityBackend 每批读取。
	c.txPort.SetFecStrategy(cfg.FecStrategy)
	c.txPort.SetFecNearWindowMs(cfg.FecNearWindowMs)
	// 单向时延物理锚定下界（µs），抑制 ref 自回包亚毫秒极值造成的锚定伪值。
	c.txPort.SetProbeMinHalfRTTUs(intValue(cfg.ProbeMinHalfRTTUs))
	// 双向时钟偏移探针：与 RTT 探针同纪律，独立协商、独立定时。仅作两端时钟偏移
	// 的观测展示（快照 clock_offset_ns），不参与单向时延分解——绝对分解欠定。
	c.clockOffset = newClockOffsetScheduler(ctx, c.probeResolveConn, c.probeActiveConns)
	c.clockOffset.start()
	// 把 θ 读取器挂到 tx 端口，使 Backend 快照能暴露时钟偏移观测值。
	c.txPort.SetClockOffsetTheta(func() (int64, uint64, bool) { return c.clockOffset.thetaNS() })
	// 跨路径 RTT 探针：解析器按 connIndex 取当前 Backend，连接数随配置固定。
	// minHalfRefUS 从端口原子读取，使配置热更在下一轮收敛即生效。
	c.rttProbe = newRttProbeScheduler(ctx, c.probeResolveConn, c.probeActiveConns,
		func() uint64 { return c.txPort.probeMinHalfRTTUS.Load() })
	c.rttProbe.start()
	lv := liveFromCfg(cfg)
	c.bootCfg.Store(cfg)
	c.cfgSnap.Store(cfg)
	c.desiredCfg.Store(cfg) // 启动时目标态=生效态=启动配置
	c.wake = make(chan struct{}, 1)
	c.instanceID.Store(uuid.New().String())
	c.live.Store(lv)
	if len(lv.targetAddrs) == 0 {
		log.Fatalf("Client addr resolved to zero endpoints; check the addr field in the config file")
	}
	c.fecStatus = "off"
	c.txPort.SetSequenceExhaustedHandler(func() {
		c.instanceID.Store(uuid.New().String())
		log.Warnf("[Client] sequence space exhausted; rotating the process instance and reconnecting with fresh keys")
		c.ForceReconnect()
	})

	// 恢复会话身份：冷启动进程第一次握手就能携带旧令牌接回既有会话，
	// 不必等 120 秒僵尸会话过期。按 clientID 绑定校验——MAC/PSK 变了
	// clientID 就变了，旧令牌与旧会话 ID 一律不沿用。
	if st.ClientID == clientID && st.SessionID != "" {
		c.serverSessionID = st.SessionID
		c.sessionEpoch = st.SessionEpoch
		if st.SessionToken != "" {
			c.sessionToken = st.SessionToken
			log.Infof("Restored session token for %s; next handshake will rejoin the existing session", st.SessionID)
		}
	}

	// 只在单物理连接时把 RX/reorder 与阻塞 TAP write 解耦。旧 real-TAP
	// 实验显示 conns=1 有正收益信号，而 conns=2/4 的额外 channel/goroutine
	// 调度会抵消收益；多连接因此继续保留直接 TAP 交付路径。
	reportTapWriteErr := func(werr error) {
		n := c.tapWriteErrs.Add(1)
		if n == 1 || n%1000 == 0 {
			log.Warnf("[Client] TAP write failed #%d: %v", n, werr)
		}
	}
	if cl.Conns == 1 {
		tapDelivery := newOwnedTapDelivery(ctx, c.tap, asyncTapDeliveryQueue, reportTapWriteErr)
		c.rxReorder = NewOwnedReorderBuffer(tapDelivery.EnqueueOwned)
	} else {
		c.rxReorder = NewActorReorderBuffer(func(orderedFrame []byte) {
			if _, werr := c.tap.Write(orderedFrame); werr != nil {
				reportTapWriteErr(werr)
			}
		})
		c.rxWorker = newRXSessionWorker(c.rxReorder)
	}

	// Web 面板（可选，web.addr 未指定时不启动）；携带完整配置供面板热更
	if cfg.Web.Addr != "" {
		goSafe(func() { startWebServer(cfg.Web.Addr, nil, c, cfg.Web.Auth, cfg.Web.Cert, cfg.Web.Key, cfg) })
	}

	// 连接明细注册表初始化
	c.conns = make(map[int]*clientConnInfo)
	for i := 0; i < lv.connsCount; i++ {
		c.conns[i] = &clientConnInfo{target: lv.targetAddrs[i%len(lv.targetAddrs)], rttCache: new(uint32)}
		c.conns[i].state.Store("connecting")
	}
	return c
}

// Run 阻塞运行客户端直到 ctx 取消：TAP 读循环 + 每条物理连接的重连监督器。
func (c *Client) Run(ctx context.Context) {
	// 程序彻底退出时才清理系统路由表并停掉重排缓冲区的后台协程
	defer func() {
		if c.usesNetifd() {
			if err := c.notifyNetifdDown(); err != nil {
				log.Warnf("netifd final link-down notification failed: %v", err)
			}
		}
		// 按已安装记录逐条清理，而不是只看当前生效配置：热更过 fwmark 时，
		// 旧 mark 的规则还留在内核里，只按新配置清理会把它留成孤儿。
		// 退出瞬间不再有新握手，先快照当前记录以免和清理互相覆盖。
		c.prMu.Lock()
		if snap := c.installedSpecFor(); snap != nil {
			c.prInstalled = append(c.prInstalled, *snap)
		}
		c.prMu.Unlock()

		specs := mergePolicySpecs(c.takePolicyRoutingInstalled(),
			[]policyRoutingSpec{policyRoutingSpecFor(c.live.Load(), c.gwV4, c.gwV6)})
		for _, spec := range specs {
			cleanPolicyRouting(c.tapName, spec)
		}
		if c.rxWorker != nil {
			c.rxWorker.Close()
			if !c.rxWorker.DoneIsClosed() {
				log.Errorf("[Client] rx worker not fully drained before reorder close (contract violation)")
			}
		}
		c.rxReorder.Close()
		c.txPort.Close()
		// 跨路径 RTT 探针调度器：其 ctx 派生自 Run 的父 ctx，这里显式 stop 让
		// 调度 goroutine 立即退出，不依赖 ctx 取消的传播时机。
		if c.rttProbe != nil {
			c.rttProbe.stop()
		}
	}()

	goSafe(func() {
		readSize, pooledRead := tapReadBufferSize(c.tapName)
		if pooledRead {
			log.Debugf("[Client] TAP zero-copy read enabled (read buffer=%d bytes)", readSize)
		}
		// 非 Linux / 无法查询 MTU 时保留旧的单缓冲 + WriteFrame(copy) 路径。
		var fallback []byte
		if !pooledRead {
			fallback = make([]byte, 65536)
		}
		consecutiveErr := 0
		for {
			var buf []byte
			if pooledRead {
				buf = getFrameAtLeast(readSize)[:readSize]
			} else {
				buf = fallback
			}
			rn, err := c.tap.Read(buf)
			if err != nil {
				if pooledRead {
					putFrame(buf)
				}
				if ctx.Err() != nil {
					return
				}
				consecutiveErr++
				if consecutiveErr == 1 {
					log.Warnf("TAP read error: %v (retrying; the interface may have been reset)", err)
				}
				delay := time.Second
				if consecutiveErr >= 5 {
					delay = 5 * time.Second
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(delay):
				}
				continue
			}
			consecutiveErr = 0
			if pooledRead {
				// 所有权转移给 AsyncPort；下一轮从 pool 取下一块 buffer。
				_ = c.txPort.WriteOwnedFrame(buf[:rn])
			} else {
				_ = c.txPort.WriteFrame(buf[:rn])
			}
		}
	})

	var wg sync.WaitGroup
	lv0 := c.live.Load()
	for i := 0; i < lv0.connsCount; i++ {
		wg.Add(1)
		goSafe(func() {
			connIndex := i
			defer wg.Done()
			var seenGen uint64 = atomic.LoadUint64(&c.forceGen)
			attempt := 0
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				atomic.AddUint64(&c.reconnects, 1)
				if ci := c.connInfoAt(connIndex); ci != nil {
					ci.retries.Add(1)
				}
				start := time.Now()
				linked, err := c.dialAndServe(ctx, connIndex)
				if linked >= reconnectBackoffReset {
					attempt = 0 // 长连接断开后以短间隔立即重试
				} else if err != nil && time.Since(start) < reconnectFastFailMax {
					// 快速失败（典型是被拒绝的连接）：对端端口根本没人听，指数退避毫无意义。
					// 只按"在线满 30s"归零不够——服务端停机时 refused 秒回、linked 恒为 0，
					// attempt 会一路顶到封顶，服务恢复后反而要多等整整一轮才拨得到。
					attempt = 0
				}
				delay := reconnectBackoffDelay(attempt)
				if err != nil {
					if ci := c.connInfoAt(connIndex); ci != nil {
						ci.lastError.Store(err.Error())
						ci.state.Store("retrying")
					}
					log.Warnf("[Conn %d] Tunnel down: %v. Reconnecting in %s...", connIndex, err, delay)
					evBus.emit("down", "warn", "", fmt.Sprintf("conn %d: %s", connIndex, err))
				} else {
					log.Infof("[Conn %d] Tunnel closed, reconnecting in %s...", connIndex, delay)
					evBus.emit("down", "info", "", fmt.Sprintf("conn %d closed by peer", connIndex))
				}
				attempt++
				// 退避等待：热更/强制重连会唤醒并重置退避
				timer := time.NewTimer(delay)
				poll := time.NewTicker(250 * time.Millisecond)
			waitLoop:
				for {
					select {
					case <-ctx.Done():
						timer.Stop()
						poll.Stop()
						return
					case <-c.wake:
						if g := atomic.LoadUint64(&c.forceGen); g != seenGen {
							seenGen = g
							attempt = 0
						}
						break waitLoop // 立即重拨（消费新配置）
					case <-poll.C:
						if g := atomic.LoadUint64(&c.forceGen); g != seenGen {
							seenGen = g
							attempt = 0
							break waitLoop
						}
					case <-timer.C:
						break waitLoop
					}
				}
				timer.Stop()
				poll.Stop()
			}
		})
	}
	wg.Wait()
}

// connInfoAt 取连接明细（热更重建注册表后索引可能越界，安全返回 nil）
func (c *Client) connInfoAt(i int) *clientConnInfo {
	c.connsMu.Lock()
	defer c.connsMu.Unlock()
	return c.conns[i]
}

// probeResolveConn 跨路径探针解析器：connIndex → 当前 Backend。
func (c *Client) probeResolveConn(i int) *Backend {
	ci := c.connInfoAt(i)
	if ci == nil {
		return nil
	}
	return ci.backend.Load()
}

// probeActiveConns 跨路径探针：返回有存活 Backend 的 connIndex 升序列表。
func (c *Client) probeActiveConns() []int {
	c.connsMu.Lock()
	defer c.connsMu.Unlock()
	out := make([]int, 0, len(c.conns))
	for i, ci := range c.conns {
		if ci != nil && ci.backend.Load() != nil {
			out = append(out, i)
		}
	}
	sort.Ints(out)
	return out
}

// 重连退避参数：1s 起指数增长，封顶 3s；持续在线 reconnectBackoffReset
// 以上视为稳定连接，断开后重置退避。
//
// 封顶刻意压到 3s：VPN 客户端的价值就是尽快恢复，而 30s 封顶的实际后果是
// 服务端停机超过一轮后就每隔约 25s 才拨一次，升级窗口被拖成几十秒。
const (
	reconnectBackoffBase  = 1 * time.Second
	reconnectBackoffMax   = 3 * time.Second
	reconnectBackoffReset = 30 * time.Second
	// 单轮拨号在此时长内就失败即视为快速失败（典型是端口被拒、或连上后立刻被拒），
	// 说明对端还没起来；这种情况不做退避，保持 attempt 归零用最短间隔重试。
	// 拨号超时（5s）与 TLS 握手超时（10s）都远超这个阈值，仍按指数退避。
	reconnectFastFailMax = 1 * time.Second
)

// reconnectBackoffDelay 第 attempt 次重试前的等待时长。基值 1s 起指数增长，
// 封顶 reconnectBackoffMax；再叠 ±33% 的对称抖动把 4 条共享同一 ISP 路径的连接在时间上
// 错开，避免 ISP 抖动时全体同步重拨。抖动带对称分布在 d 附近；封顶阶段
// 抖动上界被 reconnectBackoffMax 裁掉（下界仍在 2d/3 处），不影响封顶。
func reconnectBackoffDelay(attempt int) time.Duration {
	d := reconnectBackoffBase << uint(min(attempt, 5))
	if d > reconnectBackoffMax || d <= 0 {
		d = reconnectBackoffMax
	}
	third := d / 3
	delay := 2*third + time.Duration(mathrand.Int64N(int64(2*third)))
	if delay > reconnectBackoffMax {
		return reconnectBackoffMax
	}
	return delay
}

// connSnapshot 面板用连接明细快照
type connSnapshot struct {
	TCP          *tcpSocketSnapshot `json:"tcp,omitempty"`
	Negotiated   bool               `json:"negotiated"`
	SessionEpoch uint64             `json:"session_epoch"`
	EncAlgo      int                `json:"enc_algo"`
	FEC          string             `json:"fec"`
	// FecStrategy 本端 egress 的 FEC parity 分发策略（auto/near），与 FEC 分组
	// （"xor K=N"）正交，来源是本端 AsyncPort 的运行时状态。面板展示用。
	FecStrategy     string `json:"fec_strategy,omitempty"`
	FecNearWindowMs int    `json:"fec_near_window_ms,omitempty"`
	Index           int    `json:"index"`
	ConnID          string `json:"conn_id,omitempty"`
	Target          string `json:"target"`
	Remote          string `json:"remote"`
	// ServerSeenAddr 是服务端视角看到的客户端来源地址（握手返回，含 NAT 后
	// 出口）。客户端连接明细的"目标/对端"在直连时是同一服务器地址，这一列
	// 才反映本连接实际出现在服务端面前的来源，用于诊断出口/NAT。空=未取得。
	ServerSeenAddr string            `json:"server_seen_addr,omitempty"`
	State          string            `json:"state"`
	LastError      string            `json:"last_error,omitempty"`
	RttMs          uint32            `json:"rtt_ms"`
	Scheduler      schedulerConnJSON `json:"scheduler"`
	TxBytes        uint64            `json:"tx_bytes"`
	RxBytes        uint64            `json:"rx_bytes"`
	Retries        uint64            `json:"retries"`
	AgeSec         uint64            `json:"age_sec"`
	// TCP Brutal 生效结果（客户端本地整形）
	BrutalApplied bool   `json:"brutal_applied"`
	BrutalErr     string `json:"brutal_error,omitempty"`
	// Rates granted by this physical connection's handshake. Zero means unshaped.
	BrutalTxMbps uint64 `json:"brutal_tx_mbps"`
	BrutalRxMbps uint64 `json:"brutal_rx_mbps"`
	// This physical connection's immutable TLS handshake result.
	SNI        string `json:"sni,omitempty"`
	TLSVersion string `json:"tls_version,omitempty"`
	TLSCipher  string `json:"tls_cipher,omitempty"`
	TLSALPN    string `json:"tls_alpn,omitempty"`
	// CertSHA256 是本连接客户端观测到的服务端证书 SHA-256 指纹（hex）。
	CertSHA256 string `json:"cert_sha256,omitempty"`
	// Stalled 表示调度器已判定该连接不健康（读写失败/连续 RTT 采样失败），
	// 不再向其分配数据；面板据此提示用户该路径已失效。
	Stalled bool `json:"stalled"`
}

// dispatchRxControlFrame 会话级控制平面分流：共享核心见 dispatchControlFrame
// （rx_control.go，含"为什么前置分流"的架构注释）。
func (c *Client) dispatchRxControlFrame(frame []byte, connIndex int) bool {
	return dispatchControlFrame(frame, connIndex, c.rttProbe, c.clockOffset, c)
}

// applyPeerActiveBitmap 实现 peerBitmapSink：按本端 conns 表的槽位编号刷新
// 各自的对端活跃时刻（0x07 位图 bit i = 对端调度器选中槽位 i），快照按窗口
// 判过期。
func (c *Client) applyPeerActiveBitmap(bitmap uint16) {
	now := time.Now().UnixNano()
	c.connsMu.Lock()
	for idx, cinfo := range c.conns {
		if idx >= 0 && idx < 16 && bitmap&(1<<uint(idx)) != 0 {
			cinfo.peerActiveAt.Store(now)
		}
	}
	c.connsMu.Unlock()
}

// snapshotConns 汇总所有物理连接明细
// avgRTT 当前所有物理连接 RTT 的均值（毫秒）；无连接时 0。供趋势采样使用。
func (c *Client) avgRTT() float64 {
	conns := c.snapshotConns()
	if len(conns) == 0 {
		return 0
	}
	var sum, count uint64
	for _, ci := range conns {
		if ci.RttMs > 0 && ci.RttMs < 100000 {
			sum += uint64(ci.RttMs)
			count++
		}
	}
	if count == 0 {
		return 0
	}
	return float64(sum) / float64(count)
}

func (c *Client) snapshotConns() []connSnapshot {
	c.connsMu.Lock()
	defer c.connsMu.Unlock()
	out := make([]connSnapshot, 0, len(c.conns))
	now := time.Now().Unix()
	for i := 0; i < int(c.connsCount); i++ {
		ci, ok := c.conns[i]
		if !ok {
			continue
		}
		var sni, tlsVer, tlsCipher, tlsAlpn, certSHA, serverSeen string
		var txRate, rxRate, epoch uint64
		var enc int
		fec := ""
		negotiated := false
		state, _ := ci.state.Load().(string)
		if neg := ci.negotiated.Load(); neg != nil && (state == "up" || state == "") {
			txRate, rxRate = neg.TxRateMbps, neg.RxRateMbps
			epoch, enc, negotiated = neg.SessionEpoch, neg.EncAlgo, true
			fec = "off"
			if neg.FEC {
				fec = fmt.Sprintf("xor K=%d", neg.FecGroup)
			}
			if neg.TLS != nil {
				sni, tlsVer, tlsCipher, tlsAlpn = neg.TLS.SNI, neg.TLS.Version, neg.TLS.CipherSuite, neg.TLS.ALPN
				certSHA = neg.TLS.CertSHA256
				serverSeen = neg.TLS.ClientAddr
			}
		}
		var rtt uint32
		if ci.rttCache != nil && ci.rttMeasured.Load() && (state == "up" || state == "") {
			rtt = atomic.LoadUint32(ci.rttCache) / 1000
		}
		snap := connSnapshot{
			Negotiated: negotiated, SessionEpoch: epoch, EncAlgo: enc, FEC: fec,
			Index:          i,
			Target:         ci.target,
			ServerSeenAddr: serverSeen,
			RttMs:          rtt,
			Scheduler:      schedulerSnapshot(ci.backend.Load()),
			TxBytes:        ci.txBytes.Load(),
			RxBytes:        ci.rxBytes.Load(),
			Retries:        ci.retries.Load(),
			BrutalTxMbps:   txRate,
			BrutalRxMbps:   rxRate,
			SNI:            sni,
			TLSVersion:     tlsVer,
			TLSCipher:      tlsCipher,
			TLSALPN:        tlsAlpn,
			CertSHA256:     certSHA,
		}
		// 对端活跃标志填进选路快照（与 serverConnSnapshot 同一呈现位置）：
		// peer_active=true 表示"服务端下行调度正活跃在本连接"。
		snap.Scheduler.PeerActive = peerActiveRecently(ci.peerActiveAt.Load())
		// FEC 策略是端口级状态（所有物理连接共享 txPort），nil 防测试直构 Client。
		if c.txPort != nil {
			snap.FecStrategy = string(c.txPort.FecStrategy())
			snap.FecNearWindowMs = c.txPort.FecNearWindowMs()
		}
		if state == "up" {
			snap.TCP = ci.tcpObservation.Load()
		}
		if v, okv := ci.connID.Load().(string); okv {
			snap.ConnID = v
		}
		if v, okv := ci.remote.Load().(string); okv {
			snap.Remote = v
		}
		if v, okv := ci.state.Load().(string); okv {
			snap.State = v
		}
		if v, okv := ci.lastError.Load().(string); okv {
			snap.LastError = v
		}
		if la := atomic.LoadInt64(&ci.linkedAt); la > 0 && (state == "up" || state == "") && now >= la {
			snap.AgeSec = uint64(now - la)
		}
		if br := ci.brutal.Load(); br != nil {
			snap.BrutalApplied = br.Applied
			snap.BrutalErr = br.Error
		}
		if backend := ci.backend.Load(); backend != nil {
			snap.Stalled = backend.isStalled()
		}
		out = append(out, snap)
	}
	return out
}

// peerCertSHA256 返回握手完成后对端（服务端）叶子证书 DER 的 SHA-256 指纹。
// 无对端证书（如未启用证书校验的纯 PSK 场景）时返回空串。复用 certFingerprintHex。
func peerCertSHA256(conn *utls.UConn) string {
	if conn == nil {
		return ""
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return ""
	}
	return certFingerprintHex(state.PeerCertificates[0].Raw)
}

// negotiateUTLS 负责配置 uTLS、选择指纹并执行 TLS 握手（参数取自热更快照）
func (c *Client) negotiateUTLS(ctx context.Context, rawConn net.Conn, lv *liveConfig) (*utls.UConn, error) {
	utlsConf := &utls.Config{
		ServerName:         lv.sni,
		InsecureSkipVerify: lv.insecure,
		NextProtos:         []string{"h2", "http/1.1"},
		// VPN 是持续大流量而不是交互式短响应；关闭动态 record sizing 后
		// 从一开始就使用满尺寸 TLS record，减少 record/AEAD/write 调用。
		DynamicRecordSizingDisabled: true,
		// 显式关闭重协商：握手 PSK 证明用 TLS exporter 导出密钥材料，而
		// ExportKeyingMaterial 在"连接允许重协商"时拒绝导出（防重协商后
		// transcript 复用）。utls 默认 FreelyAsClient，必须压回 Never。
		Renegotiation: utls.RenegotiateNever,
	}

	// 自定义证书哈希校验
	if lv.certHash != "" {
		utlsConf.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return verifyCertHash(rawCerts, lv.certHash)
		}
	}

	// 映射 ClientHello 指纹
	var utlsID string = "chrome"
	var clientHelloID utls.ClientHelloID
	switch strings.ToLower(utlsID) {
	case "firefox":
		clientHelloID = utls.HelloFirefox_Auto
	case "ios":
		clientHelloID = utls.HelloIOS_Auto
	case "random":
		clientHelloID = utls.HelloRandomized
	default:
		clientHelloID = utls.HelloChrome_Auto // 默认 Chrome
	}

	// 构建 uTLS 连接并握手
	utlsConn := utls.UClient(rawConn, utlsConf, clientHelloID)
	// 指纹预设（Chrome 等）自带 RenegotiationInfoExtension，其 writeToUConn 会
	// 无条件用它自己的 Renegotiation 值覆盖 config——显式 Never 被改写回
	// Freely，导致握手 PSK 证明的 ExportKeyingMaterial 拒绝导出。Build 一次
	// 让预设填充扩展列表，再把 reneg 扩展替换为 Never 版本钉住 config。
	if err := utlsConn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("uTLS build ClientHello failed: %v", err)
	}
	for i, ext := range utlsConn.Extensions {
		if _, ok := ext.(*utls.RenegotiationInfoExtension); ok {
			utlsConn.Extensions[i] = &utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateNever}
		}
	}
	if err := utlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("uTLS handshake failed: %v", err)
	}

	return utlsConn, nil
}

// dialAndServe 建立一条物理连接并服务到断开。返回该连接的在线时长
// （用于重连退避归零判断；从未在线则为 0）与最终错误。
// 每次重拨前从 c.live 取最新热更配置。
func (c *Client) dialAndServe(parentCtx context.Context, connIndex int) (linked time.Duration, err error) {
	runCtx, runCancel := context.WithCancel(parentCtx)
	defer runCancel()

	lv := c.live.Load()
	ci := c.beginConnAttempt(connIndex, lv.targetAddrs[connIndex%len(lv.targetAddrs)])
	linkedAt := time.Time{}
	defer func() {
		if !linkedAt.IsZero() {
			linked = time.Since(linkedAt)
		}
	}()

	target := lv.targetAddrs[connIndex%len(lv.targetAddrs)]
	if isSocks5Enabled() {
		log.Infof("[Conn %d] Initiating connection to %s via SOCKS5 %s ...", connIndex, target, globalSocks5Addr)
	} else {
		log.Infof("[Conn %d] Initiating connection...", connIndex)
	}
	// 统一走全局拨号器：启用 -socks5 时所有 socket 均经由代理，否则全部直连
	rawConn, err := dialContext(runCtx, "tcp", target)
	if err != nil {
		return 0, err
	}
	ci.remote.Store(rawConn.RemoteAddr().String())
	if observed, ok := rawConn.(*observedProxyTransport); ok {
		ci.observedTCP.Store(observed.tcp)
		ci.observedProxy.Store(true)
	} else {
		ci.observedTCP.Store(underlyingTCPConn(rawConn))
	}
	ci.conn.Store(connHolder{rawConn})

	// 保留 TCP_NODELAY；不要用 SO_RCVBUF/SO_SNDBUF 固定窗口。
	// Linux 在未被 setsockopt 锁定时会按 tcp_rmem/tcp_wmem 自动调优，
	// 对高 RTT / 高 BDP WAN 比固定 1MiB/512KiB 更容易跑满带宽。
	if sock := underlyingTCPConn(rawConn); sock != nil {
		_ = sock.SetNoDelay(true)
	}

	// tcpConn 仅用于端到端语义的内核调优（Brutal/RTT）；代理模式下为 nil 并自动跳过
	tcpConn := asTCPConn(rawConn)
	padRecordLimit := paddingRecordLimit(tcpConn)

	// 握手声明所有连接共享的总速率；服务端会按自己的配置裁剪，响应回来后再
	// 用裁剪结果重新套用，避免多连接把总预算乘以连接数。
	clientTxRateBps := splitLegacyBrutalRateBps(lv.brutalUp, lv.connsCount, connIndex)
	instanceID := c.instanceID.Load().(string)
	groupID := brutalGroupID("client", instanceID)

	// Brutal 是数据面优化，不能在 TLS / TLSVPN 握手前接管拥塞控制。
	// 先保持系统当前 congestion control，等服务端返回协商后的会话预算再应用。
	ci.brutal.Store((&brutalApplyResult{}).clone())

	rawConn.SetDeadline(time.Now().Add(10 * time.Second)) // tls握手超时
	tlsConn, err := c.negotiateUTLS(runCtx, rawConn, lv)
	rawConn.SetDeadline(time.Time{})
	if err != nil {
		rawConn.Close()
		return 0, err
	}
	defer tlsConn.Close()

	scanner := NewFrameScanner(tlsConn)
	// 首帧是握手响应（<2KB）：用小上限防畸形帧头撑大缓冲，认证完成后恢复
	scanner.SetMaxDataLen(maxHandshakeDataLen)
	// 握手帧不含填充：rawDataLen+padLen 同样收紧，防 padLen 绕过 dataLen 上限
	scanner.SetMaxTotalLen(maxHandshakeDataLen)
	fecGroupReq := 0
	if lv.fecMode {
		fecGroupReq = clampFecGroup(lv.fecGroup)
	}
	// 回带上一次握手收到的会话令牌（首次接入时为空）。客户端服务重启时
	// 新旧进程可能短暂重叠：旧进程可能在新进程启动后完成 token rollover 并
	// 把更新的 token 写回同一 state 文件。每次握手前重新吸收同一 SessionID
	// 的较新落盘状态，避免新进程永远拿着启动瞬间读到的旧 token 重试。
	c.refreshSessionStateFromDisk()
	c.sessionMu.Lock()
	sessionToken := c.sessionToken
	c.sessionMu.Unlock()

	// ConnID 只标识这一条物理连接/这一次握手。重连必须重新生成，不能沿用，
	// 否则服务端与客户端 WebUI 无法区分旧连接和重建后的新连接。
	connID := uuid.New().String()
	ci.connID.Store(connID)

	// 握手 PSK 证明绑定本条 TLS 连接的 exporter 密钥材料（协议 v4）：录制的
	// 历史握手无法在其他连接上重放。exporter 在 TLS 握手完成后可用。
	ucs := tlsConn.ConnectionState()
	exporter, perr := ucs.ExportKeyingMaterial(pskProofLabel, nil, pskProofLen)
	if perr != nil {
		return 0, fmt.Errorf("export TLS keying material for psk proof: %w", perr)
	}

	req := HandshakeReq{
		ProtocolVersion: protocolVersion,
		ClientInstance:  instanceID,
		ConnID:          connID,
		ClientID:        c.clientID,
		PSK:             pskProofHex(lv.psk, exporter),
		MAC:             c.macAddr,
		IPv4:            lv.reqV4,
		IPv6:            lv.reqV6,
		Padding:         generatePadding(100, 500),
		FEC:             lv.fecMode,
		FecGroup:        fecGroupReq,
		BrutalGroups:    true,
		BrutalTotalTx:   lv.brutalUp,
		BrutalTotalRx:   lv.brutalDown,
		BrutalConns:     lv.connsCount,
		BrutalConnIndex: connIndex,
		RTTProbe:        true, // 声明支持跨路径 RTT 探针；服务端同意后才启用
		ClockOffset:     true, // 声明支持双向时钟偏移探针；服务端同意后才启用
		Encrypt:         lv.encrypt,
		EncAlgo: func() int {
			if lv.encrypt {
				return lv.encAlgo
			}
			return encAlgoNone
		}(),
		SessionToken: sessionToken,
		PeerInfo:     localPeerInfo(),
	}
	log.Debugf("[Conn %d] => handshake request conn_id=%s client=%s proto=%d instance=%s fec=%v/%d enc=%v/%d token_present=%v",
		connIndex, req.ConnID, req.ClientID, req.ProtocolVersion, req.ClientInstance, req.FEC, req.FecGroup, req.Encrypt, req.EncAlgo, req.SessionToken != "")
	reqData, err := json.Marshal(req)
	if err != nil {
		return 0, fmt.Errorf("marshal handshake request: %w", err)
	}
	tlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err = writeStreamFrame(tlsConn, reqData, padRecordLimit)
	tlsConn.SetWriteDeadline(time.Time{})
	if err != nil {
		return 0, fmt.Errorf("write handshake request: %w", err)
	}

	tlsConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respData, _, err := scanner.ReadFrame()
	tlsConn.SetReadDeadline(time.Time{})
	if err != nil {
		return 0, err
	}

	var resp HandshakeResp
	if err := json.Unmarshal(respData, &resp); err != nil || !resp.Success {
		return 0, fmt.Errorf("handshake rejected")
	}
	// 握手完成：后续数据帧恢复线路全量上限
	scanner.SetMaxDataLen(maxWireDataLen)
	// 认证后放开到线路全量上限+最大填充，容纳合法 jumbo 帧与混淆填充
	scanner.SetMaxTotalLen(maxWireDataLen + maxWirePadLen)
	log.Debugf("[Conn %d] <= handshake response conn_id=%s session=%s proto=%d epoch=%d fec=%v/%d enc=%v/%d token_present=%v",
		connIndex, connID, resp.SessionID, resp.ProtocolVersion, resp.SessionEpoch, resp.FEC, resp.FecGroup, resp.Encrypt, resp.EncAlgo, resp.SessionToken != "")
	if resp.ProtocolVersion != protocolVersion {
		return 0, fmt.Errorf("unsupported server protocol version %d", resp.ProtocolVersion)
	}
	c.sessionMu.Lock()
	if resp.PeerInfo != nil {
		c.peerInfo = normalizePeerInfo(resp.PeerInfo)
	} else {
		// Optional peer_info may be absent from a v3 response. Clear the
		// previous node's metadata instead of showing stale identity in WebUI.
		c.peerInfo = PeerInfo{}
	}
	c.sessionMu.Unlock()

	// TLS 和 TLSVPN 应用层握手都已完成，现在才切换 TCP congestion control。
	// 优先使用服务端裁剪后的会话总预算；若对端未提供 group 语义，则兼容旧端，
	// 按客户端自己的配置使用原逐连接预算。这样 Brutal 永远不会影响 TLS 握手可靠性。
	if lv.brutal && clientTxRateBps > 0 {
		totalRate := lv.brutalUp
		legacyRateBps := clientTxRateBps
		if resp.BrutalGroups && resp.BrutalTotalTx > 0 {
			totalRate = resp.BrutalTotalTx
			legacyRateBps = splitLegacyBrutalRateBps(resp.BrutalTotalTx, lv.connsCount, connIndex)
		}
		br := applyTCPBrutal(tcpConn, totalRate, legacyRateBps, groupID)
		ci.brutal.Store(br.clone())
		// 保存重协商参数：连接数变化（其余物理连接断开/重连）时，幸存连接需
		// 重新计算逐连接份额，否则 v1 逐连接 ABI 会一直停在初始均分份额上。
		ci.brutalCfg.Store(&brutalRebalanceCfg{
			totalRateMbps: totalRate,
			groupID:       groupID,
			connIndex:     connIndex,
			enabled:       br.Applied,
		})
		if !br.Applied {
			log.Warnf("[Conn %d] TCP Brutal shaping skipped after handshake: %s", connIndex, br.Error)
		} else if br.Error != "" {
			log.Warnf("[Conn %d] TCP Brutal shaping active after handshake with limited observability: %s", connIndex, br.Error)
		}
	}

	if resp.Encrypt != lv.encrypt {
		return 0, fmt.Errorf("server encryption mismatch")
	}

	// 内层加密：算法由配置显式选择。gcm256 是兼容默认；gcm128 是性能模式。
	// 两者共享 nonce/AAD/tag/wire format，但使用独立 KDF label，不能跨算法复用 key。
	encAlgo := encAlgoNone
	var icTx, icRx, fecTx, fecRx *innerCipher
	if lv.encrypt {
		if resp.EncAlgo != lv.encAlgo {
			return 0, fmt.Errorf("server negotiated inner cipher %d (%s), want %d (%s)",
				resp.EncAlgo, encAlgoLabel(resp.EncAlgo), lv.encAlgo, encAlgoLabel(lv.encAlgo))
		}
		saltTx, err1 := hex.DecodeString(resp.EncSalt)  // c2s
		saltRx, err2 := hex.DecodeString(resp.EncSalt2) // s2c
		if err1 != nil || err2 != nil || len(saltTx) != encSaltSize || len(saltRx) != encSaltSize {
			return 0, fmt.Errorf("server sent invalid enc salts")
		}
		var errTx, errRx error
		icTx, errTx = newInnerCipherForAlgo(lv.psk, saltTx, resp.EncAlgo)
		icRx, errRx = newInnerCipherForAlgo(lv.psk, saltRx, resp.EncAlgo)
		if errTx != nil || errRx != nil {
			return 0, fmt.Errorf("inner AEAD init failed: %v/%v", errTx, errRx)
		}
		// FEC 域与数据域同 salt/algo，派生失败理论上只可能由内部错误引起；
		// 仍不静默忽略——FEC 帧走独立 key domain，若派生失败后续解密会错乱。
		var errFecTx, errFecRx error
		fecTx, errFecTx = newInnerCipherDomainForAlgo(lv.psk, saltTx, "fec", resp.EncAlgo)
		fecRx, errFecRx = newInnerCipherDomainForAlgo(lv.psk, saltRx, "fec", resp.EncAlgo)
		if errFecTx != nil || errFecRx != nil {
			return 0, fmt.Errorf("inner FEC AEAD init failed: %v/%v", errFecTx, errFecRx)
		}
		encAlgo = resp.EncAlgo
	}

	// min_enc=gcm 要求任一种认证内层 AEAD；算法具体强度由 enc_algo 显式固定，
	// 所以这里不把 不同 AEAD 悄悄升级/降级。
	if lv.minEnc > 0 && !isInnerAEADAlgo(encAlgo) {
		return 0, fmt.Errorf("server negotiated inner cipher %d is below min_enc %q", encAlgo, "gcm")
	}

	// 会话级协商：首个连接的握手决定本端解码与端口编码模式，后续连接沿用。
	// 服务端响应带 fec_group >= fecMinGroup 表示启用了 XOR 校验；否则视为未
	// 启用 FEC（不再有逐帧复制的回退路径，fecNegotiated 保持 0 以便后续连接重试）。
	c.sessionMu.Lock()
	if lv.fecMode && c.fecNegotiated == 0 {
		if resp.FecGroup >= fecMinGroup {
			c.fecNegotiated = resp.FecGroup
			c.fecStatus = fmt.Sprintf("xor K=%d", resp.FecGroup)
			log.Infof("[Conn %d] XOR FEC negotiated: K=%d (overhead 1/%d)", connIndex, resp.FecGroup, resp.FecGroup)
		} else {
			c.fecStatus = "off"
			log.Warnf("[Conn %d] FEC requested but server negotiated fec_group=%d, FEC disabled", connIndex, resp.FecGroup)
		}
	}
	// Resolve the receive epoch before touching decoder state. Multi-connection
	// readers may still own partial batches from the old key/session generation;
	// AdvanceEpoch invalidates them and waits for all already-queued work before
	// FEC/reorder are reset or rebound below.
	isNewSession := false
	if c.serverSessionID != resp.SessionID || c.sessionEpoch != resp.SessionEpoch {
		isNewSession = true
		c.serverSessionID = resp.SessionID
		c.sessionEpoch = resp.SessionEpoch
	}
	if isNewSession && c.rxWorker != nil {
		c.rxWorker.AdvanceEpochAndReset(c.fecDec)
	}

	fecRebuild := false
	useXorFec := lv.fecMode && c.fecNegotiated > 0
	if useXorFec {
		// FEC 编解码器绑定当前会话的加密器与盐：会话/盐变化即重建
		if c.fecDec == nil || c.fecAlgo != encAlgo || c.fecSaltKey != resp.EncSalt {
			if c.fecDec != nil && c.rxWorker == nil {
				c.fecDec.Reset()
			}
			fecRebuild = true
			c.fecAlgo = encAlgo
			c.fecSaltKey = resp.EncSalt
		}
		if fecRebuild {
			// XOR FEC 解码器：恢复出的帧按原 seq 注入重排缓冲，保证输出有序。
			// client.conns 属于 restart-only 拓扑配置，因此 ==1 时可以安全使用
			// 静态 RX bypass；不能用 liveConns，因为临时 2->1 时 parity 仍有价值。
			rxFECOut, rxReorderProgress := fecReorderHooks(c.rxReorder, c.rxWorker)
			c.fecDec = NewFECDecoder(c.fecNegotiated, fecRx, rxFECOut)
			c.fecDec.lifetime = &c.fecLifetime
			c.fecDec.SetReorderProgress(rxReorderProgress)
			c.fecDec.SetStaticSinglePath(isStaticSinglePathTopology(lv.connsCount))
			c.txPort.AttachFEC(c.fecNegotiated, fecTx)
		}
	}
	if c.encAlgo != encAlgo {
		c.encAlgo = encAlgo
		c.icTx = icTx
		c.icRx = icRx
	}
	// 记下服务端下发的会话令牌，供后续重连回带。服务端未开启 session_token
	// 时该字段为空，行为与旧版一致。
	c.sessionToken = resp.SessionToken
	// 协商快照：面板展示的是服务端实际回传的取值，而不是本地配置声明。
	// BrutalTotalTx/Rx 是服务端分配给本端上下行的整形总速率（0 = 未整形）。
	negTx, negRx := resp.BrutalTotalTx, resp.BrutalTotalRx
	connNeg := &sessionNeg{
		ProtocolVersion: resp.ProtocolVersion,
		FEC:             resp.FEC,
		FecGroup:        int(resp.FecGroup),
		EncAlgo:         resp.EncAlgo,
		PadMode:         padModeName(),
		SessionToken:    resp.SessionToken != "",
		SessionEpoch:    resp.SessionEpoch,
		TxRateMbps:      negTx,
		RxRateMbps:      negRx,
		TLS:             resp.TLS,
	}
	// 采集对端（服务端）证书的 SHA-256 指纹：客户端在握手完成后可从
	// ConnectionState 读取服务端叶子证书 DER，供 WebUI 展示与日志输出。
	// 服务端未回传 TLS 信息时 connNeg.TLS 为 nil，跳过（无法挂载指纹）。
	if peerHash := peerCertSHA256(tlsConn); peerHash != "" && connNeg.TLS != nil {
		connNeg.TLS.CertSHA256 = peerHash
		log.Infof("[Conn %d] TLS server certificate SHA256: %s", connIndex, peerHash)
	}
	c.negInfo = connNeg
	ci.negotiated.Store(connNeg)
	c.gwV4 = resp.GwV4
	c.gwV6 = resp.GwV6
	// 面板展示：分配的隧道地址
	c.assignedV4 = strings.Split(resp.IPv4, "/")[0]
	c.assignedV6 = strings.Split(resp.IPv6, "/")[0]
	c.sessionMu.Unlock()

	if isNewSession {
		if !useXorFec {
			c.txPort.ResetEpoch(0, nil)
		}
		log.Infof("[Conn %d] 🔄 server reset the session; flushing stale local receive buffers...", connIndex)
		if c.rxWorker == nil {
			c.rxReorder.Reset()
		}
	}

	// 会话身份落盘：进程被杀后重启，第一次握手即回带旧令牌接回既有会话，
	// 而不是等 120 秒僵尸会话过期才自然恢复连通。
	c.persistSessionState(resp.SessionID, resp.SessionToken, resp.SessionEpoch)

	// 服务端同意跨路径 RTT 探针：开启探测（幂等）。旧服务端无 RTTProbe 字段则
	// 保持关闭，不会发送 0x03/0x04 控制帧，向后兼容。
	if resp.RTTProbe && c.rttProbe != nil {
		c.rttProbe.enable()
	}
	// 服务端同意双向时钟偏移探针：开启偏移探测（幂等）。未协商成功时 rttProbe
	// 仍按锚定法 + δ 工作，单向时延行为不变。
	if resp.ClockOffset && c.clockOffset != nil {
		c.clockOffset.enable()
	}

	c.networkSetup.Lock()
	var lifecycleErr error
	if !c.usesNetifd() && c.tapName != "mem" && netlinkTunnelSupported() {
		// Self-managed mode owns the real TAP addresses and policy routing.
		// The in-memory backend is used by e2e/perf harnesses and has no netlink device.
		if err := c.setupInterface(resp.IPv4, resp.IPv6); err != nil {
			log.Errorf("[Conn %d] tunnel interface configuration failed; tunnel address not applied: %v", connIndex, err)
			lifecycleErr = err
		}
		if err := c.installPolicyRouting(policyRoutingSpecFor(lv, resp.GwV4, resp.GwV6)); err != nil && lifecycleErr == nil {
			lifecycleErr = err
		}
	}

	if !c.usesNetifd() && c.hooks != nil && c.hooks.Configured() {
		cfgPath := ""
		if snap := c.cfgSnap.Load(); snap != nil {
			cfgPath = snap.SourcePath
		}
		hookEnv := HookEnv{Mode: "client", Dev: c.tapName, Config: cfgPath,
			IPv4: resp.IPv4, IPv6: resp.IPv6, GatewayV4: resp.GwV4, GatewayV6: resp.GwV6}
		if lifecycleErr != nil {
			c.hooks.Activate(hookEnv)
			lifecycleErr = fmt.Errorf("cannot run lifecycle up hook before tunnel networking is ready: %w", lifecycleErr)
		} else if err := c.hooks.Up(hookEnv); err != nil {
			lifecycleErr = err
		}
	}
	c.networkSetup.Unlock()
	if lifecycleErr != nil && c.hooks != nil && c.hooks.Configured() {
		c.failProcess(lifecycleErr)
		return 0, lifecycleErr
	}

	rttCache := new(uint32)
	atomic.StoreUint32(rttCache, 50000)
	minRttCache := new(uint32)
	atomic.StoreUint32(minRttCache, 50000)

	// 连接明细：握手成功，进入 up 态
	c.connsMu.Lock()
	ci.rttMeasured.Store(false)
	ci.rttCache = rttCache
	ci.minRttCache = minRttCache
	c.connsMu.Unlock()
	ci.conn.Store(connHolder{tlsConn})
	atomic.StoreInt64(&ci.linkedAt, time.Now().Unix())
	ci.state.Store("up")
	ci.lastError.Store("")

	errChan := make(chan error, 2)
	connTxChan := make(chan *VPNFrameBatch, 32)
	backend := c.txPort.RegisterOwnedBackend(connTxChan, rttCache, connIndex)
	backend.minRttCache = minRttCache
	backend.probeCh = make(chan []byte, 8)
	ci.backend.Store(backend)
	defer func() {
		ci.backend.CompareAndSwap(backend, nil)
		c.txPort.UnregisterOwnedBackend(connTxChan)
	}()
	// 新路径注册：立即发起一轮跨路径探针，加速单向估计收敛。
	if c.rttProbe != nil {
		c.rttProbe.kick()
	}

	batchCork := newTLSBatchCork(rawConn)
	batchCork.BindCarryState(&backend.carryPending)
	defer batchCork.Close()

	// netifd represents the aggregate VPN session, not one TCP backend.
	// The first live backend publishes UP; only the final backend loss publishes
	// DOWN. notifyNetifdUp itself deduplicates identical address/gateway updates.
	liveNow := atomic.AddInt32(&c.liveConns, 1)
	evBus.emit("up", "info", "", fmt.Sprintf("conn %d linked conn_id=%s", connIndex, connID))
	if c.usesNetifd() {
		if err := c.notifyNetifdUp(resp.IPv4, resp.IPv6, resp.GwV4, resp.GwV6); err != nil {
			atomic.AddInt32(&c.liveConns, -1)
			return 0, fmt.Errorf("netifd link update failed: %w", err)
		}
		if liveNow == 1 {
			log.Infof("[Conn %d] netifd interface %s is up on %s", connIndex, c.netifdInterface, c.tapName)
		}
	}
	// 连接数变化：重新分配每条存活连接的 Brutal 份额（新连接不跳过，用新份额覆盖）。
	c.rebalanceBrutalRates(-1)
	defer func() {
		if atomic.AddInt32(&c.liveConns, -1) == 0 && c.usesNetifd() {
			if err := c.notifyNetifdDown(); err != nil {
				log.Warnf("netifd link-down notification failed: %v", err)
			}
		}
		// 跳过正在断开的这条连接（socket 已关闭），其余幸存连接拿回更大份额。
		c.rebalanceBrutalRates(connIndex)
	}()

	goSafe(func() {
		sendBuffer := make([]byte, 0, 64*1024+4096)
		var txAEADScratch nonceAADScratch
		keepAliveTicker := time.NewTicker(keepaliveInterval)
		defer keepAliveTicker.Stop()

		// RTT 刷新复用现有发送 goroutine，避免每条物理连接再起一个
		// 200ms ticker goroutine。代理模式 tcpConn=nil 时 nil channel 自动禁用。
		var rttTicker *time.Ticker
		var rttC <-chan time.Time
		// 全进程共享 1Hz 粗时钟；热路径只做 atomic Load + 整数比较。
		// epoch 变化时才真正读取时钟并更新 poll deadline。
		writeDeadlineEpoch := currentDeadlineEpoch()
		_ = tlsConn.SetWriteDeadline(time.Now().Add(datapathWriteTimeout))
		refreshWriteDeadline := func() {
			epoch := currentDeadlineEpoch()
			if epoch != writeDeadlineEpoch {
				// 绝对截止保证任意时刻开始阻塞的 Write 仍会在约
				// datapathWriteTimeout 内失败。
				_ = tlsConn.SetWriteDeadline(time.Now().Add(datapathWriteTimeout))
				writeDeadlineEpoch = epoch
			}
		}
		if tcpConn != nil {
			rttTicker = time.NewTicker(200 * time.Millisecond)
			rttC = rttTicker.C
			defer rttTicker.Stop()
		}

		// 控制帧/数据帧写队列优先级：数值高者先。相等则两者皆 false，下方
		// 只走原 select（随机竞争，零行为变化）。
		controlFirst, dataFirst := queuePriorityPref(lv.priorityControl, lv.priorityData)

		// 三条写体抽成闭包复用：优先级分支与主 select 都要用到，避免重复大段
		// 记账代码。返回 false 表示写失败（已置 stalled 并上报 errChan），
		// 调用方应立即退出写 goroutine。
		sampleRTT := func() {
			if rtt, minRtt, err := getTCPRTTAndMinRTT(tcpConn); err == nil && rtt > 0 {
				atomic.StoreUint32(rttCache, rtt)
				if minRtt > 0 {
					atomic.StoreUint32(minRttCache, minRtt)
				}
				ci.rttMeasured.Store(true)
				backend.noteRTTSuccess()
			} else if err != nil {
				// 连续多次 RTT 采样失败说明连接正在关闭/已不可用，尽早把
				// 该后端标记为 stalled，调度器不再向其分配数据。
				// 注意 rtt==0 是引导期正常状态（尚未取得采样），不算失败。
				backend.noteRTTFailure()
			}
		}
		writeKeepalive := func() bool {
			// 空心跳帧不计入填充累计：bucket 模式会给它补 118B 填充，
			// 那是保活代价而不是流量开销，算进去会把开销顶到一个与业务
			// 流量无关的地板上。
			sendBuffer = sendBuffer[:0]
			sendBuffer, _ = appendPaddedFrame(sendBuffer, VPNFrame{Seq: 0, Data: nil}, nil, padRecordLimit)
			// 心跳写必须带超时：数据帧分支写完即清成 time.Time{}，空闲期写路径上
			// 没有任何 deadline。半开路径会让 Write 挂到 tcp_retries2 耗尽
			// （约 15 分钟才放弃），期间心跳停发，服务端先在自己的读超时上判死
			// 本端连接，而本端读方向可能仍在正常收帧——面板显示 tunnel up 但
			// 链路已单向死亡。加超时后本端 10s 内自发现并重拨。
			refreshWriteDeadline()
			nw, err := tlsConn.Write(sendBuffer)
			if err == nil && nw != len(sendBuffer) {
				err = io.ErrShortWrite
			}
			if err != nil {
				backend.markStalled()
				errChan <- err
				return false
			}
			return true
		}
		writeProbe := func(probe []byte) bool {
			// 跨路径 RTT 探针/回包 + 时钟偏移探针/回包：与 keepalive 同路
			// （appendPaddedFrame 逐帧随机桶尺寸 + randomPool 覆盖字节），与数据
			// 记录/保活同尺寸分布，消除流量特征。探针（0x03/0x05）在 Write 前写入
			// send_ts（固定偏移），即使排队也测得精确发送时刻。
			sendBuffer = sendBuffer[:0]
			sendBuffer, _ = appendPaddedFrame(sendBuffer, VPNFrame{Seq: 0, Data: probe}, nil, padRecordLimit)
			// 两种探针的 send_ts 都在偏移 20（帧头 10 + 载荷偏移 10），
			// 故共用同一 patch 路径；写两次无副作用。
			if len(probe) > 0 && (probe[0] == controlKindRttProbe || probe[0] == controlKindClockProbe) {
				patchRttProbeSendTS(sendBuffer, time.Now())
			}
			refreshWriteDeadline()
			nw, err := tlsConn.Write(sendBuffer)
			if err == nil && nw != len(sendBuffer) {
				err = io.ErrShortWrite
			}
			if err != nil {
				backend.markStalled()
				errChan <- err
				return false
			}
			return true
		}
		drainWrite := func(batch *VPNFrameBatch) bool {
			sendBuffer = sendBuffer[:0]
			txPackets := 0
			var written txFrameTotals
			padEpoch := padAccountingEpoch()
			queuedPayload := uint64(0)
			lastFrameStart := -1
		drainBatches:
			for {
				queuedPayload += batch.RateBytes
				var n, last int
				sendBuffer, n, last = appendOwnedVPNFrameBatchStreamWithScratch(sendBuffer, batch, icTx, &txAEADScratch, &written)
				txPackets += n
				if last >= 0 {
					lastFrameStart = last
				}
				if len(sendBuffer) >= maxTLSWriteBatchBytes {
					break
				}
				select {
				case batch = <-connTxChan:
					continue
				default:
					break drainBatches
				}
			}
			var tailPad int
			sendBuffer, tailPad = padStreamBatchTail(sendBuffer, lastFrameStart, padRecordLimit)
			// 填充决策之后再统一加密封装：AAD 绑定每帧帧头的最终 padLen
			sealStreamBatchInPlace(sendBuffer, icTx, &txAEADScratch)
			padTotal := uint64(tailPad)
			refreshWriteDeadline()
			batchCork.BeforeWrite(len(sendBuffer))
			nw, err := tlsConn.Write(sendBuffer)
			if err == nil && nw != len(sendBuffer) {
				err = io.ErrShortWrite
			}
			if err != nil {
				// 写失败即连接不可用：尽早置 stalled，调度器立即停用该后端。
				backend.markStalled()
				errChan <- err
				return false
			}
			c.txPort.written.record(written)
			backend.completeQueuedBytes(queuedPayload)
			backend.observeDelivered(queuedPayload)
			// 填充记账与 TxBytes 同源：都只在 Write 成功之后累加
			recordPadBytesAt(uint64(len(sendBuffer)), padTotal, padEpoch)
			// deadline 不需要清零：下一次写之前会刷新；保留旧 deadline
			// 可少一次 runtime_pollSetDeadline syscall。
			c.TxBytes.Add(uint64(len(sendBuffer)))
			c.TxPackets.Add(uint64(txPackets))
			ci.txBytes.Add(uint64(len(sendBuffer)))
			dailyTraffic.Add(uint64(len(sendBuffer)), 0) // 上行 = client→server
			return true
		}

		for {
			// RTT 采样（200ms ticker）与优先级无关：任何分支都要及时处理，
			// 否则高优先级洪流会把它压到过期，调度器用陈旧 RTT 做路径决策。
			// 非阻塞取一次，采样本身很轻，逐轮检查足够跟上 200ms 节奏。
			select {
			case <-rttC:
				sampleRTT()
			default:
			}
			// 优先级分支：非阻塞优先服务"此刻已就绪"的高优先级源，保证它不被
			// 低优先级洪流长期压后；高优先级源空闲时落入下方阻塞 select，低优
			// 先级源照常被服务 —— 任何一方都不会被饿死。
			if controlFirst {
				// 控制帧优先：清空当前就绪的控制源（含心跳/RTT 探针）。
				drained := false
				for {
					select {
					case <-runCtx.Done():
						return
					case probe := <-backend.probeCh:
						if !writeProbe(probe) {
							return
						}
						drained = true
						continue
					case <-keepAliveTicker.C:
						if !writeKeepalive() {
							return
						}
						drained = true
						continue
					default:
					}
					break
				}
				if drained {
					continue // 已写控制帧：回到顶部，控制帧不落后于数据帧
				}
			} else if dataFirst {
				// 数据帧优先：非阻塞取一个数据批；写完给控制帧一次非阻塞机会，
				// 防止 keepalive 被数据洪流饿死（饿死会触发对端读超时判死）。
				select {
				case batch := <-connTxChan:
					if !drainWrite(batch) {
						return
					}
					select {
					case probe := <-backend.probeCh:
						if !writeProbe(probe) {
							return
						}
					case <-keepAliveTicker.C:
						if !writeKeepalive() {
							return
						}
					default:
					}
					continue
				default:
				}
			}

			// 阻塞 select：等下一个事件（所有源 + 连接关闭 + RTT 采样）。
			select {
			case <-runCtx.Done():
				return
			case <-rttC:
				sampleRTT()
			case batch := <-connTxChan:
				if !drainWrite(batch) {
					return
				}
			case <-keepAliveTicker.C:
				if !writeKeepalive() {
					return
				}
			case probe := <-backend.probeCh:
				if !writeProbe(probe) {
					return
				}
			}
		}
	})

	c.sessionMu.Lock()
	connDecoder, connWorker, connReorder := c.fecDec, c.rxWorker, c.rxReorder
	c.sessionMu.Unlock()
	goSafe(func() {
		var rxBytesBatch, rxPacketsBatch uint64
		var rxAEADScratch nonceAADScratch
		var rxProducer *rxBatchProducer
		if connWorker != nil {
			rxProducer = connWorker.NewProducer(connDecoder, func(cerr error) {
				select {
				case errChan <- fmt.Errorf("protocol v%d control: %w", protocolVersion, cerr):
				default:
				}
				_ = tlsConn.Close()
			})
			defer rxProducer.Flush()
		}
		flushRxStats := func() {
			if rxPacketsBatch == 0 {
				return
			}
			c.RxBytes.Add(rxBytesBatch)
			c.RxPackets.Add(rxPacketsBatch)
			ci.rxBytes.Add(rxBytesBatch)
			dailyTraffic.Add(0, rxBytesBatch) // 下行 = server→client
			rxBytesBatch, rxPacketsBatch = 0, 0
		}
		defer flushRxStats()

		readDeadlineEpoch := currentDeadlineEpoch()
		_ = tlsConn.SetReadDeadline(time.Now().Add(datapathReadTimeout))
		for {
			frame, seq, err := scanner.ReadFrame()
			if err != nil {
				// 对端消失/读超时：尽早置 stalled，调度器立即停用该后端。
				backend.markStalled()
				errChan <- err
				return
			}
			epoch := currentDeadlineEpoch()
			if epoch != readDeadlineEpoch {
				// 1s 粗粒度刷新、datapathReadTimeout deadline => 实际空闲判死约
				// datapathReadTimeout 秒。
				_ = tlsConn.SetReadDeadline(time.Now().Add(datapathReadTimeout))
				readDeadlineEpoch = epoch
			}
			// 心跳/控制帧（frame=nil）：读超时已被 SetReadDeadline 刷新，
			// 直接进入下一轮循环即可保持空闲连接存活
			if frame == nil {
				// 空闲连接也周期性归并本地统计，避免低流量时面板长期看不到增量。
				flushRxStats()
				continue
			}

			if err == nil && frame != nil {
				rxBytesBatch += scanner.lastWireSize
				rxPacketsBatch++
				if rxPacketsBatch >= 64 || !scanner.BufferedFrameReady() {
					flushRxStats()
				}
				if seq != 0 && icRx != nil {
					plain, derr := icRx.openInPlaceWithScratch(frame, seq, uint32(len(frame)), uint16(scanner.lastPadLen), &rxAEADScratch)
					if derr != nil {
						// GCM 校验失败：篡改或异源注入的帧，直接丢弃
						log.Debugf("[Conn %d] dropped tampered/foreign frame (seq=%d): %v", connIndex, seq, derr)
						putFrame(frame)
						continue
					}
					frame = plain
				}
				if seq == 0 {
					// 会话级控制平面分流：0x07 active-paths / RTT 探针 / 时钟偏移
					// 都是与数据流无关的旁路信号（不需要保序/重排/FEC 恢复，且
					// 无 FEC 会话也存在），因此必须在 FEC 门控之前认领——否则
					// 无 FEC 会话会把合法控制帧判成协议违规断链。
					if c.dispatchRxControlFrame(frame, connIndex) {
						putFrame(frame)
						continue
					}
					// 未被控制平面认领的 typed control → FEC 门控（其载荷属于
					// FEC 会话管线）。
					if !useXorFec || connDecoder == nil {
						putFrame(frame)
						errChan <- fmt.Errorf("protocol v%d: unexpected typed control without negotiated FEC", protocolVersion)
						return
					}
					if rxProducer != nil {
						rxProducer.Push(0, frame)
						if !scanner.BufferedFrameReady() {
							rxProducer.Flush()
						}
						continue
					}
					if cerr := connDecoder.OnControlWithScratch(frame, &rxAEADScratch); cerr != nil {
						putFrame(frame)
						errChan <- fmt.Errorf("protocol v%d control: %w", protocolVersion, cerr)
						return
					}
					putFrame(frame)
					continue
				}
				if rxProducer != nil {
					rxProducer.Push(seq, frame)
					if !scanner.BufferedFrameReady() {
						rxProducer.Flush()
					}
					continue
				}
				if useXorFec {
					connDecoder.OnData(seq, frame)
				}
				// 丢入重排缓冲区，后续的 Write 和 putFrame 由缓冲区内部接管
				connReorder.Insert(seq, frame)
			}
		}
	})

	select {
	case err := <-errChan:
		return 0, err
	case <-runCtx.Done():
		return 0, nil
	}
}

func (c *Client) setupInterface(v4cidr, v6cidr string) error {
	// 不等待 TAP 出现：设备是本进程在 NewClient 里 water.New 建的，走到这里
	// 必然已存在；mem 后端则永远没有同名 netlink 链接。这里若阻塞，会卡住整条
	// 握手路径——每条物理连接白等一轮超时才上报，且晚到的接口下次重拨自会重试。
	link, err := netlink.LinkByName(c.tapName)
	if err != nil {
		return fmt.Errorf("tap %s not found: %v", c.tapName, err)
	}
	// 先 up 再挂地址：web.bind=tunnel 第一轮就要能 bind（要求 IFF_UP），
	// 且 v6 在接口 up 的瞬间还会重新触发一次 DAD
	if err := netlink.LinkSetUp(link); err != nil {
		log.Errorf("Client failed to bring up tap %s: %v", c.tapName, err)
	}
	if err := assignTapAddr(link, "v4", v4cidr); err != nil {
		return err
	}
	if err := assignTapAddr(link, "v6", v6cidr); err != nil {
		return err
	}
	return nil
}

// assignTapAddr 把服务端分配的隧道地址挂上 tap；空串或裸 "/" 视为未配置。
// 失败必须向上返回而不是就地吞掉：静默丢弃时表现为"隧道在线但本机不通"，
// 重启后接口地址没挂上却看不到任何线索。
func assignTapAddr(link netlink.Link, fam, cidr string) error {
	if cidr == "" || cidr == "/" {
		return nil
	}
	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return fmt.Errorf("invalid %s tunnel address %q: %v", fam, cidr, err)
	}
	if fam == "v6" {
		addr.Flags = ifaNoDAD
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("assign %s tunnel address %s to %s: %v",
			fam, cidr, link.Attrs().Name, err)
	}
	return nil
}

// refreshSessionStateFromDisk 吸收另一个、仍在退出中的同客户端进程刚刚
// 写下的 token rollover。SessionEpoch 只在同一个 SessionID 内可比较；不同
// SessionID 可能来自服务端重启，不能用 epoch 大小判断新旧。
func (c *Client) refreshSessionStateFromDisk() {
	if c.stateFile == "" {
		return
	}
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	disk, err := loadClientState(c.stateFile)
	if err != nil {
		log.Warnf("Client failed to refresh persisted session state: %v", err)
		return
	}
	if disk == nil || disk.ClientID != c.clientID || disk.SessionID == "" || disk.SessionToken == "" {
		return
	}

	c.sessionMu.Lock()
	defer c.sessionMu.Unlock()
	// 只自动吸收同一服务端 session 的进展。不同 SessionID 的磁盘状态可能是
	// 当前进程建立新会话之前留下的旧状态，不能在这里反向覆盖内存。
	if disk.SessionID != c.serverSessionID {
		return
	}
	if disk.SessionEpoch < c.sessionEpoch {
		return
	}
	if disk.SessionEpoch == c.sessionEpoch && disk.SessionToken == c.sessionToken {
		return
	}
	c.serverSessionID = disk.SessionID
	c.sessionEpoch = disk.SessionEpoch
	c.sessionToken = disk.SessionToken
	c.state = disk
	log.Infof("Refreshed session token from state file for %s at epoch %d", disk.SessionID, disk.SessionEpoch)
}

// persistSessionState 把服务端下发的会话身份落盘，供进程重启后第一次握手
// 复用既有会话。SessionEpoch 是 session-local generation：服务端重启后会生成
// 新 SessionID，并可能从更小的 epoch 重新开始，因此绝不能拿旧 SessionID 的
// epoch 阻止新 SessionID 落盘。
func (c *Client) persistSessionState(sessionID, token string, epoch uint64) {
	if c.stateFile == "" {
		return
	}

	// 多条物理连接可能并发返回；只允许仍与当前内存会话完全一致的响应落盘。
	// 若期间另一条握手已经切到新 SessionID/epoch/token，这个迟到响应直接丢弃。
	c.sessionMu.Lock()
	currentID, currentToken, currentEpoch := c.serverSessionID, c.sessionToken, c.sessionEpoch
	c.sessionMu.Unlock()
	// 生产握手路径一定已经初始化 current session；保留空值兼容直接调用
	// persistSessionState 的单元测试/内部工具。
	if currentID != "" && (sessionID != currentID || epoch != currentEpoch || token != currentToken) {
		return
	}

	c.stateMu.Lock()
	defer c.stateMu.Unlock()

	// stateMu 只能序列化当前进程。服务管理器重启时新旧进程可能短暂重叠，
	// 所以再读一次磁盘：同一 SessionID 下不允许较低 epoch 覆盖较高 epoch；
	// 同 epoch 出现不同 token 时保留已经落盘的一方，避免交叉进程回滚。
	if disk, err := loadClientState(c.stateFile); err == nil && disk != nil && disk.ClientID == c.clientID && disk.SessionID == sessionID {
		if disk.SessionEpoch > epoch || (disk.SessionEpoch == epoch && disk.SessionToken != "" && disk.SessionToken != token) {
			c.state = disk
			return
		}
	}

	st := c.state
	if st == nil {
		st = &clientState{}
	}
	// 只有同一 SessionID 的 epoch 才能比较。不同 SessionID 表示服务端会话已
	// 重建（最常见是服务端重启），即使新 epoch 更小也必须覆盖旧状态。
	if st.ClientID == c.clientID && st.SessionID == sessionID && epoch < st.SessionEpoch {
		return
	}
	st.ClientID = c.clientID
	st.SessionID = sessionID
	st.SessionToken = token
	st.SessionEpoch = epoch
	if err := saveClientState(c.stateFile, st); err != nil {
		log.Warnf("Client failed to persist session state: %v", err)
		return
	}
	c.state = st
}

func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
func duplicateIP(ip net.IP) net.IP         { dup := make(net.IP, len(ip)); copy(dup, ip); return dup }
func maskSize(m net.IPMask) int            { ones, _ := m.Size(); return ones }
func getFirstIP(network *net.IPNet) net.IP { ip := duplicateIP(network.IP); incrementIP(ip); return ip }

// NeedsRestart 客户端无法热更、需重启的字段差异
func (c *Client) NeedsRestart(cfg *Config) []string {
	var out []string
	if old := c.bootCfg.Load(); old != nil {
		o := old
		if o.Tap != cfg.Tap {
			out = append(out, "tap")
		}
		if o.Mac != cfg.Mac {
			out = append(out, "mac")
		}
		if o.Socks5 != cfg.Socks5 {
			out = append(out, "socks5")
		}
		if o.Client.Fwmark != cfg.Client.Fwmark {
			out = append(out, "client.fwmark")
		}
		if o.Client.Conns != cfg.Client.Conns {
			out = append(out, "client.conns")
		}
		if o.Up != cfg.Up || o.Down != cfg.Down {
			out = append(out, "up/down")
		}
		if o.Client.InterfaceManager != cfg.Client.InterfaceManager {
			out = append(out, "client.interface_manager")
		}
	}
	return out
}

// connHolder 统一 atomic.Value 存储的连接类型（raw/tls 两种具体类型）
type connHolder struct{ c net.Conn }

// CloseIfOpen 强制重连时关闭底层连接（幂等）
func (h connHolder) CloseIfOpen() {
	if h.c != nil {
		h.c.Close()
	}
}

// Each physical attempt owns its counters; old writer/reader goroutines may still
// flush while a replacement is dialing, but cannot contaminate the new row.
func (c *Client) beginConnAttempt(index int, target string) *clientConnInfo {
	ci := &clientConnInfo{target: target, rttCache: new(uint32)}
	ci.state.Store("connecting")
	c.connsMu.Lock()
	defer c.connsMu.Unlock()
	if old := c.conns[index]; old != nil {
		ci.retries.Store(old.retries.Load())
		ci.peerActiveAt.Store(0) // 重拨是对端重新评估的槽位，旧活跃时刻不延续
		if err, ok := old.lastError.Load().(string); ok {
			ci.lastError.Store(err)
		}
		c.conns[index] = ci
	}
	return ci
}
