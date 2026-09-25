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
type Backend struct {
	ch       chan []VPNFrame
	rttCache *uint32
}

type AsyncPort struct {
	id         string
	ch         chan []byte
	ctx        context.Context
	cancel     context.CancelFunc
	backendsMu sync.RWMutex
	backends   []*Backend
	preferred  atomic.Pointer[Backend]
	encoder    *fecEncoder
	txSeq      uint32
	resetEpoch chan portEpochReset
	exhausted  atomic.Bool
	onExhaust  func()
	dropped    uint64 // 各环节丢弃帧计数（面板/metrics）
	paritySent    atomic.Uint64
	parityScratch [][]byte // run goroutine 独占，复用 FEC parity 描述符切片
	parityNext    uint32   // run goroutine 独占：单份 parity 在健康后端间轮转
	dataNext      uint32   // run goroutine 独占：高负载时在相近 RTT 后端间轮转
}

type portEpochReset struct {
	k    int
	ic   *innerCipher
	done chan struct{}
}

// Dropped 累计丢弃帧数（队列满、后端投递失败、无后端）
func (p *AsyncPort) Dropped() uint64 { return atomic.LoadUint64(&p.dropped) }

// ParitySent 已生成的 FEC 校验帧数（未启用 FEC 时为 0）
func (p *AsyncPort) ParitySent() uint64 {
	return p.paritySent.Load()
}

func (p *AsyncPort) dropN(n int) {
	if n > 0 {
		atomic.AddUint64(&p.dropped, uint64(n))
	}
}

func NewAsyncPort(ctx context.Context, id string) *AsyncPort {
	pCtx, pCancel := context.WithCancel(ctx)
	p := &AsyncPort{
		id: id, ch: make(chan []byte, 4096), ctx: pCtx, cancel: pCancel,
		resetEpoch: make(chan portEpochReset),
		parityScratch: make([][]byte, 0, 32),
	}
	go p.run()
	return p
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
			go p.onExhaust()
		}
		return 0, false
	}
	p.txSeq++
	return p.txSeq, true
}

func (p *AsyncPort) ID() string { return p.id }
func (p *AsyncPort) RegisterBackend(ch chan []VPNFrame, rttCache *uint32) {
	p.backendsMu.Lock()
	defer p.backendsMu.Unlock()
	p.backends = append(p.backends, &Backend{ch: ch, rttCache: rttCache})
}
func (p *AsyncPort) UnregisterBackend(ch chan []VPNFrame) {
	p.backendsMu.Lock()
	defer p.backendsMu.Unlock()
	for i, b := range p.backends {
		if b.ch == ch {
			p.preferred.CompareAndSwap(b, nil)
			p.backends = append(p.backends[:i], p.backends[i+1:]...)
			break
		}
	}
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
	select {
	case p.ch <- frame:
	default:
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

		p.backendsMu.RLock()
		n := len(p.backends)
		ready := false
		for _, b := range p.backends {
			if cap(b.ch) > 0 && len(b.ch) < cap(b.ch) {
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
	const MaxBatchBytes = 64 * 1024
	batch := make([]VPNFrame, 0, 128)
	var batchBytes int

	for {
		select {
		case <-p.ctx.Done():
			return
		case reset := <-p.resetEpoch:
			p.txSeq = 0
			p.parityNext = 0
			p.dataNext = 0
			p.exhausted.Store(false)
			if reset.k >= fecMinGroup {
				p.encoder = newFECEncoder(reset.k, reset.ic)
			} else {
				p.encoder = nil
			}
			close(reset.done)
		case frame := <-p.ch:
			if len(frame) == 0 {
				// 零长帧不携带数据：不消耗 seq、不参与 FEC 分组
				// （否则接收端按算术分组会把该槽位视为永久缺失，毒化整组恢复）
				putFrame(frame)
				continue
			}
			if !p.waitForBackendSlot() {
				// 没有活动后端时在 seq 分配前丢弃；连接建立后新的 TAP
				// 帧会重新进入队列，不给接收端留下不存在的序号洞。
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
			batch = append(batch, VPNFrame{Seq: seq, Data: frame})
			batchBytes += len(frame)

			queueLen := len(p.ch)
			for i := 0; i < queueLen && batchBytes < MaxBatchBytes; i++ {
				f := <-p.ch
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
				batch = append(batch, VPNFrame{Seq: s, Data: f})
				batchBytes += len(f)
			}

			p.dispatchBatch(batch)

			batch = batch[:0]
			batchBytes = 0
		}
	}
}

// dispatchBatch 把一批帧分发给后端，并接管 batch 内全部缓冲的所有权：
//   - XOR FEC：数据帧 MinRTT 单路发送，校验帧只发送一份并在其它健康路径间轮转；
//   - 普通模式：MinRTT 单路发送。
// wire format 不变，旧端/新端 decoder 都只要求收到至少一份 parity。
func (p *AsyncPort) dispatchBatch(batch []VPNFrame) {
	// register/unregister 是冷路径；发送是非阻塞 channel 投递。直接在 RLock
	// 下使用后端切片，避免每个 batch append([]*Backend(nil), ...) 分配快照。
	p.backendsMu.RLock()
	defer p.backendsMu.RUnlock()
	backends := p.backends
	if len(backends) == 0 {
		p.dropN(len(batch))
		freeFrames(batch)
		return
	}

	if p.encoder != nil {
		parities := p.parityScratch[:0]
		for _, vf := range batch {
			if par := p.encoder.add(vf); par != nil {
				parities = append(parities, par)
			}
		}
		best := p.pickDataBackend(backends)
		// 低负载仍走 MinRTT；持续 backlog 时会在 RTT 接近的健康路径间主动 striping。
		// 若目标连接瞬时满则继续尝试其它后端；全部满时
		// 做有界短退让，让拥塞尽量回推到 seq 分配之前的输入队列。
		p.dropN(sendBatchToAny(backends, best, batch))
		for _, par := range parities {
			if len(backends) < 2 {
				// 单条 TCP 是严格有序流：原始数据若因 TCP 丢包/HOL 尚未到达，
				// 同一路径后面的 parity 也不可能越过它，因此没有提前恢复价值。
				// 仍持续喂 encoder 保持 seq/K 分组对齐，但不把 parity 发上线路。
				putFrame(par)
				continue
			}
			p.paritySent.Add(1)
			// parity 与数据尽量走不同物理路径，并在健康后端间轮转。decoder
			// 是会话级共享状态，只需任意一条连接收到一份即可恢复单帧丢失。
			target := p.pickParityBackend(backends, best)
			p.dropN(sendOwnedFrameTo(target, VPNFrame{Seq: 0, Data: par}))
		}
		clear(parities) // 不让 scratch 长期持有已归池 payload
		p.parityScratch = parities[:0]
		return
	}

	p.dropN(sendBatchToAny(backends, p.pickDataBackend(backends), batch))
}

const backendRTTHysteresisMin = 5_000 // 微秒

func backendScore(b *Backend) (uint32, bool) {
	qLen := len(b.ch)
	if qLen >= cap(b.ch)-2 {
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
		bestBackend = backends[0]
		p.preferred.Store(bestBackend)
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
				hysteresis := max(uint32(backendRTTHysteresisMin), atomic.LoadUint32(current.rttCache)/8)
				if uint64(currentScore) <= uint64(minScore)+uint64(hysteresis) {
					bestBackend = current
				}
			}
		}
	}
	p.preferred.Store(bestBackend)
	return bestBackend
}


const multipathStripeBacklog = 64

// pickDataBackend 保留低负载 MinRTT 行为；只有 AsyncPort 输入出现持续 backlog 时，
// 才在 RTT 接近最佳路径的健康后端中轮转。这样 bulk 流量可以真正并行使用多条
// TCP 连接，而交互式小流量仍保持最低延迟并避免不必要的跨流乱序。
func (p *AsyncPort) pickDataBackend(backends []*Backend) *Backend {
	best := p.pickBackend(backends)
	if len(backends) < 2 || len(p.ch) < multipathStripeBacklog || best == nil {
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
func (p *AsyncPort) pickParityBackend(backends []*Backend, dataBest *Backend) *Backend {
	if len(backends) == 0 {
		return nil
	}
	start := int(p.parityNext % uint32(len(backends)))
	p.parityNext++
	if len(backends) > 1 {
		for i := 0; i < len(backends); i++ {
			b := backends[(start+i)%len(backends)]
			if b == dataBest {
				continue
			}
			if _, ok := backendScore(b); ok {
				return b
			}
		}
	}
	if dataBest != nil {
		if _, ok := backendScore(dataBest); ok {
			return dataBest
		}
	}
	for i := 0; i < len(backends); i++ {
		b := backends[(start+i)%len(backends)]
		if _, ok := backendScore(b); ok {
			return b
		}
	}
	return backends[start]
}

// sendBatchToAny 把数据 batch 的 payload 所有权转移给某个可写后端。
// 热路径先无阻塞尝试 preferred/其它连接；只有所有连接都满时才进入最多 5ms
// 的短退让。这样可以显著减少“分配 seq 后再丢 batch”造成的重排序号洞。
// 成功或最终失败后，调用方 batch 中的 Data 都会被置 nil。
func sendBatchToAny(backends []*Backend, preferred *Backend, batch []VPNFrame) int {
	out := getVPNFrameBatch(len(batch))
	copy(out, batch)
	for i := range batch {
		batch[i].Data = nil
	}

	trySend := func(b *Backend) bool {
		if b == nil {
			return false
		}
		select {
		case b.ch <- out:
			return true
		default:
			return false
		}
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

	// 仅拥塞慢路径进入这里。5ms 远低于 50ms reorder skip deadline，
	// 同时给 TLS writer 足够机会腾出一个 batch slot。
	deadline := time.Now().Add(5 * time.Millisecond)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Microsecond)
		if tryAll() {
			return 0
		}
	}

	freeFrames(out)
	putVPNFrameBatch(out)
	return len(out)
}

// sendBatchTo 保留给单后端测试/兼容调用；内部仍走同一所有权转移路径。
func sendBatchTo(b *Backend, batch []VPNFrame) int {
	return sendBatchToAny([]*Backend{b}, b, batch)
}

// sendOwnedFrameTo 把单帧 payload 所有权直接转移给一个后端；用于
// 单份 FEC parity，避免旧广播路径的 N 次 clone/memcpy。
func sendOwnedFrameTo(b *Backend, vf VPNFrame) int {
	if b == nil {
		if vf.Data != nil {
			putFrame(vf.Data)
		}
		return 1
	}
	out := getVPNFrameBatch(1)
	out[0] = vf
	select {
	case b.ch <- out:
		return 0
	default:
		freeFrames(out)
		putVPNFrameBatch(out)
		return 1
	}
}

// sendFrameTo 保留给需要独立副本的兼容/测试路径。
func sendFrameTo(b *Backend, vf VPNFrame) int {
	out := getVPNFrameBatch(1)
	out[0] = VPNFrame{Seq: vf.Seq, Data: cloneFrame(vf.Data)}
	select {
	case b.ch <- out:
		return 0
	default:
		freeFrames(out)
		putVPNFrameBatch(out)
		return 1
	}
}

// FECRecovered FEC 解码恢复帧数（客户端会话级，面板/metrics 用）
func (c *Client) FECRecovered() uint64 {
	if c.fecDec == nil {
		return 0
	}
	rec, _ := c.fecDec.FECStats()
	return rec
}

// FECLost FEC 无法恢复的确认丢失帧数
func (c *Client) FECLost() uint64 {
	if c.fecDec == nil {
		return 0
	}
	_, lost := c.fecDec.FECStats()
	return lost
}

// FECStats 恢复/丢失计数（面板用）
func (c *Client) FECStats() (uint64, uint64) {
	if c.fecDec == nil {
		return 0, 0
	}
	return c.fecDec.FECStats()
}

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
	live          atomic.Pointer[liveConfig]
	interfaceManager string
	netifdInterface  string
	netifdMu         sync.Mutex
	netifdState      netifdLinkState
	tapName       string
	macAddr       string
	tap           io.ReadWriteCloser
	connsCount    int32  // 与 live.conns 一致的只读影子（连接注册表按此建）
	fecNegotiated int    // 0=未协商, >0=XOR 分组大小
	fecStatus     string // 面板展示用
	fecAlgo       int    // fecDec 绑定的加密算法（会话重建判据）
	fecSaltKey    string // fecDec 绑定的盐（会话重建判据）
	txPort        *AsyncPort
	rxReorder     *ReorderBuffer
	fecDec        *fecDecoder
	TxBytes       uint64
	RxBytes       uint64
	TxPackets     uint64
	RxPackets     uint64
	icTx          *innerCipher           // 当前会话发送方向（GCM）
	icRx          *innerCipher           // 当前会话接收方向（GCM）
	encAlgo       int                    // 当前会话协商结果（encAlgoNone / encAlgoGCM）
	assignedV4    string                 // 服务端分配的 IPv4（面板展示）
	assignedV6    string                 // 服务端分配的 IPv6（面板展示）
	liveConns     int32                  // 当前已建立的物理连接数（面板展示）
	tapWriteErrs  atomic.Uint64          // TAP 交付失败帧数（旧实现被静默吞掉）
	reconnects    uint64                 // 累计重连尝试次数（面板展示）
	forceGen      uint64                 // 强制重连世代：递增即要求重连循环跳过退避
	wake          chan struct{}          // 重连唤醒：强制重连/热更配置时广播（缓冲 1，非阻塞）
	instanceID    atomic.Value           // string：本进程实例；变化即要求服务端换密钥代际
	sessionEpoch  uint64                 // 服务端确认的密钥代际
	negInfo       *sessionNeg            // 上次成功握手的协商快照（面板展示用）
	cfgSnap       atomic.Pointer[Config] // 当前生效完整配置（面板"状态"页数据源）
	bootCfg       atomic.Pointer[Config] // 启动时配置（NeedsRestart 差异基准）
	connsMu       sync.Mutex
	conns         map[int]*clientConnInfo // 每物理连接明细（connIndex → 状态）
	startedAt     time.Time
	hooks         *LifecycleHooks
	runCancel     context.CancelFunc
	fatalOnce     sync.Once
	fatalErr      chan error
	networkSetup  sync.Mutex
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
		c.prInstalled = append(c.prInstalled, s)
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
	c.live.Store(lv)
	c.cfgSnap.Store(cfg)
	// 内层加密器不在此处重建：GCM 实例由每次握手的会话盐派生，直接取自
	// 刚更新的 lv.psk，无需额外的共享回退加密器。

	// 填充策略全局生效于发送路径
	if actual := setPadMode(cfg.PadMode); actual != cfg.PadMode {
		log.Warnf("[Client] Invalid pad_mode %q, using %s", cfg.PadMode, actual)
	}
	if int32(lv.connsCount) != c.connsCount {
		// 监督器数量属于进程拓扑，当前实现不在运行中增删 goroutine。保留启动
		// 值并由 NeedsRestart 明确报告，避免面板声称已热更但实际没有生效。
		lv.connsCount = int(c.connsCount)
		log.Warnf("[Client] client.conns change requires restart (effective=%d requested=%d)", c.connsCount, cfg.Client.Conns)
	}
	c.ForceReconnect()
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

// clientConnInfo 单条物理连接的运行明细（面板展示 + 强制重连句柄）
type clientConnInfo struct {
	target    string
	remote    atomic.Value // string：对端地址（握手后可得）
	state     atomic.Value // string：connecting / up / retrying
	lastError atomic.Value // string：最近一次失败原因
	rttCache  *uint32      // 微秒（200ms 刷新）
	conn      atomic.Value // connHolder：强制重连时关闭（统一包装类型避免 Value 类型不一致 panic）
	txBytes   uint64
	rxBytes   uint64
	retries   uint64
	brutal    atomic.Pointer[brutalApplyResult] // 本连接的内核实际状态；nil=尚未尝试
	linkedAt  int64                             // 最近一次握手成功时间（unix 秒，0=未连接过）
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
	lv := liveFromCfg(cfg)
	c.bootCfg.Store(cfg)
	c.cfgSnap.Store(cfg)
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

	// 初始化重排缓冲区：当包按序理顺后，统一写入 c.tap
	c.rxReorder = NewReorderBuffer(func(orderedFrame []byte) {
		if _, werr := c.tap.Write(orderedFrame); werr != nil {
			// 旧实现静默丢弃错误：TAP 故障时表现为"隧道在线但本机不通"
			n := c.tapWriteErrs.Add(1)
			if n == 1 || n%1000 == 0 {
				log.Warnf("[Client] TAP write failed #%d: %v", n, werr)
			}
		}
	})

	// Web 面板（可选，web.addr 未指定时不启动）；携带完整配置供面板热更
	if cfg.Web.Addr != "" {
		go startWebServer(cfg.Web.Addr, nil, c, cfg.Web.Auth, cfg.Web.Cert, cfg.Web.Key, cfg)
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
		c.rxReorder.Close()
		c.txPort.Close()
	}()

	go func() {
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
	}()

	var wg sync.WaitGroup
	lv0 := c.live.Load()
	for i := 0; i < lv0.connsCount; i++ {
		wg.Add(1)
		go func(connIndex int) {
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
					atomic.AddUint64(&ci.retries, 1)
				}
				linked, err := c.dialAndServe(ctx, connIndex)
				if linked >= reconnectBackoffReset {
					attempt = 0 // 长连接断开后以短间隔立即重试
				}
				delay := reconnectBackoffDelay(attempt)
				if err != nil {
					if ci := c.connInfoAt(connIndex); ci != nil {
						ci.lastError.Store(err.Error())
						ci.state.Store("retrying")
					}
					log.Warnf("[Conn %d] Tunnel down: %v. Reconnecting in %s...", connIndex, err, delay)
				} else {
					log.Infof("[Conn %d] Tunnel closed, reconnecting in %s...", connIndex, delay)
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
		}(i)
	}
	wg.Wait()
}

// connInfoAt 取连接明细（热更重建注册表后索引可能越界，安全返回 nil）
func (c *Client) connInfoAt(i int) *clientConnInfo {
	c.connsMu.Lock()
	defer c.connsMu.Unlock()
	return c.conns[i]
}

// 重连退避参数：1s 起指数增长，封顶 30s；持续在线 reconnectBackoffReset
// 以上视为稳定连接，断开后重置退避
const (
	reconnectBackoffBase  = 1 * time.Second
	reconnectBackoffMax   = 30 * time.Second
	reconnectBackoffReset = 30 * time.Second
)

// reconnectBackoffDelay 第 attempt 次重试前的等待时长。基值 1s 起指数增长，
// 封顶 30s；再叠 ±33% 的对称抖动把 4 条共享同一 ISP 路径的连接在时间上
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
	Index     int    `json:"index"`
	Target    string `json:"target"`
	Remote    string `json:"remote"`
	State     string `json:"state"`
	LastError string `json:"last_error,omitempty"`
	RttMs     uint32 `json:"rtt_ms"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxBytes   uint64 `json:"rx_bytes"`
	Retries   uint64 `json:"retries"`
	AgeSec    uint64 `json:"age_sec"`
	// TCP Brutal 生效结果（客户端本地整形）
	BrutalApplied bool   `json:"brutal_applied"`
	BrutalErr     string `json:"brutal_error,omitempty"`
	// 服务端授予本端的整形速率。会话级取值（最近一次握手响应），不是逐连接：
	// 服务端对每条物理连接各授各的，客户端只拿到握手响应里那一份，所以同一会话
	// 的多条连接会显示同一组数——这是"客户端只有一份协商结果"的真实反映，
	// 不是聚合错误。0 = 服务端没给（brutal 关或预算为 0）。
	BrutalTxMbps uint64 `json:"brutal_tx_mbps"`
	BrutalRxMbps uint64 `json:"brutal_rx_mbps"`
}

// snapshotConns 汇总所有物理连接明细
// avgRTT 当前所有物理连接 RTT 的均值（毫秒）；无连接时 0。供趋势采样使用。
func (c *Client) avgRTT() float64 {
	conns := c.snapshotConns()
	if len(conns) == 0 {
		return 0
	}
	var sum uint64
	for _, ci := range conns {
		sum += uint64(ci.RttMs)
	}
	return float64(sum) / float64(len(conns))
}

func (c *Client) snapshotConns() []connSnapshot {
	// negInfo 归 sessionMu，连接表归 connsMu。这里用两段不重叠的临界区各取各的，
	// 而不是持着一把再拿另一把：现有代码里没有确定的锁序，嵌套一把就制造出
	// 一个全仓库唯一的 connsMu→sessionMu 路径，将来谁在 sessionMu 里碰 connsMu
	// 就死锁。握手侧只整体替换 negInfo 指针、不原地改字段，所以取出后即可无锁读。
	c.sessionMu.Lock()
	neg := c.negInfo
	c.sessionMu.Unlock()
	txRate, rxRate := uint64(0), uint64(0)
	if neg != nil {
		txRate, rxRate = neg.TxRateMbps, neg.RxRateMbps
	}
	c.connsMu.Lock()
	defer c.connsMu.Unlock()
	out := make([]connSnapshot, 0, len(c.conns))
	now := time.Now().Unix()
	for i := 0; i < int(c.connsCount); i++ {
		ci, ok := c.conns[i]
		if !ok {
			continue
		}
		snap := connSnapshot{
			Index:        i,
			Target:       ci.target,
			RttMs:        atomic.LoadUint32(ci.rttCache) / 1000,
			TxBytes:      atomic.LoadUint64(&ci.txBytes),
			RxBytes:      atomic.LoadUint64(&ci.rxBytes),
			Retries:      atomic.LoadUint64(&ci.retries),
			BrutalTxMbps: txRate,
			BrutalRxMbps: rxRate,
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
		if la := atomic.LoadInt64(&ci.linkedAt); la > 0 {
			snap.AgeSec = uint64(now - la)
		}
		if br := ci.brutal.Load(); br != nil {
			snap.BrutalApplied = br.Applied
			snap.BrutalErr = br.Error
		}
		out = append(out, snap)
	}
	return out
}

// negotiateUTLS 负责配置 uTLS、选择指纹并执行 TLS 握手（参数取自热更快照）
func (c *Client) negotiateUTLS(ctx context.Context, rawConn net.Conn, lv *liveConfig) (*utls.UConn, error) {
	utlsConf := &utls.Config{
		ServerName:                  lv.sni,
		InsecureSkipVerify:          lv.insecure,
		NextProtos:                  []string{"h2", "http/1.1"},
		// VPN 是持续大流量而不是交互式短响应；关闭动态 record sizing 后
		// 从一开始就使用满尺寸 TLS record，减少 record/AEAD/write 调用。
		DynamicRecordSizingDisabled: true,
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
	ci := c.connInfoAt(connIndex)
	shadow := &clientConnInfo{target: lv.targetAddrs[connIndex%len(lv.targetAddrs)], rttCache: new(uint32)}
	shadow.state.Store("connecting")
	if ci == nil {
		ci = shadow // 热更后注册表索引越界：使用影子明细，仅丢失展示
	}
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
	ci.conn.Store(connHolder{rawConn})

	// 保留 TCP_NODELAY；不要用 SO_RCVBUF/SO_SNDBUF 固定窗口。
	// Linux 在未被 setsockopt 锁定时会按 tcp_rmem/tcp_wmem 自动调优，
	// 对高 RTT / 高 BDP WAN 比固定 1MiB/512KiB 更容易跑满带宽。
	if sock := underlyingTCPConn(rawConn); sock != nil {
		_ = sock.SetNoDelay(true)
	}

	// tcpConn 仅用于端到端语义的内核调优（Brutal/RTT）；代理模式下为 nil 并自动跳过
	tcpConn := asTCPConn(rawConn)

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
	fecGroupReq := 0
	if lv.fecMode {
		fecGroupReq = clampFecGroup(lv.fecGroup)
	}
	// 回带上一次握手收到的会话令牌（首次接入时为空）。与 PSK 快照一起读，
	// 避免与握手响应处理协程的写入构成数据竞争。
	c.sessionMu.Lock()
	sessionToken := c.sessionToken
	c.sessionMu.Unlock()

	req := HandshakeReq{
		ProtocolVersion: 2,
		ClientInstance:  instanceID,
		ClientID:        c.clientID,
		PSK:             hashPSK(lv.psk),
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
		Encrypt:         lv.encrypt,
		EncAlgo:         func() int { if lv.encrypt { return lv.encAlgo }; return encAlgoNone }(),
		SessionToken:    sessionToken,
	}
	log.Debugf("[Conn %d] => handshake request client=%s proto=%d instance=%s fec=%v/%d enc=%v/%d token_present=%v",
		connIndex, req.ClientID, req.ProtocolVersion, req.ClientInstance, req.FEC, req.FecGroup, req.Encrypt, req.EncAlgo, req.SessionToken != "")
	reqData, err := json.Marshal(req)
	if err != nil {
		return 0, fmt.Errorf("marshal handshake request: %w", err)
	}
	tlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err = writeStreamFrame(tlsConn, reqData)
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
	log.Debugf("[Conn %d] <= handshake response session=%s proto=%d epoch=%d fec=%v/%d enc=%v/%d token_present=%v",
		connIndex, resp.SessionID, resp.ProtocolVersion, resp.SessionEpoch, resp.FEC, resp.FecGroup, resp.Encrypt, resp.EncAlgo, resp.SessionToken != "")
	if resp.ProtocolVersion != 2 {
		return 0, fmt.Errorf("unsupported server protocol version %d", resp.ProtocolVersion)
	}

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
		icTx, errTx = newGCMInnerCipherForAlgo(lv.psk, saltTx, resp.EncAlgo)
		icRx, errRx = newGCMInnerCipherForAlgo(lv.psk, saltRx, resp.EncAlgo)
		if errTx != nil || errRx != nil {
			return 0, fmt.Errorf("GCM cipher init failed: %v/%v", errTx, errRx)
		}
		fecTx, _ = newGCMInnerCipherDomainForAlgo(lv.psk, saltTx, "fec", resp.EncAlgo)
		fecRx, _ = newGCMInnerCipherDomainForAlgo(lv.psk, saltRx, "fec", resp.EncAlgo)
		encAlgo = resp.EncAlgo
	}

	// min_enc=gcm 要求任一种认证 GCM；算法具体强度由 enc_algo 显式固定，
	// 所以这里不把 AES-128 悄悄升级/降级成 AES-256。
	if lv.minEnc > 0 && !isGCMAlgo(encAlgo) {
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
	fecRebuild := false
	useXorFec := lv.fecMode && c.fecNegotiated > 0
	if useXorFec {
		// FEC 编解码器绑定当前会话的加密器与盐：会话/盐变化即重建
		if c.fecDec == nil || c.fecAlgo != encAlgo || c.fecSaltKey != resp.EncSalt {
			if c.fecDec != nil {
				c.fecDec.Reset()
			}
			fecRebuild = true
			c.fecAlgo = encAlgo
			c.fecSaltKey = resp.EncSalt
		}
		if fecRebuild {
			// XOR FEC 解码器：恢复出的帧按原 seq 注入重排缓冲，保证输出有序
			c.fecDec = NewFECDecoder(c.fecNegotiated, fecRx, c.rxReorder.Insert)
			c.txPort.AttachFEC(c.fecNegotiated, fecTx)
		}
	}
	if c.encAlgo != encAlgo {
		c.encAlgo = encAlgo
		c.icTx = icTx
		c.icRx = icRx
	}
	isNewSession := false
	if c.serverSessionID != resp.SessionID || c.sessionEpoch != resp.SessionEpoch {
		isNewSession = true
		c.serverSessionID = resp.SessionID
		c.sessionEpoch = resp.SessionEpoch
	}
	// 记下服务端下发的会话令牌，供后续重连回带。服务端未开启 session_token
	// 时该字段为空，行为与旧版一致。
	c.sessionToken = resp.SessionToken
	// 协商快照：面板展示的是服务端实际回传的取值，而不是本地配置声明。
	// BrutalTotalTx/Rx 是服务端分配给本端上下行的整形总速率（0 = 未整形）。
	negTx, negRx := resp.BrutalTotalTx, resp.BrutalTotalRx
	c.negInfo = &sessionNeg{
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
		c.rxReorder.Reset()
	}

	// 会话身份落盘：进程被杀后重启，第一次握手即回带旧令牌接回既有会话，
	// 而不是等 120 秒僵尸会话过期才自然恢复连通。
	c.persistSessionState(resp.SessionID, resp.SessionToken, resp.SessionEpoch)

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

	// 连接明细：握手成功，进入 up 态
	ci.rttCache = rttCache
	ci.conn.Store(connHolder{tlsConn})
	ci.linkedAt = time.Now().Unix()
	ci.state.Store("up")
	ci.lastError.Store("")

	errChan := make(chan error, 2)
	connTxChan := make(chan []VPNFrame, 32)
	c.txPort.RegisterBackend(connTxChan, rttCache)
	defer c.txPort.UnregisterBackend(connTxChan)

	// netifd represents the aggregate VPN session, not one TCP backend.
	// The first live backend publishes UP; only the final backend loss publishes
	// DOWN. notifyNetifdUp itself deduplicates identical address/gateway updates.
	liveNow := atomic.AddInt32(&c.liveConns, 1)
	if c.usesNetifd() {
		if err := c.notifyNetifdUp(resp.IPv4, resp.IPv6, resp.GwV4, resp.GwV6); err != nil {
			atomic.AddInt32(&c.liveConns, -1)
			return 0, fmt.Errorf("netifd link update failed: %w", err)
		}
		if liveNow == 1 {
			log.Infof("[Conn %d] netifd interface %s is up on %s", connIndex, c.netifdInterface, c.tapName)
		}
	}
	defer func() {
		if atomic.AddInt32(&c.liveConns, -1) == 0 && c.usesNetifd() {
			if err := c.notifyNetifdDown(); err != nil {
				log.Warnf("netifd link-down notification failed: %v", err)
			}
		}
	}()

	go func() {
		sendBuffer := make([]byte, 0, 64*1024+4096)
		keepAliveTicker := time.NewTicker(4 * time.Second)
		defer keepAliveTicker.Stop()

		// RTT 刷新复用现有发送 goroutine，避免每条物理连接再起一个
		// 200ms ticker goroutine。代理模式 tcpConn=nil 时 nil channel 自动禁用。
		var rttTicker *time.Ticker
		var rttC <-chan time.Time
		// 全进程共享 1Hz 粗时钟；热路径只做 atomic Load + 整数比较。
		// epoch 变化时才真正读取时钟并更新 poll deadline。
		writeDeadlineEpoch := currentDeadlineEpoch()
		_ = tlsConn.SetWriteDeadline(time.Now().Add(11 * time.Second))
		refreshWriteDeadline := func() {
			epoch := currentDeadlineEpoch()
			if epoch != writeDeadlineEpoch {
				// 11s 绝对截止保证任意时刻开始阻塞的 Write 仍会在约
				// 10~11s 内失败。
				_ = tlsConn.SetWriteDeadline(time.Now().Add(11 * time.Second))
				writeDeadlineEpoch = epoch
			}
		}
		if tcpConn != nil {
			rttTicker = time.NewTicker(200 * time.Millisecond)
			rttC = rttTicker.C
			defer rttTicker.Stop()
		}

		for {
			select {
			case <-runCtx.Done():
				return
			case <-rttC:
				if rtt, err := getTCPRTT(tcpConn); err == nil && rtt > 0 {
					atomic.StoreUint32(rttCache, rtt)
				}
			case frames := <-connTxChan:
				sendBuffer = sendBuffer[:0]
				txPackets := 0
			drainBatches:
				for {
					var n int
					sendBuffer, n = appendOwnedFrameBatch(sendBuffer, frames, icTx)
					txPackets += n
					if len(sendBuffer) >= maxTLSWriteBatchBytes {
						break
					}
					select {
					case frames = <-connTxChan:
						continue
					default:
						break drainBatches
					}
				}
				refreshWriteDeadline()
				if _, err := tlsConn.Write(sendBuffer); err != nil {
					errChan <- err
					return
				}
				// deadline 不需要清零：下一次写之前会刷新；保留旧 deadline
				// 可少一次 runtime_pollSetDeadline syscall。
				atomic.AddUint64(&c.TxBytes, uint64(len(sendBuffer)))
				atomic.AddUint64(&c.TxPackets, uint64(txPackets))
				atomic.AddUint64(&ci.txBytes, uint64(len(sendBuffer)))
				dailyTraffic.Add(uint64(len(sendBuffer)), 0) // 上行 = client→server
			case <-keepAliveTicker.C:
				sendBuffer = sendBuffer[:0]
				sendBuffer = appendPaddedFrame(sendBuffer, VPNFrame{Seq: 0, Data: nil}, nil)
				// 心跳写必须带超时：数据帧分支写完即清成 time.Time{}，空闲期写路径上
				// 没有任何 deadline。半开路径会让 Write 挂到 tcp_retries2 耗尽
				// （约 15 分钟才放弃），期间心跳停发，服务端先在自己的读超时上判死
				// 本端连接，而本端读方向可能仍在正常收帧——面板显示 tunnel up 但
				// 链路已单向死亡。加超时后本端 10s 内自发现并重拨。
				refreshWriteDeadline()
				if _, err := tlsConn.Write(sendBuffer); err != nil {
					errChan <- err
					return
				}
			}
		}
	}()

	go func() {
		var rxBytesBatch, rxPacketsBatch uint64
		flushRxStats := func() {
			if rxPacketsBatch == 0 {
				return
			}
			atomic.AddUint64(&c.RxBytes, rxBytesBatch)
			atomic.AddUint64(&c.RxPackets, rxPacketsBatch)
			atomic.AddUint64(&ci.rxBytes, rxBytesBatch)
			dailyTraffic.Add(0, rxBytesBatch) // 下行 = server→client
			rxBytesBatch, rxPacketsBatch = 0, 0
		}
		defer flushRxStats()

		readDeadlineEpoch := currentDeadlineEpoch()
		_ = tlsConn.SetReadDeadline(time.Now().Add(16 * time.Second))
		for {
			frame, seq, err := scanner.ReadFrame()
			if err != nil {
				errChan <- err
				return
			}
			epoch := currentDeadlineEpoch()
			if epoch != readDeadlineEpoch {
				// 1s 粗粒度刷新、16s deadline => 实际空闲判死约 15~16s。
				_ = tlsConn.SetReadDeadline(time.Now().Add(16 * time.Second))
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
				rxBytesBatch += uint64(len(frame))
				rxPacketsBatch++
				if rxPacketsBatch >= 64 {
					flushRxStats()
				}
				if seq != 0 && icRx != nil {
					plain, derr := icRx.openInPlace(frame, seq, uint32(len(frame)))
					if derr != nil {
						// GCM 校验失败：篡改或异源注入的帧，直接丢弃
						log.Debugf("[Conn %d] dropped tampered/foreign frame (seq=%d): %v", connIndex, seq, derr)
						putFrame(frame)
						continue
					}
					frame = plain
				}
				if seq == 0 && useXorFec && c.isParityFrame(frame) {
					// XOR 校验帧：交给 FEC 解码器，恢复出的帧由其回调写 TAP
					c.fecDec.OnParity(frame)
					putFrame(frame)
					continue
				}
				if useXorFec {
					c.fecDec.OnData(seq, frame)
				}
				// 丢入重排缓冲区，后续的 Write 和 putFrame 由缓冲区内部接管
				c.rxReorder.Insert(seq, frame)
			}
		}
	}()

	select {
	case err := <-errChan:
		return 0, err
	case <-runCtx.Done():
		return 0, nil
	}
}

// isParityFrame 识别 XOR 校验帧：线路帧 seq=0（不加密），负载首字节为魔数
// 0xFE；普通控制/心跳帧负载为空，握手帧以 '{' 开头，均不会误判。
func (c *Client) isParityFrame(frame []byte) bool {
	return len(frame) >= 7 && frame[0] == fecMagic
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

// persistSessionState 把服务端下发的会话身份落盘，供进程重启后第一次握手
// 复用既有会话。按 clientID（MAC+PSK 派生）绑定：配置变更后旧令牌自动失效。
func (c *Client) persistSessionState(sessionID, token string, epoch uint64) {
	if c.stateFile == "" {
		return
	}
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	st := c.state
	if st == nil {
		st = &clientState{}
	}
	// 多条物理连接会并发完成握手。迟到的旧响应不能覆盖已经持久化的
	// 新 epoch，否则下次进程重启会携带不匹配的令牌和代际。
	if epoch < st.SessionEpoch {
		return
	}
	st.ClientID = c.clientID
	st.SessionID = sessionID
	st.SessionToken = token
	st.SessionEpoch = epoch
	if err := saveClientState(c.stateFile, st); err != nil {
		log.Warnf("Client failed to persist session state: %v", err)
	}
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
