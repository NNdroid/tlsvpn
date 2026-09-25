package main

import (
	"sync"
	"sync/atomic"
	"time"
)

// ======================= 乱序重排缓冲区 (Reorder Buffer) =======================

const (
	// 初始窗口保持小内存；多 TCP 路径在高吞吐时可能出现数万帧路径偏斜，
	// 再按需倍增到 65536。两者都必须是 2 的幂。
	ReorderWindowSize    = 2048
	ReorderMaxWindowSize = 65536
)

// 交付 channel 保持足够的短突发余量；满时直接丢 batch，而不是给每个
// Insert 创建 time.Timer 再最多阻塞 5s。连接读循环绝不能被慢 TAP 反压住。
const reorderOutQueue = 256

// pending/outChan 的 [][]byte 只保存 slice 描述符；高 PPS 顺序流几乎每包都会
// 生成一个小 batch。池化描述符容器可以消除这一类持续 GC 压力。
const reorderBatchHotCap = 64

var reorderBatchPool = sync.Pool{
	New: func() any { return new([reorderBatchHotCap][]byte) },
}

func getReorderBatch() [][]byte {
	return reorderBatchPool.Get().(*[reorderBatchHotCap][]byte)[:0]
}

func putReorderBatch(batch [][]byte) {
	if batch == nil {
		return
	}
	clear(batch)
	if cap(batch) == reorderBatchHotCap {
		reorderBatchPool.Put((*[reorderBatchHotCap][]byte)(batch[:reorderBatchHotCap]))
	}
}

// reorderSkipDelay 从“已经收到未来序号、确认存在缺口”的时刻开始计时。
// 旧实现用历史最大推进间隔自适应；空闲流量或 4 秒心跳会把阈值永久推到
// 500ms，叠加 250ms 轮询后形成明显的 0/突发吞吐。数据连接采用粘性选路后，
// 50ms 足以覆盖正常调度抖动，同时不会让一个已丢帧长期阻塞内层 TCP。
const reorderSkipDelay = 50 * time.Millisecond

type ReorderBufferStats struct {
	GapEvents      uint64
	TimeoutFlushes uint64
	SkippedFrames  uint64
	DroppedFrames  uint64 // deliver queue 满时丢帧数（TAP 慢兜底）
}

// ReorderBuffer 按序输出收到的帧。
//
// 交付路径与锁解耦：Insert 在锁内只做"塞槽 + 收集连续帧"，收集到的批次经
// outChan 交给唯一的交付协程按 FIFO 写 TAP/VSwitch。这样乱序帧的 Insert
// 立即返回，不再被一次 TAP 写系统调用阻塞整个锁；多连接并发 Insert 也只在
// 真正交付时才串行化。
type ReorderBuffer struct {
	mu          sync.Mutex
	expectedSeq uint32
	ring        [][]byte
	seqSlots    []uint32
	windowMask  uint32
	buffered    int
	pending     [][]byte // 锁内收集、出锁后交给交付协程的批次

	outChan chan [][]byte
	outFunc func([]byte)

	gapSince time.Time // 第一个未来序号到达、确认存在缺口的时间
	gapWake  chan struct{}

	gapEvents      atomic.Uint64
	timeoutFlushes atomic.Uint64
	skippedFrames  atomic.Uint64
	droppedFrames  atomic.Uint64 // deliver queue 满时累计丢帧数（慢 TAP 兜底）

	// shutting 由 Close 在锁内置位：之后的 Insert 直接释放帧而不再投递，
	// 因此 outChan 里不会残留 outWorker 退出后无人消费的批次（无泄漏窗口）。
	shutting  bool
	closed    chan struct{}
	closeOnce sync.Once
}

// NewReorderBuffer 创建重排缓冲区，参数为按序输出时的处理函数
func NewReorderBuffer(outFunc func([]byte)) *ReorderBuffer {
	rb := &ReorderBuffer{
		ring:       make([][]byte, ReorderWindowSize),
		seqSlots:   make([]uint32, ReorderWindowSize),
		windowMask: ReorderWindowSize - 1,
		outFunc: outFunc,
		outChan: make(chan [][]byte, reorderOutQueue),
		gapWake: make(chan struct{}, 1),
		closed:  make(chan struct{}),
	}
	go rb.timeoutWorker()
	go rb.outWorker()
	return rb
}

// Close 停止后台协程并释放在途缓冲。会话销毁时必须调用，否则每个会话泄漏两个协程。
// 幂等；关闭后 Insert 仍安全（帧被释放而非阻塞，也不会投递到已退出的交付协程）。
func (rb *ReorderBuffer) Close() {
	rb.closeOnce.Do(func() {
		rb.mu.Lock()
		rb.shutting = true
		drain := rb.takePendingLocked()
		rb.releaseRingLocked()
		// enqueue 全部发生在 rb.mu 内；置 shutting 后不会再出现新的入队。
		rb.mu.Unlock()
		close(rb.closed)
		rb.freeBatch(drain)
	})
}

// Reset 清空缓冲区（会话重置时调用），在途帧不交付直接释放
func (rb *ReorderBuffer) Reset() {
	rb.mu.Lock()
	drain := rb.takePendingLocked()
	hadGap := !rb.gapSince.IsZero()
	rb.expectedSeq = 0
	rb.releaseRingLocked()
	rb.gapSince = time.Time{}
	rb.mu.Unlock()
	if hadGap {
		rb.signalGapWorker()
	}
	rb.freeBatch(drain)
}

func (rb *ReorderBuffer) Stats() ReorderBufferStats {
	return ReorderBufferStats{
		GapEvents:      rb.gapEvents.Load(),
		TimeoutFlushes: rb.timeoutFlushes.Load(),
		SkippedFrames:  rb.skippedFrames.Load(),
		DroppedFrames:  rb.droppedFrames.Load(),
	}
}

// Insert 将收到的包推入缓冲区
func (rb *ReorderBuffer) Insert(seq uint32, frame []byte) {
	if seq == 0 {
		if frame != nil {
			putFrame(frame)
		}
		return
	}

	rb.mu.Lock()
	if rb.shutting {
		rb.mu.Unlock()
		putFrame(frame)
		return
	}
	wake := rb.insertLocked(seq, frame)
	// 大范围补齐时 drainLocked 已按固定 64 帧 chunk 入队；这里只冲刷尾块。
	rb.flushPendingLocked()
	rb.mu.Unlock()
	if wake {
		rb.signalGapWorker()
	}
}

// insertLocked 单帧入槽 + 尝试按序输出（调用方须持锁）
func (rb *ReorderBuffer) insertLocked(seq uint32, frame []byte) bool {
	if rb.expectedSeq == 0 {
		rb.expectedSeq = seq
	}

	diff := int32(seq - rb.expectedSeq)

	// 丢弃太老的包
	if diff < 0 {
		putFrame(frame)
		return false
	}

	// 多路径高速场景可能出现远大于 2048 帧的合法路径偏斜。只在真实需要
	// 时倍增窗口；最大 65536 防止异常序号造成无界内存增长。
	if uint32(diff) >= uint32(len(rb.ring)) {
		if uint32(diff) >= ReorderMaxWindowSize || !rb.growWindowLocked(uint32(diff)+1) {
			putFrame(frame)
			return false
		}
	}

	// 去重：窗口内每个槽位同时记录真实 seq，动态扩容后也能安全重散列。
	idx := seq & rb.windowMask
	if rb.ring[idx] != nil {
		if rb.seqSlots[idx] == seq {
			putFrame(frame)
			return false
		}
		// 正常窗口数学上不应发生不同 seq 冲突；保守丢弃避免覆盖在途帧。
		putFrame(frame)
		return false
	}

	rb.ring[idx] = frame
	rb.seqSlots[idx] = seq
	rb.buffered++

	// 刚好匹配，批量按序输出
	if seq == rb.expectedSeq {
		return rb.drainLocked()
	}
	return rb.refreshGapLocked(time.Now())
}

// growWindowLocked 把 ring 扩到足以容纳 requiredDistance 的 2 次幂。
// 仅多路径偏斜真正超过当前窗口时触发，因此正常 2K 窗口没有额外热路径成本。
func (rb *ReorderBuffer) growWindowLocked(requiredDistance uint32) bool {
	oldSize := len(rb.ring)
	if oldSize >= ReorderMaxWindowSize {
		return false
	}
	newSize := oldSize
	for uint32(newSize) <= requiredDistance && newSize < ReorderMaxWindowSize {
		newSize <<= 1
	}
	if newSize > ReorderMaxWindowSize {
		newSize = ReorderMaxWindowSize
	}
	if uint32(newSize) <= requiredDistance {
		return false
	}

	newRing := make([][]byte, newSize)
	newSeqs := make([]uint32, newSize)
	newMask := uint32(newSize - 1)
	for i, frame := range rb.ring {
		if frame == nil {
			continue
		}
		seq := rb.seqSlots[i]
		idx := seq & newMask
		newRing[idx] = frame
		newSeqs[idx] = seq
	}
	rb.ring = newRing
	rb.seqSlots = newSeqs
	rb.windowMask = newMask
	return true
}

// drainLocked 按序提取连续的包进 pending（调用方须持锁）
func (rb *ReorderBuffer) drainLocked() bool {
	hadGap := !rb.gapSince.IsZero()
	rb.gapSince = time.Time{}
	for {
		idx := rb.expectedSeq & rb.windowMask
		frame := rb.ring[idx]
		if frame == nil {
			break // 依然有缺口，等待
		}
		if rb.pending == nil {
			rb.pending = getReorderBatch()
		}
		rb.pending = append(rb.pending, frame)
		rb.ring[idx] = nil
		rb.seqSlots[idx] = 0
		rb.buffered--
		rb.expectedSeq++

		// adaptive window 可能一次补齐数万帧。固定 chunk 满了就立刻交给
		// outWorker，绝不让 [] []byte 从 64 档继续扩容并制造大对象。
		if len(rb.pending) == cap(rb.pending) {
			rb.flushPendingLocked()
		}
	}
	startedGap := rb.refreshGapLocked(time.Now())
	return hadGap || startedGap
}

// refreshGapLocked 只在缓冲区里确实存在未来帧时建立缺口计时。单纯空闲不算
// 缺口，否则心跳间隔会污染超时状态。返回值表示应唤醒定时协程重算 deadline。
func (rb *ReorderBuffer) refreshGapLocked(now time.Time) bool {
	hasGap := rb.buffered > 0 && rb.expectedSeq != 0 && rb.ring[rb.expectedSeq&rb.windowMask] == nil
	if hasGap {
		if rb.gapSince.IsZero() {
			rb.gapSince = now
			rb.gapEvents.Add(1)
			return true
		}
		return false
	}
	if !rb.gapSince.IsZero() {
		rb.gapSince = time.Time{}
		return true
	}
	return false
}

func (rb *ReorderBuffer) signalGapWorker() {
	select {
	case rb.gapWake <- struct{}{}:
	default:
	}
}

// takePendingLocked 取走已收集的批次（调用方须持锁）
func (rb *ReorderBuffer) takePendingLocked() [][]byte {
	b := rb.pending
	rb.pending = nil
	return b
}

// flushPendingLocked 把当前固定 chunk 非阻塞排给唯一 outWorker。
// 调用方持 rb.mu，因此所有并发 Insert/timeout flush 的 channel 入队顺序
// 就是重排后的序号顺序，无需额外 deliverMu。
func (rb *ReorderBuffer) flushPendingLocked() {
	batch := rb.takePendingLocked()
	if len(batch) == 0 {
		putReorderBatch(batch)
		return
	}
	select {
	case rb.outChan <- batch:
	default:
		rb.droppedFrames.Add(uint64(len(batch)))
		rb.freeBatch(batch)
	}
}

// releaseRingLocked 释放全部槽位（调用方须持锁）
func (rb *ReorderBuffer) releaseRingLocked() {
	for i := range rb.ring {
		if rb.ring[i] != nil {
			putFrame(rb.ring[i])
			rb.ring[i] = nil
			rb.seqSlots[i] = 0
		}
	}
	rb.buffered = 0
}

// outWorker 唯一的交付协程：单一消费者保证跨 Insert 的严格交付顺序
func (rb *ReorderBuffer) outWorker() {
	for {
		select {
		case <-rb.closed:
			// 排空通道里剩余的批次后退出
			for {
				select {
				case batch := <-rb.outChan:
					rb.outputBatch(batch)
				default:
					return
				}
			}
		case batch := <-rb.outChan:
			rb.outputBatch(batch)
		}
	}
}

func (rb *ReorderBuffer) outputBatch(batch [][]byte) {
	for _, frame := range batch {
		if rb.outFunc != nil && len(frame) > 0 {
			rb.outFunc(frame)
		}
		putFrame(frame)
	}
	putReorderBatch(batch)
}

func (rb *ReorderBuffer) freeBatch(batch [][]byte) {
	for _, frame := range batch {
		putFrame(frame)
	}
	putReorderBatch(batch)
}

// timeoutWorker 平时完全休眠；第一个未来帧确认缺口时由 Insert 唤醒并精确等待
// deadline。缺口被补齐或 Reset 时同样会被唤醒重算，不再固定轮询。
func (rb *ReorderBuffer) timeoutWorker() {
	// 一个 ReorderBuffer 生命周期只分配一个 timer。多路径抖动时 gap 可能很频繁，
	// 旧实现每个 gap 都 NewTimer，给 GC 制造无意义的短命对象。
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	stopTimer := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}

	for {
		rb.mu.Lock()
		if rb.shutting {
			rb.mu.Unlock()
			return
		}
		if rb.gapSince.IsZero() {
			rb.mu.Unlock()
			select {
			case <-rb.closed:
				return
			case <-rb.gapWake:
			}
			continue
		}
		deadline := rb.gapSince.Add(reorderSkipDelay)
		wait := time.Until(deadline)
		rb.mu.Unlock()

		if wait > 0 {
			timer.Reset(wait)
			select {
			case <-rb.closed:
				stopTimer()
				return
			case <-rb.gapWake:
				stopTimer()
				continue
			case <-timer.C:
			}
		}

		rb.mu.Lock()
		if rb.gapSince.IsZero() || time.Now().Before(rb.gapSince.Add(reorderSkipDelay)) ||
			rb.buffered == 0 || rb.expectedSeq == 0 || rb.ring[rb.expectedSeq&rb.windowMask] != nil {
			rb.mu.Unlock()
			continue
		}
		// 预期的坑为空且已超时：确认丢包，往后找第一个有包的坑
		skipped := uint32(0)
		for i := uint32(1); i < uint32(len(rb.ring)); i++ {
			if rb.ring[(rb.expectedSeq+i)&rb.windowMask] != nil {
				rb.expectedSeq += i
				skipped = i
				break
			}
		}
		rb.gapSince = time.Time{}
		if skipped > 0 {
			rb.timeoutFlushes.Add(1)
			rb.skippedFrames.Add(uint64(skipped))
			rb.drainLocked()
		}
		rb.flushPendingLocked()
		rb.mu.Unlock()
	}
}
