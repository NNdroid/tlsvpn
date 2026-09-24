package main

import (
	"sync"
	"sync/atomic"
	"time"
)

// ======================= 乱序重排缓冲区 (Reorder Buffer) =======================

const ReorderWindowSize = 2048 // 必须是 2 的幂，方便位运算优化性能

const reorderWindowMask = ReorderWindowSize - 1

// reorderSkipDelay 从“已经收到未来序号、确认存在缺口”的时刻开始计时。
// 旧实现用历史最大推进间隔自适应；空闲流量或 4 秒心跳会把阈值永久推到
// 500ms，叠加 250ms 轮询后形成明显的 0/突发吞吐。数据连接采用粘性选路后，
// 50ms 足以覆盖正常调度抖动，同时不会让一个已丢帧长期阻塞内层 TCP。
const reorderSkipDelay = 50 * time.Millisecond

type ReorderBufferStats struct {
	GapEvents      uint64
	TimeoutFlushes uint64
	SkippedFrames  uint64
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
	buffered    int
	pending     [][]byte // 锁内收集、出锁后交给交付协程的批次

	outChan chan [][]byte
	outFunc func([]byte)
	// deliverMu 在不把慢 TAP/VSwitch 写放回重排锁的前提下，保留多个 Insert
	// 和超时协程从锁内取出批次时的先后次序。
	deliverMu sync.Mutex

	gapSince time.Time // 第一个未来序号到达、确认存在缺口的时间
	gapWake  chan struct{}

	gapEvents      atomic.Uint64
	timeoutFlushes atomic.Uint64
	skippedFrames  atomic.Uint64

	// shutting 由 Close 在锁内置位：之后的 Insert 直接释放帧而不再投递，
	// 因此 outChan 里不会残留 outWorker 退出后无人消费的批次（无泄漏窗口）。
	shutting  bool
	closed    chan struct{}
	closeOnce sync.Once
}

// NewReorderBuffer 创建重排缓冲区，参数为按序输出时的处理函数
func NewReorderBuffer(outFunc func([]byte)) *ReorderBuffer {
	rb := &ReorderBuffer{
		ring:    make([][]byte, ReorderWindowSize),
		outFunc: outFunc,
		outChan: make(chan [][]byte, 64),
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
		// 与 Insert/timeoutWorker 的锁顺序一致。等待已经从重排锁取出的批次
		// 完成入队，再关闭 closed，避免 outWorker 排空后又有批次入队。
		rb.deliverMu.Lock()
		rb.mu.Unlock()
		close(rb.closed)
		rb.deliverMu.Unlock()
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
	batch := rb.takePendingLocked()
	if len(batch) > 0 {
		rb.deliverMu.Lock()
	}
	rb.mu.Unlock()
	if wake {
		rb.signalGapWorker()
	}
	rb.deliver(batch)
	if len(batch) > 0 {
		rb.deliverMu.Unlock()
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

	// 乱序窗口超出限制，防极端情况内存溢出
	if diff >= ReorderWindowSize {
		putFrame(frame)
		return false
	}

	// 去重：如果坑里已经有包了，说明是 FEC 冗余包
	idx := seq & reorderWindowMask
	if rb.ring[idx] != nil {
		putFrame(frame)
		return false
	}

	rb.ring[idx] = frame
	rb.buffered++

	// 刚好匹配，批量按序输出
	if seq == rb.expectedSeq {
		return rb.drainLocked()
	}
	return rb.refreshGapLocked(time.Now())
}

// drainLocked 按序提取连续的包进 pending（调用方须持锁）
func (rb *ReorderBuffer) drainLocked() bool {
	hadGap := !rb.gapSince.IsZero()
	rb.gapSince = time.Time{}
	for {
		idx := rb.expectedSeq & reorderWindowMask
		frame := rb.ring[idx]
		if frame == nil {
			break // 依然有缺口，等待
		}
		rb.pending = append(rb.pending, frame)
		rb.ring[idx] = nil
		rb.buffered--
		rb.expectedSeq++
	}
	startedGap := rb.refreshGapLocked(time.Now())
	return hadGap || startedGap
}

// refreshGapLocked 只在缓冲区里确实存在未来帧时建立缺口计时。单纯空闲不算
// 缺口，否则心跳间隔会污染超时状态。返回值表示应唤醒定时协程重算 deadline。
func (rb *ReorderBuffer) refreshGapLocked(now time.Time) bool {
	hasGap := rb.buffered > 0 && rb.expectedSeq != 0 && rb.ring[rb.expectedSeq&reorderWindowMask] == nil
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

// releaseRingLocked 释放全部槽位（调用方须持锁）
func (rb *ReorderBuffer) releaseRingLocked() {
	for i := range rb.ring {
		if rb.ring[i] != nil {
			putFrame(rb.ring[i])
			rb.ring[i] = nil
		}
	}
	rb.buffered = 0
}

// deliver 把批次交给交付协程（锁外调用）；已关闭时直接释放
func (rb *ReorderBuffer) deliver(batch [][]byte) {
	if len(batch) == 0 {
		return
	}
	select {
	case rb.outChan <- batch:
	case <-rb.closed:
		rb.freeBatch(batch)
	}
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
}

func (rb *ReorderBuffer) freeBatch(batch [][]byte) {
	for _, frame := range batch {
		putFrame(frame)
	}
}

// timeoutWorker 平时完全休眠；第一个未来帧确认缺口时由 Insert 唤醒并精确等待
// deadline。缺口被补齐或 Reset 时同样会被唤醒重算，不再固定轮询。
func (rb *ReorderBuffer) timeoutWorker() {
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
			timer := time.NewTimer(wait)
			select {
			case <-rb.closed:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				return
			case <-rb.gapWake:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				continue
			case <-timer.C:
			}
		}

		rb.mu.Lock()
		if rb.gapSince.IsZero() || time.Now().Before(rb.gapSince.Add(reorderSkipDelay)) ||
			rb.buffered == 0 || rb.expectedSeq == 0 || rb.ring[rb.expectedSeq&reorderWindowMask] != nil {
			rb.mu.Unlock()
			continue
		}
		// 预期的坑为空且已超时：确认丢包，往后找第一个有包的坑
		skipped := uint32(0)
		for i := uint32(1); i < ReorderWindowSize; i++ {
			if rb.ring[(rb.expectedSeq+i)&reorderWindowMask] != nil {
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
		batch := rb.takePendingLocked()
		if len(batch) > 0 {
			rb.deliverMu.Lock()
		}
		rb.mu.Unlock()
		rb.deliver(batch)
		if len(batch) > 0 {
			rb.deliverMu.Unlock()
		}
	}
}
