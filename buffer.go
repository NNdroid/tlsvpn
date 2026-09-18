package main

import (
	"sync"
	"time"
)

// ======================= 乱序重排缓冲区 (Reorder Buffer) =======================

const ReorderWindowSize = 2048 // 必须是 2 的幂，方便位运算优化性能

const reorderWindowMask = ReorderWindowSize - 1

// 缺口跳过阈值：旧实现固定 20ms，一次普通的 25ms 网络停顿就会把在途的所有帧
// 判为永久丢失（隧道内的 TCP ACK 一旦被丢会直接打掉吞吐）。现在阈值按观测到的
// 最大推进间隔自适应，上下界之间取 8 倍余量。
const (
	reorderSkipFloor = 20 * time.Millisecond
	reorderSkipCeil  = 500 * time.Millisecond
	reorderSkipMult  = 8
	// reorderIdlePoll 无缺口时的轮询间隔（替代旧的固定 5ms 空转）
	reorderIdlePoll = 250 * time.Millisecond
)

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
	pending     [][]byte // 锁内收集、出锁后交给交付协程的批次

	outChan chan [][]byte
	outFunc func([]byte)

	lastAdvance    time.Time // 最近一次推进时间
	gapSince       time.Time // 当前缺口首次出现的时间（零值=无在决缺口）
	maxAdvanceSpan time.Duration

	// shutting 由 Close 在锁内置位：之后的 Insert 直接释放帧而不再投递，
	// 因此 outChan 里不会残留 outWorker 退出后无人消费的批次（无泄漏窗口）。
	shutting  bool
	closed    chan struct{}
	closeOnce sync.Once
}

// NewReorderBuffer 创建重排缓冲区，参数为按序输出时的处理函数
func NewReorderBuffer(outFunc func([]byte)) *ReorderBuffer {
	rb := &ReorderBuffer{
		ring:        make([][]byte, ReorderWindowSize),
		outFunc:     outFunc,
		outChan:     make(chan [][]byte, 64),
		lastAdvance: time.Now(),
		closed:      make(chan struct{}),
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
		rb.mu.Unlock()
		close(rb.closed)
		rb.freeBatch(drain)
	})
}

// Reset 清空缓冲区（会话重置时调用），在途帧不交付直接释放
func (rb *ReorderBuffer) Reset() {
	rb.mu.Lock()
	drain := rb.takePendingLocked()
	rb.expectedSeq = 0
	rb.releaseRingLocked()
	rb.maxAdvanceSpan = 0
	rb.gapSince = time.Time{}
	rb.lastAdvance = time.Time{}
	rb.mu.Unlock()
	rb.freeBatch(drain)
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
	rb.insertLocked(seq, frame)
	batch := rb.takePendingLocked()
	shutting := rb.shutting
	rb.mu.Unlock()
	if shutting {
		rb.freeBatch(batch)
		return
	}
	rb.deliver(batch)
}

// insertLocked 单帧入槽 + 尝试按序输出（调用方须持锁）
func (rb *ReorderBuffer) insertLocked(seq uint32, frame []byte) {
	if rb.expectedSeq == 0 {
		rb.expectedSeq = seq
	}

	diff := int32(seq - rb.expectedSeq)

	// 丢弃太老的包
	if diff < 0 {
		putFrame(frame)
		return
	}

	// 乱序窗口超出限制，防极端情况内存溢出
	if diff >= ReorderWindowSize {
		putFrame(frame)
		return
	}

	// 去重：如果坑里已经有包了，说明是 FEC 冗余包
	idx := seq & reorderWindowMask
	if rb.ring[idx] != nil {
		putFrame(frame)
		return
	}

	rb.ring[idx] = frame

	// 刚好匹配，批量按序输出
	if seq == rb.expectedSeq {
		rb.drainLocked()
	}
}

// drainLocked 按序提取连续的包进 pending（调用方须持锁）
func (rb *ReorderBuffer) drainLocked() {
	n := 0
	for {
		idx := rb.expectedSeq & reorderWindowMask
		frame := rb.ring[idx]
		if frame == nil {
			break // 依然有缺口，等待
		}
		rb.pending = append(rb.pending, frame)
		rb.ring[idx] = nil
		rb.expectedSeq++
		n++
	}
	if n == 0 {
		return // 没推进就不刷新时钟，否则会掩盖缺口的真实持续时间
	}
	// 每次 drain 只取一次时钟：逐帧 time.Now() 在高速流下是纯开销
	now := time.Now()
	if rb.lastAdvance.IsZero() {
		rb.lastAdvance = now
	} else if span := now.Sub(rb.lastAdvance); span > rb.maxAdvanceSpan {
		rb.maxAdvanceSpan = span
	}
	rb.lastAdvance = now
	rb.gapSince = time.Time{}
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

// skipThreshold 当前缺口跳过阈值：按观测到的最大推进间隔自适应
func (rb *ReorderBuffer) skipThreshold() time.Duration {
	ms := int64(20)
	if rb.maxAdvanceSpan > 0 {
		ms = int64(rb.maxAdvanceSpan/time.Microsecond) * reorderSkipMult / 1000
	}
	if ms < int64(reorderSkipFloor/time.Millisecond) {
		ms = int64(reorderSkipFloor / time.Millisecond)
	}
	if ms > int64(reorderSkipCeil/time.Millisecond) {
		ms = int64(reorderSkipCeil / time.Millisecond)
	}
	return time.Duration(ms) * time.Millisecond
}

// timeoutWorker 在缺口持续超过自适应阈值时强制跳过，避免彻底丢包导致卡死
func (rb *ReorderBuffer) timeoutWorker() {
	for {
		rb.mu.Lock()
		if rb.shutting {
			rb.mu.Unlock()
			return
		}
		hasGap := rb.expectedSeq != 0 && rb.ring[rb.expectedSeq&reorderWindowMask] == nil
		if !hasGap {
			rb.mu.Unlock()
			select {
			case <-rb.closed:
				return
			case <-time.After(reorderIdlePoll):
			}
			continue
		}
		if rb.gapSince.IsZero() {
			rb.gapSince = time.Now()
		}
		wait := rb.skipThreshold() - time.Since(rb.gapSince)
		rb.mu.Unlock()

		if wait > 0 {
			select {
			case <-rb.closed:
				return
			case <-time.After(wait):
			}
			continue
		}

		rb.mu.Lock()
		if rb.expectedSeq == 0 || rb.ring[rb.expectedSeq&reorderWindowMask] != nil {
			rb.mu.Unlock()
			continue
		}
		// 预期的坑为空且已超时：确认丢包，往后找第一个有包的坑
		for i := uint32(1); i < ReorderWindowSize; i++ {
			if rb.ring[(rb.expectedSeq+i)&reorderWindowMask] != nil {
				rb.expectedSeq += i
				break
			}
		}
		rb.gapSince = time.Time{}
		rb.drainLocked()
		batch := rb.takePendingLocked()
		rb.mu.Unlock()
		rb.deliver(batch)
	}
}
