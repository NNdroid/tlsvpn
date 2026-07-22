package main

import (
	"sync"
	"time"
)

// ======================= 高速环形去重器 (用于 FEC 过滤) =======================
type DeDuplicator struct {
	mu   sync.Mutex
	set  map[uint32]struct{}
	ring [4096]uint32
	idx  int
}

func NewDeDuplicator() *DeDuplicator {
	return &DeDuplicator{
		set: make(map[uint32]struct{}, 4096),
	}
}

func (d *DeDuplicator) IsDuplicate(seq uint32) bool {
	if seq == 0 {
		return false // 保活空包、控制帧不参与去重
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.set[seq]; exists {
		return true // 发现重复包！
	}

	// 淘汰最老的记录
	oldest := d.ring[d.idx]
	if oldest != 0 {
		delete(d.set, oldest)
	}

	// 加入新记录
	d.ring[d.idx] = seq
	d.set[seq] = struct{}{}
	d.idx = (d.idx + 1) % 4096

	return false
}

func (d *DeDuplicator) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.set = make(map[uint32]struct{}, 4096)
	d.ring = [4096]uint32{}
	d.idx = 0
}

func (rb *ReorderBuffer) Reset() {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.expectedSeq = 0
	for i := range rb.ring {
		if rb.ring[i] != nil {
			putFrame(*rb.ring[i])
			rb.ring[i] = nil
		}
	}
}

// ======================= 乱序重排缓冲区 (Reorder Buffer) =======================
const ReorderWindowSize = 2048 // 必须是 2 的幂，方便位运算优化性能
type ReorderBuffer struct {
	mu          sync.Mutex
	expectedSeq uint32
	ring        []*[]byte
	outFunc     func([]byte) // 提取出回调函数，方便 Client 写 TAP，Server 写 VSwitch
	lastAdvance time.Time
}

// NewReorderBuffer 创建重排缓冲区，参数为按序输出时的处理函数
func NewReorderBuffer(outFunc func([]byte)) *ReorderBuffer {
	rb := &ReorderBuffer{
		ring:        make([]*[]byte, ReorderWindowSize),
		outFunc:     outFunc,
		lastAdvance: time.Now(),
	}
	go rb.timeoutWorker() // 启动后台防死锁协程
	return rb
}

// timeoutWorker 定期检查是否因为彻底丢包而卡死
func (rb *ReorderBuffer) timeoutWorker() {
	ticker := time.NewTicker(5 * time.Millisecond) // 提高到 5ms 减小缺口积压
	defer ticker.Stop()

	for range ticker.C {
		rb.mu.Lock()
		// 如果距离上一次推进已经超过 20ms，说明预期的包彻底丢了，强制跳过缺口
		if rb.expectedSeq != 0 && time.Since(rb.lastAdvance) > 20*time.Millisecond {
			idx := rb.expectedSeq % ReorderWindowSize
			// 如果当前预期的坑里没包，说明确实丢了，往后找第一个有包的坑
			if rb.ring[idx] == nil {
				for i := uint32(1); i < ReorderWindowSize; i++ {
					nextSeq := rb.expectedSeq + i
					if rb.ring[nextSeq%ReorderWindowSize] != nil {
						rb.expectedSeq = nextSeq
						rb.flushLocked()
						break
					}
				}
			}
		}
		rb.mu.Unlock()
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
	defer rb.mu.Unlock()

	if rb.expectedSeq == 0 {
		rb.expectedSeq = seq
	}

	// 丢弃太老的包
	diff := int32(seq - rb.expectedSeq)
	if diff < 0 {
		if frame != nil {
			putFrame(frame)
		}
		return
	}

	// 乱序窗口超出限制，防极端情况内存溢出
	if diff >= ReorderWindowSize {
		if frame != nil {
			putFrame(frame)
		}
		return
	}

	idx := seq % ReorderWindowSize
	// 去重：如果坑里已经有包了，说明是 FEC 冗余包
	if rb.ring[idx] != nil {
		if frame != nil {
			putFrame(frame)
		}
		return
	}

	// 放入环形槽
	rb.ring[idx] = &frame

	// 刚好匹配，批量按序输出
	if seq == rb.expectedSeq {
		rb.flushLocked()
	}
}

// flushLocked 按序提取连续的包
func (rb *ReorderBuffer) flushLocked() {
	for {
		idx := rb.expectedSeq % ReorderWindowSize
		framePtr := rb.ring[idx]
		if framePtr == nil {
			break // 依然有缺口，等待
		}

		frame := *framePtr
		if len(frame) > 0 {
			rb.outFunc(frame)
		}

		putFrame(frame)
		rb.ring[idx] = nil // 释放槽位

		rb.expectedSeq++
		rb.lastAdvance = time.Now()
	}
}
