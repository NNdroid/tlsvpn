package main

import (
	"sync"
	"testing"
	"time"
)

func pooledTestFrame(v byte) []byte {
	b := getFrameAtLeast(64)[:64]
	b[0] = v
	return b
}

func TestRXSessionWorkerBatchesAcrossProducers(t *testing.T) {
	var mu sync.Mutex
	got := make([]byte, 0, 4)
	done := make(chan struct{})
	rb := NewActorReorderBuffer(func(frame []byte) {
		mu.Lock()
		got = append(got, frame[0])
		if len(got) == 4 {
			select {
			case <-done:
			default:
				close(done)
			}
		}
		mu.Unlock()
	})
	w := newRXSessionWorker(rb)
	defer func() { w.Close(); rb.Close() }()

	p1 := w.NewProducer(nil, func(err error) { t.Errorf("unexpected RX error: %v", err) })
	p2 := w.NewProducer(nil, func(err error) { t.Errorf("unexpected RX error: %v", err) })
	p1.Push(1, pooledTestFrame(1))
	p1.Push(3, pooledTestFrame(3))
	p1.Flush()
	p2.Push(2, pooledTestFrame(2))
	p2.Push(4, pooledTestFrame(4))
	p2.Flush()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ordered RX delivery")
	}
	mu.Lock()
	defer mu.Unlock()
	for i, want := range []byte{1, 2, 3, 4} {
		if got[i] != want {
			t.Fatalf("ordered byte[%d]=%d want=%d (all=%v)", i, got[i], want, got)
		}
	}
}

func TestRXSessionWorkerEpochDropsStaleProducer(t *testing.T) {
	got := make(chan byte, 2)
	rb := NewActorReorderBuffer(func(frame []byte) { got <- frame[0] })
	w := newRXSessionWorker(rb)
	defer func() { w.Close(); rb.Close() }()

	stale := w.NewProducer(nil, nil)
	stale.Push(1, pooledTestFrame(9))
	w.AdvanceEpoch()
	stale.Flush()

	fresh := w.NewProducer(nil, nil)
	fresh.Push(1, pooledTestFrame(1))
	fresh.Flush()
	select {
	case v := <-got:
		if v != 1 {
			t.Fatalf("stale epoch delivered byte=%d", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fresh epoch frame not delivered")
	}
}

func BenchmarkFECDecoderDataSerial16(b *testing.B) {
	d := NewFECDecoder(4, nil, nil)
	frame := make([]byte, 256)
	seq := uint32(1)
	b.ReportAllocs()
	b.SetBytes(16 * int64(len(frame)))
	for n := 0; n < b.N; n++ {
		for i := 0; i < 16; i++ {
			d.OnData(seq, frame)
			seq++
		}
	}
}

// TestRXSessionWorkerCloseDrainsAllEnqueuedWork 并发 Flush 与 Close 竞争：
// Close 返回（run 已退出并完成排空）后 queue 必须为空——"队列有位"与
// "已关闭"同时就绪时若走 select 随机分支入队，work 会滞留在无人消费的
// queue 里（batch 描述符与帧缓冲只能等 GC）。同时验证 enqueue 在关闭后
// 返回 false 且不 panic。
func TestRXSessionWorkerCloseDrainsAllEnqueuedWork(t *testing.T) {
	rb := NewActorReorderBuffer(nil)
	defer rb.Close()
	w := newRXSessionWorker(rb)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := w.NewProducer(nil, nil)
			for i := 0; i < 200; i++ {
				select {
				case <-stop:
					return
				default:
				}
				p.Push(uint32(i+1), pooledTestFrame(byte(i)))
				p.Flush()
			}
		}()
	}
	time.Sleep(2 * time.Millisecond)
	close(stop)
	w.Close()
	wg.Wait()
	if !w.DoneIsClosed() {
		t.Fatal("worker run 未退出")
	}
	if n := len(w.queue); n != 0 {
		t.Fatalf("Close 排空后 queue 残留 %d 个 work（滞留泄漏）", n)
	}
	// 关闭后的 Flush 必须被拒绝（enqueue 返回 false → Flush 自行释放批），
	// 且不得再向 queue 投递任何 work。
	p := w.NewProducer(nil, nil)
	p.Push(1, pooledTestFrame(1))
	p.Flush()
	if n := len(w.queue); n != 0 {
		t.Fatalf("关闭后 Flush 仍入队: queue=%d", n)
	}
}

// TestRXSessionWorkerAdvanceEpochReturnsAfterImmediateClose barrier 入队后
// 立即 Close：barrier 必须被 run 排空路径关闭（或 enqueue 被拒后经
// w.closed 放行），AdvanceEpoch 不得永久阻塞。
func TestRXSessionWorkerAdvanceEpochReturnsAfterImmediateClose(t *testing.T) {
	rb := NewActorReorderBuffer(nil)
	defer rb.Close()
	w := newRXSessionWorker(rb)
	returned := make(chan struct{})
	go func() {
		w.AdvanceEpoch()
		close(returned)
	}()
	w.Close()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("AdvanceEpoch 未返回（barrier 泄漏）")
	}
}
