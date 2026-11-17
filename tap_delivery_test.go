package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type recordingTapWriter struct {
	mu      sync.Mutex
	frames  [][]byte
	started chan struct{}
	release chan struct{}
	err     error
	once    sync.Once
}

func (w *recordingTapWriter) Write(p []byte) (int, error) {
	if w.started != nil {
		w.once.Do(func() { close(w.started) })
	}
	if w.release != nil {
		<-w.release
	}
	w.mu.Lock()
	w.frames = append(w.frames, append([]byte(nil), p...))
	w.mu.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	return len(p), nil
}

func (w *recordingTapWriter) snapshot() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([][]byte, len(w.frames))
	for i := range w.frames {
		out[i] = append([]byte(nil), w.frames[i]...)
	}
	return out
}

func TestOwnedTapDeliveryPreservesOrderAndDoesNotBlockNormalBurst(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &recordingTapWriter{started: make(chan struct{}), release: make(chan struct{})}
	d := newOwnedTapDelivery(ctx, w, 4, nil)

	f1 := getFrameAtLeast(16)[:3]
	copy(f1, []byte{1, 2, 3})
	d.EnqueueOwned(f1)
	select {
	case <-w.started:
	case <-time.After(time.Second):
		t.Fatal("TAP worker did not start first write")
	}

	done := make(chan struct{})
	go func() {
		for i := byte(4); i <= 6; i++ {
			f := getFrameAtLeast(16)[:1]
			f[0] = i
			d.EnqueueOwned(f)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("queued TAP burst unexpectedly blocked")
	}

	close(w.release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		got := w.snapshot()
		if len(got) == 4 {
			want := [][]byte{{1, 2, 3}, {4}, {5}, {6}}
			for i := range want {
				if string(got[i]) != string(want[i]) {
					t.Fatalf("frame %d = %v, want %v", i, got[i], want[i])
				}
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("only %d frames reached TAP", len(w.snapshot()))
}

func TestOwnedTapDeliveryReportsWriteError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wantErr := errors.New("tap write failed")
	w := &recordingTapWriter{err: wantErr}
	errCh := make(chan error, 1)
	d := newOwnedTapDelivery(ctx, w, 1, func(err error) { errCh <- err })

	f := getFrameAtLeast(16)[:1]
	f[0] = 9
	d.EnqueueOwned(f)
	select {
	case got := <-errCh:
		if !errors.Is(got, wantErr) {
			t.Fatalf("write error = %v, want %v", got, wantErr)
		}
	case <-time.After(time.Second):
		t.Fatal("write error callback was not invoked")
	}
}

func TestOwnedTapDeliveryReleasesFrameAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	d := newOwnedTapDelivery(ctx, &recordingTapWriter{}, 1, nil)
	f := getFrameAtLeast(16)[:1]
	f[0] = 7
	d.EnqueueOwned(f)
}

// TestOwnedTapDeliveryCancelledEnqueueNeverStrandsFrames 取消后入队不得滞留
// channel：select 在"队列有位"与"ctx.Done"同时就绪时随机选择，run 已
// releaseQueued 退出后入队的帧会无人消费（上限 128 池缓冲流失）。修复后
// 入队前先查 ctx.Err，命中取消直接归还池缓冲，确定性断言 channel 恒空。
func TestOwnedTapDeliveryCancelledEnqueueNeverStrandsFrames(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	d := newOwnedTapDelivery(ctx, &recordingTapWriter{}, asyncTapDeliveryQueue, nil)
	cancel()
	// 等 run 观察到取消并执行 releaseQueued（channel 排空后再断言）。
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(d.ch) != 0 {
		time.Sleep(time.Millisecond)
	}
	for i := 0; i < 128; i++ {
		f := getFrameAtLeast(16)[:1]
		f[0] = byte(i)
		d.EnqueueOwned(f)
	}
	if n := len(d.ch); n != 0 {
		t.Fatalf("取消后入队滞留 channel: %d 帧（应直接归还池缓冲）", n)
	}
}

func TestAsyncTapDeliveryQueueIsBounded(t *testing.T) {
	if asyncTapDeliveryQueue < 32 || asyncTapDeliveryQueue > 256 {
		t.Fatalf("asyncTapDeliveryQueue=%d, want bounded low-latency range [32,256]", asyncTapDeliveryQueue)
	}
}
