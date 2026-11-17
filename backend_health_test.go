package main

import (
	"sync/atomic"
	"testing"
)

// TestPickBackendSkipsStalled verifies that a backend marked stalled (dead/half-open
// connection detected) is excluded from scheduling so the scheduler stops sending
// data into the dead path.
func TestPickBackendSkipsStalled(t *testing.T) {
	rttA, rttB := uint32(250_000), uint32(240_000)
	a := &Backend{ch: make(chan []VPNFrame, 32), rttCache: &rttA}
	b := &Backend{ch: make(chan []VPNFrame, 32), rttCache: &rttB}
	p := &AsyncPort{}

	// b is lower RTT, so it is initially preferred.
	if got := p.pickBackend([]*Backend{a, b}); got != b {
		t.Fatal("initial selection did not choose the lower-RTT backend")
	}

	// Mark b stalled (dead path): scheduler must switch to a.
	b.markStalled()
	if got := p.pickBackend([]*Backend{a, b}); got != a {
		t.Fatalf("stalled backend was not skipped: got %v want a", got)
	}

	// Mark a stalled too: degenerate all-stalled case must still return a backend
	// (first non-stalled, else backends[0]) rather than nil.
	a.markStalled()
	if got := p.pickBackend([]*Backend{a, b}); got == nil {
		t.Fatal("all-stalled fallback returned nil")
	}
}

// TestBackendScoreStalledRejected verifies backendScore rejects a stalled backend.
func TestBackendScoreStalledRejected(t *testing.T) {
	rtt := uint32(200_000)
	b := &Backend{ch: make(chan []VPNFrame, 32), rttCache: &rtt}
	if _, ok := backendScore(b); !ok {
		t.Fatal("healthy backend should be scoreable")
	}
	b.markStalled()
	if _, ok := backendScore(b); ok {
		t.Fatal("stalled backend must be rejected by backendScore")
	}
}

// TestBackendRTTFailureStalls verifies consecutive RTT sampling failures mark the
// backend stalled after the configured threshold, while a success resets it.
func TestBackendRTTFailureStalls(t *testing.T) {
	rtt := uint32(200_000)
	b := &Backend{ch: make(chan []VPNFrame, 32), rttCache: &rtt}

	// rtt==0 is bootstrap, not a failure: it must not advance the failure counter.
	b.noteRTTFailure()
	// Success resets the counter.
	b.noteRTTSuccess()

	for i := 0; i < rttFailuresStall-1; i++ {
		if b.isStalled() {
			t.Fatalf("backend stalled too early at failure %d", i)
		}
		b.noteRTTFailure()
	}
	b.noteRTTFailure()
	if !b.isStalled() {
		t.Fatal("backend was not stalled after consecutive RTT failures")
	}
	_ = atomic.LoadUint32(&rtt)
}

// TestRebalanceBrutalShare verifies the per-connection share recomputation used by
// the Brutal rebalance (Fix 3): when live connections shrink, the surviving
// connection's legacy share must grow toward the total budget.
func TestRebalanceBrutalShare(t *testing.T) {
	const totalMbps = uint64(100)
	// 4 connections, index 0.
	if got := splitLegacyBrutalRateBps(totalMbps, 4, 0); got != totalMbps*1_000_000/8/4 {
		t.Fatalf("4-conn share = %d, want %d", got, totalMbps*1_000_000/8/4)
	}
	// After 3 die, index 0's share must become the full budget (1 live conn).
	if got := splitLegacyBrutalRateBps(totalMbps, 1, 0); got != totalMbps*1_000_000/8 {
		t.Fatalf("1-conn share = %d, want full budget %d", got, totalMbps*1_000_000/8)
	}
	// 2 live conns, index 1 gets the second half.
	if got := splitLegacyBrutalRateBps(totalMbps, 2, 1); got != totalMbps*1_000_000/8/2 {
		t.Fatalf("2-conn share index1 = %d, want %d", got, totalMbps*1_000_000/8/2)
	}
}

// TestPickBackendStickySymmetryUnlocksFromSlowerCurrent 单向锁死回归：current 为较慢
// 路径（其 rttCache 大、hysteresis 偏大），但快路径领先 d 恰好落在"快路径自己的
// 滞回带"与"慢路径的滞回带"之间。修复前 hysteresis 锚定 current（慢）的 RTT，
// d≤hyst_slow 恒真，一旦落到慢路径就再也回不到快路径。修复后锚定 bestBackend（快）
// 的 RTT，两个方向共用同一锚：快路径领先超过它自己的滞回带即切换回快路径。
func TestPickBackendStickySymmetryUnlocksFromSlowerCurrent(t *testing.T) {
	// fast：rtt=40ms → hysteresis=max(5000, 40000/8=5000)=5000µs。
	// slow：rtt=45.6ms → hysteresis=max(5000, 45600/8=5700)=5700µs。
	// 领先 d=45.6-40=5.6ms，落在 (fast_hyst=5ms, slow_hyst=5.7ms] 之间：
	// 修复前 5.6≤5.7 保留 slow（锁死）；修复后 5.6>5.0 切回 fast。
	rttFast, rttSlow := uint32(40_000), uint32(45_600)
	fast := &Backend{ch: make(chan []VPNFrame, 32), rttCache: &rttFast}
	slow := &Backend{ch: make(chan []VPNFrame, 32), rttCache: &rttSlow}
	p := &AsyncPort{backends: []*Backend{fast, slow}}
	p.storePreferredIfCurrent(slow) // current 锚定在慢路径

	if got := p.pickBackend([]*Backend{fast, slow}); got != fast {
		t.Fatalf("sticky stuck on slower path: got=%p want=%p (fast path not re-adopted)", got, fast)
	}
}
