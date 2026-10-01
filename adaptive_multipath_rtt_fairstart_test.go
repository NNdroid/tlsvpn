package main

import "testing"

func TestAdaptiveSchedulerFairStartsUnknownRTTPaths(t *testing.T) {
	p := &AsyncPort{}
	measured := testAdaptiveBackend(800)
	unknownA := testAdaptiveBackend(adaptiveUnknownRTTUS)
	unknownB := testAdaptiveBackend(adaptiveUnknownRTTUS)
	unknownC := testAdaptiveBackend(adaptiveUnknownRTTUS)
	backends := []*Backend{measured, unknownA, unknownB, unknownC}

	// Reproduce the real server-download startup state: one socket has obtained
	// a low TCP_INFO RTT while the other physical connections still contain the
	// legacy 50 ms bootstrap estimate. Under sustained bulk demand those unknown
	// paths must receive fair-start traffic instead of being excluded forever by
	// the near-MinRTT envelope.
	p.inputRateBytesPerSec.Store(adaptiveActive4RateBytesPerSec)
	counts := map[*Backend]int{}
	for i := 0; i < 40; i++ {
		counts[p.pickAdaptiveBackend(backends, 0, 12*1024)]++
	}
	if got := p.activePaths.Load(); got != 4 {
		t.Fatalf("activePaths=%d want 4", got)
	}
	for i, b := range backends {
		if counts[b] == 0 {
			t.Fatalf("path %d starved before RTT warm-up: counts=%v", i, counts)
		}
		if !b.active.Load() {
			t.Fatalf("path %d not active during RTT fair-start", i)
		}
	}
}

func TestAdaptiveSchedulerMeasuredSlowRTTStillExcluded(t *testing.T) {
	p := &AsyncPort{}
	fastA := testAdaptiveBackend(800)
	fastB := testAdaptiveBackend(900)
	unknown := testAdaptiveBackend(adaptiveUnknownRTTUS)
	slow := testAdaptiveBackend(80_000)
	// A measured path needs both RTT and a writer sample. Keep unknown cold.
	for _, b := range []*Backend{fastA, fastB, slow} {
		b.rateBytesPerSec.Store(100_000_000)
	}
	backends := []*Backend{fastA, fastB, unknown, slow}

	p.inputRateBytesPerSec.Store(adaptiveActive4RateBytesPerSec)
	counts := map[*Backend]int{}
	for i := 0; i < 30; i++ {
		counts[p.pickAdaptiveBackend(backends, 0, 12*1024)]++
	}
	if counts[unknown] == 0 {
		t.Fatalf("unknown RTT path did not receive fair-start traffic: counts=%v", counts)
	}
	if counts[slow] != 0 || slow.active.Load() {
		t.Fatalf("measured slow path entered near-MinRTT active set: counts=%v active=%v", counts, slow.active.Load())
	}
	if got := p.activePaths.Load(); got != 3 {
		t.Fatalf("activePaths=%d want 3 eligible paths", got)
	}
}
