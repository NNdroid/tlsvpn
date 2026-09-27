package main

import "testing"

func TestPickDataBackendBulkHintStripesWithoutResidualQueueBacklog(t *testing.T) {
	p := &AsyncPort{ch: make(chan []byte, 128)}
	rttA, rttB, rttC := uint32(10_000), uint32(11_000), uint32(50_000)
	a := &Backend{ch: make(chan []VPNFrame, 64), rttCache: &rttA}
	b := &Backend{ch: make(chan []VPNFrame, 64), rttCache: &rttB}
	c := &Backend{ch: make(chan []VPNFrame, 64), rttCache: &rttC}
	backends := []*Backend{a, b, c}

	// No residual p.ch backlog: this models AsyncPort.run after it has drained a
	// full Ethernet batch. The explicit bulk hint must still stripe across the
	// two near-RTT paths instead of falling back to one preferred TCP flow.
	counts := map[*Backend]int{}
	for i := 0; i < 32; i++ {
		counts[p.pickDataBackendFor(backends, true)]++
	}
	if counts[a] == 0 || counts[b] == 0 {
		t.Fatalf("bulk selection did not stripe near-RTT paths: A=%d B=%d C=%d", counts[a], counts[b], counts[c])
	}
	if counts[c] != 0 {
		t.Fatalf("bulk selection used high-RTT path C %d times", counts[c])
	}
}

func TestPickDataBackendWithoutBulkHintKeepsMinRTT(t *testing.T) {
	p := &AsyncPort{ch: make(chan []byte, 128)}
	rttA, rttB := uint32(10_000), uint32(11_000)
	a := &Backend{ch: make(chan []VPNFrame, 64), rttCache: &rttA}
	b := &Backend{ch: make(chan []VPNFrame, 64), rttCache: &rttB}
	backends := []*Backend{a, b}

	for i := 0; i < 16; i++ {
		if got := p.pickDataBackendFor(backends, false); got != a {
			t.Fatalf("interactive selection chose %p, want min-RTT backend %p", got, a)
		}
	}
}
