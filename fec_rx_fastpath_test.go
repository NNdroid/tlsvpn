package main

import (
	"bytes"
	"testing"
)

func TestFECDecoderFullDataGroupReleasedWithoutParity(t *testing.T) {
	for _, k := range []int{2, 4, 64} {
		t.Run(string(rune('A'+k%26)), func(t *testing.T) {
			d := NewFECDecoder(k, nil, nil)
			frame := bytes.Repeat([]byte{0x5a}, 256)
			for i := 0; i < k; i++ {
				d.OnData(uint32(i+1), frame)
			}

			d.mu.Lock()
			groups := len(d.groups)
			done := d.isDoneLocked(1)
			d.mu.Unlock()
			if groups != 0 {
				t.Fatalf("K=%d full data-only group retained %d pending groups, want 0", k, groups)
			}
			if !done {
				t.Fatalf("K=%d full data-only group was not marked done", k)
			}
			recovered, lost := d.FECStats()
			if recovered != 0 || lost != 0 {
				t.Fatalf("K=%d full data-only group stats recovered/lost=%d/%d, want 0/0", k, recovered, lost)
			}
		})
	}
}

func TestFECDecoderStaticSinglePathBypassesAllGroupState(t *testing.T) {
	d := NewFECDecoder(4, nil, nil)
	d.SetStaticSinglePath(true)
	frame := bytes.Repeat([]byte{0x33}, 1400)

	for seq := uint32(1); seq <= 128; seq++ {
		d.OnData(seq, frame)
	}

	e := newFECEncoder(4, nil)
	var parity []byte
	for seq := uint32(129); seq <= 132; seq++ {
		if p := e.add(VPNFrame{Seq: seq, Data: frame}); p != nil {
			parity = p
		}
	}
	if parity == nil {
		t.Fatal("expected parity test fixture")
	}
	d.OnParity(parity)
	putFrame(parity)

	d.mu.Lock()
	groups := len(d.groups)
	order := len(d.groupOrder)
	d.mu.Unlock()
	if groups != 0 || order != 0 {
		t.Fatalf("static single-path RX created decoder state: groups=%d order=%d", groups, order)
	}
	recovered, lost := d.FECStats()
	if recovered != 0 || lost != 0 {
		t.Fatalf("static single-path RX stats recovered/lost=%d/%d, want 0/0", recovered, lost)
	}
}

func TestFECDecoderStaticSinglePathToggleClearsAndRestores(t *testing.T) {
	recovered := make(chan uint32, 1)
	d := NewFECDecoder(4, nil, func(seq uint32, frame []byte) {
		recovered <- seq
		putFrame(frame)
	})
	frame := bytes.Repeat([]byte{0x44}, 512)

	d.OnData(1, frame)
	d.mu.Lock()
	before := len(d.groups)
	d.mu.Unlock()
	if before != 1 {
		t.Fatalf("precondition pending groups=%d, want 1", before)
	}

	d.SetStaticSinglePath(true)
	d.mu.Lock()
	after := len(d.groups)
	d.mu.Unlock()
	if after != 0 {
		t.Fatalf("enabling static single-path did not clear pending state: %d groups", after)
	}

	d.OnData(2, frame) // bypassed
	d.SetStaticSinglePath(false)

	e := newFECEncoder(4, nil)
	var parity []byte
	for seq := uint32(5); seq <= 8; seq++ {
		if p := e.add(VPNFrame{Seq: seq, Data: frame}); p != nil {
			parity = p
		}
		if seq != 8 {
			d.OnData(seq, frame)
		}
	}
	if parity == nil {
		t.Fatal("expected parity after re-enabling decoder")
	}
	d.OnParity(parity)
	putFrame(parity)

	select {
	case seq := <-recovered:
		if seq != 8 {
			t.Fatalf("recovered seq=%d, want 8", seq)
		}
	default:
		t.Fatal("decoder did not recover after static bypass was disabled")
	}
}

func TestStaticSinglePathTopologyIsStrict(t *testing.T) {
	if !isStaticSinglePathTopology(1) {
		t.Fatal("configuredConns=1 must enable static single-path topology")
	}
	for _, n := range []int{0, 2, 4, 16} {
		if isStaticSinglePathTopology(n) {
			t.Fatalf("configuredConns=%d must not be treated as static single-path", n)
		}
	}
}
