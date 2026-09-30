package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"
)

func fecParityStart(t *testing.T, parity []byte) uint32 {
	t.Helper()
	if len(parity) < 6 || parity[0] != controlKindFECParity {
		t.Fatalf("invalid FEC parity payload: len=%d", len(parity))
	}
	return binary.BigEndian.Uint32(parity[1:5])
}

func TestFECEncoderSinglePathBypassDoesNoWork(t *testing.T) {
	e := newFECEncoder(4, nil)
	e.setPhysicalPathCount(1)

	payload := bytes.Repeat([]byte{0x5a}, 1400)
	for seq := uint32(1); seq <= 64; seq++ {
		if par := e.add(VPNFrame{Seq: seq, Data: payload}); par != nil {
			putFrame(par)
			t.Fatalf("single-path encoder emitted parity at seq=%d", seq)
		}
	}

	if got := e.ParitySent(); got != 0 {
		t.Fatalf("single-path encoder built %d parity frames, want 0", got)
	}
	if len(e.seqs) != 0 || len(e.lens) != 0 || e.activeLen != 0 {
		t.Fatalf("single-path encoder retained FEC work: seqs=%d lens=%d activeLen=%d", len(e.seqs), len(e.lens), e.activeLen)
	}
}

func TestFECEncoderResumesOnlyAtNextFullGroupBoundary(t *testing.T) {
	e := newFECEncoder(4, nil)
	payload := bytes.Repeat([]byte{0x33}, 512)

	// seq 1-2 were sent while only one physical path existed.
	e.setPhysicalPathCount(1)
	for seq := uint32(1); seq <= 2; seq++ {
		if par := e.add(VPNFrame{Seq: seq, Data: payload}); par != nil {
			putFrame(par)
			t.Fatalf("single-path encoder emitted parity at seq=%d", seq)
		}
	}

	// A second path appears in the middle of the arithmetic group [1..4].
	// seq 3-4 must stay unprotected; the first valid new group is [5..8].
	e.setPhysicalPathCount(2)
	for seq := uint32(3); seq <= 4; seq++ {
		if par := e.add(VPNFrame{Seq: seq, Data: payload}); par != nil {
			putFrame(par)
			t.Fatalf("encoder resumed inside partial group at seq=%d", seq)
		}
	}
	if len(e.seqs) != 0 || e.activeLen != 0 {
		t.Fatalf("partial boundary wait accumulated FEC state: seqs=%d activeLen=%d", len(e.seqs), e.activeLen)
	}

	var parity []byte
	for seq := uint32(5); seq <= 8; seq++ {
		if par := e.add(VPNFrame{Seq: seq, Data: payload}); par != nil {
			parity = par
		}
	}
	if parity == nil {
		t.Fatal("full group after multipath recovery did not emit parity")
	}
	defer putFrame(parity)
	if start := fecParityStart(t, parity); start != 5 {
		t.Fatalf("resumed parity group start=%d, want 5", start)
	}
}

func TestFECEncoderDropsPartialGroupWhenPathCountCollapses(t *testing.T) {
	e := newFECEncoder(4, nil)
	payload := bytes.Repeat([]byte{0x77}, 700)

	// Start a multipath group but lose the second path before the group is full.
	for seq := uint32(1); seq <= 2; seq++ {
		if par := e.add(VPNFrame{Seq: seq, Data: payload}); par != nil {
			putFrame(par)
			t.Fatalf("partial group emitted parity at seq=%d", seq)
		}
	}
	if len(e.seqs) != 2 {
		t.Fatalf("precondition: partial group members=%d, want 2", len(e.seqs))
	}

	e.setPhysicalPathCount(1)
	if len(e.seqs) != 0 || len(e.lens) != 0 || e.activeLen != 0 {
		t.Fatalf("path collapse did not discard partial group: seqs=%d lens=%d activeLen=%d", len(e.seqs), len(e.lens), e.activeLen)
	}
	for seq := uint32(3); seq <= 6; seq++ {
		if par := e.add(VPNFrame{Seq: seq, Data: payload}); par != nil {
			putFrame(par)
			t.Fatalf("single-path interval emitted parity at seq=%d", seq)
		}
	}

	// Multipath returns at seq 7, still inside [5..8], so the encoder must wait
	// for the next complete arithmetic group [9..12].
	e.setPhysicalPathCount(2)
	for seq := uint32(7); seq <= 8; seq++ {
		if par := e.add(VPNFrame{Seq: seq, Data: payload}); par != nil {
			putFrame(par)
			t.Fatalf("encoder resumed before the next full boundary at seq=%d", seq)
		}
	}
	var parity []byte
	for seq := uint32(9); seq <= 12; seq++ {
		if par := e.add(VPNFrame{Seq: seq, Data: payload}); par != nil {
			parity = par
		}
	}
	if parity == nil {
		t.Fatal("encoder did not resume after path flap")
	}
	defer putFrame(parity)
	if start := fecParityStart(t, parity); start != 9 {
		t.Fatalf("post-flap parity group start=%d, want 9", start)
	}
}

func TestAsyncPortSinglePathDoesNotBuildDiscardedParity(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	p := NewAsyncPort(ctx, "fec-single-path-fast-bypass")
	p.AttachFEC(2, nil)

	rtt0 := uint32(1000)
	ch0 := make(chan []VPNFrame, 16)
	p.RegisterBackend(ch0, &rtt0)
	defer p.UnregisterBackend(ch0)

	for i := 0; i < 8; i++ {
		if err := p.WriteFrame(bytes.Repeat([]byte{byte(i + 1)}, 1400)); err != nil {
			t.Fatal(err)
		}
	}

	dataFrames := 0
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) && dataFrames < 8 {
		select {
		case batch := <-ch0:
			for _, vf := range batch {
				if vf.Seq == 0 {
					freeFrames(batch)
					putVPNFrameBatch(batch)
					t.Fatal("single physical path transmitted parity")
				}
				dataFrames++
			}
			freeFrames(batch)
			putVPNFrameBatch(batch)
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if dataFrames != 8 {
		t.Fatalf("single-path data frames=%d, want 8", dataFrames)
	}
	if got := p.encoder.ParitySent(); got != 0 {
		t.Fatalf("single-path dispatch built and discarded %d parity frames, want 0", got)
	}

	// seq 9 is a K=2 boundary. Once a second physical backend is registered,
	// normal FEC should resume immediately and produce exactly one parity for 9-10.
	rtt1 := uint32(2000)
	ch1 := make(chan []VPNFrame, 16)
	p.RegisterBackend(ch1, &rtt1)
	defer p.UnregisterBackend(ch1)
	for i := 0; i < 2; i++ {
		if err := p.WriteFrame(bytes.Repeat([]byte{byte(0x40 + i)}, 1400)); err != nil {
			t.Fatal(err)
		}
	}

	parityFrames := 0
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) && parityFrames == 0 {
		for _, ch := range []chan []VPNFrame{ch0, ch1} {
			for {
				select {
				case batch := <-ch:
					for _, vf := range batch {
						if vf.Seq == 0 {
							parityFrames++
						}
					}
					freeFrames(batch)
					putVPNFrameBatch(batch)
				default:
					goto nextBackend
				}
			}
		nextBackend:
		}
		if parityFrames == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	if parityFrames != 1 {
		t.Fatalf("multipath recovery parity frames=%d, want 1", parityFrames)
	}
	if got := p.encoder.ParitySent(); got != 1 {
		t.Fatalf("encoder generated parity count=%d, want 1 after recovery", got)
	}
}
