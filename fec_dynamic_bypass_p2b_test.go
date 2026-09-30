package main

import (
	"context"
	"encoding/binary"
	"testing"
)

func drainTestBatch(t *testing.T, ch chan []VPNFrame) []VPNFrame {
	t.Helper()
	select {
	case b := <-ch:
		return b
	default:
		t.Fatal("expected queued backend batch")
		return nil
	}
}

func releaseTestBatch(batch []VPNFrame) {
	freeFrames(batch)
	putVPNFrameBatch(batch)
}

func TestDynamicFECFencePrependedToActualDataBackend(t *testing.T) {
	p := &AsyncPort{encoder: newFECEncoder(4, nil)}
	p.encoder.publishModeControl(fecControlSuspend, 5)

	rtt1, rtt2 := uint32(10_000), uint32(20_000)
	b1 := &Backend{ch: make(chan []VPNFrame, 1), rttCache: &rtt1}
	b2 := &Backend{ch: make(chan []VPNFrame, 2), rttCache: &rtt2}

	// Fill the preferred backend. The sender must fall back to b2 and prepend the
	// fence to b2's actual data batch rather than losing the control on b1.
	dummy := getVPNFrameBatch(1)
	dummy[0] = VPNFrame{Seq: 99, Data: cloneFrame([]byte("dummy"))}
	b1.ch <- dummy

	batch := getVPNFrameBatch(1)
	batch[0] = VPNFrame{Seq: 5, Data: cloneFrame([]byte("payload"))}
	if dropped := sendBatchToAnyFenced(p, []*Backend{b1, b2}, b1, batch); dropped != 0 {
		t.Fatalf("dropped=%d want=0", dropped)
	}

	if got := b1.fecFenceGen.Load(); got != 0 {
		t.Fatalf("full backend incorrectly marked fenced generation=%d", got)
	}
	if got := b2.fecFenceGen.Load(); got != 1 {
		t.Fatalf("fallback backend fence generation=%d want=1", got)
	}

	out := drainTestBatch(t, b2.ch)
	defer releaseTestBatch(out)
	if len(out) != 2 || out[0].Seq != 0 || out[1].Seq != 5 {
		t.Fatalf("unexpected fenced batch: len=%d seqs=%v/%v", len(out), out[0].Seq, out[1].Seq)
	}
	ctrl, ok := parseFECModeControl(out[0].Data)
	if !ok || ctrl.Op != fecControlSuspend || ctrl.Boundary != 5 || ctrl.Generation != 1 {
		t.Fatalf("bad control: %+v ok=%v", ctrl, ok)
	}

	releaseTestBatch(<-b1.ch)
}

func TestDynamicFECFenceOnlyOncePerBackendGeneration(t *testing.T) {
	p := &AsyncPort{encoder: newFECEncoder(4, nil)}
	p.encoder.publishModeControl(fecControlResume, 9)
	rtt := uint32(10_000)
	b := &Backend{ch: make(chan []VPNFrame, 4), rttCache: &rtt}

	first := getVPNFrameBatch(1)
	first[0] = VPNFrame{Seq: 9, Data: cloneFrame([]byte("a"))}
	if dropped := sendBatchToAnyFenced(p, []*Backend{b}, b, first); dropped != 0 {
		t.Fatalf("first dropped=%d", dropped)
	}
	out1 := drainTestBatch(t, b.ch)
	if len(out1) != 2 || out1[0].Seq != 0 || out1[1].Seq != 9 {
		t.Fatalf("first batch missing fence: %+v", out1)
	}
	releaseTestBatch(out1)

	second := getVPNFrameBatch(1)
	second[0] = VPNFrame{Seq: 10, Data: cloneFrame([]byte("b"))}
	if dropped := sendBatchToAnyFenced(p, []*Backend{b}, b, second); dropped != 0 {
		t.Fatalf("second dropped=%d", dropped)
	}
	out2 := drainTestBatch(t, b.ch)
	defer releaseTestBatch(out2)
	if len(out2) != 1 || out2[0].Seq != 10 {
		t.Fatalf("duplicate fence emitted: len=%d seq=%d", len(out2), out2[0].Seq)
	}
}

func TestDynamicFECResetEpochClearsBackendFenceGeneration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := NewAsyncPort(ctx, "dynamic-fence-epoch-test")
	defer p.Close()

	rtt := uint32(10_000)
	ch := make(chan []VPNFrame, 1)
	b := p.RegisterBackend(ch, &rtt)
	defer p.UnregisterBackend(ch)
	b.fecFenceGen.Store(9)

	p.ResetEpoch(4, nil)
	if got := b.fecFenceGen.Load(); got != 0 {
		t.Fatalf("backend fence generation survived epoch reset: got=%d want=0", got)
	}
}

func TestDynamicFECEncoderPublishesSuspendAndResumeBoundaries(t *testing.T) {
	e := newFECEncoder(4, nil)

	// Build a partial 5..8 group under multipath.
	for seq := uint32(1); seq <= 6; seq++ {
		par := e.add(VPNFrame{Seq: seq, Data: []byte{byte(seq)}})
		if par != nil {
			putFrame(par)
		}
	}
	if len(e.seqs) != 2 || e.seqs[0] != 5 {
		t.Fatalf("partial group=%v want start=5", e.seqs)
	}

	e.setPhysicalPathCount(1)
	ctrl, ok := e.currentModeControl()
	if !ok || ctrl.Op != fecControlSuspend || ctrl.Boundary != 5 {
		t.Fatalf("suspend=%+v ok=%v want boundary=5", ctrl, ok)
	}

	// Single-path data must still advance lastSeq even though no XOR work occurs.
	if par := e.add(VPNFrame{Seq: 7, Data: []byte{7}}); par != nil {
		t.Fatal("single-path encoder unexpectedly emitted parity")
	}

	e.setPhysicalPathCount(2)
	ctrl, ok = e.currentModeControl()
	if !ok || ctrl.Op != fecControlResume || ctrl.Boundary != 9 || ctrl.Generation != 2 {
		t.Fatalf("resume=%+v ok=%v want gen=2 boundary=9", ctrl, ok)
	}
}

func TestDynamicRXDataBypassAndResume(t *testing.T) {
	dec := NewFECDecoder(4, nil, nil)

	suspend := appendFECModeControl(nil, fecModeControl{Generation: 1, Op: fecControlSuspend, Boundary: 5})
	dec.OnData(0, suspend)
	for seq := uint32(5); seq <= 8; seq++ {
		dec.OnData(seq, []byte{byte(seq)})
	}
	if got := len(dec.groups); got != 0 {
		t.Fatalf("bypass interval created %d decoder groups", got)
	}

	resume := appendFECModeControl(nil, fecModeControl{Generation: 2, Op: fecControlResume, Boundary: 9})
	dec.OnData(0, resume)
	dec.OnData(9, []byte{9})
	if got := len(dec.groups); got != 1 {
		t.Fatalf("resumed data groups=%d want=1", got)
	}
}

func TestDynamicRXStillAcceptsOldParityAfterSuspend(t *testing.T) {
	var recoveredSeq uint32
	var recovered []byte
	dec := NewFECDecoder(4, nil, func(seq uint32, frame []byte) {
		recoveredSeq = seq
		recovered = append(recovered[:0], frame...)
		putFrame(frame)
	})
	enc := newFECEncoder(4, nil)
	data := [][]byte{{1, 1}, {2, 2}, {3, 3}, {4, 4}}
	var parity []byte
	for i := range data {
		if p := enc.add(VPNFrame{Seq: uint32(i + 1), Data: data[i]}); p != nil {
			parity = p
		}
	}
	if parity == nil {
		t.Fatal("encoder did not produce parity")
	}
	defer putFrame(parity)

	dec.OnData(1, data[0])
	dec.OnData(2, data[1])
	dec.OnData(4, data[3])
	dec.OnData(0, appendFECModeControl(nil, fecModeControl{Generation: 1, Op: fecControlSuspend, Boundary: 5}))
	dec.OnParity(parity)
	if recoveredSeq != 3 || len(recovered) != 2 || recovered[0] != 3 || recovered[1] != 3 {
		t.Fatalf("old parity recovery seq=%d data=%v", recoveredSeq, recovered)
	}
}

func TestDynamicControlFrameHeaderUsesSeqZero(t *testing.T) {
	payload := appendFECModeControl(nil, fecModeControl{Generation: 7, Op: fecControlSuspend, Boundary: 13})
	buf, _ := appendUnpaddedFrame(nil, VPNFrame{Seq: 0, Data: payload}, nil)
	if got := binary.BigEndian.Uint32(buf[6:10]); got != 0 {
		t.Fatalf("control wire seq=%d want=0", got)
	}
}
