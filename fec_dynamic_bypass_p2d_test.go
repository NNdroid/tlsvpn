package main

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

func dynamicFaultPayload(seq uint32) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint32(b[:4], seq)
	for i := 4; i < len(b); i++ {
		b[i] = byte(seq + uint32(i))
	}
	return b
}

func dynamicFaultBatch(seqs ...uint32) []VPNFrame {
	batch := make([]VPNFrame, len(seqs))
	for i, seq := range seqs {
		batch[i] = VPNFrame{Seq: seq, Data: cloneFrame(dynamicFaultPayload(seq))}
	}
	return batch
}

func drainDynamicBackend(ch chan []VPNFrame) [][]VPNFrame {
	var out [][]VPNFrame
	for {
		select {
		case batch := <-ch:
			out = append(out, batch)
		default:
			return out
		}
	}
}

func releaseDynamicBatchDescriptors(batch []VPNFrame) {
	// Payload ownership is transferred individually by the fault-injection feed.
	// Only return the descriptor container here.
	clear(batch)
	putVPNFrameBatch(batch)
}

func TestDynamicFECFaultTransition2To1To2(t *testing.T) {
	const k = 4

	// Sender side: use the real AsyncPort backend list, adaptive picker, encoder,
	// parity placement and same-batch control fencing. No network/socket mock is
	// involved in topology transition detection itself.
	p := &AsyncPort{
		encoder:       newFECEncoder(k, nil),
		parityScratch: make([][]byte, 0, 8),
	}
	rtt1, rtt2, rtt3 := uint32(10_000), uint32(12_000), uint32(11_000)
	ch1 := make(chan []VPNFrame, 32)
	ch2 := make(chan []VPNFrame, 32)
	b1 := p.RegisterBackend(ch1, &rtt1)
	_ = b1
	p.RegisterBackend(ch2, &rtt2)

	// Full group 1..4, then partial group 5..6 while two paths exist.
	p.dispatchBatch(dynamicFaultBatch(1, 2, 3, 4), 48)
	p.dispatchBatch(dynamicFaultBatch(5, 6), 24)

	// Physical path 2 disappears. Its already-queued data/parity stays available
	// below to model bytes that were already in flight when failure was detected.
	p.UnregisterBackend(ch2)
	p.dispatchBatch(dynamicFaultBatch(7, 8, 9, 10, 11, 12), 72)

	phase1Primary := drainDynamicBackend(ch1)
	phase1Failed := drainDynamicBackend(ch2)

	// Receiver side: normal ReorderBuffer + dynamic fecDecoder, including P2c
	// progress callback. Output payload starts with its original sequence number.
	var outMu sync.Mutex
	var delivered []uint32
	rb := NewReorderBuffer(func(frame []byte) {
		if len(frame) >= 4 {
			outMu.Lock()
			delivered = append(delivered, binary.BigEndian.Uint32(frame[:4]))
			outMu.Unlock()
		}
	})
	defer rb.Close()
	dec := NewFECDecoder(k, nil, rb.Insert)
	dec.SetReorderProgress(rb.ExpectedSeqSnapshot)

	var controls []fecModeControl
	var heldOldParity []byte
	feed := func(vf VPNFrame) {
		data := vf.Data
		vf.Data = nil
		if data == nil {
			return
		}
		if vf.Seq == 0 {
			if ctrl, ok := parseFECModeControl(data); ok {
				controls = append(controls, ctrl)
				dec.OnData(0, data)
				putFrame(data)
				return
			}
			if len(data) >= 7 && data[0] == fecMagic {
				start := binary.BigEndian.Uint32(data[1:5])
				if start == 1 && heldOldParity == nil {
					heldOldParity = data
					return
				}
				dec.OnParity(data)
				putFrame(data)
				return
			}
			putFrame(data)
			return
		}

		// Model one data record stranded on the failed physical stream. Its old
		// parity is deliberately delivered only after SUSPEND below.
		if vf.Seq == 3 {
			putFrame(data)
			return
		}
		dec.OnData(vf.Seq, data)
		rb.Insert(vf.Seq, data) // ReorderBuffer now owns the data buffer.
	}

	// Drain the surviving stream first so its SUSPEND can overtake old bytes from
	// the failed stream. Hold group-1 parity regardless of which stream carried it.
	for _, batch := range phase1Primary {
		for i := range batch {
			feed(batch[i])
			batch[i].Data = nil
		}
		releaseDynamicBatchDescriptors(batch)
	}
	for _, batch := range phase1Failed {
		for i := range batch {
			feed(batch[i])
			batch[i].Data = nil
		}
		releaseDynamicBatchDescriptors(batch)
	}

	if len(controls) != 1 || controls[0].Op != fecControlSuspend || controls[0].Generation != 1 || controls[0].Boundary != 5 {
		t.Fatalf("phase1 controls=%+v want SUSPEND gen=1 boundary=5", controls)
	}
	if heldOldParity == nil {
		t.Fatal("did not capture old group-1 parity for delayed delivery")
	}
	from, until := dec.fence.Window()
	if from != 5 || until != 0 {
		t.Fatalf("single-path RX window=%d..%d want=5..open", from, until)
	}

	// P2c must have removed the abandoned group 5..8, while group 1 remains
	// recoverable because reorder is still blocked at missing seq 3.
	groups := decoderGroupStarts(dec)
	if groups[5] {
		t.Fatalf("abandoned partial group survived SUSPEND: groups=%v", groups)
	}
	if !groups[1] {
		t.Fatalf("pre-boundary group retired before delayed parity: groups=%v", groups)
	}

	// Late old parity arrives after SUSPEND and must still recover seq 3. Recovery
	// advances reorder through all buffered single-path data, after which P2c can
	// retire the old boundary.
	dec.OnParity(heldOldParity)
	putFrame(heldOldParity)
	heldOldParity = nil
	if got := rb.ExpectedSeqSnapshot(); got != 13 {
		t.Fatalf("reorder expected after late recovery=%d want=13", got)
	}
	if got := dec.retiredBefore.Load(); got != 5 {
		t.Fatalf("retiredBefore=%d want=5 after reorder crossed SUSPEND", got)
	}
	if groups := decoderGroupStarts(dec); len(groups) != 0 {
		t.Fatalf("single-path interval retained decoder groups: %v", groups)
	}

	// Restore a second physical path. The first post-restore dispatch begins at a
	// complete K boundary (13), so generation 2 must RESUME at 13.
	ch3 := make(chan []VPNFrame, 32)
	p.RegisterBackend(ch3, &rtt3)
	p.dispatchBatch(dynamicFaultBatch(13, 14, 15, 16), 48)

	phase2Primary := drainDynamicBackend(ch1)
	phase2Restored := drainDynamicBackend(ch3)
	for _, batches := range [][][]VPNFrame{phase2Primary, phase2Restored} {
		for _, batch := range batches {
			for i := range batch {
				feed(batch[i])
				batch[i].Data = nil
			}
			releaseDynamicBatchDescriptors(batch)
		}
	}

	if len(controls) != 2 || controls[1].Op != fecControlResume || controls[1].Generation != 2 || controls[1].Boundary != 13 {
		t.Fatalf("phase2 controls=%+v want RESUME gen=2 boundary=13", controls)
	}
	from, until = dec.fence.Window()
	if from != 5 || until != 13 {
		t.Fatalf("resumed RX window=%d..%d want=5..13", from, until)
	}
	if dec.fence.BypassData(13) {
		t.Fatal("first resumed group is still bypassed")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		outMu.Lock()
		n := len(delivered)
		outMu.Unlock()
		if n >= 16 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	outMu.Lock()
	got := append([]uint32(nil), delivered...)
	outMu.Unlock()
	if len(got) != 16 {
		t.Fatalf("delivered %d frames, want 16: %v", len(got), got)
	}
	for i, seq := range got {
		want := uint32(i + 1)
		if seq != want {
			t.Fatalf("delivered[%d]=%d want=%d full=%v", i, seq, want, got)
		}
	}

	recovered, lost := dec.FECStats()
	if recovered != 1 {
		t.Fatalf("fecRecovered=%d want=1", recovered)
	}
	if lost != 0 {
		t.Fatalf("fecLost=%d want=0", lost)
	}
}