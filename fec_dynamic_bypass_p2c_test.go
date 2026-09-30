package main

import (
	"sync/atomic"
	"testing"
)

func testFECParity(t *testing.T, start uint32, k int) []byte {
	t.Helper()
	e := newFECEncoder(k, nil)
	var parity []byte
	for i := 0; i < k; i++ {
		seq := start + uint32(i)
		if p := e.add(VPNFrame{Seq: seq, Data: []byte{byte(seq), byte(seq >> 8)}}); p != nil {
			parity = p
		}
	}
	if parity == nil {
		t.Fatalf("no parity generated for start=%d k=%d", start, k)
	}
	return parity
}

func decoderGroupStarts(d *fecDecoder) map[uint32]bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make(map[uint32]bool, len(d.groups))
	for start := range d.groups {
		out[start] = true
	}
	return out
}

func TestDynamicFECSuspendDropsOnlyBypassGroups(t *testing.T) {
	var progress atomic.Uint32
	progress.Store(1)
	d := NewFECDecoder(4, nil, nil)
	d.SetReorderProgress(func() uint32 { return progress.Load() })

	// Two incomplete groups exist when the sender announces SUSPEND at group 5.
	d.OnData(1, []byte{1})
	d.OnData(2, []byte{2})
	d.OnData(5, []byte{5})
	d.OnData(6, []byte{6})

	before := decoderGroupStarts(d)
	if !before[1] || !before[5] {
		t.Fatalf("precondition groups=%v want starts 1 and 5", before)
	}

	d.OnData(0, appendFECModeControl(nil, fecModeControl{
		Generation: 1,
		Op:         fecControlSuspend,
		Boundary:   5,
	}))

	after := decoderGroupStarts(d)
	if !after[1] {
		t.Fatalf("pre-boundary recoverable group was discarded: groups=%v", after)
	}
	if after[5] {
		t.Fatalf("sender-abandoned bypass group survived SUSPEND: groups=%v", after)
	}
}

func TestDynamicFECResumeDropsParityOnlyBypassGroup(t *testing.T) {
	var progress atomic.Uint32
	progress.Store(1)
	d := NewFECDecoder(4, nil, nil)
	d.SetReorderProgress(func() uint32 { return progress.Load() })

	d.OnData(0, appendFECModeControl(nil, fecModeControl{
		Generation: 1,
		Op:         fecControlSuspend,
		Boundary:   5,
	}))

	parity5 := testFECParity(t, 5, 4)
	parity9 := testFECParity(t, 9, 4)
	defer putFrame(parity5)
	defer putFrame(parity9)

	// P2b deliberately keeps parity conservative. A parity-only group may be
	// created while data 5..8 is bypassed; group 9 is the first resumed group.
	d.OnParity(parity5)
	d.OnParity(parity9)
	before := decoderGroupStarts(d)
	if !before[5] || !before[9] {
		t.Fatalf("precondition groups=%v want parity-only starts 5 and 9", before)
	}

	d.OnData(0, appendFECModeControl(nil, fecModeControl{
		Generation: 2,
		Op:         fecControlResume,
		Boundary:   9,
	}))

	after := decoderGroupStarts(d)
	if after[5] {
		t.Fatalf("closed bypass interval group survived RESUME: groups=%v", after)
	}
	if !after[9] {
		t.Fatalf("valid resumed group was discarded: groups=%v", after)
	}
}

func TestDynamicFECOldGroupsRetireOnlyAfterReorderCrossesFence(t *testing.T) {
	var progress atomic.Uint32
	progress.Store(4)
	d := NewFECDecoder(4, nil, nil)
	d.SetReorderProgress(func() uint32 { return progress.Load() })

	d.OnData(1, []byte{1})
	d.OnData(2, []byte{2})
	d.OnData(0, appendFECModeControl(nil, fecModeControl{
		Generation: 1,
		Op:         fecControlSuspend,
		Boundary:   5,
	}))
	if !decoderGroupStarts(d)[1] {
		t.Fatal("old group retired before reorder reached the fence")
	}

	progress.Store(5)
	d.cleanupByReorderProgress()
	if groups := decoderGroupStarts(d); groups[1] {
		t.Fatalf("old group survived after reorder crossed fence: %v", groups)
	}
	if got := d.retiredBefore.Load(); got != 5 {
		t.Fatalf("retiredBefore=%d want=5", got)
	}

	// Very late old data/parity must not recreate state that can no longer affect
	// ordered output.
	d.OnData(1, []byte{1})
	parity1 := testFECParity(t, 1, 4)
	defer putFrame(parity1)
	d.OnParity(parity1)
	if groups := decoderGroupStarts(d); len(groups) != 0 {
		t.Fatalf("retired old traffic recreated decoder groups: %v", groups)
	}
}

func TestDynamicFECBypassProgressCheckIsSparse(t *testing.T) {
	var progress atomic.Uint32
	var calls atomic.Uint32
	progress.Store(1)
	d := NewFECDecoder(4, nil, nil)
	d.SetReorderProgress(func() uint32 {
		calls.Add(1)
		return progress.Load()
	})

	d.OnData(0, appendFECModeControl(nil, fecModeControl{
		Generation: 1,
		Op:         fecControlSuspend,
		Boundary:   5,
	}))
	base := calls.Load()
	if base == 0 {
		t.Fatal("control path did not perform initial reorder cleanup check")
	}

	for seq := uint32(5); seq < 256; seq++ {
		d.OnData(seq, []byte{1})
	}
	if got := calls.Load(); got != base {
		t.Fatalf("bypassed data polled reorder on the hot path: calls=%d base=%d", got, base)
	}

	d.OnData(256, []byte{1})
	if got := calls.Load(); got != base+1 {
		t.Fatalf("sparse cleanup probe calls=%d want=%d", got, base+1)
	}
}

func TestReorderExpectedSeqSnapshot(t *testing.T) {
	rb := NewReorderBuffer(func([]byte) {})
	defer rb.Close()
	if got := rb.ExpectedSeqSnapshot(); got != 0 {
		t.Fatalf("initial expected seq=%d want=0", got)
	}
	rb.Insert(1, []byte{1})
	if got := rb.ExpectedSeqSnapshot(); got != 2 {
		t.Fatalf("expected seq after in-order insert=%d want=2", got)
	}
}
