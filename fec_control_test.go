package main

import (
	"bytes"
	"sync"
	"testing"
)

func TestFECModeControlCodec(t *testing.T) {
	want := fecModeControl{Generation: 42, Op: fecControlSuspend, Boundary: 101}
	buf := appendFECModeControl(nil, want)
	if len(buf) != fecControlWireLen {
		t.Fatalf("wire len=%d want=%d", len(buf), fecControlWireLen)
	}
	got, ok := parseFECModeControl(buf)
	if !ok || got != want {
		t.Fatalf("decode=%+v ok=%v want=%+v", got, ok, want)
	}

	bad := append([]byte(nil), buf...)
	bad[0] = 0
	if _, ok := parseFECModeControl(bad); ok {
		t.Fatal("accepted bad magic")
	}
	bad = append([]byte(nil), buf...)
	bad[3] = 1
	if _, ok := parseFECModeControl(bad); ok {
		t.Fatal("accepted non-zero reserved byte")
	}
	if _, ok := parseFECModeControl(buf[:len(buf)-1]); ok {
		t.Fatal("accepted truncated control")
	}
}

func TestFECFenceBoundaries(t *testing.T) {
	const k = 4
	cases := []struct {
		seq       uint32
		group     uint32
		nextGroup uint32
	}{
		{1, 1, 1},
		{2, 1, 5},
		{3, 1, 5},
		{4, 1, 5},
		{5, 5, 5},
		{6, 5, 9},
		{7, 5, 9},
		{8, 5, 9},
		{9, 9, 9},
	}
	for _, tc := range cases {
		if got := fecGroupStart(tc.seq, k); got != tc.group {
			t.Errorf("groupStart(%d)=%d want=%d", tc.seq, got, tc.group)
		}
		if got := fecNextGroupStart(tc.seq, k); got != tc.nextGroup {
			t.Errorf("nextGroupStart(%d)=%d want=%d", tc.seq, got, tc.nextGroup)
		}
	}
}

func TestFECFenceResumeBoundaryDoesNotWrapEpoch(t *testing.T) {
	const maxSeq = ^uint32(0)
	// K=4 boundaries are 1 mod 4. maxSeq is 3 mod 4, so no complete group
	// boundary remains after maxSeq-1 or maxSeq in this sequence epoch.
	for _, seq := range []uint32{maxSeq - 1, maxSeq} {
		if got := fecNextGroupStart(seq, 4); got != 0 {
			t.Fatalf("nextGroupStart(%d)=0x%x want 0 (epoch exhausted)", seq, got)
		}
	}
}

func TestFECFenceSuspendRewindsPartialGroup(t *testing.T) {
	// K=4, seq 5/6 may have been sent while two paths existed, but if collapse
	// is observed at seq 7 the encoder discards that partial group. Therefore
	// the receiver may bypass the whole 5.. interval, not merely seq >= 7.
	boundary := fecGroupStart(7, 4)
	if boundary != 5 {
		t.Fatalf("boundary=%d want=5", boundary)
	}
	var s fecRXFenceState
	if !s.Apply(fecModeControl{Generation: 1, Op: fecControlSuspend, Boundary: boundary}) {
		t.Fatal("suspend not applied")
	}
	for _, seq := range []uint32{1, 4} {
		if s.BypassData(seq) {
			t.Fatalf("old recoverable seq %d bypassed", seq)
		}
	}
	for _, seq := range []uint32{5, 6, 7, 100} {
		if !s.BypassData(seq) {
			t.Fatalf("seq %d not bypassed", seq)
		}
	}
	if s.BypassParity(1) {
		t.Fatal("old group parity must remain recoverable")
	}
	if !s.BypassParity(5) {
		t.Fatal("unrecoverable partial/new group parity should be bypassed")
	}
}

func TestFECFenceResumeKeepsGapBypassedUntilBoundary(t *testing.T) {
	var s fecRXFenceState
	s.Apply(fecModeControl{Generation: 10, Op: fecControlSuspend, Boundary: 5})
	if !s.Apply(fecModeControl{Generation: 11, Op: fecControlResume, Boundary: 9}) {
		t.Fatal("resume not applied")
	}
	from, until := s.Window()
	if from != 5 || until != 9 {
		t.Fatalf("window=%d..%d want=5..9", from, until)
	}
	for _, seq := range []uint32{5, 6, 7, 8} {
		if !s.BypassData(seq) {
			t.Fatalf("single-path seq %d not bypassed", seq)
		}
	}
	for _, seq := range []uint32{1, 4, 9, 10, 12} {
		if s.BypassData(seq) {
			t.Fatalf("seq %d incorrectly bypassed", seq)
		}
	}
	if s.BypassParity(1) {
		t.Fatal("old parity incorrectly bypassed")
	}
	if !s.BypassParity(5) {
		t.Fatal("single-path interval parity not bypassed")
	}
	if s.BypassParity(9) {
		t.Fatal("resumed parity incorrectly bypassed")
	}
}

func TestFECFenceStaleSuspendCannotOverrideNewerResume(t *testing.T) {
	var s fecRXFenceState
	// The receiver can see generation 11 first on a newly joined/fast stream.
	if !s.Apply(fecModeControl{Generation: 11, Op: fecControlResume, Boundary: 9}) {
		t.Fatal("newer resume not applied")
	}
	if s.Apply(fecModeControl{Generation: 10, Op: fecControlSuspend, Boundary: 5}) {
		t.Fatal("stale suspend was applied")
	}
	if from, until := s.Window(); from != 0 || until != 0 {
		t.Fatalf("stale suspend changed conservative active state: %d..%d", from, until)
	}
	if s.Generation() != 11 {
		t.Fatalf("generation=%d want=11", s.Generation())
	}
}

func TestFECFenceRapidTransitionsNeverRegressGeneration(t *testing.T) {
	var s fecRXFenceState
	controls := []fecModeControl{
		{Generation: 1, Op: fecControlSuspend, Boundary: 5},
		{Generation: 2, Op: fecControlResume, Boundary: 9},
		{Generation: 3, Op: fecControlSuspend, Boundary: 13},
		{Generation: 4, Op: fecControlResume, Boundary: 17},
	}
	for _, c := range controls {
		if !s.Apply(c) {
			t.Fatalf("control %+v not applied", c)
		}
	}
	if s.Apply(controls[1]) {
		t.Fatal("old duplicate transition applied")
	}
	if s.Generation() != 4 {
		t.Fatalf("generation=%d want=4", s.Generation())
	}
	from, until := s.Window()
	if from != 13 || until != 17 {
		t.Fatalf("latest window=%d..%d want=13..17", from, until)
	}
}

func TestFECFenceConcurrentControlApplication(t *testing.T) {
	var s fecRXFenceState
	controls := []fecModeControl{
		{Generation: 10, Op: fecControlSuspend, Boundary: 41},
		{Generation: 11, Op: fecControlResume, Boundary: 45},
		{Generation: 12, Op: fecControlSuspend, Boundary: 49},
		{Generation: 13, Op: fecControlResume, Boundary: 53},
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, c := range controls {
		c := c
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 100; i++ {
				s.Apply(c)
				_ = s.BypassData(c.Boundary)
				_ = s.BypassParity(c.Boundary)
			}
		}()
	}
	close(start)
	wg.Wait()
	if s.Generation() != 13 {
		t.Fatalf("generation=%d want=13", s.Generation())
	}
}

func TestFECControlDoesNotCollideWithParityMagic(t *testing.T) {
	control := appendFECModeControl(nil, fecModeControl{Generation: 1, Op: fecControlSuspend, Boundary: 5})
	if len(control) == 0 || control[0] == controlKindFECParity {
		t.Fatal("control magic collides with parity magic")
	}
	if bytes.Equal(control, []byte{controlKindFECParity}) {
		t.Fatal("impossible parity/control alias")
	}
}
