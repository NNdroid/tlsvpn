package main

import "testing"

func TestFECParitySchedulerTelemetry(t *testing.T) {
	b := &Backend{ch: make(chan []VPNFrame, 1)}
	payload := []byte{1, 2, 3, 4, 5}
	if dropped := sendOwnedFrameTo(b, VPNFrame{Seq: 0, Data: payload}); dropped != 0 {
		t.Fatalf("sendOwnedFrameTo dropped=%d, want 0", dropped)
	}
	s := schedulerSnapshot(b)
	if s.AssignedBytes != 0 || s.AssignedBatches != 0 {
		t.Fatalf("data counters changed for FEC parity: bytes=%d batches=%d", s.AssignedBytes, s.AssignedBatches)
	}
	if s.FECAssignedBytes != uint64(len(payload)) || s.FECAssignedBatches != 1 {
		t.Fatalf("FEC telemetry bytes/batches=%d/%d, want %d/1", s.FECAssignedBytes, s.FECAssignedBatches, len(payload))
	}
}
