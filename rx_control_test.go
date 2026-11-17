package main

import (
	"context"
	"testing"
)

// spySink 记录 applyPeerActiveBitmap 调用次数与最后位图。
type spySink struct {
	calls  int
	bitmap uint16
}

func (s *spySink) applyPeerActiveBitmap(bitmap uint16) {
	s.calls++
	s.bitmap = bitmap
}

// TestDispatchControlFrame 控制平面分流器的完整行为契约：
// kind 精确认领、畸形/未协商不认领（fail-closed）、位图回调语义、以及
// 0x01/0x02（FEC 管线）不在此认领。
func withKind(frame []byte, kind byte) []byte {
	frame[0] = kind
	return frame
}

func TestDispatchControlFrame(t *testing.T) {
	sink := &spySink{}
	rtt := newRttProbeScheduler(context.Background(),
		func(int) *Backend { return nil }, func() []int { return nil }, nil)
	clock := newClockOffsetScheduler(context.Background(),
		func(int) *Backend { return nil }, func() []int { return nil })

	cases := []struct {
		name    string
		frame   []byte
		rtt     *rttProbeScheduler
		clock   *clockOffsetScheduler
		want    bool
		wantBM  uint16
		wantCap bool // 期望位图回调被调用
	}{
		{"0x07 valid bitmap", appendActivePathsFrame(nil, 0b101), nil, nil, true, 0b101, true},
		{"0x07 zero bitmap claimed silently", appendActivePathsFrame(nil, 0), nil, nil, true, 0, false},
		{"0x07 short not claimed", appendActivePathsFrame(nil, 1)[:activePathsWireLen-1], nil, nil, false, 0, false},
		{"0x07 long not claimed", append(appendActivePathsFrame(nil, 1), 0), nil, nil, false, 0, false},
		{"0x03 probe with plane", appendRttProbeFrame(nil, 7, 0), rtt, nil, true, 0, false},
		{"0x04 reply with plane", withKind(appendRttProbeFrame(nil, 7, 0), controlKindRttReply), rtt, nil, true, 0, false},
		{"0x03 without plane not claimed", appendRttProbeFrame(nil, 7, 0), nil, nil, false, 0, false},
		{"0x03 malformed not claimed", appendRttProbeFrame(nil, 7, 0)[:rttProbeWireLen-1], rtt, nil, false, 0, false},
		{"0x05 clock with plane", appendClockOffsetProbeFrame(nil, 9, 0), nil, clock, true, 0, false},
		{"0x05 without clock not claimed", appendClockOffsetProbeFrame(nil, 9, 0), nil, nil, false, 0, false},
		{"0x01 parity belongs to FEC pipeline", []byte{controlKindFECParity, 0, 0, 0, 0, 0}, nil, nil, false, 0, false},
		{"0x02 fec mode belongs to FEC pipeline", []byte{controlKindFECMode, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, nil, nil, false, 0, false},
		{"unknown kind 0x7f not claimed", []byte{0x7f, 0, 0}, nil, nil, false, 0, false},
		{"empty frame not claimed", nil, rtt, clock, false, 0, false},
	}
	for _, tc := range cases {
		got := dispatchControlFrame(tc.frame, 3, tc.rtt, tc.clock, sink)
		if got != tc.want {
			t.Errorf("%s: claimed=%v want %v", tc.name, got, tc.want)
		}
		if sink.calls > 0 {
			if !tc.wantCap {
				t.Errorf("%s: unexpected bitmap callback (bm=%d)", tc.name, sink.bitmap)
			} else if sink.bitmap != tc.wantBM {
				t.Errorf("%s: bitmap=%d want %d", tc.name, sink.bitmap, tc.wantBM)
			}
		}
		// 每个用例重置 spy
		sink.calls, sink.bitmap = 0, 0
	}
}
