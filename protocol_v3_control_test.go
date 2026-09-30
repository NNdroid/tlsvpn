package main

import (
	"encoding/hex"
	"testing"
)

func TestProtocolV3VersionAndControlKinds(t *testing.T) {
	if protocolVersion != 3 {
		t.Fatalf("protocolVersion=%d want=3", protocolVersion)
	}
	for _, kind := range []byte{controlKindFECParity, controlKindFECMode} {
		got, err := parseControlKind([]byte{kind})
		if err != nil || got != kind {
			t.Fatalf("kind=0x%02x got=0x%02x err=%v", kind, got, err)
		}
	}
	if _, err := parseControlKind([]byte{0x7f}); err == nil {
		t.Fatal("unknown v3 control kind was accepted")
	}
	if _, err := parseControlKind(nil); err == nil {
		t.Fatal("empty keepalive payload was accepted as typed control")
	}
}

func TestProtocolV3FECModeWireLayout(t *testing.T) {
	payload := appendFECModeControl(nil, fecModeControl{
		Generation: 0x0102030405060708,
		Op:         fecControlSuspend,
		Boundary:   9,
	})
	const want = "02010000010203040506070800000009"
	if got := hex.EncodeToString(payload); got != want {
		t.Fatalf("FEC_MODE payload=%s want=%s", got, want)
	}
	ctrl, ok := parseFECModeControl(payload)
	if !ok || ctrl.Generation != 0x0102030405060708 || ctrl.Op != fecControlSuspend || ctrl.Boundary != 9 {
		t.Fatalf("decoded control=%+v ok=%v", ctrl, ok)
	}
}

func TestProtocolV3DecoderRejectsUnknownOrMalformedControls(t *testing.T) {
	d := NewFECDecoder(4, nil, nil)
	if err := d.OnControl([]byte{0x7f, 1, 2, 3}); err == nil {
		t.Fatal("unknown typed control was silently ignored")
	}
	bad := appendFECModeControl(nil, fecModeControl{Generation: 1, Op: fecControlSuspend, Boundary: 5})
	bad[2] = 1 // flags are reserved and MUST be zero in v3.
	if err := d.OnControl(bad); err == nil {
		t.Fatal("malformed FEC_MODE was silently ignored")
	}
}

func TestProtocolV3ParityUsesTypedControlKind(t *testing.T) {
	e := newFECEncoder(2, nil)
	if p := e.add(VPNFrame{Seq: 1, Data: []byte{1, 2}}); p != nil {
		putFrame(p)
		t.Fatal("unexpected early parity")
	}
	p := e.add(VPNFrame{Seq: 2, Data: []byte{3, 4}})
	if p == nil {
		t.Fatal("missing parity")
	}
	defer putFrame(p)
	if p[0] != controlKindFECParity {
		t.Fatalf("parity kind=0x%02x want=0x%02x", p[0], controlKindFECParity)
	}
	if err := NewFECDecoder(2, nil, nil).OnControl(p); err != nil {
		t.Fatalf("valid FEC_PARITY control rejected: %v", err)
	}
}
