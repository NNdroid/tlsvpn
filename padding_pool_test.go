package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestPaddedFrameUsesRandomPool(t *testing.T) {
	oldMode := padModeName()
	defer setPadMode(oldMode)
	setPadMode(padModeBucket)

	payload := bytes.Repeat([]byte{0x5a}, 73)
	out, padLen := appendPaddedFrame(make([]byte, 0, 256), VPNFrame{Seq: 1, Data: payload}, nil)
	if padLen <= 0 {
		t.Fatal("bucket mode produced no padding")
	}
	if got := int(binary.BigEndian.Uint16(out[4:6])); got != padLen {
		t.Fatalf("header padLen=%d, returned=%d", got, padLen)
	}
	if got := int(binary.BigEndian.Uint32(out[0:4])); got != len(payload) {
		t.Fatalf("dataLen=%d, want %d", got, len(payload))
	}

	pad := out[10+len(payload):]
	if len(pad) != padLen {
		t.Fatalf("padding bytes=%d, want %d", len(pad), padLen)
	}
	// Production padding is copied from the process-wide 1 MiB random pool.
	// Any generated padding slice must therefore occur somewhere in that pool.
	if !bytes.Contains(randomPool, pad) {
		t.Fatal("padding was not sourced from randomPool")
	}
}

func TestPaddedFramePaddingOutsidePayload(t *testing.T) {
	oldMode := padModeName()
	defer setPadMode(oldMode)
	setPadMode(padModeBucket)

	payload := []byte("payload-boundary-check")
	out, padLen := appendPaddedFrame(nil, VPNFrame{Seq: 7, Data: payload}, nil)
	dataLen := int(binary.BigEndian.Uint32(out[:4]))
	if dataLen != len(payload) {
		t.Fatalf("dataLen includes padding: got %d want %d", dataLen, len(payload))
	}
	if !bytes.Equal(out[10:10+dataLen], payload) {
		t.Fatal("payload changed while appending padding")
	}
	if len(out) != 10+dataLen+padLen {
		t.Fatalf("wire length=%d want %d", len(out), 10+dataLen+padLen)
	}
}

func BenchmarkAppendPaddedFramePool(b *testing.B) {
	oldMode := padModeName()
	defer setPadMode(oldMode)
	setPadMode(padModeBucket)

	payload := bytes.Repeat([]byte{0x42}, 1400)
	vf := VPNFrame{Seq: 1, Data: payload}
	buf := make([]byte, 0, 2048)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf = buf[:0]
		var pad int
		buf, pad = appendPaddedFrame(buf, vf, nil)
		if pad == 0 {
			b.Fatal("expected bucket padding")
		}
	}
}

func BenchmarkAppendPaddedFramePoolParallel(b *testing.B) {
	oldMode := padModeName()
	defer setPadMode(oldMode)
	setPadMode(padModeBucket)

	payload := bytes.Repeat([]byte{0x42}, 1400)
	vf := VPNFrame{Seq: 1, Data: payload}
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		buf := make([]byte, 0, 2048)
		for pb.Next() {
			buf = buf[:0]
			buf, _ = appendPaddedFrame(buf, vf, nil)
		}
	})
}
