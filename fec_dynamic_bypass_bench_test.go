package main

import "testing"

func BenchmarkDynamicFECDecoderDataPath(b *testing.B) {
	frame := make([]byte, 1400)
	for i := range frame {
		frame[i] = byte(i)
	}

	b.Run("active", func(b *testing.B) {
		d := NewFECDecoder(4, nil, nil)
		b.ReportAllocs()
		b.SetBytes(int64(len(frame)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			d.OnData(uint32(i)+1, frame)
		}
	})

	b.Run("dynamic-bypass", func(b *testing.B) {
		d := NewFECDecoder(4, nil, nil)
		if err := d.OnControl(appendFECModeControl(nil, fecModeControl{
			Generation: 1,
			Op:         fecControlSuspend,
			Boundary:   1,
		})); err != nil {
			b.Fatalf("apply FEC_MODE control: %v", err)
		}
		b.ReportAllocs()
		b.SetBytes(int64(len(frame)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			d.OnData(uint32(i)+1, frame)
		}
	})

	b.Run("static-single", func(b *testing.B) {
		d := NewFECDecoder(4, nil, nil)
		d.SetStaticSinglePath(true)
		b.ReportAllocs()
		b.SetBytes(int64(len(frame)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			d.OnData(uint32(i)+1, frame)
		}
	})
}
