package main

import (
	"context"
	"testing"
)

type discardTapWriter struct{}

func (discardTapWriter) Write(p []byte) (int, error) { return len(p), nil }

func BenchmarkOwnedTapDelivery(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := newOwnedTapDelivery(ctx, discardTapWriter{}, asyncTapDeliveryQueue, nil)
	payload := make([]byte, 1500)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		frame := getFrameAtLeast(len(payload))[:len(payload)]
		copy(frame, payload)
		d.EnqueueOwned(frame)
	}
}
