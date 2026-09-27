package main

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func TestOwnedReorderDoesNotReturnDeliveredFrameToPool(t *testing.T) {
	oldProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(oldProcs)

	delivered := make(chan []byte, 1)
	rb := NewOwnedReorderBuffer(func(frame []byte) {
		delivered <- frame
	})
	defer rb.Close()

	frame := getFrame()[:64]
	frame[0] = 0x5a
	ptr := &frame[0]
	rb.Insert(1, frame)

	var owned []byte
	select {
	case owned = <-delivered:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for owned reorder delivery")
	}
	if &owned[0] != ptr {
		t.Fatal("owned reorder copied the frame")
	}

	held := make([][]byte, 0, 512)
	found := false
	for i := 0; i < cap(held); i++ {
		probe := getFrame()
		held = append(held, probe)
		if &probe[0] == ptr {
			found = true
			break
		}
	}
	for _, probe := range held {
		putFrame(probe)
	}
	if found {
		t.Fatal("owned reorder returned a delivered frame to the pool")
	}
	putFrame(owned)
}

func TestVSwitchOwnedSessionUnicastTransfersAndValidatesMAC(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	vs := NewVSwitch()
	src := NewAsyncPort(ctx, "owned-session-src")
	dst := NewAsyncPort(ctx, "owned-session-dst")
	vs.AddPort(src)
	vs.AddPort(dst)
	defer vs.RemovePort(src.ID())
	defer vs.RemovePort(dst.ID())

	rtt := uint32(1)
	dstCh := make(chan []VPNFrame, 4)
	dst.RegisterBackend(dstCh, &rtt)
	defer dst.UnregisterBackend(dstCh)

	srcMAC := macKey{0x02, 0, 0, 0, 0, 0x11}
	dstMAC := macKey{0x02, 0, 0, 0, 0, 0x22}
	vs.AddStaticMAC(src.ID(), srcMAC)
	vs.AddStaticMAC(dst.ID(), dstMAC)

	frame := getFrameAtLeast(1400)[:1400]
	copy(frame[0:6], dstMAC[:])
	copy(frame[6:12], srcMAC[:])
	ptr := &frame[0]
	vs.ProcessOwnedSessionFrame(src.ID(), srcMAC, frame)

	select {
	case batch := <-dstCh:
		if len(batch) != 1 || len(batch[0].Data) != 1400 {
			t.Fatalf("unexpected owned session batch: %+v", batch)
		}
		if &batch[0].Data[0] != ptr {
			t.Fatal("owned session unicast copied payload before AsyncPort delivery")
		}
		freeFrames(batch)
		putVPNFrameBatch(batch)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for owned session frame")
	}

	before := vs.spoofDrops.Load()
	spoof := getFrameAtLeast(64)[:64]
	copy(spoof[0:6], dstMAC[:])
	copy(spoof[6:12], []byte{0x02, 0, 0, 0, 0, 0x99})
	vs.ProcessOwnedSessionFrame(src.ID(), srcMAC, spoof)
	if got := vs.spoofDrops.Load(); got != before+1 {
		t.Fatalf("spoof drop counter=%d, want %d", got, before+1)
	}
	select {
	case batch := <-dstCh:
		freeFrames(batch)
		putVPNFrameBatch(batch)
		t.Fatal("spoofed owned session frame reached destination")
	default:
	}
}
