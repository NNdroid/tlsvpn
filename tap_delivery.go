package main

import (
	"context"
	"io"
)

// asyncTapDeliveryQueue is deliberately much smaller than the initial experiment's
// 1024-frame queue. 128 Ethernet frames are enough to overlap short TAP write
// stalls without retaining ~1.5 MiB of packet buffers or adding a large latency
// reservoir in front of the kernel device. The repeated real-TAP validation
// below is intended to verify this smaller queue on the final integrated code.
const asyncTapDeliveryQueue = 128

// ownedTapDelivery decouples the receive/reorder hot path from the blocking TAP
// write syscall. EnqueueOwned takes ownership of a pooled frame and a single
// worker writes frames in FIFO order, preserving Ethernet packet ordering.
//
// The queue is bounded. When it fills, the producer blocks and applies
// backpressure instead of adding packet loss. The client only enables this path for a
// single physical connection; multipath keeps the direct TAP path because the
// real-TAP matrix showed scheduler/channel overhead there outweighed the
// overlap benefit.
type ownedTapDelivery struct {
	ctx        context.Context
	writer     io.Writer
	ch         chan []byte
	onWriteErr func(error)
}

func newOwnedTapDelivery(ctx context.Context, writer io.Writer, queue int, onWriteErr func(error)) *ownedTapDelivery {
	if queue < 1 {
		queue = 1
	}
	d := &ownedTapDelivery{
		ctx:        ctx,
		writer:     writer,
		ch:         make(chan []byte, queue),
		onWriteErr: onWriteErr,
	}
	go d.run()
	return d
}

// EnqueueOwned permanently takes ownership of frame. It either hands it to the
// FIFO worker or, during shutdown, returns the buffer to the frame pool.
func (d *ownedTapDelivery) EnqueueOwned(frame []byte) {
	if frame == nil {
		return
	}
	select {
	case d.ch <- frame:
	case <-d.ctx.Done():
		putFrame(frame)
	}
}

func (d *ownedTapDelivery) run() {
	for {
		select {
		case frame := <-d.ch:
			d.writeOwned(frame)
		case <-d.ctx.Done():
			d.releaseQueued()
			return
		}
	}
}

func (d *ownedTapDelivery) writeOwned(frame []byte) {
	if _, err := d.writer.Write(frame); err != nil && d.onWriteErr != nil {
		d.onWriteErr(err)
	}
	putFrame(frame)
}

func (d *ownedTapDelivery) releaseQueued() {
	for {
		select {
		case frame := <-d.ch:
			putFrame(frame)
		default:
			return
		}
	}
}
