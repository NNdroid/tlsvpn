package main

import (
	"errors"
	"io"
	"sync"
)

// tapQueues owns every fd attached to one device. Delivery remains serialized
// through queue zero: parallel writes after reorder would reorder frames again.
type tapQueues struct {
	queues   []io.ReadWriteCloser
	once     sync.Once
	closeErr error
}

func (t *tapQueues) Read(p []byte) (int, error)  { return t.queues[0].Read(p) }
func (t *tapQueues) Write(p []byte) (int, error) { return t.queues[0].Write(p) }
func (t *tapQueues) Close() error {
	t.once.Do(func() {
		for _, q := range t.queues {
			t.closeErr = errors.Join(t.closeErr, q.Close())
		}
	})
	return t.closeErr
}

// runTapReaders gives each queue its own buffer owner. The existing AsyncPort
// remains the sole owner of sequence allocation, epoch transitions and FEC.
func runTapReaders(t io.ReadWriteCloser, read func(io.Reader)) func() {
	readers := []io.ReadWriteCloser{t}
	if mq, ok := t.(*tapQueues); ok {
		readers = mq.queues
	}
	var wg sync.WaitGroup
	for _, r := range readers {
		wg.Add(1)
		go func(r io.Reader) { defer wg.Done(); read(r) }(r)
	}
	return func() { _ = t.Close(); wg.Wait() }
}
