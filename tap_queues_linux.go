//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"syscall"

	"github.com/songgao/water"
)

func openConfiguredTap(cfg *Config) (io.ReadWriteCloser, error) {
	return openTapQueues(cfg.Tap, cfg.TapQueues, cfg.TapMultiQueue, func(c water.Config) (io.ReadWriteCloser, error) {
		return water.New(c)
	})
}

// Only unsupported/incompatible queue flags allow fallback. Permission, fd
// exhaustion and other operational failures must not silently change topology.
func openTapQueues(name string, count int, multi bool, open func(water.Config) (io.ReadWriteCloser, error)) (io.ReadWriteCloser, error) {
	if count == 0 {
		count = 1
	}
	if count < 1 || count > 16 {
		return nil, fmt.Errorf("tap_queues must be between 1 and 16")
	}
	c := newTapConfig(name)
	c.MultiQueue = multi || count > 1
	t := &tapQueues{}
	for i := 0; i < count; i++ {
		q, err := open(c)
		if err != nil {
			if closeErr := t.Close(); closeErr != nil {
				return nil, errors.Join(err, closeErr)
			}
			if c.MultiQueue && (errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EOPNOTSUPP)) {
				log.Warnf("TAP multi-queue unavailable: %v; falling back to one queue", err)
				c.MultiQueue = false
				q, fallbackErr := open(c)
				if fallbackErr != nil {
					return nil, fallbackErr
				}
				return &tapQueues{queues: []io.ReadWriteCloser{q}}, nil
			}
			return nil, fmt.Errorf("open TAP queue %d: %w", i, err)
		}
		t.queues = append(t.queues, q)
	}
	log.Infof("TAP %s: %d read queue(s), multi-queue=%t, serialized delivery", name, len(t.queues), c.MultiQueue)
	return t, nil
}
