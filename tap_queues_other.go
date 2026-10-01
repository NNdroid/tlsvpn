//go:build !linux

package main

import (
	"fmt"
	"github.com/songgao/water"
	"io"
)

func openConfiguredTap(cfg *Config) (io.ReadWriteCloser, error) {
	if cfg.TapQueues > 1 || cfg.TapMultiQueue {
		return nil, fmt.Errorf("TAP multi-queue requires Linux")
	}
	return water.New(newTapConfig(cfg.Tap))
}
