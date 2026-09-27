package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
	"strings"
	"sync"
)

const (
	cpuProfileEnv  = "TLSVPN_CPU_PROFILE"
	heapProfileEnv = "TLSVPN_HEAP_PROFILE"
)

type runtimeProfilePaths struct {
	CPU  string
	Heap string
}

type runtimeProfiler struct {
	paths   runtimeProfilePaths
	cpuFile *os.File
	once    sync.Once
	closeErr error
}

func runtimeProfilePathsFromEnv() runtimeProfilePaths {
	return runtimeProfilePaths{
		CPU:  strings.TrimSpace(os.Getenv(cpuProfileEnv)),
		Heap: strings.TrimSpace(os.Getenv(heapProfileEnv)),
	}
}

func startRuntimeProfiler() (*runtimeProfiler, error) {
	paths := runtimeProfilePathsFromEnv()
	if paths.CPU == "" && paths.Heap == "" {
		return nil, nil
	}

	p := &runtimeProfiler{paths: paths}
	if paths.CPU != "" {
		f, err := createProfileFile(paths.CPU)
		if err != nil {
			return nil, fmt.Errorf("create CPU profile %q: %w", paths.CPU, err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("start CPU profile %q: %w", paths.CPU, err)
		}
		p.cpuFile = f
	}
	return p, nil
}

func createProfileFile(path string) (*os.File, error) {
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}
	return os.Create(path)
}

func (p *runtimeProfiler) Close() error {
	if p == nil {
		return nil
	}
	p.once.Do(func() {
		if p.cpuFile != nil {
			pprof.StopCPUProfile()
			if err := p.cpuFile.Close(); err != nil {
				p.closeErr = fmt.Errorf("close CPU profile: %w", err)
			}
		}

		if p.paths.Heap != "" {
			f, err := createProfileFile(p.paths.Heap)
			if err != nil {
				if p.closeErr == nil {
					p.closeErr = fmt.Errorf("create heap profile %q: %w", p.paths.Heap, err)
				}
				return
			}
			if err := pprof.WriteHeapProfile(f); err != nil && p.closeErr == nil {
				p.closeErr = fmt.Errorf("write heap profile %q: %w", p.paths.Heap, err)
			}
			if err := f.Close(); err != nil && p.closeErr == nil {
				p.closeErr = fmt.Errorf("close heap profile %q: %w", p.paths.Heap, err)
			}
		}
	})
	return p.closeErr
}
