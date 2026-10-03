package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// linuxMatrix mirrors scripts/build.sh LINUX_MATRIX. Keep generic compatibility
// targets and optimized ISA variants here so a release-only target cannot silently rot.
var linuxMatrix = []string{
	"linux/amd64",
	"linux/amd64@v2",
	"linux/amd64@v3",
	"linux/amd64@v4",
	"linux/386",
	"linux/arm64",
	"linux/arm64@v8.2",
	"linux/arm@v5",
	"linux/arm@v6",
	"linux/arm",
	"linux/mipsle",
	"linux/mips",
	"linux/mips64le",
	"linux/mips64",
	"linux/riscv64",
	"linux/ppc64le",
	"linux/ppc64le@power9",
	"linux/ppc64le@power10",
	"linux/ppc64",
	"linux/s390x",
	"linux/loong64",
}

type crossTarget struct {
	name   string
	goos   string
	goarch string
	extra  string
}

func parseCrossTarget(target string) (crossTarget, error) {
	platform := target
	variant := ""
	if before, after, ok := strings.Cut(target, "@"); ok {
		platform, variant = before, after
	}
	goos, goarch, ok := strings.Cut(platform, "/")
	if !ok || goos == "" || goarch == "" {
		return crossTarget{}, fmt.Errorf("invalid target %q", target)
	}
	ct := crossTarget{name: target, goos: goos, goarch: goarch}
	if variant == "" {
		return ct, nil
	}
	switch goarch {
	case "amd64":
		ct.extra = "GOAMD64=" + variant
	case "arm64":
		ct.extra = "GOARM64=" + variant
	case "arm":
		ct.extra = "GOARM=" + strings.TrimPrefix(variant, "v")
	case "ppc64", "ppc64le":
		ct.extra = "GOPPC64=" + variant
	case "riscv64":
		ct.extra = "GORISCV64=" + variant
	default:
		return crossTarget{}, fmt.Errorf("target %q uses unsupported ISA variant", target)
	}
	return ct, nil
}

func crossOutputName(target string) string {
	r := strings.NewReplacer("/", "_", "@", "_", ",", "_", ".", "_")
	return r.Replace(target)
}

// TestCrossCompileLinuxMatrix ensures every release target can compile. The bounded
// semaphore matters now that the release matrix includes multiple ISA variants: an
// unbounded fan-out can exhaust memory on small CI runners even though each build is valid.
func TestCrossCompileLinuxMatrix(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not in PATH; skipping cross-build matrix")
	}
	dir, err := os.MkdirTemp("", "tlsvpn-xbuild")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var failed []string
	sem := make(chan struct{}, 4)

	for _, raw := range linuxMatrix {
		target, err := parseCrossTarget(raw)
		if err != nil {
			t.Fatalf("parse release target: %v", err)
		}
		wg.Add(1)
		go func(target crossTarget) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			cmd := exec.Command(goBin, "build", "-pgo=off", "-o", filepath.Join(dir, crossOutputName(target.name)), ".")
			cmd.Env = append(os.Environ(),
				"CGO_ENABLED=0", "GOOS="+target.goos, "GOARCH="+target.goarch)
			if target.extra != "" {
				cmd.Env = append(cmd.Env, target.extra)
			}
			out, err := cmd.CombinedOutput()
			if err != nil {
				mu.Lock()
				failed = append(failed, target.name)
				mu.Unlock()
				t.Errorf("%s build failed: %v\n%s", target.name, err, out)
			}
		}(target)
	}
	wg.Wait()
	if len(failed) > 0 {
		t.Errorf("release matrix targets failed: %s", strings.Join(failed, ", "))
	}
}
