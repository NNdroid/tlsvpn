package main

import (
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestLifecycleHooksRunOnceAndReuseActivationEnvironment(t *testing.T) {
	type call struct {
		path string
		env  map[string]string
	}
	var mu sync.Mutex
	var calls []call
	runner := func(path, _ string, raw []string) (string, error) {
		env := make(map[string]string)
		for _, item := range raw {
			if key, value, ok := strings.Cut(item, "="); ok {
				env[key] = value
			}
		}
		mu.Lock()
		calls = append(calls, call{path: path, env: env})
		mu.Unlock()
		return "", nil
	}
	h := newLifecycleHooksWithRunner("/hooks/up", "/hooks/down", runner)
	env := HookEnv{Mode: "client", Dev: "tap7", Config: "/etc/tlsvpn/client.json",
		IPv4: "10.5.8.2/24", IPv6: "fd00::2/64", GatewayV4: "10.5.8.1", GatewayV6: "fd00::1"}

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := h.Up(env); err != nil {
				t.Errorf("Up: %v", err)
			}
		}()
	}
	wg.Wait()
	if err := h.Down(); err != nil {
		t.Fatalf("Down: %v", err)
	}
	if err := h.Down(); err != nil {
		t.Fatalf("second Down: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 || calls[0].path != "/hooks/up" || calls[1].path != "/hooks/down" {
		t.Fatalf("calls = %#v, want exactly one up then one down", calls)
	}
	for i, scriptType := range []string{"up", "down"} {
		got := calls[i].env
		if got["script_type"] != scriptType || got["dev"] != "tap7" || got["ifconfig_local"] != "10.5.8.2" {
			t.Fatalf("call %d environment = %#v", i, got)
		}
		if got["TLSVPN_IPV4"] != "10.5.8.2/24" || got["route_vpn_gateway"] != "10.5.8.1" {
			t.Fatalf("call %d TLSVPN/OpenVPN aliases missing: %#v", i, got)
		}
	}
}

func TestLifecycleHooksRunDownAfterFailedUp(t *testing.T) {
	var paths []string
	h := newLifecycleHooksWithRunner("/hooks/up", "/hooks/down", func(path, _ string, _ []string) (string, error) {
		paths = append(paths, path)
		if strings.HasSuffix(path, "/up") {
			return "partial setup", errors.New("exit status 3")
		}
		return "", nil
	})
	if err := h.Up(HookEnv{Dev: "tap0"}); err == nil || !strings.Contains(err.Error(), "partial setup") {
		t.Fatalf("Up error = %v, want captured diagnostic output", err)
	}
	if err := h.Down(); err != nil {
		t.Fatalf("Down rollback: %v", err)
	}
	if got := strings.Join(paths, ","); got != "/hooks/up,/hooks/down" {
		t.Fatalf("hook order = %q", got)
	}
}

func TestLifecycleHookConfigurationRequiresAbsolutePaths(t *testing.T) {
	cfg := &Config{Up: "relative.sh"}
	if err := validateHookPath("up", cfg.Up); err == nil {
		t.Fatal("relative hook path unexpectedly accepted")
	}
	for _, path := range []string{"/etc/openvpn/up.sh", `C:\hooks\up.exe`} {
		if err := validateHookPath("up", path); err != nil {
			t.Fatalf("absolute hook path %q rejected: %v", path, err)
		}
	}
}

func TestCappedBufferDoesNotShortWrite(t *testing.T) {
	b := &cappedBuffer{limit: 4}
	if n, err := b.Write([]byte("abcdefgh")); err != nil || n != 8 {
		t.Fatalf("Write = (%d, %v), want (8, nil)", n, err)
	}
	if got := b.String(); got != "abcd" {
		t.Fatalf("buffer = %q, want capped prefix", got)
	}
}

func TestLifecycleHooksExecuteARealProgram(t *testing.T) {
	path, err := exec.LookPath("whoami")
	if err != nil {
		t.Skip("whoami is unavailable")
	}
	path, err = filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	h := NewLifecycleHooks(path, path)
	if err := h.Up(HookEnv{Mode: "client", Dev: "tap0"}); err != nil {
		t.Fatalf("real up command: %v", err)
	}
	if err := h.Down(); err != nil {
		t.Fatalf("real down command: %v", err)
	}
}

func TestHookEnvironmentDoesNotInheritSecrets(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "must-not-cross-hook-boundary")
	for _, item := range hookEnvironment("up", HookEnv{Dev: "tap0"}) {
		if strings.HasPrefix(item, "AWS_SECRET_ACCESS_KEY=") {
			t.Fatalf("secret-bearing parent environment was inherited: %q", item)
		}
	}
}

func TestHookChangesAreReportedAsRestartRequired(t *testing.T) {
	boot := &Config{Up: "/hooks/up-v1", Down: "/hooks/down-v1"}
	next := &Config{Up: "/hooks/up-v2", Down: "/hooks/down-v1"}

	srv := &Server{bootCfg: boot}
	if got := strings.Join(srv.NeedsRestart(next), ","); !strings.Contains(got, "up/down") {
		t.Fatalf("server needs_restart = %q, want up/down", got)
	}
	cli := &Client{}
	cli.bootCfg.Store(boot)
	if got := strings.Join(cli.NeedsRestart(next), ","); !strings.Contains(got, "up/down") {
		t.Fatalf("client needs_restart = %q, want up/down", got)
	}
}
