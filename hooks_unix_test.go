//go:build unix

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestExecutableLifecycleHooksRunOnce(t *testing.T) {
	dir := t.TempDir()
	events := filepath.Join(dir, "events")
	script := filepath.Join(dir, "hook.sh")
	config := filepath.Join(dir, "client.json")
	if err := os.WriteFile(config, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	quotedEvents := strings.ReplaceAll(events, "'", `'"'"'`)
	body := fmt.Sprintf("#!/bin/sh\nprintf '%%s|%%s|%%s|%%s\\n' \"$script_type\" \"$dev\" \"$ifconfig_local\" \"$TLSVPN_IPV4\" >> '%s'\n", quotedEvents)
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}

	hooks := NewLifecycleHooks(script, script)
	env := HookEnv{Mode: "client", Dev: "tap7", Config: config,
		IPv4: "10.5.8.2/24", IPv6: "fd00::2/64", GatewayV4: "10.5.8.1", GatewayV6: "fd00::1"}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := hooks.Up(env); err != nil {
				t.Errorf("Up: %v", err)
			}
		}()
	}
	wg.Wait()
	if err := hooks.Down(); err != nil {
		t.Fatal(err)
	}
	if err := hooks.Down(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(raw)), "\n")
	want := []string{"up|tap7|10.5.8.2|10.5.8.2/24", "down|tap7|10.5.8.2|10.5.8.2/24"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("events = %#v, want %#v", got, want)
	}
}
