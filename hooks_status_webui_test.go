package main

import (
	"errors"
	"strings"
	"testing"
)

func TestLifecycleHooksStatusExposesOutputAndTime(t *testing.T) {
	runs := 0
	h := newLifecycleHooksWithRunner("/tmp/up.sh", "/tmp/down.sh", func(path, workDir string, env []string) (string, error) {
		runs++
		if strings.Contains(path, "down") {
			return "down cleanup output", errors.New("exit status 2")
		}
		return "up configured route", nil
	})

	env := HookEnv{Mode: "client", Dev: "tap0", Config: "/etc/tlsvpn.json"}
	if err := h.Up(env); err != nil {
		t.Fatalf("Up() error: %v", err)
	}
	st := h.Status()
	if st == nil {
		t.Fatal("Status() = nil")
	}
	if !st.UpRan || !st.UpOK || st.UpOut != "up configured route" {
		t.Fatalf("unexpected up status: %+v", st)
	}
	if st.UpAt == "" {
		t.Fatal("up_at must be populated")
	}

	if err := h.Down(); err == nil {
		t.Fatal("Down() expected error")
	}
	st = h.Status()
	if !st.DownRan || st.DownOK {
		t.Fatalf("unexpected down state: %+v", st)
	}
	if st.DownOut != "down cleanup output" {
		t.Fatalf("down_out = %q", st.DownOut)
	}
	if st.DownAt == "" {
		t.Fatal("down_at must be populated")
	}
	if st.DownErr == "" || !strings.Contains(st.DownErr, "exit status 2") {
		t.Fatalf("down_error = %q", st.DownErr)
	}
	if runs != 2 {
		t.Fatalf("runner calls = %d, want 2", runs)
	}
}
