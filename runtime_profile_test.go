package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeProfilePathsFromEnv(t *testing.T) {
	t.Setenv(cpuProfileEnv, " /tmp/tlsvpn-cpu.prof ")
	t.Setenv(heapProfileEnv, " /tmp/tlsvpn-heap.prof ")

	got := runtimeProfilePathsFromEnv()
	if got.CPU != "/tmp/tlsvpn-cpu.prof" {
		t.Fatalf("CPU profile path = %q, want %q", got.CPU, "/tmp/tlsvpn-cpu.prof")
	}
	if got.Heap != "/tmp/tlsvpn-heap.prof" {
		t.Fatalf("heap profile path = %q, want %q", got.Heap, "/tmp/tlsvpn-heap.prof")
	}
}

func TestCreateProfileFileCreatesParentDirectory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "profiles", "cpu.prof")
	f, err := createProfileFile(path)
	if err != nil {
		t.Fatalf("createProfileFile: %v", err)
	}
	if _, err := f.Write([]byte("profile")); err != nil {
		_ = f.Close()
		t.Fatalf("write profile fixture: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close profile fixture: %v", err)
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatalf("profile file not created: %v", err)
	} else if info.Size() == 0 {
		t.Fatal("profile file is empty")
	}
}
