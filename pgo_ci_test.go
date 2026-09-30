package main

import (
	"os"
	"strings"
	"testing"
)

func TestPGOBuildScriptSupportsAutoAndOff(t *testing.T) {
	b, err := os.ReadFile("scripts/build.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		`PGO_MODE="${PGO_MODE:-auto}"`,
		`-pgo="$PGO_MODE"`,
		`PGO_MODE=off`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("scripts/build.sh missing PGO contract %q", want)
		}
	}
}

func TestPGOPerfWorkflowTrainsOffAndTestsOn(t *testing.T) {
	b, err := os.ReadFile(".github/workflows/perf.yml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		"go build -pgo=off",
		"profile-upload/server.cpu.prof",
		"profile-upload/client.cpu.prof",
		"profile-download/server.cpu.prof",
		"profile-download/client.cpu.prof",
		"go tool pprof -proto",
		`-pgo="$PWD/perf-artifacts/default.pgo"`,
		"Run isolated paired PGO A/B",
		"main-off -> candidate-PGO geomean",
		"Promote validated profile to default.pgo",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("perf workflow missing PGO contract %q", want)
		}
	}
}
