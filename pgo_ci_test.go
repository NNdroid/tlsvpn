package main

import (
	"os"
	"os/exec"
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
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("scripts/build.sh missing PGO contract %q", want)
		}
	}

	// Validate supported modes by behavior rather than requiring a particular
	// source-code spelling such as a literal "PGO_MODE=off" assignment. --list
	// exercises argument/default validation without spending time compiling the
	// full release matrix.
	for _, mode := range []string{"auto", "off"} {
		cmd := exec.Command("bash", "scripts/build.sh", "--list")
		env := make([]string, 0, len(os.Environ())+1)
		for _, item := range os.Environ() {
			if !strings.HasPrefix(item, "PGO_MODE=") {
				env = append(env, item)
			}
		}
		cmd.Env = append(env, "PGO_MODE="+mode)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("scripts/build.sh rejected PGO_MODE=%s: %v\n%s", mode, err, out)
		}
	}
}

func TestPGOPerfWorkflowTrainsSelectsAndValidatesReleaseCandidate(t *testing.T) {
	b, err := os.ReadFile(".github/workflows/perf.yml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{
		// Training remains deterministic and unprofiled.
		"go build -pgo=off",
		"profile-upload/server.cpu.prof",
		"profile-upload/client.cpu.prof",
		"profile-download/server.cpu.prof",
		"profile-download/client.cpu.prof",
		"go tool pprof -proto",
		// A freshly trained profile is still built and benchmarked explicitly.
		`-pgo="$PWD/perf-artifacts/default.pgo"`,
		"Run isolated paired newly-trained PGO A/B",
		// The already committed profile must remain a selectable release fallback
		// when retraining is neutral or noisy.
		"tlsvpn-candidate-committed",
		"pgo-selection.txt",
		"selected release profile",
		// Full real-TAP gates must validate the binary that would actually ship.
		"Run paired main-off/release-candidate throughput matrix",
		"main-off -> release-candidate geomean",
		// Only a newly trained profile that clears selection may replace default.pgo.
		"Promote newly trained profile when selected",
		"retaining committed default.pgo",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("perf workflow missing PGO contract %q", want)
		}
	}
}
