package main

import (
	"os"
	"strings"
	"testing"
)

func TestInstallerWritesReadableJSON(t *testing.T) {
	data, err := os.ReadFile("scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, compact := range []string{
		`"web": {"addr":`,
		`"server": {"v4_cidr":`,
		`"client": {"interface_manager":`,
	} {
		if strings.Contains(s, compact) {
			t.Fatalf("installer still emits compact JSON object %q", compact)
		}
	}
	for _, pretty := range []string{
		`"web": {` + "\n" + `    "addr":`,
		`"server": {` + "\n" + `    "v4_cidr":`,
		`"client": {` + "\n" + `    "interface_manager":`,
	} {
		if !strings.Contains(s, pretty) {
			t.Fatalf("installer missing pretty JSON layout %q", pretty)
		}
	}
}
