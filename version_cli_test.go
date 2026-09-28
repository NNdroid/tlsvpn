package main

import (
	"os"
	"strings"
	"testing"
)

func TestVersionFlagAndDocsContract(t *testing.T) {
	readme, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(readme)
	for _, want := range []string{"tlsvpn -version", "`-version`", "Go 1.26.1+"} {
		if !strings.Contains(s, want) {
			t.Fatalf("README missing %q", want)
		}
	}
	installer, err := os.ReadFile("scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(installer), "binary_version()") {
		t.Fatal("installer does not query the binary version")
	}
}
