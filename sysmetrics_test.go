package main

import "testing"

func TestParseLoadAvg(t *testing.T) {
	l := parseLoadAvg([]byte("0.52 0.58 0.59 1/480 12345\n"))
	if l == nil || l.One != 0.52 || l.Five != 0.58 || l.Fifteen != 0.59 {
		t.Fatalf("parseLoadAvg wrong: %+v", l)
	}
	if parseLoadAvg([]byte("garbage")) != nil {
		t.Fatal("malformed loadavg must yield nil")
	}
}

func TestParseMemInfo(t *testing.T) {
	data := []byte("MemTotal:       16384256 kB\nMemFree:         1024000 kB\nMemAvailable:   12300000 kB\nSwapTotal:             0 kB\n")
	m := parseMemInfo(data)
	if m == nil {
		t.Fatal("parseMemInfo returned nil")
	}
	if m.TotalMB != 16000.25 {
		t.Fatalf("total = %v, want 16000.25", m.TotalMB)
	}
	used := 16384256 - 12300000
	if m.UsedMB != float64(used)/1024 {
		t.Fatalf("used = %v, want %v", m.UsedMB, float64(used)/1024)
	}
	if parseMemInfo([]byte("nothing here")) != nil {
		t.Fatal("malformed meminfo must yield nil")
	}
}
