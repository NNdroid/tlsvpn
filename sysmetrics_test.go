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

func TestParseProcStatCPU(t *testing.T) {
	// comm 允许含空格与嵌套括号，解析必须从**最后一个** ')' 之后切分
	// 32 字段：字段 14 为 utime、字段 15 为 stime
	data := []byte("4242 (proc with spaces (nested)) S 4241 4242 4241 0 -1 4194304 100 0 0 0 123 7 0 0 20 0 1 0 900 4096 100")
	n, ok := parseProcStatCPU(data)
	if !ok {
		t.Fatal("well-formed /proc/stat line must parse")
	}
	if n != 130 {
		t.Fatalf("utime+stime = %d, want 130", n)
	}

	for name, in := range map[string][]byte{
		"no closing paren":    []byte("4242 (still open S 1 1"),
		"too few fields":      []byte("4242 (x) S 1 1 1 1 100 50 0"),
		"non-numeric utime":   []byte("4242 (x) S 1 1 1 1 -1 4194304 100 0 0 0 abc 0 0"),
		"negative stime":      []byte("4242 (x) S 1 1 1 1 -1 4194304 100 0 0 0 100 -1 0"),
		"paren then no space": []byte("4242 (x))"),
		"empty":               []byte(""),
	} {
		if _, ok := parseProcStatCPU(in); ok {
			t.Errorf("%s: must not parse", name)
		}
	}
}
