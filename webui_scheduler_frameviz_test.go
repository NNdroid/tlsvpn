package main

import (
	"os"
	"strings"
	"testing"
)

func readWebUIAsset(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestWebUISchedulerUsesIntervalMetrics(t *testing.T) {
	s := readWebUIAsset(t, "webui/metrics.js")
	for _, want := range []string{
		"assigned - p.assigned",
		"batches - p.batches",
		"_assign_bps",
		"_share_pct",
		"_batch_ps",
		"_queue_eta_us",
		"queued_bytes",
		"lifetime assigned",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("metrics.js missing scheduler interval semantic %q", want)
		}
	}
	if strings.Contains(s, "t('th.tx') + ' ' + fmtBytes(s.assigned_bytes") {
		t.Fatal("scheduler cell must not present lifetime assigned_bytes as current TX")
	}
}

func TestWebUIFrameVizMatchesStreamAggregation(t *testing.T) {
	s := readWebUIAsset(t, "webui/frameviz.js")
	for _, want := range []string{
		"12 KiB",
		"16 KiB",
		"padLen=0",
		"10%",
		"512 B",
		"Final frame",
		"'zh-CN'",
		"'zh-TW'",
		"en:",
		"de:",
		"fr:",
		"ja:",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("frameviz.js missing current framing detail %q", want)
		}
	}
	for _, stale := range []string{"bucket 1600B", "padLen=60"} {
		if strings.Contains(s, stale) {
			t.Fatalf("frameviz.js still contains obsolete per-frame padding example %q", stale)
		}
	}
}
