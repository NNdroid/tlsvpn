package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestWebUIStalledI18n verifies the stalled scheduler state is present in every
// locale dictionary (zh-CN, en, de, fr, ja) plus the zh-TW runtime override.
func TestWebUIStalledI18n(t *testing.T) {
	s := readWebUIAsset(t, "webui/i18n.js")
	for _, want := range []string{
		"sched:{active:'活跃'", "sched:{active:'Active'", "sched:{active:'Aktiv'",
		"sched:{active:'Actif'", "sched:{active:'稼働'",
		"stalled:'失效'", "stalled:'Stalled'", "stalled:'Gestört'", "stalled:'Défaillant'", "stalled:'停止'",
		"stalled_tip:", "stalled_note:",
		"zh-TW'].sched.stalled",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("i18n.js missing stalled translation %q", want)
		}
	}
}

// TestWebUISchedulerCellRendersStalled verifies schedulerCell renders a stalled
// badge when the backend is marked unhealthy, independent of active/standby.
func TestWebUISchedulerCellRendersStalled(t *testing.T) {
	s := readWebUIAsset(t, "webui/app.js")
	for _, want := range []string{
		"function schedulerCell(s,stalled)",
		"t('sched.stalled')",
		"t('sched.stalled_note')",
		"schedulerCell(r.sched,r.stalled)",
		"stalled:!!c.stalled",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("app.js missing stalled scheduler rendering %q", want)
		}
	}
}

// TestConnSnapshotSerializesStalled verifies the client/server connection JSON
// snapshots expose the stalled flag to the dashboard.
func TestConnSnapshotSerializesStalled(t *testing.T) {
	cs := connSnapshot{Stalled: true}
	b, err := json.Marshal(cs)
	if err != nil {
		t.Fatalf("marshal connSnapshot: %v", err)
	}
	if !strings.Contains(string(b), `"stalled":true`) {
		t.Fatalf("connSnapshot JSON missing stalled=true: %s", b)
	}

	ss := serverConnSnapshot{Stalled: true}
	b, err = json.Marshal(ss)
	if err != nil {
		t.Fatalf("marshal serverConnSnapshot: %v", err)
	}
	if !strings.Contains(string(b), `"stalled":true`) {
		t.Fatalf("serverConnSnapshot JSON missing stalled=true: %s", b)
	}
}
