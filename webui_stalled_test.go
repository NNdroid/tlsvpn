package main

import (
	"encoding/json"
	"regexp"
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

// TestWebUIConnTableOneWayColumn 连接表"去/回"列的 WebUI 契约（方案A）：单元格
// 读 scheduler.fwd_oneway_us/ret_oneway_us、不对称着色、tooltip 文案，且五个
// locale 字典都带 th.rtt_tip（zh-TW 走运行期覆盖）。
func TestWebUIConnTableOneWayColumn(t *testing.T) {
	app := readWebUIAsset(t, "webui/app.js")
	for _, want := range []string{
		"scheduler.fwd_oneway_us",
		"scheduler.ret_oneway_us",
		"scheduler.min_rtt_us",
		"th.rtt_tip",
		"rtt-asym",
	} {
		if !strings.Contains(app, want) {
			t.Errorf("webui/app.js 缺少“去/回”渲染片段 %q", want)
		}
	}
	i18n := readWebUIAsset(t, "webui/i18n.js")
	// 每个 locale 的连接表头块（th:{connid ... }）都必须带 rtt_tip 提示。
	// dg.rtt_tip 是既有的"最小·平均·P95·最大"提示，属性名同形，故按 th 块切分。
	blocks := regexp.MustCompile(`th:\{connid:[^}]*\}`).FindAllString(i18n, -1)
	if len(blocks) != 5 {
		t.Fatalf("th 字典数量=%d want=5", len(blocks))
	}
	for i, blk := range blocks {
		if !strings.Contains(blk, "rtt_tip:'") {
			t.Errorf("第 %d 个 locale 的连接表头缺少 rtt_tip", i+1)
		}
	}
	if !strings.Contains(i18n, "I18N['zh-TW'].th.rtt_tip") {
		t.Error("zh-TW 缺少 th.rtt_tip 运行期覆盖")
	}
	if !strings.Contains(readWebUIAsset(t, "webui/style.css"), "td.rtt-asym") {
		t.Error("style.css 缺少 rtt-asym 不对称着色规则")
	}
}
