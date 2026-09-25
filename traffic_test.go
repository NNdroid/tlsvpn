package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func trafficTestCfg(days int, file string) *Config {
	return &Config{TrafficDays: days, TrafficFile: file, SourcePath: "/tmp/fake/config.json"}
}

func TestTrafficDailyBucketsAndDayRotation(t *testing.T) {
	ta := NewTrafficAccounting()
	ta.OnConfig(trafficTestCfg(30, "")) // 无文件：仅内存

	day1 := time.Date(2026, 9, 24, 10, 0, 0, 0, time.Local)
	day2 := time.Date(2026, 9, 25, 0, 30, 0, 0, time.Local)

	ta.Add(100, 200)
	ta.flush(day1)
	ta.Add(50, 80)
	ta.flush(day2) // 跨天：增量 50/80 记入 9-25

	snap := ta.Snapshot()
	if snap.Today != day2.Format(trafficDayLayout) {
		t.Fatalf("today = %q, want %q", snap.Today, day2.Format(trafficDayLayout))
	}
	if len(snap.Daily) != 2 {
		t.Fatalf("expect 2 daily buckets, got %d", len(snap.Daily))
	}
	// 升序：9-24 在前
	if snap.Daily[0].Date != "2026-09-24" || snap.Daily[0].Up != 100 || snap.Daily[0].Down != 200 {
		t.Fatalf("day1 bucket wrong: %+v", snap.Daily[0])
	}
	if snap.Daily[1].Date != "2026-09-25" || snap.Daily[1].Up != 50 || snap.Daily[1].Down != 80 {
		t.Fatalf("day2 bucket wrong: %+v", snap.Daily[1])
	}
	// 快照里的"今天"实时值
	if snap.Up != 50 || snap.Down != 80 {
		t.Fatalf("today live values wrong: up=%d down=%d", snap.Up, snap.Down)
	}
}

func TestTrafficSnapshotIncludesUnsampledDelta(t *testing.T) {
	ta := NewTrafficAccounting()
	ta.OnConfig(trafficTestCfg(30, ""))
	now := time.Now()
	ta.flush(now)
	ta.Add(1024, 2048) // 尚未 flush
	snap := ta.Snapshot()
	if snap.Up != 1024 || snap.Down != 2048 {
		t.Fatalf("unsampled delta missing from snapshot: up=%d down=%d", snap.Up, snap.Down)
	}
	if len(snap.Daily) != 1 || snap.Daily[0].Up != 1024 || snap.Daily[0].Down != 2048 {
		t.Fatalf("daily must expose today's live values: %+v", snap.Daily)
	}
}

func TestTrafficRetentionTrims(t *testing.T) {
	ta := NewTrafficAccounting()
	ta.OnConfig(trafficTestCfg(3, ""))
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.Local)
	for i := 0; i < 5; i++ {
		ta.Add(10, 10)
		ta.flush(base.AddDate(0, 0, i))
	}
	snap := ta.Snapshot()
	if len(snap.Daily) != 3 {
		t.Fatalf("retention must keep 3 days, got %d", len(snap.Daily))
	}
	// 保留的是最近的 3 天：9-3、9-4、9-5
	if snap.Daily[0].Date != "2026-09-03" || snap.Daily[2].Date != "2026-09-05" {
		t.Fatalf("kept wrong days: %+v", snap.Daily)
	}
}

func TestTrafficPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "traffic.json")
	ta := NewTrafficAccounting()
	ta.OnConfig(&Config{TrafficDays: 30, TrafficFile: file})
	now := time.Date(2026, 9, 25, 9, 0, 0, 0, time.Local)
	ta.Add(4096, 8192)
	ta.flush(now)

	// 新实例从同一文件恢复
	ta2 := NewTrafficAccounting()
	ta2.OnConfig(&Config{TrafficDays: 30, TrafficFile: file})
	snap := ta2.Snapshot()
	if len(snap.Daily) != 1 || snap.Daily[0].Up != 4096 || snap.Daily[0].Down != 8192 {
		t.Fatalf("restored snapshot wrong: %+v", snap.Daily)
	}
	if snap.Up != 4096 || snap.Down != 8192 {
		t.Fatalf("restored today live values wrong: %d/%d", snap.Up, snap.Down)
	}
}

func TestTrafficCorruptFileStartsEmpty(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "traffic.json")
	if err := os.WriteFile(file, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	ta := NewTrafficAccounting()
	ta.OnConfig(&Config{TrafficDays: 30, TrafficFile: file})
	snap := ta.Snapshot()
	if len(snap.Daily) != 0 {
		t.Fatalf("corrupt file must start empty, got %+v", snap.Daily)
	}
	// 正常采样后能覆盖坏文件
	ta.Add(7, 7)
	ta.flush(time.Now())
	data, err := os.ReadFile(file)
	if err != nil || !strings.Contains(string(data), `"up":7`) {
		t.Fatalf("flush must rewrite a valid file: err=%v data=%s", err, data)
	}
}

func TestTrafficDefaultFileNextToConfig(t *testing.T) {
	ta := NewTrafficAccounting()
	ta.OnConfig(trafficTestCfg(0, "")) // days=0 → 默认 30；file 空 → 配置文件同目录
	if ta.days != defaultTrafficDays {
		t.Fatalf("days = %d, want %d", ta.days, defaultTrafficDays)
	}
	if ta.file != filepath.Join("/tmp/fake", defaultTrafficFile) {
		t.Fatalf("file = %q, want default next to SourcePath", ta.file)
	}
}

func TestTrafficConfigValidate(t *testing.T) {
	cfg := &Config{Mode: "client", Addr: "127.0.0.1:4000", PSK: "k", TrafficDays: 5000}
	cfg.applyDefaults()
	if err := cfg.Validate(); err == nil {
		t.Fatal("traffic_days beyond max must be rejected")
	}
	cfg.TrafficDays = 0
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default traffic_days must pass: %v", err)
	}
	if cfg.TrafficDays != defaultTrafficDays {
		t.Fatalf("default traffic_days = %d, want %d", cfg.TrafficDays, defaultTrafficDays)
	}
}

func TestTrafficStatsJSONExposesTraffic(t *testing.T) {
	// /api/stats 的 JSON 必须带 traffic 字段（面板数据源）
	stats := WebStats{Mode: "server"}
	ts := dailyTraffic.Snapshot()
	stats.Traffic = &ts
	data, err := json.Marshal(stats)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"traffic":`) {
		t.Fatal("stats JSON missing traffic field")
	}
}
