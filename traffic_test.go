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
	if snap.Today != time.Now().Format(trafficDayLayout) {
		t.Fatalf("today = %q, want real today", snap.Today)
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
	// 用历史时间戳采样时，实时今日值不适用（今日=真实日历日），日桶断言已覆盖
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

	// 新实例从同一文件恢复（快照的实时今日值以真实日历日为准，这里只看日桶）
	ta2 := NewTrafficAccounting()
	ta2.OnConfig(&Config{TrafficDays: 30, TrafficFile: file})
	snap := ta2.Snapshot()
	if len(snap.Daily) != 1 || snap.Daily[0].Up != 4096 || snap.Daily[0].Down != 8192 {
		t.Fatalf("restored snapshot wrong: %+v", snap.Daily)
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

func TestTrafficTrendRingAndAggregation(t *testing.T) {
	ta := NewTrafficAccounting()
	ta.OnConfig(trafficTestCfg(30, ""))
	ta.SetRTTSampler(func() float64 { return 42.5 })
	base := time.Date(2026, 9, 25, 10, 0, 0, 0, time.Local)
	for i := 0; i < 1500; i++ {
		ta.Add(60*1024, 0) // 每分钟 60KB → 1KB/s
		ta.flush(base.Add(time.Duration(i) * time.Minute))
	}
	if len(ta.trend) != trendCap {
		t.Fatalf("trend ring must cap at %d, got %d", trendCap, len(ta.trend))
	}
	// 1 小时窗口：60 个原始点，步长 60s
	oneHour := ta.TrendSnapshot(60)
	if len(oneHour.Points) != 60 || oneHour.StepSec != 60 {
		t.Fatalf("1h trend: %d points step %d", len(oneHour.Points), oneHour.StepSec)
	}
	// 24 小时窗口：1440 点聚合到 ≤120 个点（步长 12 分钟）
	day := ta.TrendSnapshot(1440)
	if len(day.Points) != 120 || day.StepSec != 720 {
		t.Fatalf("24h trend: %d points step %d", len(day.Points), day.StepSec)
	}
	if day.Points[0].RttMs != 42.5 {
		t.Fatalf("rtt sample missing: %v", day.Points[0].RttMs)
	}
	// 每点速率：60KB/60s = 1KB/s
	if day.Points[0].UpBps != 1024 {
		t.Fatalf("up bps = %v, want 1024", day.Points[0].UpBps)
	}
}

func TestTrafficRecentRingAndSnapshot(t *testing.T) {
	ta := NewTrafficAccounting()
	if snap := ta.RecentSnapshot(); len(snap.Points) != 0 || snap.StepSec != 1 {
		t.Fatalf("空缓冲应返回 1s 步长的空点列: %+v", snap)
	}
	base := time.Date(2026, 9, 25, 9, 0, 0, 0, time.Local)
	// 灌 recentCap+30 个点，超出的旧点应被滚动淘汰
	for i := 0; i < recentCap+30; i++ {
		ta.appendRecent(trendPoint{
			TUnix:   base.Add(time.Duration(i) * time.Second).Unix(),
			UpBps:   float64(i),
			DownBps: float64(i) * 2,
			RttMs:   12,
		})
	}
	snap := ta.RecentSnapshot()
	if snap.StepSec != 1 {
		t.Fatalf("2 分钟视图步长应为 1 秒, got %d", snap.StepSec)
	}
	if len(snap.Points) != recentCap {
		t.Fatalf("recent 环形应封顶 %d 点, got %d", recentCap, len(snap.Points))
	}
	// 最旧的 30 个点应被淘汰，剩下的从 i=30 开始
	if snap.Points[0].TUnix != base.Add(30*time.Second).Unix() || snap.Points[0].UpBps != 30 {
		t.Fatalf("最旧点未被滚动淘汰: %+v", snap.Points[0])
	}
	if want := float64(recentCap + 29); snap.Points[recentCap-1].UpBps != want {
		t.Fatalf("最新点应保留: got %v want %v", snap.Points[recentCap-1].UpBps, want)
	}
	for i := 1; i < len(snap.Points); i++ {
		if snap.Points[i].TUnix <= snap.Points[i-1].TUnix {
			t.Fatalf("TUnix 应单调递增: %d -> %d", snap.Points[i-1].TUnix, snap.Points[i].TUnix)
		}
	}
	if snap.Points[0].RttMs != 12 {
		t.Fatalf("rtt 采样缺失: %v", snap.Points[0].RttMs)
	}
	// 快照必须是副本，调用方改动不得回写内部缓冲
	snap.Points[0].UpBps = -1
	if got := ta.RecentSnapshot().Points[0].UpBps; got != 30 {
		t.Fatalf("RecentSnapshot 返回了内部切片, UpBps=%v", got)
	}
	// recent 与分钟粒度的 trend 各自独立
	if got := len(ta.TrendSnapshot(60).Points); got != 0 {
		t.Fatalf("recent 采样不应污染 trend, got %d 点", got)
	}
}

func TestTrafficRttNowSampler(t *testing.T) {
	ta := NewTrafficAccounting()
	if got := ta.rttNow(); got != 0 {
		t.Fatalf("无采样回调时应返回 0, got %v", got)
	}
	ta.SetRTTSampler(func() float64 { return 25 })
	if got := ta.rttNow(); got != 25 {
		t.Fatalf("应返回回调值 25, got %v", got)
	}
}

func TestTrafficPerClientDailyBuckets(t *testing.T) {
	ta := NewTrafficAccounting()
	ta.OnConfig(trafficTestCfg(30, ""))
	var cu, cd uint64
	ta.SetClientSampler(func() map[string][2]uint64 {
		return map[string][2]uint64{"client-a": {cu, cd}}
	})
	base := time.Date(2026, 9, 25, 10, 0, 0, 0, time.Local)
	cu, cd = 1000, 5000
	ta.flush(base) // 首轮：全量入桶
	cu, cd = 3000, 7000
	ta.flush(base.Add(time.Minute)) // 差分 2000/2000
	cu, cd = 50, 60
	ta.flush(base.Add(2 * time.Minute)) // 会话重建回绕：负增量必须记 0

	var ct clientTrafficJSON
	found := false
	for _, c := range ta.ClientSnapshot() {
		if c.ID == "client-a" {
			found = true
			ct = c
		}
	}
	if !found {
		t.Fatal("client-a missing from snapshot")
	}
	if len(ct.Daily) != 1 {
		t.Fatalf("expect 1 day, got %d", len(ct.Daily))
	}
	if ct.Daily[0].Up != 3000 || ct.Daily[0].Down != 7000 {
		t.Fatalf("daily bucket wrong: %+v", ct.Daily[0])
	}
}

func TestTrafficPerClientPersistence(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "traffic.json")
	ta := NewTrafficAccounting()
	ta.OnConfig(&Config{TrafficDays: 30, TrafficFile: main})
	var cu, cd uint64
	ta.SetClientSampler(func() map[string][2]uint64 {
		return map[string][2]uint64{"client-b": {cu, cd}}
	})
	cu, cd = 4096, 8192
	ta.flush(time.Date(2026, 9, 25, 9, 0, 0, 0, time.Local))

	ta2 := NewTrafficAccounting()
	ta2.OnConfig(&Config{TrafficDays: 30, TrafficFile: main})
	snap := ta2.ClientSnapshot()
	if len(snap) != 1 || snap[0].ID != "client-b" || len(snap[0].Daily) != 1 || snap[0].Daily[0].Up != 4096 {
		t.Fatalf("per-client history not restored: %+v", snap)
	}
}
