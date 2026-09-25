package main

// ======================= 按日流量统计 =======================
//
// 语义：up = client→server（上行），down = server→client（下行）。
// 口径与面板 TX/RX 完全一致——线路字节，含帧头、混淆填充与 FEC 校验帧。
// 服务端进程聚合全部客户端；客户端进程只记自身。两种模式互不并存于
// 生产部署（e2e 测试同进程跑双端时会计入同一份进程级统计，仅影响测试观测）。
//
// 设计要点：
//   - 热路径零锁：数据面只在既有字节计数点旁多做一次 atomic.Add；日期轮转、
//     保留裁剪与持久化全部挪到低频采样协程（trafficFlushInterval）。
//   - 采样协程每轮取计数器增量累进"今天"的桶：跨天瞬间未采样的流量会计入
//     新的一天（边界误差 ≤ 一个采样周期），断电最多丢最近一个周期的计数。
//   - 保留天数 traffic_days 热生效（面板"保存并应用"即改）；持久化文件默认
//     放在配置文件同目录（tlsvpn-traffic.json），文件损坏时告警并从空表
//     开始，绝不影响隧道数据面。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	trafficDayLayout     = "2006-01-02"
	defaultTrafficDays   = 30
	maxTrafficDays       = 3650
	trafficFlushInterval = 60 * time.Second
	defaultTrafficFile   = "tlsvpn-traffic.json"
)

type trafficDay struct {
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

type trafficFileJSON struct {
	Today string                `json:"today"`
	Days  map[string]*trafficDay `json:"days"`
}

type trafficDayJSON struct {
	Date string `json:"date"`
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

// trafficSnapshotJSON /api/stats 里 traffic 字段的快照。
// Up/Down 是"今天"的实时值（桶内累计 + 尚未采样的增量）。
type trafficSnapshotJSON struct {
	Days  int              `json:"days"`  // 当前保留天数（traffic_days）
	Today string           `json:"today"` // 本地时区的今天，YYYY-MM-DD
	Up    uint64           `json:"up"`
	Down  uint64           `json:"down"`
	Daily []trafficDayJSON `json:"daily"` // 按日期升序，含今天
}

type TrafficAccounting struct {
	up, down atomic.Uint64 // 进程启动以来的线路字节累计（单调）
	lastUp   uint64        // 上次采样值，用于算增量
	lastDown uint64

	mu      sync.Mutex
	started bool
	days    int
	file    string
	buckets map[string]*trafficDay
	today   string
	saved   string // 上次落盘的 JSON，避免每轮都写文件
}

// dailyTraffic 进程级单例。服务端与客户端的计数点都汇入这里。
var dailyTraffic = NewTrafficAccounting()

func NewTrafficAccounting() *TrafficAccounting {
	return &TrafficAccounting{buckets: make(map[string]*trafficDay)}
}

// OnConfig 应用保留天数与持久化路径；进程首次拿到配置时恢复历史并启动采样
// 协程，之后每次调用（面板热更）只更新参数。并发安全。
func (t *TrafficAccounting) OnConfig(cfg *Config) {
	if cfg == nil {
		return
	}
	days := cfg.TrafficDays
	if days <= 0 {
		days = defaultTrafficDays
	}
	if days > maxTrafficDays {
		days = maxTrafficDays
	}
	file := cfg.TrafficFile
	if file == "" && cfg.SourcePath != "" {
		file = filepath.Join(filepath.Dir(cfg.SourcePath), defaultTrafficFile)
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.days = days
	if !t.started {
		t.started = true
		t.file = file
		t.loadLocked()
		go t.loop()
	} else {
		t.file = file // 热更：下一轮采样落到新路径
	}
	t.trimLocked()
}

// Add 数据面记账：up/down 各在既有计数点旁调用一次。
func (t *TrafficAccounting) Add(up, down uint64) {
	if up > 0 {
		t.up.Add(up)
	}
	if down > 0 {
		t.down.Add(down)
	}
}

func (t *TrafficAccounting) loop() {
	for {
		time.Sleep(trafficFlushInterval)
		t.flush(time.Now())
	}
}

// flush 采样一轮：把计数器增量累进当天桶，跨天则轮转，然后裁剪并按需落盘。
func (t *TrafficAccounting) flush(now time.Time) {
	up := t.up.Load()
	down := t.down.Load()
	dUp, dDown := up-t.lastUp, down-t.lastDown
	t.lastUp, t.lastDown = up, down

	t.mu.Lock()
	defer t.mu.Unlock()
	today := now.Format(trafficDayLayout)
	if today != t.today {
		t.today = today
		if t.buckets[today] == nil {
			t.buckets[today] = &trafficDay{}
		}
	}
	if dUp > 0 || dDown > 0 {
		b := t.buckets[today]
		if b == nil {
			b = &trafficDay{}
			t.buckets[today] = b
		}
		b.Up += dUp
		b.Down += dDown
	}
	t.trimLocked()
	t.saveLocked()
}

// trimLocked 只保留最近 days 天（按日期字符串排序即可比较）。
func (t *TrafficAccounting) trimLocked() {
	if t.days <= 0 || len(t.buckets) <= t.days {
		return
	}
	keys := make([]string, 0, len(t.buckets))
	for k := range t.buckets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys[:len(keys)-t.days] {
		delete(t.buckets, k)
	}
}


// loadLocked 启动时恢复历史。文件缺失视为首次运行；损坏则告警并从空表开始
// （下一轮采样会用合法内容覆盖，绝不因统计文件坏了影响进程）。
func (t *TrafficAccounting) loadLocked() {
	if t.file == "" {
		return
	}
	data, err := os.ReadFile(t.file)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warnf("[Traffic] cannot read %s: %v (starting with empty history)", t.file, err)
		}
		return
	}
	var f trafficFileJSON
	if err := json.Unmarshal(data, &f); err != nil {
		log.Warnf("[Traffic] %s is corrupt: %v (starting with empty history)", t.file, err)
		return
	}
	buckets := make(map[string]*trafficDay, len(f.Days))
	for k, v := range f.Days {
		if v == nil {
			continue
		}
		buckets[k] = v
	}
	t.buckets = buckets
	t.today = f.Today
	t.saved = string(data)
	log.Infof("[Traffic] restored %d day(s) of accounting from %s", len(buckets), t.file)
}

// saveLocked 原子落盘：临时文件 + rename。内容没变就跳过，减少落盘次数。
func (t *TrafficAccounting) saveLocked() {
	if t.file == "" {
		return
	}
	data, err := json.Marshal(trafficFileJSON{Today: t.today, Days: t.buckets})
	if err != nil {
		return
	}
	if string(data) == t.saved {
		return
	}
	tmp := t.file + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Warnf("[Traffic] cannot write %s: %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, t.file); err != nil {
		log.Warnf("[Traffic] cannot rename %s: %v", t.file, err)
		return
	}
	t.saved = string(data)
}

// Snapshot 供 /api/stats 使用。"今天"的值补上尚未采样的增量，保证顶部汇总、
// 柱状图与日表三处数字一致。今日之外的历史桶不含未采样增量（历史已定格）。
func (t *TrafficAccounting) Snapshot() trafficSnapshotJSON {
	up, down := t.up.Load(), t.down.Load()
	dUp, dDown := up-t.lastUp, down-t.lastDown

	t.mu.Lock()
	defer t.mu.Unlock()
	today := time.Now().Format(trafficDayLayout)
	out := trafficSnapshotJSON{
		Days:  t.days,
		Today: today,
		Daily: make([]trafficDayJSON, 0, len(t.buckets)),
	}
	keys := make([]string, 0, len(t.buckets))
	for k := range t.buckets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b := t.buckets[k]
		d := trafficDayJSON{Date: k, Up: b.Up, Down: b.Down}
		if k == today {
			d.Up += dUp
			d.Down += dDown
		}
		out.Daily = append(out.Daily, d)
		if k == today {
			out.Up, out.Down = d.Up, d.Down
		}
	}
	if out.Up == 0 && out.Down == 0 && (dUp > 0 || dDown > 0) {
		// 进程刚启动、今天还没有任何已采样桶时，也要能看到实时增量
		out.Up, out.Down = dUp, dDown
		out.Daily = append(out.Daily, trafficDayJSON{Date: today, Up: dUp, Down: dDown})
	}
	return out
}
