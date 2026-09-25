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
	"strings"
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
	trendCap             = 1440 // 1 分钟粒度 × 1440 = 24 小时（仅内存，不持久化）
	trendAggThreshold    = 120  // 趋势点数超过该值时按 5 分钟聚合，控制载荷
)

type trafficDay struct {
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

type trafficFileJSON struct {
	Today string                 `json:"today"`
	Days  map[string]*trafficDay `json:"days"`
}

type clientTrafficFileJSON struct {
	Today string                            `json:"today"`
	Days  map[string]map[string]*trafficDay `json:"days"`
}

type trafficDayJSON struct {
	Date string `json:"date"`
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

// trendPoint 长周期趋势的一个采样点。Up/Down 是该分钟的平均速率（B/s），
// Rtt 是该分钟内各物理连接 RTT 的均值（毫秒，无采样回调时缺位）。
type trendPoint struct {
	Minute  int64   `json:"t"`             // 对齐到分钟的 Unix 秒
	UpBps   float64 `json:"up"`            // 字节/秒
	DownBps float64 `json:"down"`          // 字节/秒
	RttMs   float64 `json:"rtt,omitempty"` // 毫秒
}

type trendSnapshotJSON struct {
	StepSec int          `json:"step_sec"` // 相邻点的时间步长
	Points  []trendPoint `json:"points"`
}

// clientTrafficJSON 单客户端的按日流量历史
type clientTrafficJSON struct {
	ID    string           `json:"id"`
	Daily []trafficDayJSON `json:"daily"`
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

	// 趋势环形缓冲：1 分钟粒度，cap 1440（24 小时）。仅内存不持久化，
	// 重启从零积累；RTT 由 mode 侧注册的采样回调提供（无则缺位）。
	trend []trendPoint
	rttFn func() float64

	// 每客户端记账：mode 侧注册采样回调返回各客户端的会话累计字节
	// （up=Rx、down=Tx），flush 时做差分入桶。会话重建导致计数器回绕时
	// 该轮增量记 0（宁可少记，不多记）。
	clientFn      func() map[string][2]uint64
	clientLast    map[string][2]uint64
	clientBuckets map[string]map[string]*trafficDay // date -> clientID -> 桶
	clientFile    string
	clientSaved   string
}

// dailyTraffic 进程级单例。服务端与客户端的计数点都汇入这里。
var dailyTraffic = NewTrafficAccounting()

func NewTrafficAccounting() *TrafficAccounting {
	return &TrafficAccounting{
		buckets:       make(map[string]*trafficDay),
		clientLast:    make(map[string][2]uint64),
		clientBuckets: make(map[string]map[string]*trafficDay),
	}
}

// SetRTTSampler 注册 RTT 采样回调（服务端=各物理连接均值，客户端=各连接均值）。
func (t *TrafficAccounting) SetRTTSampler(fn func() float64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rttFn = fn
}

// SetClientSampler 注册每客户端流量采样回调：返回 clientID → {上行累计, 下行累计}
// （服务端视角：上行取会话 Rx、下行取会话 Tx，均为单调计数）。
func (t *TrafficAccounting) SetClientSampler(fn func() map[string][2]uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.clientFn = fn
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
	// 每客户端历史与总量同目录同保留策略，文件名加 -clients 后缀
	clientFile := ""
	if file != "" {
		clientFile = strings.TrimSuffix(file, filepath.Ext(file)) + "-clients.json"
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	t.days = days
	if !t.started {
		t.started = true
		t.file = file
		t.clientFile = clientFile
		t.loadLocked()
		go t.loop()
	} else {
		t.file = file // 热更：下一轮采样落到新路径
		t.clientFile = clientFile
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

// flush 采样一轮：把计数器增量累进当天桶与趋势缓冲，跨天则轮转，
// 然后裁剪并按需落盘。
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
	// 趋势点：60 秒增量 → 平均速率；同一分钟只记一个点。空闲且有历史时
	// 不补零点（图表断线即为空闲），缓冲按 trendCap 滚动淘汰。
	thisMinute := now.Unix() / 60
	lastMinute := int64(-1)
	if n := len(t.trend); n > 0 {
		lastMinute = t.trend[n-1].Minute / 60
	}
	if dUp > 0 || dDown > 0 || thisMinute != lastMinute {
		p := trendPoint{Minute: thisMinute * 60, UpBps: float64(dUp) / 60, DownBps: float64(dDown) / 60}
		if t.rttFn != nil {
			p.RttMs = t.rttFn()
		}
		t.trend = append(t.trend, p)
		if len(t.trend) > trendCap {
			t.trend = t.trend[len(t.trend)-trendCap:]
		}
	}
	t.sampleClientsLocked(today, now)
	t.trimLocked()
	t.saveLocked()
}

// sampleClientsLocked 拉取各客户端的会话累计字节并差分入当天桶。
func (t *TrafficAccounting) sampleClientsLocked(today string, now time.Time) {
	if t.clientFn == nil {
		return
	}
	sample := t.clientFn()
	for id, c := range sample {
		last := t.clientLast[id]
		dUp, dDown := uint64(0), uint64(0)
		if c[0] >= last[0] {
			dUp = c[0] - last[0]
		}
		if c[1] >= last[1] {
			dDown = c[1] - last[1]
		}
		t.clientLast[id] = c
		if dUp == 0 && dDown == 0 {
			continue
		}
		m := t.clientBuckets[today]
		if m == nil {
			m = make(map[string]*trafficDay)
			t.clientBuckets[today] = m
		}
		b := m[id]
		if b == nil {
			b = &trafficDay{}
			m[id] = b
		}
		b.Up += dUp
		b.Down += dDown
	}
	// 已消失的客户端（会话销毁）不再保留采样基线
	for id := range t.clientLast {
		if _, ok := sample[id]; !ok {
			delete(t.clientLast, id)
		}
	}
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
	// 每客户端历史同样按日期裁剪
	if t.days <= 0 || len(t.clientBuckets) <= t.days {
		return
	}
	ckeys := make([]string, 0, len(t.clientBuckets))
	for k := range t.clientBuckets {
		ckeys = append(ckeys, k)
	}
	sort.Strings(ckeys)
	for _, k := range ckeys[:len(ckeys)-t.days] {
		delete(t.clientBuckets, k)
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
	// 恢复每客户端历史（独立文件；缺失/损坏只影响该维度）
	if t.clientFile == "" {
		return
	}
	cdata, err := os.ReadFile(t.clientFile)
	if err != nil {
		return
	}
	var cf clientTrafficFileJSON
	if err := json.Unmarshal(cdata, &cf); err != nil {
		log.Warnf("[Traffic] %s is corrupt: %v (per-client history reset)", t.clientFile, err)
		return
	}
	t.clientBuckets = cf.Days
	if t.clientBuckets == nil {
		t.clientBuckets = make(map[string]map[string]*trafficDay)
	}
	t.clientSaved = string(cdata)
	log.Infof("[Traffic] restored per-client history (%d day(s)) from %s", len(t.clientBuckets), t.clientFile)
}

// saveLocked 原子落盘：临时文件 + rename。内容没变就跳过，减少落盘次数。
func (t *TrafficAccounting) saveLocked() {
	if t.file != "" {
		data, err := json.Marshal(trafficFileJSON{Today: t.today, Days: t.buckets})
		if err == nil && string(data) != t.saved {
			if t.writeFileAtomic(t.file, data) {
				t.saved = string(data)
			}
		}
	}
	if t.clientFile == "" || len(t.clientBuckets) == 0 {
		return
	}
	cdata, err := json.Marshal(clientTrafficFileJSON{Today: t.today, Days: t.clientBuckets})
	if err == nil && string(cdata) != t.clientSaved {
		if t.writeFileAtomic(t.clientFile, cdata) {
			t.clientSaved = string(cdata)
		}
	}
}

// writeFileAtomic 临时文件 + rename；返回是否成功。
func (t *TrafficAccounting) writeFileAtomic(path string, data []byte) bool {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		log.Warnf("[Traffic] cannot write %s: %v", tmp, err)
		return false
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Warnf("[Traffic] cannot rename %s: %v", path, err)
		return false
	}
	return true
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

// TrendSnapshot 返回最近 minutes 分钟的吞吐/RTT 趋势。点数超过
// trendAggThreshold 时按 5 分钟聚合，控制 JSON 载荷；相邻点步长随聚合变化。
func (t *TrafficAccounting) TrendSnapshot(minutes int) trendSnapshotJSON {
	if minutes <= 0 {
		minutes = 60
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	raw := t.trend
	if len(raw) > minutes {
		raw = raw[len(raw)-minutes:]
	}
	step := 1
	if len(raw) > trendAggThreshold {
		step = (len(raw) + trendAggThreshold - 1) / trendAggThreshold
	}
	out := trendSnapshotJSON{StepSec: 60 * step, Points: make([]trendPoint, 0, len(raw)/step+1)}
	for i := 0; i < len(raw); i += step {
		end := i + step
		if end > len(raw) {
			end = len(raw)
		}
		group := raw[i:end]
		p := trendPoint{Minute: group[0].Minute}
		for _, g := range group {
			p.UpBps += g.UpBps
			p.DownBps += g.DownBps
			p.RttMs += g.RttMs
		}
		n := float64(len(group))
		p.UpBps /= n
		p.DownBps /= n
		p.RttMs /= n
		out.Points = append(out.Points, p)
	}
	return out
}

// ClientSnapshot 返回各客户端的按日流量历史（按客户端 ID 与日期排序）。
// 今日值不含未采样增量（最多滞后一个采样周期）。
func (t *TrafficAccounting) ClientSnapshot() []clientTrafficJSON {
	t.mu.Lock()
	defer t.mu.Unlock()
	ids := make([]string, 0)
	seen := make(map[string]bool)
	for _, m := range t.clientBuckets {
		for id := range m {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)
	out := make([]clientTrafficJSON, 0, len(ids))
	for _, id := range ids {
		ct := clientTrafficJSON{ID: id, Daily: make([]trafficDayJSON, 0, len(t.clientBuckets))}
		dates := make([]string, 0, len(t.clientBuckets))
		for date := range t.clientBuckets {
			if b, ok := t.clientBuckets[date][id]; ok && b != nil {
				dates = append(dates, date)
			}
		}
		sort.Strings(dates)
		for _, date := range dates {
			b := t.clientBuckets[date][id]
			ct.Daily = append(ct.Daily, trafficDayJSON{Date: date, Up: b.Up, Down: b.Down})
		}
		out = append(out, ct)
	}
	return out
}
