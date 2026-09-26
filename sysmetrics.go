package main

// ======================= 宿主系统运行指标（尽力而为） =======================
//
// 只在 Linux 上通过 /proc 采集负载、内存与文件描述符数；其他平台或读取失败
// 时字段缺位，面板不渲染对应行（"空值不占行"约定）。解析函数独立出来便于
// 用合成数据做单元测试。

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// loadJSON 系统 1/5/15 分钟平均负载
type loadJSON struct {
	One     float64 `json:"one"`
	Five    float64 `json:"five"`
	Fifteen float64 `json:"fifteen"`
}

// memJSON 物理内存水位（MB）
type memJSON struct {
	UsedMB  float64 `json:"used_mb"`
	TotalMB float64 `json:"total_mb"`
}

func parseLoadAvg(data []byte) *loadJSON {
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return nil
	}
	var l loadJSON
	var err error
	if l.One, err = strconv.ParseFloat(fields[0], 64); err != nil {
		return nil
	}
	if l.Five, err = strconv.ParseFloat(fields[1], 64); err != nil {
		return nil
	}
	if l.Fifteen, err = strconv.ParseFloat(fields[2], 64); err != nil {
		return nil
	}
	return &l
}

func parseMemInfo(data []byte) *memJSON {
	var total, avail float64
	for _, line := range strings.Split(string(data), "\n") {
		// 形如 "MemTotal:       16384256 kB"
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		kb, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			continue
		}
		switch {
		case strings.HasPrefix(fields[0], "MemTotal:"):
			total = kb
		case strings.HasPrefix(fields[0], "MemAvailable:"):
			avail = kb
		}
	}
	if total <= 0 || avail > total {
		return nil
	}
	const kb = 1.0 / 1024
	return &memJSON{UsedMB: (total - avail) * kb, TotalMB: total * kb}
}

func readLoadAvg() *loadJSON {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return nil
	}
	return parseLoadAvg(data)
}

func readMemInfo() *memJSON {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return nil
	}
	return parseMemInfo(data)
}

// countFDs 当前进程打开的文件描述符数；非 Linux 或读取失败返回 0（面板不显示）
func countFDs() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0
	}
	return len(entries)
}

// cpuBase 进程 CPU 采样的基线。面板每 2 秒轮一次，两次之间的 utime+stime 差
// 就是这段时间的占用；首次采样没有基线，返回 0。
type cpuBase struct {
	ticks uint64
	wall  time.Time
	armed bool
}

var (
	cpuMu  sync.Mutex
	cpuBsn cpuBase
)

// parseProcStatCPU 从 /proc/<pid>/stat 内容里取 utime+stime（单位 CLK_TCK）。
// 单独拆出来便于用合成数据做单测。
func parseProcStatCPU(data []byte) (uint64, bool) {
	// comm（第 2 列）允许含空格与括号，只能在**最后一个** ')' 之后按空格切分
	idx := strings.LastIndexByte(string(data), ')')
	if idx < 0 || idx+2 > len(data) {
		return 0, false
	}
	fields := strings.Fields(string(data)[idx+2:])
	// 切分后第 1 列对应 stat 第 3 列(state)，故 utime/stime 是第 12/13 列
	if len(fields) < 13 {
		return 0, false
	}
	utime, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return 0, false
	}
	stime, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return 0, false
	}
	return utime + stime, true
}

// readProcCPU 本进程 CPU 占用（单位：单核百分比，即 100 = 跑满一核）。
// 非 Linux 或读取失败返回 nil，面板不渲染该行。
func readProcCPU() *cpuJSON {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return nil
	}
	ticks, ok := parseProcStatCPU(data)
	if !ok {
		return nil
	}
	now := time.Now()
	cpuMu.Lock()
	defer cpuMu.Unlock()
	out := &cpuJSON{}
	if cpuBsn.armed {
		elapsed := now.Sub(cpuBsn.wall).Seconds()
		if elapsed > 0 && ticks >= cpuBsn.ticks {
			const clkTck = 100.0 // Linux 默认 HZ，utime/stime 的计数单位
			out.Percent = float64(ticks-cpuBsn.ticks) / clkTck / elapsed * 100.0
		}
	}
	cpuBsn.ticks = ticks
	cpuBsn.wall = now
	cpuBsn.armed = true
	return out
}
