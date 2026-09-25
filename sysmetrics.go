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
)

// loadJSON 系统 1/5/15 分钟平均负载
type loadJSON struct {
	One    float64 `json:"one"`
	Five   float64 `json:"five"`
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
