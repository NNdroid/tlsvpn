package main

import (
	"strings"
	"testing"
)

// TestQueuePriorityPref 优先级偏好纯函数：数值高者先；相等时两者皆 false
// （写循环保持原 select 随机竞争，零行为变化）。
func TestQueuePriorityPref(t *testing.T) {
	cases := []struct {
		name         string
		control, data int
		wantC, wantD bool
	}{
		{"control higher", 10, 5, true, false},
		{"data higher", 5, 10, false, true},
		{"equal", 10, 10, false, false},
		{"default pair control-first", defaultPriorityControl, defaultPriorityData, true, false},
		{"max bounds", maxFramePriority, 1, true, false},
		{"reversed max bounds", 1, maxFramePriority, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotC, gotD := queuePriorityPref(c.control, c.data)
			if gotC != c.wantC || gotD != c.wantD {
				t.Fatalf("queuePriorityPref(%d,%d)=(%v,%v) want (%v,%v)",
					c.control, c.data, gotC, gotD, c.wantC, c.wantD)
			}
		})
	}
}

// TestConfigPriorityDefaultsAndValidate 优先级字段默认值与范围校验：
// 0=未配置回落默认（控制优先）；越界（0/101）被拒并带字段名。
func TestConfigPriorityDefaultsAndValidate(t *testing.T) {
	// 0=未配置：applyDefaults 填充默认 10/5（控制优先）
	cfg := &Config{Mode: "client", PSK: "test-secret", Addr: "127.0.0.1:4000"}
	cfg.applyDefaults()
	if cfg.PriorityControl != defaultPriorityControl || cfg.PriorityData != defaultPriorityData {
		t.Fatalf("defaults not applied: got control=%d data=%d", cfg.PriorityControl, cfg.PriorityData)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if c, d := queuePriorityPref(cfg.PriorityControl, cfg.PriorityData); !c || d {
		t.Fatalf("default priorities should prefer control, got controlFirst=%v dataFirst=%v", c, d)
	}

	// 越界：0（等于"未配置"哨兵，禁止显式 0）与 >maxFramePriority 都要被拒
	for _, bad := range []struct {
		field string
		val   int
	}{
		{"priority_control", 0},
		{"priority_control", maxFramePriority + 1},
		{"priority_data", 0},
		{"priority_data", maxFramePriority + 1},
	} {
		c := &Config{Mode: "client", PSK: "test-secret", Addr: "127.0.0.1:4000"}
		c.applyDefaults()
		if bad.field == "priority_control" {
			c.PriorityControl = bad.val
		} else {
			c.PriorityData = bad.val
		}
		err := c.Validate()
		if err == nil {
			t.Fatalf("%s=%d must be rejected", bad.field, bad.val)
		}
		if !strings.Contains(err.Error(), bad.field) {
			t.Fatalf("%s=%d error %q missing field name", bad.field, bad.val, err)
		}
	}

	// 边界合法：1 与 maxFramePriority
	for _, ok := range []struct {
		control, data int
	}{
		{1, 1},
		{maxFramePriority, maxFramePriority},
		{maxFramePriority, 1},
		{1, maxFramePriority},
	} {
		c := &Config{Mode: "client", PSK: "test-secret", Addr: "127.0.0.1:4000"}
		c.applyDefaults()
		c.PriorityControl, c.PriorityData = ok.control, ok.data
		if err := c.Validate(); err != nil {
			t.Fatalf("boundary (%d,%d) rejected: %v", ok.control, ok.data, err)
		}
	}
}
