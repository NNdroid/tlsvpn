package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestQueuePriorityPref 优先级偏好纯函数：数值高者先；相等时两者皆 false
// （写循环保持原 select 随机竞争，零行为变化）。
func TestQueuePriorityPref(t *testing.T) {
	cases := []struct {
		name          string
		control, data int
		wantC, wantD  bool
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
// nil=未配置回落默认（控制优先）；显式 0 合法（最低优先级，不再当"未配置"）；
// 负值与 >maxFramePriority 越界被拒并带字段名。
func TestConfigPriorityDefaultsAndValidate(t *testing.T) {
	// nil=未配置：applyDefaults 填充默认 7/5（控制优先）
	cfg := &Config{Mode: "client", PSK: "test-only-high-entropy-secret", Addr: "127.0.0.1:4000"}
	cfg.applyDefaults()
	if cfg.PriorityControl == nil || *cfg.PriorityControl != defaultPriorityControl {
		t.Fatalf("control default not applied: got %v", cfg.PriorityControl)
	}
	if cfg.PriorityData == nil || *cfg.PriorityData != defaultPriorityData {
		t.Fatalf("data default not applied: got %v", cfg.PriorityData)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if c, d := queuePriorityPref(*cfg.PriorityControl, *cfg.PriorityData); !c || d {
		t.Fatalf("default priorities should prefer control, got controlFirst=%v dataFirst=%v", c, d)
	}

	// 越界：-1（负值）与 >maxFramePriority 都要被拒
	for _, bad := range []struct {
		field string
		val   int
	}{
		{"priority_control", -1},
		{"priority_control", maxFramePriority + 1},
		{"priority_data", -1},
		{"priority_data", maxFramePriority + 1},
	} {
		c := &Config{Mode: "client", PSK: "test-only-high-entropy-secret", Addr: "127.0.0.1:4000"}
		c.applyDefaults()
		v := bad.val
		if bad.field == "priority_control" {
			c.PriorityControl = &v
		} else {
			c.PriorityData = &v
		}
		err := c.Validate()
		if err == nil {
			t.Fatalf("%s=%d must be rejected", bad.field, bad.val)
		}
		if !strings.Contains(err.Error(), bad.field) {
			t.Fatalf("%s=%d error %q missing field name", bad.field, bad.val, err)
		}
	}

	// 边界合法：0（最低）与 maxFramePriority
	for _, ok := range []struct {
		control, data int
	}{
		{0, 0},
		{0, maxFramePriority},
		{maxFramePriority, 0},
		{1, 1},
		{maxFramePriority, maxFramePriority},
		{maxFramePriority, 1},
		{1, maxFramePriority},
	} {
		c := &Config{Mode: "client", PSK: "test-only-high-entropy-secret", Addr: "127.0.0.1:4000"}
		c.applyDefaults()
		ctl, dat := ok.control, ok.data
		c.PriorityControl, c.PriorityData = &ctl, &dat
		if err := c.Validate(); err != nil {
			t.Fatalf("boundary (%d,%d) rejected: %v", ok.control, ok.data, err)
		}
	}

	// 显式 0 必须被 applyDefaults 保留：指针非 nil 指向 0，不被覆盖成默认。
	zero := 0
	cfg2 := &Config{Mode: "client", PSK: "test-only-high-entropy-secret", Addr: "127.0.0.1:4000", PriorityControl: &zero, PriorityData: &zero}
	cfg2.applyDefaults()
	if cfg2.PriorityControl == nil || *cfg2.PriorityControl != 0 {
		t.Fatalf("explicit 0 overwritten by defaults: %v", cfg2.PriorityControl)
	}
	if c, d := queuePriorityPref(*cfg2.PriorityControl, *cfg2.PriorityData); c || d {
		t.Fatalf("equal priorities should fall back to select competition, got controlFirst=%v dataFirst=%v", c, d)
	}
}

// TestPriorityZeroJSONRoundTrip 显式 0 经 JSON 往返必须保留（面板编辑回传
// "priority_control:0" 不能被当成"未配置"覆盖成默认）。omitempty 对指向 0
// 的非 nil 指针不省略，这是 *int 区别于 int 的关键行为。
func TestPriorityZeroJSONRoundTrip(t *testing.T) {
	raw := []byte(`{"mode":"client","psk":"test-only-high-entropy-secret","addr":"127.0.0.1:4000","priority_control":0,"priority_data":0}`)
	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	c.applyDefaults()
	if c.PriorityControl == nil || *c.PriorityControl != 0 {
		t.Fatalf("explicit 0 lost after defaults: %v", c.PriorityControl)
	}
	out, err := json.Marshal(&c)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(out), `"priority_control":0`) || !strings.Contains(string(out), `"priority_data":0`) {
		t.Fatalf("zero not serialized back: %s", out)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("explicit-0 config rejected: %v", err)
	}
}
