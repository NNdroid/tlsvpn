package main

import (
	"strconv"
	"strings"
	"testing"
)

func TestParseRouteSpec(t *testing.T) {
	cases := []struct {
		in        string
		prefix    string
		dev       string
		wantErr   bool
		errSubstr string
	}{
		{"192.0.2.0/24", "192.0.2.0/24", "", false, ""},
		{"fd99:10:5:8::/64 dev tap0", "fd99:10:5:8::/64", "tap0", false, ""},
		{"10.0.0.0/8 dev eth0", "10.0.0.0/8", "eth0", false, ""},
		// 缺掩码按主机路由补全，地址族决定是 /32 还是 /128
		{"203.0.113.7", "203.0.113.7/32", "", false, ""},
		{"2001:db8::1", "2001:db8::1/128", "", false, ""},
		// IPv4-mapped 写法归一化成普通 v4
		{"::ffff:203.0.113.9", "203.0.113.9/32", "", false, ""},
		// 多余空白与制表符
		{"  10.9.0.0/24\tdev tap0  ", "10.9.0.0/24", "tap0", false, ""},
		{"", "", "", true, "empty"},
		{"   ", "", "", true, "empty"},
		{"dev tap0", "", "", true, "invalid prefix"},
		{"192.0.2.0/24 dev", "", "", true, "requires an interface name"},
		{"192.0.2.0/24 999", "", "", true, "unsupported option"},
		{"192.0.2.0/24 src 10.0.0.1", "", "", true, "unsupported option"},
		{"192.0.2.0/24 dev tap0 dev eth0", "", "", true, "duplicate"},
		{"192.0.2.0/33", "", "", true, "invalid prefix"},
		{"banana", "", "", true, "invalid prefix"},
	}
	for _, c := range cases {
		prefix, dev, err := parseRouteSpec(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseRouteSpec(%q) 期望失败", c.in)
				continue
			}
			if c.errSubstr != "" && !strings.Contains(err.Error(), c.errSubstr) {
				t.Errorf("parseRouteSpec(%q) 错误信息 %q 不含 %q", c.in, err, c.errSubstr)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseRouteSpec(%q) 意外失败: %v", c.in, err)
			continue
		}
		if prefix != c.prefix || dev != c.dev {
			t.Errorf("parseRouteSpec(%q) = (%q, %q), want (%q, %q)", c.in, prefix, dev, c.prefix, c.dev)
		}
	}
}

// TestValidateExtraRoutes 校验在配置加载期生效，握手后才发现问题就太晚了。
func TestValidateExtraRoutes(t *testing.T) {
	if err := validateExtraRoutes(nil); err != nil {
		t.Fatalf("未配置额外路由应通过: %v", err)
	}
	if err := validateExtraRoutes([]string{"10.0.0.0/8", "fd00::/64 dev tap0"}); err != nil {
		t.Fatalf("合法列表应通过: %v", err)
	}
	bad := []string{"", "not-a-prefix", "10.0.0.0/8 src 1.1.1.1", "10.0.0.0/8 dev"}
	for _, raw := range bad {
		if err := validateExtraRoutes([]string{raw}); err == nil {
			t.Errorf("validateExtraRoutes(%q) 应失败", raw)
		}
	}
}

// TestValidateSourceRules 按源前缀规则在配置加载期就拦住写坏的值；
// 表号保留值 253/254/255 必须拒绝，那是内核自己的 default/main/local 表。
func TestValidateSourceRules(t *testing.T) {
	if err := validateSourceRules(nil); err != nil {
		t.Fatalf("未配置 source_rules 应通过: %v", err)
	}

	// 合法：前缀就地补全成带掩码的形式
	rules := []SourceRule{{From: "2001:db8::1", Table: 100, Routes: []string{"fd99:10:5:8::/64 dev tap0"}}}
	if err := validateSourceRules(rules); err != nil {
		t.Fatalf("合法 source_rules 应通过: %v", err)
	}
	if rules[0].From != "2001:db8::1/128" {
		t.Errorf("裸地址应补全为主机路由，得到 %q", rules[0].From)
	}

	valid := []SourceRule{
		{From: "2600:70ff:f0a1::/48", Table: 100, Priority: 1000},
		{From: "203.0.113.0/24", Table: 1, Priority: 0},
		{From: "203.0.113.7", Table: 65535},
	}
	for i := range valid {
		if err := validateSourceRules([]SourceRule{valid[i]}); err != nil {
			t.Errorf("合法条目 %v 应通过: %v", valid[i], err)
		}
	}

	bad := []SourceRule{
		{From: "", Table: 100},
		{From: "banana", Table: 100},
		{From: "2600:70ff:f0a1::/48", Table: 0},
		{From: "2600:70ff:f0a1::/48", Table: 65536},
		{From: "2600:70ff:f0a1::/48", Table: 253},
		{From: "2600:70ff:f0a1::/48", Table: 254},
		{From: "2600:70ff:f0a1::/48", Table: 255},
		{From: "2600:70ff:f0a1::/48", Table: 100, Priority: -1},
		{From: "2600:70ff:f0a1::/48", Table: 100, Routes: []string{"not-a-prefix"}},
	}
	for _, r := range bad {
		if err := validateSourceRules([]SourceRule{r}); err == nil {
			t.Errorf("非法条目 %v 应校验失败", r)
		}
	}
}

// TestClientPolicyRoutingConfigValidation fwmark_priority 是 uint32；负值与
// 超出回绕值都要被拦下，且错误信息里带上字段名便于用户定位。
func TestClientPolicyRoutingConfigValidation(t *testing.T) {
	cfg := &Config{Mode: "client", PSK: "k", Addr: "1.2.3.4:4000", Client: ClientConfig{Conns: 1}}
	cfg.applyDefaults()
	cfg.Client.Fwmark = 256
	cfg.Client.FwmarkPriority = 1000
	cfg.Client.ExtraRoutes = []string{"fd99:10:5:8::/64 dev tap0"}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("合法策略路由配置应通过: %v", err)
	}

	cfg.Client.FwmarkPriority = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("负数 fwmark_priority 应校验失败")
	} else if !strings.Contains(err.Error(), "client.fwmark_priority") {
		t.Errorf("错误信息应带字段名: %v", err)
	}

	// 上界用例需要 int 能装下 2^32；32 位平台上常量本身编不过，
	// 那里的 int 天然装不下越界值，越界无从发生。
	if strconv.IntSize == 32 {
		return
	}
	cfg.Client.FwmarkPriority = 4294967296
	if err := cfg.Validate(); err == nil {
		t.Fatal("超出 uint32 的 fwmark_priority 应校验失败")
	}
	cfg.Client.FwmarkPriority = 4294967295
	if err := cfg.Validate(); err != nil {
		t.Fatalf("uint32 上限值应通过: %v", err)
	}

	cfg.Client.FwmarkPriority = 1000
	cfg.Client.ExtraRoutes = []string{"not-a-prefix"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("写坏的 extra_routes 应校验失败")
	}

	// source_rules：表号省略时必须被拦下，因为它不像 fwmark 有可推导的默认值
	cfg.Client.ExtraRoutes = []string{"fd99:10:5:8::/64 dev tap0"}
	cfg.Client.SourceRules = []SourceRule{{From: "2600:70ff:f0a1::/48"}}
	if err := cfg.Validate(); err == nil {
		t.Fatal("缺表号的 source_rules 应校验失败")
	}
	cfg.Client.SourceRules = []SourceRule{{From: "2600:70ff:f0a1::/48", Table: 100, Priority: 1000}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("合法 source_rules 应通过: %v", err)
	}
}

// TestSamePolicySpec 策略路由的安装记录按"同一组规则"判定，而不是只按 mark：
// 否则热更时改了 source_rules 会把旧规则留在内核里。
func TestSamePolicySpec(t *testing.T) {
	base := policyRoutingSpec{mark: 0, sourceRules: []SourceRule{{From: "2001:db8::/32", Table: 100}}}
	if !samePolicySpec(base, base) {
		t.Error("完全相同的 spec 应判为同一组")
	}
	// 网关不参与判定：同一组规则在两次握手间可以换网关
	if !samePolicySpec(policyRoutingSpec{sourceRules: base.sourceRules, gwV4: "10.0.0.1"},
		policyRoutingSpec{sourceRules: base.sourceRules, gwV4: "10.0.0.2"}) {
		t.Error("仅网关不同应判为同一组")
	}
	if samePolicySpec(base, policyRoutingSpec{mark: 1}) {
		t.Error("mark 不同不应判为同一组")
	}
	if samePolicySpec(base, policyRoutingSpec{sourceRules: []SourceRule{{From: "2001:db8::/32", Table: 101}}}) {
		t.Error("表号不同不应判为同一组")
	}
	if samePolicySpec(base, policyRoutingSpec{sourceRules: []SourceRule{{From: "2001:db8::/32", Table: 100, Priority: 9}}}) {
		t.Error("优先级不同不应判为同一组")
	}
	if samePolicySpec(base, policyRoutingSpec{}) {
		t.Error("source_rules 条数不同不应判为同一组")
	}
}
