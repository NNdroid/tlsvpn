package main

import (
	"fmt"
	"net"
	"strings"
)

// parseRouteSpec 把 "fd99:10:5:8::/64 dev tap0" 这类 iproute2 序列化写法拆成
// 前缀和出接口。只覆盖本项目需要的最小集合：单个前缀 + 至多一个 dev，且 dev
// 必须紧跟前缀。多段或带 src/mtu/weight 等选项的写法一律按非法处理——配置期
// 报错永远好过静默配错。缺掩码的裸地址按主机路由补全（/32 或 /128），与 ip
// route 的推断一致。
//
// 不依赖 netlink，所以可以放在跨平台文件里直接单测；两个平台共用一份解析
// 语义，Rust 端按同样的最小集合实现。
func parseRouteSpec(raw string) (prefix, dev string, err error) {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return "", "", fmt.Errorf("entry must not be empty")
	}
	// 先校验前缀：写 "dev tap0" 这种漏前缀的串要报"前缀非法"，
	// 而不是被当成选项报错、让用户对着接口名犯迷糊。
	prefix, err = normalizePrefix(fields[0])
	if err != nil {
		return "", "", err
	}
	rest := fields[1:]
	for len(rest) > 0 {
		if rest[0] == "dev" {
			if dev != "" {
				return "", "", fmt.Errorf(`duplicate "dev" option`)
			}
			if len(rest) < 2 {
				return "", "", fmt.Errorf(`"dev" requires an interface name`)
			}
			dev, rest = rest[1], rest[2:]
			continue
		}
		return "", "", fmt.Errorf(`unsupported option %q`, rest[0])
	}
	return prefix, dev, nil
}

// normalizePrefix 把 "fd99:10:5:8::/64" 或裸地址 "fd99:10:5:8::2" 规范成带掩码
// 的前缀；裸地址按主机路由补全（/32 或 /128），与 ip route 的推断一致。
func normalizePrefix(raw string) (string, error) {
	if _, _, err := net.ParseCIDR(raw); err == nil {
		return raw, nil
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return "", fmt.Errorf("invalid prefix %q", raw)
	}
	bits := 128
	if ip.To4() != nil {
		bits = 32
	}
	return fmt.Sprintf("%s/%d", ip.String(), bits), nil
}

// validateExtraRoutes 在配置加载期就拦住写坏的路由串，而不是等握手后才发现。
// 与 parseRouteSpec 一样跨平台：语法对不对与在哪个系统上运行无关，两个平台
// 都必须给出同一条报错。
func validateExtraRoutes(routes []string) error {
	for _, raw := range routes {
		if _, _, err := parseRouteSpec(raw); err != nil {
			return fmt.Errorf("client.extra_routes %q: %v", raw, err)
		}
	}
	return nil
}

// validateSourceRules 在配置加载期拦住写坏的按源前缀规则。和 validateExtraRoutes
// 一样跨平台：语法对不对与在哪个系统上运行无关，两个平台必须给出同一条报错。
//
// from 会就地补全成带掩码的形式，让后续安装逻辑不再需要自己判断裸地址。
func validateSourceRules(rules []SourceRule) error {
	for i := range rules {
		r := &rules[i]
		prefix, err := normalizePrefix(strings.TrimSpace(r.From))
		if err != nil {
			return fmt.Errorf("client.source_rules[%d].from: %v", i, err)
		}
		r.From = prefix
		// 表号空间同 iproute2，但 253/254/255 是 default/main/local 三个保留表，
		// 写进去等于往内核表里塞东西，必须拒绝。
		if r.Table < 1 || r.Table > 65535 || r.Table == 253 || r.Table == 254 || r.Table == 255 {
			return fmt.Errorf("client.source_rules[%d].table %d must be in [1, 65535] and not the reserved 253/254/255", i, r.Table)
		}
		if r.Priority < 0 || int(uint32(r.Priority)) != r.Priority {
			return fmt.Errorf("client.source_rules[%d].priority %d must be a uint32 in [0, 4294967295]", i, r.Priority)
		}
		for _, raw := range r.Routes {
			if _, _, err := parseRouteSpec(raw); err != nil {
				return fmt.Errorf("client.source_rules[%d].routes %q: %v", i, raw, err)
			}
		}
	}
	return nil
}
