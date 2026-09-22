//go:build linux
// +build linux

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ifaNoDAD 关闭 DAD：隧道地址由对端显式分配、网关由配置指定，不存在需要
// 探测的重复地址。挂上即 permanent，第一轮 web 绑定不用白等内核 1~2s 的
// 探测窗口（等不到 RA 时地址会一直停在 tentative，v6 bind 永久失败）。
const ifaNoDAD = unix.IFA_F_NODAD

// netlinkTunnelSupported 报告本平台能否配置隧道网卡（MAC/地址/策略路由）。
// 非 Linux 上这些函数都是编译桩，调用方据此跳过而不是每次握手按失败告警。
func netlinkTunnelSupported() bool { return true }

// ======================= TCP Brutal & RTT 探测 =======================
// brutalAvailableAlgos 每次读取实时列表；模块可在进程运行期间加载/卸载，面板
// 不能把启动时的“不支持”永久缓存。读不到时返回 nil，apply 仍直接尝试 sockopt。
func brutalAvailableAlgos() []string {
	data, err := os.ReadFile("/proc/sys/net/ipv4/tcp_available_congestion_control")
	if err != nil {
		return nil
	}
	return strings.Fields(string(data))
}

// brutalStatus 定义在 api.go（两平台共用），这里只给 Linux 实现读内核值的逻辑。
// 类型不能放 tap_other.go / net_linux.go 任何一边——带 build tag 的文件在另一侧
// 不参与编译，跨平台的类型放那里会让其中一侧直接编不过。

// brutalSystemStatus 系统级状态：内核是否提供 brutal 算法、全局当前算法、
// 以及完整可用列表。面板用它区分"配置了但内核不支持"与"配置了且生效中"。
func brutalSystemStatus() brutalStatus {
	st := brutalStatus{available: brutalAvailableAlgos()}
	cur, curErr := os.ReadFile("/proc/sys/net/ipv4/tcp_congestion_control")
	st.current = strings.TrimSpace(string(cur))
	if curErr != nil {
		st.err = fmt.Sprintf("cannot read tcp_congestion_control: %v", curErr)
	}
	for _, a := range st.available {
		if a == "brutal" {
			st.supported = true
		}
	}
	return st
}

type linuxBrutalSocket struct{ fd int }

func mapBrutalSockoptError(err error) error {
	if err == unix.EPERM {
		return fmt.Errorf("%w: %v", errBrutalLocked, err)
	}
	return err
}

func (s linuxBrutalSocket) setCongestion(algo string) error {
	return mapBrutalSockoptError(unix.SetsockoptString(s.fd, unix.IPPROTO_TCP, unix.TCP_CONGESTION, algo))
}

func (s linuxBrutalSocket) getCongestion() (string, error) {
	return unix.GetsockoptString(s.fd, unix.IPPROTO_TCP, unix.TCP_CONGESTION)
}

func (s linuxBrutalSocket) getVersion() (uint32, error) {
	v, err := unix.GetsockoptInt(s.fd, unix.IPPROTO_TCP, tcpBrutalVersionOption)
	if err == unix.ENOPROTOOPT {
		return 0, errBrutalNoVersion
	}
	return uint32(v), err
}

func (s linuxBrutalSocket) setParams(b []byte) error {
	if len(b) == 0 {
		return unix.EINVAL
	}
	_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(s.fd), unix.IPPROTO_TCP,
		tcpBrutalParamsOption, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0)
	if errno != 0 {
		return mapBrutalSockoptError(errno)
	}
	return nil
}

func (s linuxBrutalSocket) getParams(size int) ([]byte, error) {
	if size != 12 && size != 20 {
		return nil, unix.EINVAL
	}
	b := make([]byte, size)
	n := uint32(size)
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(s.fd), unix.IPPROTO_TCP,
		tcpBrutalParamsOption, uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&n)), 0)
	if errno != 0 {
		return nil, mapBrutalSockoptError(errno)
	}
	if int(n) != size {
		return nil, fmt.Errorf("TCP_BRUTAL_PARAMS returned %d bytes, want %d", n, size)
	}
	return b, nil
}

func applyTCPBrutal(conn *net.TCPConn, totalRate, legacyRate, groupID uint64) brutalApplyResult {
	// 经由 SOCKS5 代理时拿不到端到端的 TCP 句柄，此处直接跳过内核调优
	if conn == nil {
		return brutalApplyResult{Error: "no raw TCP connection available (proxied?)"}
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return brutalApplyResult{Attempted: true, Error: err.Error()}
	}
	var result brutalApplyResult
	err = raw.Control(func(fd uintptr) {
		result = configureTCPBrutal(linuxBrutalSocket{fd: int(fd)}, totalRate, legacyRate, groupID)
	})
	if err != nil {
		return brutalApplyResult{Attempted: true, Error: err.Error()}
	}
	return result
}

func getTCPRTT(conn *net.TCPConn) (uint32, error) {
	if conn == nil {
		return 0, fmt.Errorf("no raw TCP connection available (proxied?)")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var rtt uint32
	var sysErr error
	err = raw.Control(func(fd uintptr) {
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if err == nil {
			rtt = info.Rtt
		} else {
			sysErr = err
		}
	})
	if err != nil {
		return 0, err
	}
	return rtt, sysErr
}

func startRTTPoller(ctx context.Context, conn *net.TCPConn, rttCache *uint32) {
	// 代理模式下无法读取内核 TCP_INFO，保持 rttCache 的默认估值即可
	if conn == nil {
		return
	}
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if rtt, err := getTCPRTT(conn); err == nil && rtt > 0 {
				atomic.StoreUint32(rttCache, rtt)
			}
		}
	}
}

// ======================= 网络接口配置 =======================
func setTapMac(tapName, macStr string) error {
	if macStr == "" {
		return nil
	}
	hwAddr, err := net.ParseMAC(macStr)
	if err != nil {
		return fmt.Errorf("invalid MAC format: %v", err)
	}
	link, err := netlink.LinkByName(tapName)
	if err != nil {
		return fmt.Errorf("tap %s not found: %v", tapName, err)
	}

	if len(hwAddr) > 0 && (hwAddr[0]&1) == 1 {
		return fmt.Errorf("cannot assign multicast/broadcast MAC address: %s", macStr)
	}

	netlink.LinkSetDown(link) // 拦截修改期间的网络占用
	if err := netlink.LinkSetHardwareAddr(link, hwAddr); err != nil {
		return fmt.Errorf("failed to set MAC address: %v", err)
	}
	log.Infof("Interface %s MAC set to %s", tapName, macStr)
	return nil
}

// removePolicyRules 删掉本进程为 fwmark 装的全部 ip rule，返回实际删除条数。
// 不依赖 priority 匹配：热更改了优先级后旧规则的原值已经不在配置里，按
// mark+table 定位才不会漏删。规则本就不存在（首次安装）时返回 0、无错误。
func removePolicyRules(mark int) (int, error) {
	if mark <= 0 {
		return 0, nil
	}
	removed := 0
	var errs []string
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			errs = append(errs, fmt.Sprintf("rule list (family=%d): %v", family, err))
			continue
		}
		for _, r := range rules {
			if r.Mark != uint32(mark) || r.Table != mark {
				continue
			}
			if err := netlink.RuleDel(&r); err != nil {
				errs = append(errs, fmt.Sprintf("rule del (family=%d): %v", family, err))
				continue
			}
			removed++
		}
	}
	if len(errs) > 0 {
		return removed, fmt.Errorf("policy routing: %s", strings.Join(errs, "; "))
	}
	return removed, nil
}

// removeSourceRules 删掉本进程为 source_rules 装的 ip rule。同样不依赖 priority：
// 热更改了优先级后旧规则的原值已经不在配置里，按 src+table 定位才不会漏删。
func removeSourceRules(rules []SourceRule) (int, error) {
	removed := 0
	var errs []string
	for _, r := range rules {
		prefix, err := netlink.ParseIPNet(r.From)
		if err != nil {
			errs = append(errs, fmt.Sprintf("rule del: invalid prefix %q: %v", r.From, err))
			continue
		}
		family := netlink.FAMILY_V4
		if prefix.IP.To4() == nil {
			family = netlink.FAMILY_V6
		}
		list, err := netlink.RuleList(family)
		if err != nil {
			errs = append(errs, fmt.Sprintf("rule list (family=%d): %v", family, err))
			continue
		}
		for _, exist := range list {
			if exist.Table != r.Table || exist.Src == nil {
				continue
			}
			// IPNet 含两个切片字段，结构体和掩码都不能直接 == 比较。
			if exist.Src.String() != prefix.String() {
				continue
			}
			if err := netlink.RuleDel(&exist); err != nil {
				errs = append(errs, fmt.Sprintf("rule del (family=%d): %v", family, err))
				continue
			}
			removed++
		}
	}
	if len(errs) > 0 {
		return removed, fmt.Errorf("policy routing: %s", strings.Join(errs, "; "))
	}
	return removed, nil
}

// parsePolicyRoute 把一条 extra 路由解析成 netlink 路由项并归位到指定表。
// 未写 dev 时默认走隧道网卡，因为整张表本来就是隧道表。
func parsePolicyRoute(link netlink.Link, table int, raw string) (*netlink.Route, error) {
	prefix, dev, err := parseRouteSpec(raw)
	if err != nil {
		return nil, fmt.Errorf("extra route %q: %v", raw, err)
	}
	linkIdx := link.Attrs().Index
	if dev != "" {
		devLink, derr := netlink.LinkByName(dev)
		if derr != nil {
			return nil, fmt.Errorf("extra route %q: dev %q not found: %v", raw, dev, derr)
		}
		linkIdx = devLink.Attrs().Index
	}
	_, ipnet, perr := net.ParseCIDR(prefix)
	if perr != nil {
		return nil, fmt.Errorf("extra route %q: invalid prefix %q", raw, prefix)
	}
	family := netlink.FAMILY_V4
	if ipnet.IP.To4() == nil {
		family = netlink.FAMILY_V6
	}
	return &netlink.Route{LinkIndex: linkIdx, Dst: ipnet, Table: table, Family: family}, nil
}

// setupPolicyRouting 安装两类独立的策略路由：
//   - fwmark 规则（表号 == mark 值），配合本进程 socket 的 SO_MARK；
//   - source_rules（ip rule from <prefix> table N），按源地址匹配。
//
// 后者用于转发流量：内核转发的包没有 socket，SO_MARK 碰不到，只能按地址或
// 由 netfilter 注入的 mark 匹配。两类规则互不依赖，任一配置了即需启动。
func setupPolicyRouting(tapName string, spec policyRoutingSpec) error {
	if spec.mark <= 0 && len(spec.sourceRules) == 0 {
		return nil
	}
	// 不等待接口出现，理由见 Client.setupInterface；规则装失败会记入返回值
	link, err := netlink.LinkByName(tapName)
	if err != nil {
		return fmt.Errorf("tap %s not available: %w", tapName, err)
	}
	// 先清后装保证幂等：重启/热更后旧规则还在，直接 add 可能撞 "File exists"。
	if _, err := removePolicyRules(spec.mark); err != nil {
		return err
	}
	if _, err := removeSourceRules(spec.sourceRules); err != nil {
		return err
	}
	var errs []string
	errs = append(errs, setupFwmarkRoutes(link, spec)...)
	errs = append(errs, setupSourceRuleRoutes(link, spec)...)
	if len(errs) > 0 {
		return fmt.Errorf("policy routing: %s", strings.Join(errs, "; "))
	}
	priority := "auto"
	if spec.priority != 0 {
		priority = strconv.FormatUint(uint64(spec.priority), 10)
	}
	log.Infof("🔀 Policy routing configured (fwmark: %d table %d priority %s, extra %d; source rules: %d)",
		spec.mark, spec.mark, priority, len(spec.extra), len(spec.sourceRules))
	return nil
}

// setupFwmarkRoutes 装 fwmark 规则及其表内路由，返回该步的错误列表。
func setupFwmarkRoutes(link netlink.Link, spec policyRoutingSpec) []string {
	if spec.mark <= 0 {
		return nil
	}
	var errs []string
	addRule := func(family int) {
		rule := netlink.NewRule()
		rule.Mark, rule.Table, rule.Family = uint32(spec.mark), spec.mark, family
		if spec.priority != 0 {
			rule.Priority = int(spec.priority)
		}
		if err := netlink.RuleAdd(rule); err != nil {
			errs = append(errs, fmt.Sprintf("rule add (family=%d): %v", family, err))
		}
	}
	replaceDefault := func(gwStr string, family int) {
		if gwStr == "" {
			return
		}
		gw := net.ParseIP(gwStr)
		if gw == nil {
			errs = append(errs, fmt.Sprintf("route replace: invalid gateway %q", gwStr))
			return
		}
		addRule(family)
		if err := netlink.RouteReplace(&netlink.Route{
			LinkIndex: link.Attrs().Index, Gw: gw, Table: spec.mark, Family: family,
		}); err != nil {
			errs = append(errs, fmt.Sprintf("route replace default via %s (family=%d): %v", gwStr, family, err))
		}
	}
	replaceDefault(spec.gwV4, netlink.FAMILY_V4)
	replaceDefault(spec.gwV6, netlink.FAMILY_V6)
	for _, raw := range spec.extra {
		route, err := parsePolicyRoute(link, spec.mark, raw)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		addRule(route.Family)
		if err := netlink.RouteReplace(route); err != nil {
			errs = append(errs, fmt.Sprintf("route replace %s: %v", raw, err))
		}
	}
	return errs
}

// setupSourceRuleRoutes 逐条装 ip rule from <prefix> table N 及其表内路由。
// 默认路由仍按握手下发的网关写入，和 fwmark 表共用同一份网关值。
//
// 规则只装到 from 自己的地址族：netlink 会拒绝把 IPv6 前缀装进 AF_INET 规则
// （RTNETLINK answers: Invalid argument）。removeSourceRules 也按前缀判族，
// 两边必须一致，否则会装出一条清理路径删不掉的规则。
func setupSourceRuleRoutes(link netlink.Link, spec policyRoutingSpec) []string {
	var errs []string
	addRule := func(r SourceRule, family int) bool {
		prefix, err := netlink.ParseIPNet(r.From)
		if err != nil {
			errs = append(errs, fmt.Sprintf("rule add: invalid prefix %q: %v", r.From, err))
			return false
		}
		rule := netlink.NewRule()
		rule.Src, rule.Table, rule.Family = prefix, r.Table, family
		if r.Priority > 0 {
			rule.Priority = int(r.Priority)
		}
		if err := netlink.RuleAdd(rule); err != nil {
			errs = append(errs, fmt.Sprintf("rule add from %s table %d (family=%d): %v", r.From, r.Table, family, err))
			return false
		}
		return true
	}
	for _, r := range spec.sourceRules {
		prefix, err := netlink.ParseIPNet(r.From)
		if err != nil {
			errs = append(errs, fmt.Sprintf("source rule: invalid prefix %q: %v", r.From, err))
			continue
		}
		family, gateway, label := netlink.FAMILY_V4, spec.gwV4, "IPv4"
		if prefix.IP.To4() == nil {
			family, gateway, label = netlink.FAMILY_V6, spec.gwV6, "IPv6"
		}
		// 服务端没下发该族网关：规则命中后表里查不到默认路由，流量只会落回主表。
		// 静默跳过等于让整条规则失效而用户毫无察觉，必须报出来。
		if gateway == "" {
			errs = append(errs, fmt.Sprintf("source rule %s table %d: no %s gateway offered",
				r.From, r.Table, label))
			continue
		}
		gw := net.ParseIP(gateway)
		if gw == nil {
			errs = append(errs, fmt.Sprintf("source rule %s: invalid %s gateway %q",
				r.From, label, gateway))
			continue
		}
		// 规则先装一次就够了；表内的 extra 路由各自按前缀判族，不能反过来用它
		// 的族去装规则，也不能重复 RuleAdd（第二次会撞 File exists）。
		if !addRule(r, family) {
			continue
		}
		if err := netlink.RouteReplace(&netlink.Route{
			LinkIndex: link.Attrs().Index, Gw: gw, Table: r.Table, Family: family,
		}); err != nil {
			errs = append(errs, fmt.Sprintf("source rule %s: route replace default via %s (family=%d): %v",
				r.From, gateway, family, err))
		}
		for _, raw := range r.Routes {
			route, err := parsePolicyRoute(link, r.Table, raw)
			if err != nil {
				errs = append(errs, fmt.Sprintf("source rule %s: %v", r.From, err))
				continue
			}
			if err := netlink.RouteReplace(route); err != nil {
				errs = append(errs, fmt.Sprintf("source rule %s: route replace %s: %v", r.From, raw, err))
			}
		}
	}
	return errs
}

func cleanPolicyRouting(tapName string, spec policyRoutingSpec) {
	if spec.mark <= 0 && len(spec.sourceRules) == 0 {
		return
	}
	link, err := netlink.LinkByName(tapName)
	if err != nil {
		log.Warnf("policy routing cleanup: tap %s not found, skipping: %v", tapName, err)
		return
	}
	if _, err := removePolicyRules(spec.mark); err != nil {
		log.Warnf("policy routing cleanup: %v", err)
	}
	if _, err := removeSourceRules(spec.sourceRules); err != nil {
		log.Warnf("policy routing cleanup: %v", err)
	}
	delRoute := func(table int, gwStr string, family int) {
		if gwStr == "" {
			return
		}
		gw := net.ParseIP(gwStr)
		if gw == nil {
			return
		}
		if err := netlink.RouteDel(&netlink.Route{
			LinkIndex: link.Attrs().Index, Gw: gw, Table: table, Family: family,
		}); err != nil {
			log.Warnf("policy routing cleanup: route del default via %s table %d (family=%d): %v", gwStr, table, family, err)
		}
	}
	delRoute(spec.mark, spec.gwV4, netlink.FAMILY_V4)
	delRoute(spec.mark, spec.gwV6, netlink.FAMILY_V6)
	for _, raw := range spec.extra {
		route, err := parsePolicyRoute(link, spec.mark, raw)
		if err != nil {
			log.Warnf("policy routing cleanup: %v", err)
			continue
		}
		if err := netlink.RouteDel(route); err != nil {
			log.Warnf("policy routing cleanup: route del extra %s: %v", raw, err)
		}
	}
	for _, r := range spec.sourceRules {
		delRoute(r.Table, spec.gwV4, netlink.FAMILY_V4)
		delRoute(r.Table, spec.gwV6, netlink.FAMILY_V6)
		for _, raw := range r.Routes {
			route, err := parsePolicyRoute(link, r.Table, raw)
			if err != nil {
				log.Warnf("policy routing cleanup: source rule %s: %v", r.From, err)
				continue
			}
			if err := netlink.RouteDel(route); err != nil {
				log.Warnf("policy routing cleanup: source rule %s route del %s: %v", r.From, raw, err)
			}
		}
	}
	log.Infof("🧹 Policy routing cleaned up (fwmark: %d table %d; source rules: %d)",
		spec.mark, spec.mark, len(spec.sourceRules))
}
