//go:build linux
// +build linux

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
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
const TCP_BRUTAL_PARAMS = 23301

var (
	brutalAvailOnce sync.Once
	brutalAvail     []string
)

// brutalAvailableAlgos 内核提供的拥塞控制算法列表（运行期不变），读一次缓存。
// 读不到（容器禁 /proc 之类）时返回 nil，调用方按"未知"处理，不阻断 apply 尝试。
func brutalAvailableAlgos() []string {
	brutalAvailOnce.Do(func() {
		data, err := os.ReadFile("/proc/sys/net/ipv4/tcp_available_congestion_control")
		if err != nil {
			return
		}
		brutalAvail = strings.Fields(string(data))
	})
	return brutalAvail
}

// brutalStatus 定义在 tap_other.go（两个平台共享的公共结构），这里只给 Linux
// 实现读内核值的逻辑。

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

func applyTCPBrutal(conn *net.TCPConn, rateMbps uint64) error {
	// 经由 SOCKS5 代理时拿不到端到端的 TCP 句柄，此处直接跳过内核调优
	if conn == nil {
		return fmt.Errorf("no raw TCP connection available (proxied?)")
	}
	if rateMbps == 0 {
		return fmt.Errorf("TCP Brutal rate cannot be 0")
	}
	avail := brutalAvailableAlgos()
	if avail != nil {
		found := false
		for _, a := range avail {
			if a == "brutal" {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("kernel has no 'brutal' congestion control: %s", strings.Join(avail, ","))
		}
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sysErr error
	err = raw.Control(func(fd uintptr) {
		err := unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "brutal")
		if err != nil {
			sysErr = fmt.Errorf("TCP_CONGESTION=brutal failed: %v", err)
			return
		}
		rateBps := rateMbps * 1000 * 1000 / 8
		b := make([]byte, 12)
		binary.LittleEndian.PutUint64(b[0:8], rateBps)
		binary.LittleEndian.PutUint32(b[8:12], 20)
		_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, fd, unix.IPPROTO_TCP, TCP_BRUTAL_PARAMS, uintptr(unsafe.Pointer(&b[0])), 12, 0)
		if errno != 0 {
			sysErr = fmt.Errorf("TCP_BRUTAL_PARAMS failed: %v", errno)
		}
	})
	if err != nil {
		return err
	}
	return sysErr
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

func setupPolicyRouting(tapName string, mark int, gwV4, gwV6 string) error {
	if mark <= 0 {
		return nil
	}
	link, err := netlink.LinkByName(tapName)
	if err != nil {
		return err
	}
	setup := func(gwStr string, family int) {
		if gwStr == "" {
			return
		}
		gw := net.ParseIP(gwStr)
		rule := netlink.NewRule()
		rule.Mark, rule.Table, rule.Family = uint32(mark), mark, family
		netlink.RuleDel(rule)
		netlink.RuleAdd(rule)
		route := &netlink.Route{LinkIndex: link.Attrs().Index, Gw: gw, Table: mark}
		netlink.RouteReplace(route)
	}
	setup(gwV4, netlink.FAMILY_V4)
	setup(gwV6, netlink.FAMILY_V6)
	log.Infof("🔀 Policy routing configured (fwmark: %d)", mark)
	return nil
}

func cleanPolicyRouting(tapName string, mark int, gwV4, gwV6 string) {
	if mark <= 0 {
		return
	}
	link, err := netlink.LinkByName(tapName)
	if err != nil {
		return
	}
	cleanup := func(gwStr string, family int) {
		if gwStr == "" {
			return
		}
		gw := net.ParseIP(gwStr)
		rule := netlink.NewRule()
		rule.Mark, rule.Table, rule.Family = uint32(mark), mark, family
		netlink.RuleDel(rule)
		route := &netlink.Route{LinkIndex: link.Attrs().Index, Gw: gw, Table: mark}
		netlink.RouteDel(route)
	}
	cleanup(gwV4, netlink.FAMILY_V4)
	cleanup(gwV6, netlink.FAMILY_V6)
}
