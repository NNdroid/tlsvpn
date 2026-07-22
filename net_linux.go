//go:build linux
// +build linux

package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// ======================= TCP Brutal & RTT 探测 =======================
const TCP_BRUTAL_PARAMS = 23301

func applyTCPBrutal(conn *net.TCPConn, rateMbps uint64) error {
	if rateMbps == 0 {
		return fmt.Errorf("TCP Brutal rate cannot be 0")
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var sysErr error
	err = raw.Control(func(fd uintptr) {
		err := unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "brutal")
		if err != nil {
			sysErr = fmt.Errorf("TCP_CONGESTION=brutal 未生效: %v", err)
			return
		}
		rateBps := rateMbps * 1000 * 1000 / 8
		b := make([]byte, 12)
		binary.LittleEndian.PutUint64(b[0:8], rateBps)
		binary.LittleEndian.PutUint32(b[8:12], 20)
		_, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, fd, unix.IPPROTO_TCP, TCP_BRUTAL_PARAMS, uintptr(unsafe.Pointer(&b[0])), 12, 0)
		if errno != 0 {
			sysErr = fmt.Errorf("设置 TCP_BRUTAL_PARAMS 失败: %v", errno)
		}
	})
	if err != nil {
		return err
	}
	return sysErr
}

func getTCPRTT(conn *net.TCPConn) (uint32, error) {
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
