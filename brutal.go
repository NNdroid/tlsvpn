package main

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	tcpBrutalParamsOption  = 23301
	tcpBrutalVersionOption = 23302
	brutalV2Version        = 0x020000
	brutalDefaultCwndGain  = 20
	// Upstream caps max_pacing_rate at 125 GB/s (1 Tbit/s).
	maxBrutalRateMbps = 1_000_000
)

var (
	errBrutalLocked    = errors.New("TCP Brutal parameters are managed by a locked rule")
	errBrutalNoVersion = errors.New("TCP Brutal version option is unavailable")
)

// brutalApplyResult is the observed state of one physical TCP connection.
// Empty Error never implies success: callers must check Applied explicitly.
type brutalApplyResult struct {
	Attempted   bool
	Applied     bool
	RuleManaged bool
	Version     uint32
	RateBps     uint64
	RateMbps    uint64
	CwndGain    uint32
	GroupID     uint64
	Error       string
}

func (r brutalApplyResult) clone() *brutalApplyResult {
	c := r
	return &c
}

func brutalMbpsToBps(rateMbps uint64) (uint64, error) {
	if rateMbps == 0 {
		return 0, fmt.Errorf("TCP Brutal rate cannot be 0")
	}
	if rateMbps > maxBrutalRateMbps {
		return 0, fmt.Errorf("TCP Brutal rate %d Mbps exceeds maximum %d Mbps", rateMbps, maxBrutalRateMbps)
	}
	return rateMbps * 1_000_000 / 8, nil
}

func brutalBpsToMbps(rateBps uint64) uint64 {
	return rateBps * 8 / 1_000_000
}

func encodeBrutalParams(rateMbps uint64, gain uint32, groupID uint64, withGroup bool) ([]byte, error) {
	rateBps, err := brutalMbpsToBps(rateMbps)
	if err != nil {
		return nil, err
	}
	return encodeBrutalParamsBps(rateBps, gain, groupID, withGroup)
}

func encodeBrutalParamsBps(rateBps uint64, gain uint32, groupID uint64, withGroup bool) ([]byte, error) {
	if rateBps == 0 || rateBps > maxBrutalRateMbps*1_000_000/8 {
		return nil, fmt.Errorf("TCP Brutal byte rate %d is outside the supported range", rateBps)
	}
	sz := 12
	if withGroup {
		sz = 20
	}
	b := make([]byte, sz)
	binary.LittleEndian.PutUint64(b[0:8], rateBps)
	binary.LittleEndian.PutUint32(b[8:12], gain)
	if withGroup {
		binary.LittleEndian.PutUint64(b[12:20], groupID)
	}
	return b, nil
}

func decodeBrutalParams(b []byte) (rateMbps uint64, gain uint32, groupID uint64, err error) {
	rateBps, gain, groupID, err := decodeBrutalParamsBps(b)
	return brutalBpsToMbps(rateBps), gain, groupID, err
}

func decodeBrutalParamsBps(b []byte) (rateBps uint64, gain uint32, groupID uint64, err error) {
	if len(b) != 12 && len(b) != 20 {
		return 0, 0, 0, fmt.Errorf("invalid TCP_BRUTAL_PARAMS length %d", len(b))
	}
	rateBps = binary.LittleEndian.Uint64(b[0:8])
	gain = binary.LittleEndian.Uint32(b[8:12])
	if len(b) == 20 {
		groupID = binary.LittleEndian.Uint64(b[12:20])
	}
	return rateBps, gain, groupID, nil
}

// splitLegacyBrutalRate computes the whole-Mbps distribution used for display.
// The actual v1 kernel ABI uses splitLegacyBrutalRateBps so sub-Mbps shares stay
// shaped and the configured aggregate remains byte-exact.
func splitLegacyBrutalRate(total uint64, conns, index int) uint64 {
	if total == 0 || conns <= 0 || index < 0 || index >= conns {
		return 0
	}
	base := total / uint64(conns)
	if uint64(index) < total%uint64(conns) {
		base++
	}
	return base
}

func splitLegacyBrutalRateBps(totalMbps uint64, conns, index int) uint64 {
	if totalMbps == 0 || conns <= 0 || index < 0 || index >= conns {
		return 0
	}
	totalBps := totalMbps * 1_000_000 / 8
	base := totalBps / uint64(conns)
	if uint64(index) < totalBps%uint64(conns) {
		base++
	}
	return base
}

// brutalGroupID creates a stable process/session-local kernel group without
// exposing identity material. Domain separation prevents client and server
// sockets in the same network namespace from accidentally sharing a group.
func brutalGroupID(domain, identity string) uint64 {
	sum := sha256.Sum256([]byte("tlsvpn/brutal/" + domain + "\x00" + identity))
	id := binary.LittleEndian.Uint64(sum[:8])
	if id == 0 {
		id = 1
	}
	return id
}

type brutalSocketOps interface {
	setCongestion(string) error
	getCongestion() (string, error)
	getVersion() (uint32, error)
	setParams([]byte) error
	getParams(int) ([]byte, error)
}

func restoreCongestion(ops brutalSocketOps, previous string) {
	if previous != "" && previous != "brutal" {
		_ = ops.setCongestion(previous)
	}
}

func readBrutalParams(ops brutalSocketOps, version uint32) (uint64, uint32, uint64, error) {
	sz := 12
	if version >= brutalV2Version {
		sz = 20
	}
	b, err := ops.getParams(sz)
	if err != nil {
		return 0, 0, 0, err
	}
	return decodeBrutalParamsBps(b)
}

// configureTCPBrutal contains the ABI/fallback state machine and is unit-testable
// without a Linux kernel. totalRate is used by v2 groups; legacyRate is the exact
// per-connection share used by v1 modules.
func configureTCPBrutal(ops brutalSocketOps, totalRate, legacyRateBps, groupID uint64) brutalApplyResult {
	result := brutalApplyResult{Attempted: true, CwndGain: brutalDefaultCwndGain}
	if totalRate == 0 {
		result.Error = "TCP Brutal rate cannot be 0"
		return result
	}
	if _, err := brutalMbpsToBps(totalRate); err != nil {
		result.Error = err.Error()
		return result
	}
	previous, _ := ops.getCongestion()
	if err := ops.setCongestion("brutal"); err != nil {
		if !errors.Is(err, errBrutalLocked) {
			result.Error = fmt.Sprintf("TCP_CONGESTION=brutal failed: %v", err)
			return result
		}
		current, getErr := ops.getCongestion()
		if getErr != nil || current != "brutal" {
			result.Error = fmt.Sprintf("TCP_CONGESTION is rule-locked and current algorithm is %q", current)
			return result
		}
		result.RuleManaged = true
	}

	version, err := ops.getVersion()
	if err != nil && !errors.Is(err, errBrutalNoVersion) {
		restoreCongestion(ops, previous)
		result.Error = fmt.Sprintf("TCP_BRUTAL_VERSION failed: %v", err)
		return result
	}
	result.Version = version
	useGroup := version >= brutalV2Version && groupID != 0
	rateBps := legacyRateBps
	if useGroup {
		rateBps, _ = brutalMbpsToBps(totalRate)
		result.GroupID = groupID
	}
	if rateBps == 0 {
		restoreCongestion(ops, previous)
		result.Error = "TCP Brutal legacy share is 0 Mbps; connection left unshaped to preserve the total limit"
		return result
	}
	params, err := encodeBrutalParamsBps(rateBps, brutalDefaultCwndGain, result.GroupID, useGroup)
	if err != nil {
		restoreCongestion(ops, previous)
		result.Error = err.Error()
		return result
	}
	if err := ops.setParams(params); err != nil {
		if !errors.Is(err, errBrutalLocked) {
			restoreCongestion(ops, previous)
			result.Error = fmt.Sprintf("TCP_BRUTAL_PARAMS failed: %v", err)
			return result
		}
		result.RuleManaged = true
	}

	actualRateBps, actualGain, actualGroup, readErr := readBrutalParams(ops, version)
	if readErr == nil {
		result.RateBps, result.CwndGain, result.GroupID = actualRateBps, actualGain, actualGroup
		result.RateMbps = brutalBpsToMbps(actualRateBps)
	} else if result.RuleManaged && errors.Is(readErr, errBrutalLocked) {
		// 锁定规则完全拥有参数，应用层既不能写也不能读。此时只能确认当前算法
		// 是 brutal，不能把请求值伪装成内核实际值；真正速率应从规则表观察。
		result.RateBps, result.RateMbps, result.GroupID = 0, 0, 0
		result.Error = "TCP Brutal is active under a locked rule; actual rate is unavailable from this socket"
	} else {
		// setParams 已成功时，读取失败不改变应用结果；保留请求值并暴露读取错误。
		result.RateBps, result.CwndGain = rateBps, brutalDefaultCwndGain
		result.RateMbps = brutalBpsToMbps(rateBps)
		result.Error = fmt.Sprintf("TCP Brutal parameters applied but readback failed: %v", readErr)
	}
	result.Applied = true
	return result
}
