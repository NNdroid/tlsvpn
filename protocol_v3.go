package main

import (
	"encoding/binary"
	"fmt"
)

// protocolVersion is the only application protocol version accepted by this
// implementation. v3 intentionally breaks compatibility with the older
// seq=0 magic-dispatch semantics: post-handshake seq=0 is now an explicit
// control plane with typed payloads.
// v4 binds the inner AEAD AAD to the frame header's padLen (data frames) and
// to the FEC parity descriptor (parity frames) — both were previously
// unauthenticated.
// v5 adds the 0x07 active-paths control frame: each side periodically
// broadcasts the connIndex bitmap its scheduler currently selected, so the
// peer's dashboard can mark the peer-active connections. Unknown control kinds
// tear down the session by design, so mixed v4/v5 pairs will not connect;
// upgrade both ends together.
const protocolVersion = 5

const (
	controlKindFECParity   byte = 0x01
	controlKindFECMode     byte = 0x02
	controlKindActivePaths byte = 0x07
)

// activePathsWireLen 0x07 帧载荷长度：[1B kind][2B connIndex 位图(BE)]。
// connIndex 由握手 BrutalConnIndex 同步（两端同槽位编号），位图 16 位覆盖
// maxConnectionsPerIP=16 的全部合法槽位。
const activePathsWireLen = 3

// appendActivePathsFrame 构建本端调度器活跃槽位位图帧。
func appendActivePathsFrame(dst []byte, bitmap uint16) []byte {
	buf := append(dst, make([]byte, activePathsWireLen)...)
	buf[0] = controlKindActivePaths
	binary.BigEndian.PutUint16(buf[1:3], bitmap)
	return buf
}

// parseActivePathsFrame 解析 0x07 帧；长度/类型不符返回 false。
func parseActivePathsFrame(payload []byte) (uint16, bool) {
	if len(payload) != activePathsWireLen || payload[0] != controlKindActivePaths {
		return 0, false
	}
	return binary.BigEndian.Uint16(payload[1:3]), true
}

// isActivePathsFrame 快速前置识别（读循环在 FEC 门控之前拦截）。
func isActivePathsFrame(payload []byte) bool {
	return len(payload) == activePathsWireLen && payload[0] == controlKindActivePaths
}

func parseControlKind(payload []byte) (byte, error) {
	if len(payload) == 0 {
		return 0, fmt.Errorf("empty payload is keepalive, not a typed control frame")
	}
	switch payload[0] {
	case controlKindFECParity, controlKindFECMode, controlKindActivePaths,
		controlKindRttProbe, controlKindRttReply,
		controlKindClockProbe, controlKindClockReply:
		return payload[0], nil
	default:
		return 0, fmt.Errorf("unsupported control kind 0x%02x", payload[0])
	}
}
