package main

import (
	"sync/atomic"
	"testing"
)

// TestServerEgressUsesForwardDirection 验证服务端 per-session port 的下行（egress）
// 选路使用的是**去程**单向时延（fwd = 服务端→客户端），与客户端上行 egress 用
// oneWayModeFwd（fwd = 客户端→服务端）语义对称。
//
// 用户语义约定：去程 = 本端发送到对端，回程 = 对端发送到本端。对服务端：
//   - fwd（服务端视角）= 服务端→客户端 = 服务端去程 = 服务端 egress 方向
//   - ret（服务端视角）= 客户端→服务端 = 服务端回程 = 服务端 ingress 方向
//
// 因此服务端下行 egress 选路必须用 oneWayModeFwd，而非 oneWayModeRet。
// 本测试在非对称时延下证明：oneWayModeRet 会选到"上行快但下行慢"的错误路径，
// oneWayModeFwd 才选出"下行快"的正确路径。
func TestServerEgressUsesForwardDirection(t *testing.T) {
	// 非对称时延（µs）：path0 下行（服务端→客户端）快 5µs、上行慢 10000µs；
	// path1 下行慢 5000µs、上行快 5µs。
	// 服务端下行应选 path0（下行快），但若用 ret（上行）会错选 path1。
	mk := func(fwd, ret int64) *Backend {
		b := &Backend{}
		// 选路读编码字段（recomputeAll 的发布路径）；显示字段与此测试无关。
		b.fwdRankUS.Store(oneWayRankEncode(fwd))
		b.retRankUS.Store(oneWayRankEncode(ret))
		mode := &atomic.Int32{}
		b.oneWayModePtr = mode
		return b
	}

	path0 := mk(5, 10000) // 下行快、上行慢
	path1 := mk(5000, 5)  // 下行慢、上行快

	// 当前 server.go 用的模式：oneWayModeRet（回程）。
	// 服务端视角 ret = 客户端→服务端 = 上行。会选"上行快"的 path1 —— 选错下行方向。
	path0.oneWayModePtr.Store(oneWayModeRet)
	path1.oneWayModePtr.Store(oneWayModeRet)
	if got0, got1 := adaptiveBackendOneWayUS(path0), adaptiveBackendOneWayUS(path1); got1 < got0 {
		t.Logf("[ret mode] selected path1 (up=fast), downlink actually slow: path0=%d path1=%d", got0, got1)
	} else {
		t.Fatalf("[ret mode] unexpected ordering path0=%d path1=%d", got0, got1)
	}

	// 正确模式：oneWayModeFwd（服务端视角 fwd = 服务端→客户端 = 下行）。
	path0.oneWayModePtr.Store(oneWayModeFwd)
	path1.oneWayModePtr.Store(oneWayModeFwd)
	if got0, got1 := adaptiveBackendOneWayUS(path0), adaptiveBackendOneWayUS(path1); got0 < got1 {
		t.Logf("[fwd mode] selected path0 (downlink fast): path0=%d path1=%d", got0, got1)
	} else {
		t.Fatalf("[fwd mode] downlink should pick path0 (fwd small), got path0=%d path1=%d", got0, got1)
	}
}
