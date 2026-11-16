package main

import (
	"sync/atomic"
	"testing"
)

// oneWayBackend 构造一个带单向时延估计（fwd/ret，µs）与 min_rtt 的合成后端，
// 模拟 WebUI 连接表里的真实路径。egress 方向按 oneWayModeFwd（客户端上行），
// 使 adaptiveBackendOneWayUS 使用 fwd 而非回退 min_rtt/2。选路值写入编码字段
// fwdRankUS/retRankUS（与 recomputeAll 发布路径一致），显示字段与此测试无关。
func oneWayBackend(minRTT, fwdUS, retUS uint32, rate uint64) *Backend {
	b := testAdaptiveBackend(minRTT)
	b.fwdRankUS.Store(oneWayRankEncode(int64(fwdUS)))
	b.retRankUS.Store(oneWayRankEncode(int64(retUS)))
	if rate > 0 {
		b.rateBytesPerSec.Store(rate)
	}
	var mode atomic.Int32
	mode.Store(oneWayModeFwd)
	b.oneWayModePtr = &mode
	return b
}

// TestAdaptiveSwitchToStrictlyBetterPath 切换核心：当前活跃路径之外存在一条
// egress 单向时延显著更好（> 滞回 slack）的健康路径时，调度器必须切换过去。
func TestAdaptiveSwitchToStrictlyBetterPath(t *testing.T) {
	p := &AsyncPort{}
	// 当前活跃：fwd=82ms（滞回 slack = clamp(168ms/16,0.5,5)=5ms）
	active := oneWayBackend(168_000, 82_000, 80_000, 30_000_000)
	// 更优候选：fwd=70ms，比活跃好 12ms（远超 5ms slack）
	better := oneWayBackend(166_000, 70_000, 90_000, 20_000_000)
	backends := []*Backend{active, better}

	// 锚定活跃路径后调度：显著更优者必须接管
	p.preferred.Store(active)
	got := p.pickAdaptiveBackend(backends, adaptiveActive2Pressure-1, 8*1024)
	if got != better {
		t.Fatalf("strictly-better path not adopted: got=%p want=%p (stuck on worse path)", got, better)
	}
	if !better.active.Load() {
		t.Fatal("better path not marked active after switch")
	}
	if active.active.Load() {
		t.Fatal("old active path still marked active after switch")
	}
}

// TestAdaptiveSwitchRejectsWithinStickySlack 滞回核心：更优候选只差 3ms（< 5ms
// slack）时，调度器必须保持当前路径，避免相邻批次来回切换。
func TestAdaptiveSwitchRejectsWithinStickySlack(t *testing.T) {
	p := &AsyncPort{}
	active := oneWayBackend(168_000, 82_000, 80_000, 30_000_000)
	slightlyBetter := oneWayBackend(166_000, 79_000, 90_000, 20_000_000) // 好 3ms < 5ms
	backends := []*Backend{active, slightlyBetter}

	p.preferred.Store(active)
	got := p.pickAdaptiveBackend(backends, adaptiveActive2Pressure-1, 8*1024)
	if got != active {
		t.Fatalf("within sticky slack must not switch: got=%p want=%p", got, active)
	}
}

// TestAdaptiveSwitchToBetterBeyondSlackBoundary 滞回边界：候选比活跃好 6ms
// （> 5ms 封顶 slack）时必须切换；正好卡在边界 5ms 时可保留。
func TestAdaptiveSwitchToBetterBeyondSlackBoundary(t *testing.T) {
	p := &AsyncPort{}
	active := oneWayBackend(168_000, 82_000, 80_000, 30_000_000)
	beyond := oneWayBackend(166_000, 76_000, 90_000, 20_000_000) // 好 6ms > 5ms
	p.preferred.Store(active)
	if got := p.pickAdaptiveBackend([]*Backend{active, beyond}, adaptiveActive2Pressure-1, 8*1024); got != beyond {
		t.Fatalf("6ms-better path not adopted: got=%p want=%p", got, beyond)
	}
}

// TestAdaptivePreferredAlwaysActive 不变量：p.preferred 必须指向当前活跃集合中
// 的路径（或 nil），绝不指向已被淘汰/standby 的路径。
func TestAdaptivePreferredAlwaysActive(t *testing.T) {
	p := &AsyncPort{}
	a := oneWayBackend(160_000, 80_000, 80_000, 30_000_000)
	b := oneWayBackend(170_000, 85_000, 85_000, 30_000_000)
	backends := []*Backend{a, b}

	// 高负载：进入多路径模式（active=2）
	p.pickAdaptiveBackend(backends, adaptiveActive2Pressure, 16*1024)
	pref := p.preferred.Load()
	if pref == nil {
		t.Fatal("preferred is nil after multi-path dispatch")
	}
	if !pref.active.Load() {
		t.Fatalf("preferred (%p) not active", pref)
	}
}

// TestAdaptiveSwitchDoesNotAdoptColdUnmeasuredPath 冷启动/未测路径不得仅凭
// 未知 RTT 的乐观估计抢走活跃槽位：未测路径（min_rtt 与 SRTT 全未知）应排在
// 已测健康路径之后，而不是被当成 25ms 的"最佳"路径。
func TestAdaptiveSwitchDoesNotAdoptColdUnmeasuredPath(t *testing.T) {
	p := &AsyncPort{}
	warm := oneWayBackend(170_000, 85_000, 85_000, 30_000_000)
	// 全新路径：rttCache/minRttCache 为 0（尚未采样），rate=0（冷）
	cold := testAdaptiveBackend(0)
	cold.rttCache = &[]uint32{0}[0]
	cold.minRttCache = &[]uint32{0}[0]
	cold.rateBytesPerSec.Store(0)
	backends := []*Backend{warm, cold}

	p.preferred.Store(warm)
	got := p.pickAdaptiveBackend(backends, adaptiveActive2Pressure-1, 8*1024)
	if got != warm {
		t.Fatalf("cold unmeasured path stole active slot: got=%p want=%p", got, warm)
	}
}
