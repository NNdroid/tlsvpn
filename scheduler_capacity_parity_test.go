package main

// 容量加权 WFQ（饱和门控容量采样）、parity 按帧轮转分发、TCP 重传惩罚的
// 回归测试。三个机制共用一个主题：让"路径当前真实质量"（容量/丢包）进入
// 调度与 parity 决策，同时不破坏既有钉死的反反馈纪律。

import (
	"testing"
)

// TestBackendCapacitySampleSaturationGate A2 回归：非饱和窗（写阻塞 < 半窗）
// 不结算——drain 速率是"被喂速率"，做权重会正反馈饿死欠估路径；仅饱和窗
// （写阻塞 ≥ 半窗）的 载荷/阻塞时长 才是容量样本，EWMA α=1/2。
func TestBackendCapacitySampleSaturationGate(t *testing.T) {
	const win = int64(200_000_000) // 200ms
	b := &Backend{}
	// 非饱和窗：阻塞 20ms ≪ 100ms 门限——哪怕载荷很大也不结算。
	b.writeBusyNS = 20_000_000
	b.writeWindowBytes = 3_000_000
	b.noteCapacitySample(win, 0, 0, 0)
	if got := b.deliverRateBytesPerSec.Load(); got != 0 {
		t.Fatalf("unsaturated window must not sample capacity, got %d", got)
	}
	// 饱和窗：阻塞 150ms / 3MB → 20MB/s。
	b.writeBusyNS = 150_000_000
	b.writeWindowBytes = 3_000_000
	b.noteCapacitySample(win, 0, 0, 0)
	if got := b.deliverRateBytesPerSec.Load(); got != 20_000_000 {
		t.Fatalf("saturated window capacity = %d B/s, want 20MB/s", got)
	}
	// 第二个饱和窗 6MB/150ms = 40MB/s → EWMA (20+40)/2 = 30MB/s。
	b.writeBusyNS = 150_000_000
	b.writeWindowBytes = 6_000_000
	b.noteCapacitySample(win, 0, 0, 0)
	if got := b.deliverRateBytesPerSec.Load(); got != 30_000_000 {
		t.Fatalf("capacity EWMA = %d B/s, want 30MB/s", got)
	}
	// 窗口结算后累积字段必须归零（下一窗从零累计）。
	if b.writeBusyNS != 0 || b.writeWindowBytes != 0 {
		t.Fatalf("window accumulators not reset: busy=%d bytes=%d", b.writeBusyNS, b.writeWindowBytes)
	}
}

// TestAdaptiveSchedulerCapacityWeightedWFQ A2 回归：饱和测得的容量差异驱动
// WFQ 字节分摊（快路径 ~10×），未测得路径拿「最大容量/4」的防饿地板而非饿死；
// writer-drain 速率（rateBytesPerSec）不影响权重（反反馈纪律，见
// TestAdaptiveSchedulerWriterRateCannotMonopolizePath）。
func TestAdaptiveSchedulerCapacityWeightedWFQ(t *testing.T) {
	p := &AsyncPort{}
	fast := testAdaptiveBackend(20_000)
	slow := testAdaptiveBackend(20_000)
	// 模拟两个饱和测得的容量：400MB/s vs 40MB/s（10:1）。
	fast.deliverRateBytesPerSec.Store(400_000_000)
	slow.deliverRateBytesPerSec.Store(40_000_000)
	// 干扰项：writer-drain 速率（遥测）必须不影响权重。
	fast.rateBytesPerSec.Store(1_000_000)
	slow.rateBytesPerSec.Store(400_000_000)
	p.inputRateBytesPerSec.Store(adaptiveActive2RateBytesPerSec)
	counts := map[*Backend]int{}
	for i := 0; i < 55; i++ {
		counts[p.pickAdaptiveBackend([]*Backend{fast, slow}, 0, 12*1024)]++
	}
	if counts[slow] == 0 {
		t.Fatalf("slow capacity starved by weight: counts=%v", counts)
	}
	ratio := float64(counts[fast]) / float64(counts[slow])
	if ratio < 4 || ratio > 20 {
		t.Fatalf("capacity-proportional sharing broken: ratio=%.1f counts=%v (want ~10:1)", ratio, counts)
	}
}

// TestAdaptiveSchedulerCapacityFloorKeepsUnmeasuredAlive A2 回归：快路径饱和测得
// 高容量、慢路径从未测得时，防饿地板（最大容量/4）保证慢路径仍有足以饱和自身、
// 修正测量的流量份额——这是容量加权不退化成"测得快者通吃"的关键。
func TestAdaptiveSchedulerCapacityFloorKeepsUnmeasuredAlive(t *testing.T) {
	p := &AsyncPort{}
	fast := testAdaptiveBackend(20_000)
	slow := testAdaptiveBackend(20_000)
	fast.deliverRateBytesPerSec.Store(400_000_000)
	// slow.deliverRate 未测得（0）。
	p.inputRateBytesPerSec.Store(adaptiveActive2RateBytesPerSec)
	counts := map[*Backend]int{}
	for i := 0; i < 40; i++ {
		counts[p.pickAdaptiveBackend([]*Backend{fast, slow}, 0, 12*1024)]++
	}
	if counts[slow] < 5 {
		t.Fatalf("unmeasured path starved without floor: counts=%v (want ≈1:4 via max/4 floor)", counts)
	}
	if counts[fast] <= counts[slow] {
		t.Fatalf("floor must not invert capacity preference: counts=%v", counts)
	}
}

// TestBackendScoreRetransPenalty C6 回归：最近采样窗的 TCP 重传抬高
// backendScore（µs 惩罚），兜底选择与 parity 轮转据此避开正在丢段的路径；
// 时延地板（min_rtt）对丢包不敏感，重传是独立维度。
func TestBackendScoreRetransPenalty(t *testing.T) {
	lossy := testAdaptiveBackend(20_000)
	if sc, ok := backendScore(lossy); !ok || sc != 20_000 {
		t.Fatalf("baseline score = %d ok=%v, want 20000", sc, ok)
	}
	lossy.retransDelta.Store(5) // 200ms 窗内 5 个重传段
	sc, ok := backendScore(lossy)
	if !ok {
		t.Fatal("lossy path with retrans must stay eligible (penalized, not excluded)")
	}
	if want := uint32(20_000 + 5*retransPenaltyUS); sc != want {
		t.Fatalf("score = %d, want %d (rtt + 5×%dµs)", sc, want, retransPenaltyUS)
	}
	// 惩罚必须把"低时延但丢包"的路径排到"高时延但干净"的路径之后。
	clean2 := testAdaptiveBackend(80_000)
	if cleanScore, _ := backendScore(clean2); cleanScore < sc {
		t.Fatalf("retrans penalty ineffective: lossy=%d clean80ms=%d", sc, cleanScore)
	}
}

// TestBackendNoteRetransBaseline C6 回归：首采样只建基线（握手期累积的重传
// 不计入首窗）、单调差分、计数回退按重置基线处理。
func TestBackendNoteRetransBaseline(t *testing.T) {
	b := &Backend{}
	b.noteRetrans(100)
	if got := b.retransDelta.Load(); got != 0 {
		t.Fatalf("first sample is baseline, delta=%d", got)
	}
	b.noteRetrans(103)
	if got := b.retransDelta.Load(); got != 3 {
		t.Fatalf("delta = %d, want 3", got)
	}
	b.noteRetrans(2) // 回绕/新 socket：重置基线，delta 保留旧值
	if got := b.retransDelta.Load(); got != 3 {
		t.Fatalf("backward counter must not fabricate delta, got %d", got)
	}
	b.noteRetrans(4)
	if got := b.retransDelta.Load(); got != 2 {
		t.Fatalf("delta after rebase = %d, want 2", got)
	}
}

// TestDistributeParitiesRotatesPerFrame C5 回归：同一次 flush 的 parity 帧按帧
// 轮转（parityNext 每帧前进）均匀散开到各后端，并按目标聚合为单个 owned batch
// （每目标一次入队/记账）。原实现整批发给单一轮转目标——大 batch 的 parity
// 全压一条流，慢流上整批 parity 一起错过重排窗口。
func TestDistributeParitiesRotatesPerFrame(t *testing.T) {
	p := &AsyncPort{parityScratch: make([][]byte, 0, 32)}
	backends := make([]*Backend, 3)
	for i := range backends {
		b := testAdaptiveBackend(20_000)
		b.ownedCh = make(chan *VPNFrameBatch, 8)
		backends[i] = b
	}
	parities := make([][]byte, 6)
	for i := range parities {
		parities[i] = getFrameAtLeast(16)[:16]
	}
	p.distributeParities(backends, nil, parities)

	total := 0
	for i, b := range backends {
		select {
		case pb := <-b.ownedCh:
			if len(pb.Frames) != 2 {
				t.Fatalf("backend %d got %d parity frames, want 2 (6 frames over 3 targets)", i, len(pb.Frames))
			}
			for _, f := range pb.Frames {
				if f.Seq != 0 {
					t.Fatalf("parity frame seq = %d, want 0 (control plane)", f.Seq)
				}
			}
			total += len(pb.Frames)
		default:
			t.Fatalf("backend %d received no parity batch", i)
		}
	}
	if total != 6 {
		t.Fatalf("parity frames accounted = %d, want 6", total)
	}
	if got := p.paritySent.Load(); got != 6 {
		t.Fatalf("paritySent = %d, want 6", got)
	}
}

// TestDistributeParitiesSuppressesWhenAllUnhealthy C5 回归：全部后端不合格时
// 逐份抑制 parity（near 语义无违例出口），不计 paritySent、不计 drop。
func TestDistributeParitiesSuppressesWhenAllUnhealthy(t *testing.T) {
	p := &AsyncPort{parityScratch: make([][]byte, 0, 32)}
	dead := testAdaptiveBackend(20_000)
	dead.stalled.Store(true)
	parities := make([][]byte, 3)
	for i := range parities {
		parities[i] = getFrameAtLeast(16)[:16]
	}
	p.distributeParities([]*Backend{dead}, nil, parities)
	if got := p.paritySent.Load(); got != 0 {
		t.Fatalf("suppressed parity must not count paritySent, got %d", got)
	}
	if got := p.dropped.Load(); got != 0 {
		t.Fatalf("suppressed parity is not a drop, got %d", got)
	}
	if p.parityTargets != nil && len(p.parityTargets) != 0 {
		t.Fatalf("scratch not reset: %d entries", len(p.parityTargets))
	}
}
