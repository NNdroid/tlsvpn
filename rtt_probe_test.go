package main

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// 方案A 的单元测试：帧编解码、单向估算器、decayed-min、回退链与抗指纹填充。
// 帧布局与估算公式是跨语言契约（Rust 端需按同一偏移实现），这里钉死字节。

// TestRttProbeFrameRoundTrip 钉死 18B 线格式与往返一致性。
func TestRttProbeFrameRoundTrip(t *testing.T) {
	// 探针的 send_ts 出厂为 0，由发送 goroutine 在 Write 前补写，故期望值尾 8B 为 0。
	const wantProbe = "0300" + "0000002a" + "00000002" + "0000000000000000"
	const wantReply = "0400" + "0000002a" + "00000000" + "0000000000000001"

	got := appendRttProbeFrame(nil, 0x2a, 2)
	if hexOf(got) != wantProbe {
		t.Fatalf("probe payload=%x want=%s", got, wantProbe)
	}
	got = appendRttReplyFrame(nil, 0x2a, 1)
	if hexOf(got) != wantReply {
		t.Fatalf("reply payload=%x want=%s", got, wantReply)
	}

	kind, nonce, replyOn, sendTS, err := parseRttProbeFrame(got)
	if err != nil || kind != controlKindRttReply || nonce != 0x2a || replyOn != 0 || sendTS != 1 {
		t.Fatalf("decoded kind=0x%02x nonce=0x%x replyOn=%d sendTS=%d err=%v", kind, nonce, replyOn, sendTS, err)
	}

	p := appendRttProbeFrame(nil, 1, 3)
	kind, nonce, replyOn, _, err = parseRttProbeFrame(p)
	if err != nil || kind != controlKindRttProbe || nonce != 1 || replyOn != 3 {
		t.Fatalf("decoded probe kind=0x%02x nonce=%d replyOn=%d err=%v", kind, nonce, replyOn, err)
	}
}

// hexOf 测试用十六进制格式化。
func hexOf(b []byte) string {
	out := make([]byte, len(b)*2)
	const digits = "0123456789abcdef"
	for i, v := range b {
		out[i*2] = digits[v>>4]
		out[i*2+1] = digits[v&0xf]
	}
	return string(out)
}

// TestRttProbeRejectsMalformed 畸形帧一律拒绝：长度、kind、flags 三关。
func TestRttProbeRejectsMalformed(t *testing.T) {
	// 长度错（少 1 字节）
	short := appendRttProbeFrame(nil, 1, 0)
	if _, _, _, _, err := parseRttProbeFrame(short[:len(short)-1]); err != errRttProbeMalformed {
		t.Fatalf("short payload accepted: err=%v", err)
	}
	// kind 未知
	bad := appendRttProbeFrame(nil, 1, 0)
	bad[rttProbeOffKind] = controlKindFECMode
	if _, _, _, _, err := parseRttProbeFrame(bad); err != errRttProbeMalformed {
		t.Fatalf("unknown kind accepted: err=%v", err)
	}
	// flags 非零
	bad = appendRttProbeFrame(nil, 1, 0)
	bad[rttProbeOffFlags] = 1
	if _, _, _, _, err := parseRttProbeFrame(bad); err != errRttProbeMalformed {
		t.Fatalf("non-zero flags accepted: err=%v", err)
	}
	// 读循环前置拦截器对非探针帧必须返回 false
	if isRttProbeFrame(appendRttProbeFrame(nil, 1, 0)[:17]) {
		t.Fatal("17-byte payload claimed as probe frame")
	}
}

// TestRttProbeSendTSPatch 固定偏移写入：帧头 10B 之后的 send_ts 槽位。
func TestRttProbeSendTSPatch(t *testing.T) {
	when := time.Unix(0, 1234567890)
	// 仅帧头、无载荷：偏移越界必须安全返回，不能 panic 也不能越界写。
	short := make([]byte, 10)
	patchRttProbeSendTS(short, when)
	if got := short[9]; got != 0 {
		t.Fatalf("short buffer was written: last byte=%d", got)
	}

	payload := appendRttProbeFrame(nil, 7, 0)
	buf := short // 帧头 10B
	buf = append(buf, payload...)
	patchRttProbeSendTS(buf, when)
	if got := uint64At(buf, 10+rttProbeOffSendTS); got != 1234567890 {
		t.Fatalf("send_ts=%d want=1234567890", got)
	}
	// 补丁只动 send_ts 槽位：kind/nonce 保持原值
	if buf[10] != controlKindRttProbe || buf[11] != 0 {
		t.Fatalf("patch disturbed kind/flags: kind=%d flags=%d", buf[10], buf[11])
	}
}

// uint64At 从 buf[off:off+8] 读 big-endian uint64。
func uint64At(buf []byte, off int) uint64 {
	var v uint64
	for i := 0; i < 8; i++ {
		v = v<<8 | uint64(buf[off+i])
	}
	return v
}

// TestRttProbeRecomputePreservesOrdering 估算器核心：合成矩阵（非对称 fwd/ret）
// 下原始有符号相对量的完整排序必须与真实单向时延一致——这正是选路依赖的性质。
func TestRttProbeRecomputePreservesOrdering(t *testing.T) {
	// 真实单向时延（µs）：path0 fwd 5 / ret 10000；path1 fwd 5000 / ret 5。
	// ref=0，RTT(i,j) = fwd_i + ret_j。decay 矩阵单位为 ns（= µs × 1000），
	// 故对角/交叉值乘 1000，halfRef 以 µs 传入（5002µs）。
	dec := map[[2]uint32]uint64{
		{0, 0}: (5 + 10000) * 1000,    // RTT(ref,ref)
		{1, 0}: (5000 + 10000) * 1000, // RTT(i=1, ref=0) → fwd_1
		{0, 1}: (5 + 5) * 1000,        // RTT(ref=0, j=1) → ret_1
	}
	fwd, ret := decomposeOneWay(dec, []int{0, 1}, 0, (5+10000)/2)

	// 100% 方向可探测：每个已测量方向都必须出现在解里（不再压 0/丢弃）。
	if _, ok := fwd[0]; !ok {
		t.Fatal("ref forward missing")
	}
	if _, ok := ret[1]; !ok {
		t.Fatal("conn1 return missing")
	}
	// 原始有符号相对量：ref 自身恒为 halfRef；比 ref 基准快的方向为负（真实
	// 信息，选路 argmin 依赖完整序，压非负会让快路径并列）。
	if fwd[0] != 5002 || ret[0] != 5002 {
		t.Fatalf("ref anchor: fwd=%d ret=%d want 5002/5002", fwd[0], ret[0])
	}
	// 相对序保留（选路核心）：
	//   去程：path0 真实 5µs < path1 5000µs → fwd[0] < fwd[1]
	//   回程：path1 真实 5µs < path0 10000µs → ret[1] < ret[0]（且为负）
	if fwd[0] >= fwd[1] {
		t.Fatalf("forward ordering broken: fwd[0]=%d fwd[1]=%d (path0 forward must be faster)", fwd[0], fwd[1])
	}
	if ret[1] >= ret[0] {
		t.Fatalf("return ordering broken: ret[0]=%d ret[1]=%d (path1 return must be faster)", ret[0], ret[1])
	}
	if ret[1] >= 0 {
		t.Fatalf("faster-than-anchor direction must stay negative: ret[1]=%d", ret[1])
	}
}

// TestDecayedMinUpdate 慢升快降：新样本更小时立即采纳，否则每秒只允许抬升
// decayPerSecNS 纳秒——与内核 tcpi_min_rtt 的地板语义平行。
func TestDecayedMinUpdate(t *testing.T) {
	if got := decayedMinUpdate(0, 1_000_000_000, 5000, rttProbeDecayPerSecNS); got != 5000 {
		t.Fatalf("first sample: got=%d want=5000", got)
	}
	// 更小样本立即采纳（快降）
	if got := decayedMinUpdate(5000, 1_000_000_000, 100, rttProbeDecayPerSecNS); got != 100 {
		t.Fatalf("faster sample: got=%d want=100", got)
	}
	// 1 秒后允许抬升 decayPerSecNS 纳秒
	got := decayedMinUpdate(100, 1_000_000_000, 999_999_999, rttProbeDecayPerSecNS)
	if got != 100+rttProbeDecayPerSecNS {
		t.Fatalf("slow rise: got=%d want=%d", got, 100+rttProbeDecayPerSecNS)
	}
	// 零流逝不抬升
	if got := decayedMinUpdate(100, 0, 999_999_999, rttProbeDecayPerSecNS); got != 100 {
		t.Fatalf("zero elapsed: got=%d want=100", got)
	}
	// 时钟回拨（elapsedNS<0）不抬升也不 wrap：uint64(负) 会污染到接近 2^64，
	// 曾致 decay 爆炸、fwd/ret 显示 1.7e13 伪值。负 elapsed 应等效于零流逝。
	if got := decayedMinUpdate(100, -500_000_000, 999_999_999, rttProbeDecayPerSecNS); got != 100 {
		t.Fatalf("clock rollback: got=%d want=100 (uint64 negative wrap polluted cur)", got)
	}
	// 时钟回拨后新样本更小仍快降（自愈路径不受负 elapsed 影响）。
	if got := decayedMinUpdate(100, -500_000_000, 50, rttProbeDecayPerSecNS); got != 50 {
		t.Fatalf("rollback + faster sample: got=%d want=50", got)
	}
}

// TestAdaptiveBackendOneWayUSFallback 回退链：估计优先，其次 min_rtt/2，再退
// SRTT/2——探针未收敛前行为与现状完全一致，不会引入回归。
func TestAdaptiveBackendOneWayUSFallback(t *testing.T) {
	// min_rtt 未知（nil）→ SRTT/2，与改造前 rtt/2 的起步值一致
	b := testAdaptiveBackend(20000) // SRTT 20ms
	b.minRttCache = nil             // 清空 helper 的默认值，覆盖真正未知的分支
	if got := adaptiveBackendOneWayUS(b); got != 10000 {
		t.Fatalf("srtt fallback: got=%d want=10000", got)
	}
	// min_rtt 已知 → min_rtt/2 优先于 SRTT/2
	c := new(uint32)
	*c = 12000
	b.minRttCache = c
	if got := adaptiveBackendOneWayUS(b); got != 6000 {
		t.Fatalf("min_rtt fallback: got=%d want=6000", got)
	}
	// 已收敛 → 原始相对量优先于 min_rtt（选路值走 fwdRankUS 编码字段，不带 δ）。
	b.fwdRankUS.Store(oneWayRankEncode(300))
	mode := &atomic.Int32{}
	mode.Store(oneWayModeFwd)
	b.oneWayModePtr = mode
	if got := adaptiveBackendOneWayUS(b); got != 300 {
		t.Fatalf("converged estimate ignored: got=%d want=300", got)
	}
	// 方向不匹配（ret 模式只有 fwd 估计）→ 退回 min_rtt/2
	mode.Store(oneWayModeRet)
	b.retRankUS.Store(0)
	if got := adaptiveBackendOneWayUS(b); got != 6000 {
		t.Fatalf("wrong direction not honoured: got=%d want=6000", got)
	}
	// roundtrip 兼容模式：无方向偏好，仍走 min_rtt/2
	mode.Store(oneWayModeRoundtrip)
	if got := adaptiveBackendOneWayUS(b); got != 6000 {
		t.Fatalf("roundtrip mode: got=%d want=6000", got)
	}
}

// TestOneWayRankExcludesDelta 核心回归：δ 抬升只进显示层，绝不进选路。
//
// 场景（快路径部署的典型形态）：ref 基线 1ms，候选 Y 的探针样本 0.5ms 快于
// 基准 → raw fwd = -500µs，联合最小为 -500 → δ = 501。此时显示层 fwd 全体
// 被 +501 抬升（面板契约，非负），但选路层必须仍是 raw——否则与未收敛候选
// （min_rtt/2 回退，不带 δ）混排时排名被系统性扭曲。
func TestOneWayRankExcludesDelta(t *testing.T) {
	us := func(v uint64) uint64 { return v * 1000 } // µs→ns
	dec := map[[2]uint32]uint64{
		{0, 0}: us(2000), // ref 基线 RTT 2ms → halfRef=1000µs
		{1, 0}: us(1400), // X：fwd 样本 1.4ms → raw 400µs
		{2, 0}: us(500),  // Y：fwd 样本 0.5ms → raw -500µs（快于基准）
	}
	fwdRaw, retRaw := decomposeOneWay(dec, []int{0, 1, 2}, 0, 1000)
	if fwdRaw[1] != 400 || fwdRaw[2] != -500 {
		t.Fatalf("raw decompose wrong: fwd=%v", fwdRaw)
	}
	delta := displayDeltaUS(fwdRaw, retRaw)
	if delta != 501 {
		t.Fatalf("delta=%d want 501 (min raw -500 lifted to 1µs)", delta)
	}

	// 显示层：δ 抬升后全体非负且最小方向恰为 1µs（面板契约）。
	if disp := uint64(fwdRaw[2] + delta); disp != 1 {
		t.Fatalf("display min: %d want 1", disp)
	}
	if fwdRaw[1]+delta <= 0 {
		t.Fatalf("display must stay non-negative: %d", fwdRaw[1]+delta)
	}

	// 选路层：原始值保序，Y(-500) < X(400)——真实序不得被 δ 抬升破坏。
	if fwdRaw[2] >= fwdRaw[1] {
		t.Fatalf("raw ordering broken: Y=%d X=%d", fwdRaw[2], fwdRaw[1])
	}

	// 编码往返：负 raw 编码后恒 >0（与 0=未收敛哨兵不冲突），解码无损。
	for _, raw := range []int64{-500, 0, 400, 3_600_000} {
		enc := oneWayRankEncode(raw)
		if enc == 0 {
			t.Fatalf("encoded value must never be 0 (sentinel clash): raw=%d", raw)
		}
		if got := oneWayRankDecode(enc); got != raw {
			t.Fatalf("roundtrip: raw=%d got=%d", raw, got)
		}
	}
}

// TestBackendOneWayRankEncoding Backend 编码字段纪律：零值 = 未收敛（编码恒 >0
// 保证），解码回有符号 raw 供选路；显示字段与选路字段互不读取。
func TestBackendOneWayRankEncoding(t *testing.T) {
	b := &Backend{}
	mode := &atomic.Int32{}
	mode.Store(oneWayModeFwd)
	b.oneWayModePtr = mode
	// 零值 Backend：两个方向都必须报告未收敛，绝不能把 0 当成"0µs 的快路径"。
	if v, ok := b.backendOneWayUS(); ok {
		t.Fatalf("zero value must be unconverged: v=%d ok=%v", v, ok)
	}
	// 负 raw（快于 ref 基准）经编码存储后解码无损。
	b.fwdRankUS.Store(oneWayRankEncode(-500))
	if v, ok := b.backendOneWayUS(); !ok || v != -500 {
		t.Fatalf("decode negative: v=%d ok=%v want -500,true", v, ok)
	}
	b.fwdRankUS.Store(oneWayRankEncode(400))
	if v, ok := b.backendOneWayUS(); !ok || v != 400 {
		t.Fatalf("decode positive: v=%d ok=%v want 400,true", v, ok)
	}
	// ret 模式读 ret 字段。
	mode.Store(oneWayModeRet)
	if v, ok := b.backendOneWayUS(); ok {
		t.Fatalf("ret unconverged: v=%d ok=%v", v, ok)
	}
	b.retRankUS.Store(oneWayRankEncode(-700))
	if v, ok := b.backendOneWayUS(); !ok || v != -700 {
		t.Fatalf("ret decode: v=%d ok=%v want -700,true", v, ok)
	}
}

// TestAdaptiveOneWayMixedConvergence 混排一致性（回归）：已收敛候选的选路值
// 不得携带显示层 δ。若无此隔离，快路径部署下 δ（可达 halfRef 量级）会把已
// 收敛候选整体抬高，输给未收敛的 min_rtt/2 回退候选。
func TestAdaptiveOneWayMixedConvergence(t *testing.T) {
	b := testAdaptiveBackend(20000)
	c := new(uint32)
	*c = 12000
	b.minRttCache = c
	mode := &atomic.Int32{}
	mode.Store(oneWayModeFwd)
	b.oneWayModePtr = mode
	// TestOneWayRankExcludesDelta 场景中的 X：raw fwd=400µs，δ=501。
	// 显示层会显示 901µs，但选路必须用 400µs（δ 只进显示）。
	b.fwdRankUS.Store(oneWayRankEncode(400))
	b.fwdOneWayUS.Store(901) // 显示字段带 δ，选路必须无视它
	if got := adaptiveBackendOneWayUS(b); got != 400 {
		t.Fatalf("rank must exclude display delta: got=%d want=400", got)
	}
}

// TestAdaptiveBackendMinRTTSentinel 未知哨兵纪律与 adaptiveBackendRTT 平行：
// nil/0/哨兵值一律报告 unknown，并以 50000µs 起步而非 0。
func TestAdaptiveBackendMinRTTSentinel(t *testing.T) {
	if v, ok := adaptiveBackendMinRTT(nil); ok != true || v != adaptiveUnknownRTTUS {
		t.Fatalf("nil backend: v=%d ok=%v", v, ok)
	}
	b := testAdaptiveBackend(20000)
	b.minRttCache = nil // helper 默认填充 min_rtt，这里显式清空以覆盖 nil 分支
	if v, ok := adaptiveBackendMinRTT(b); ok != true || v != adaptiveUnknownRTTUS {
		t.Fatalf("nil minRttCache: v=%d ok=%v", v, ok)
	}
	c := new(uint32)
	b.minRttCache = c
	// min_rtt 为 0（未观测）→ 退回 SRTT 当包络参考，绝不能用 50000µs 哨兵。
	if v, unknown := adaptiveBackendMinRTT(b); unknown || v != 20000 {
		t.Fatalf("zero min_rtt must fall back to srtt: v=%d unknown=%v", v, unknown)
	}
	*c = 8000
	// bool 为 unknownRTT：已知 min_rtt 时 false
	if v, unknown := adaptiveBackendMinRTT(b); unknown || v != 8000 {
		t.Fatalf("known min_rtt: v=%d unknown=%v", v, unknown)
	}
	*c = adaptiveUnknownRTTUS
	if v, unknown := adaptiveBackendMinRTT(b); unknown || v != 20000 {
		t.Fatalf("sentinel min_rtt must fall back to srtt: v=%d unknown=%v", v, unknown)
	}
	// SRTT 也未知时才是真的 unknown（哨兵 + true）
	*b.minRttCache = adaptiveUnknownRTTUS
	*b.rttCache = adaptiveUnknownRTTUS
	if v, unknown := adaptiveBackendMinRTT(b); unknown != true || v != adaptiveUnknownRTTUS {
		t.Fatalf("both unknown: v=%d unknown=%v", v, unknown)
	}
}

// TestRttProbePaddingIndistinguishable 抗指纹：探针帧经 appendPaddedFrame 后
// 必须落入 padBuckets 分布、载荷起点固定为帧头后 10B、覆盖字节来自 randomPool。
// 这保证探针/回包在尺寸与字节分布上与正常记录/保活不可区分。
func TestRttProbePaddingIndistinguishable(t *testing.T) {
	old := padModeCode.Load()
	defer padModeCode.Store(old)
	setPadMode(padModeBucket)

	payload := appendRttProbeFrame(nil, 42, 1)
	for i := 0; i < 200; i++ {
		buf, pad := appendPaddedFrame(nil, VPNFrame{Seq: 0, Data: payload}, nil, 0)
		if len(buf) != 10+len(payload)+pad {
			t.Fatalf("record %d: len=%d want=%d", i, len(buf), 10+len(payload)+pad)
		}
		inBucket := false
		for _, b := range padBuckets {
			if len(buf) == b {
				inBucket = true
				break
			}
		}
		if !inBucket {
			t.Fatalf("record %d size %d outside padBuckets", i, len(buf))
		}
		// kind 字节在载荷起点（帧头 10B 之后），必须原样落地
		if buf[10] != controlKindRttProbe {
			t.Fatalf("record %d: kind byte not at payload start", i)
		}
		// 覆盖字节非零概率等于全零（randomPool 覆盖），200 次内至少一次非零
		if i == 0 && pad == 0 {
			t.Fatalf("bucket padding produced zero pad bytes")
		}
	}
}

// TestRttProbeSubClamp 保证 subClamp 非零且保留真实量级：正常差值原样返回，
// 矩阵反转（b>=a，该方向不比锚定快）返回 0——0 是"不可测"哨兵，选路回退
// min_rtt/2、前端显示 '-'，绝不能伪装成 1µs（旧实现压成 1 会让前端显示"1ms"）。
func TestRttProbeSubClamp(t *testing.T) {
	if got := subClamp(12000, 5000); got != 7000 {
		t.Fatalf("subClamp(12000,5000)=%d want=7000", got)
	}
	if got := subClamp(5000, 5000); got != 0 {
		t.Fatalf("zero difference must be 'unmeasurable' (0), not a fake 1: got=%d", got)
	}
	if got := subClamp(4000, 5000); got != 0 {
		t.Fatalf("inverted matrix: got=%d want=0", got)
	}
	if got := subClamp(math.MaxUint64, 0); got != math.MaxUint64 {
		t.Fatalf("max range: got=%d", got)
	}
}

// TestOneWayUS 探针样本为 ns、对外发布为 µs：oneWayUS 只做 /1000 换算，保证
// fwdOneWayUS/retOneWayUS 恒为 µs（回归：混装 ns/µs 导致"去/回"列量级错乱）。
func TestOneWayUS(t *testing.T) {
	if got := oneWayUS(175448399); got != 175448 {
		t.Fatalf("oneWayUS(175448399)=%d want=175448", got)
	}
	if got := oneWayUS(999); got != 0 {
		t.Fatalf("oneWayUS(999)=%d want=0 (sub-µs 样本下取整)", got)
	}
	if got := oneWayUS(0); got != 0 {
		t.Fatalf("oneWayUS(0)=%d want=0", got)
	}
}

// TestRttProbeSchedulerLifecycle 调度器生命周期：ctx 取消后 goroutine 必须退出，
// 且 enable/kick/stop 并发安全。不读内部 map（调度 goroutine 独占），只断言
// 可观测的退出行为。
func TestRttProbeSchedulerLifecycle(t *testing.T) {
	resolve := func(int) *Backend { return nil }
	active := func() []int { return []int{0, 1, 2} }
	ctx, cancel := context.WithCancel(t.Context())
	s := newRttProbeScheduler(ctx, resolve, active, nil)
	s.start()
	s.kick()
	s.enable()
	s.kick()
	done := make(chan struct{})
	go func() { s.stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stop() did not return in time")
	}
	cancel()
}

// TestRttProbePendingSweep 过期与超量 pending 必须被清掉（防泄漏）：这里直接
// 驱动 sweepPending，它是调度 goroutine 独占路径，单 goroutine 调用即无竞态。
func TestRttProbePendingSweep(t *testing.T) {
	s := newRttProbeScheduler(context.Background(), func(int) *Backend { return nil }, func() []int { return nil }, nil)

	// 未过期：保留
	s.pending[1] = pendingProbe{srcConn: 0, replyOn: 0, issued: time.Now()}
	s.sweepPending()
	if _, ok := s.pending[1]; !ok {
		t.Fatal("fresh pending was swept")
	}
	// 过期：清除（超过 rttProbePendingTimeout）
	s.pending[2] = pendingProbe{srcConn: 0, replyOn: 0, issued: time.Now().Add(-2 * rttProbePendingTimeout)}
	s.sweepPending()
	if _, ok := s.pending[2]; ok {
		t.Fatal("expired pending retained")
	}
	// 超量：裁剪到上限
	for i := uint32(3); i < uint32(rttProbePendingMax)+10; i++ {
		s.pending[i] = pendingProbe{srcConn: 0, replyOn: 0, issued: time.Now()}
	}
	s.sweepPending()
	if len(s.pending) > rttProbePendingMax {
		t.Fatalf("pending over cap: %d > %d", len(s.pending), rttProbePendingMax)
	}
}

// TestRttProbeSchedulerJSONFields 快照字段名是 WebUI 与 Rust 端的共同契约：
// 改名即破坏面板与跨语言实现。
func TestRttProbeSchedulerJSONFields(t *testing.T) {
	// 字段带 omitempty：未收敛（0）时整个键缺席，故这里给非零值断言键名。
	b := testAdaptiveBackend(10000)
	b.fwdOneWayUS.Store(11)
	b.retOneWayUS.Store(22)
	b.probeUpdatedAt.Store(123) // 面板"上次计算时间"来源，非零才出现在 omitempty JSON
	snap := schedulerSnapshot(b)
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal schedulerSnapshot: %v", err)
	}
	for _, want := range []string{`"fwd_oneway_us":`, `"ret_oneway_us":`, `"min_rtt_us":`, `"probe_at_ms":`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("快照 JSON 缺少 %s：%s", want, raw)
		}
	}
}

// TestRttProbeRecomputeProbeScaledAnchor 锚定必须用探针基线 (ref,ref)/2，而
// 不是内核 min_rtt/2。探针 RTT（recvAt-sendTS）含应用层处理/队列/TLS 批处理/
// 调度延迟，显著大于物理 min_rtt；若用 min_rtt/2 锚定，fwd/ret 会被系统性
// 抬高，且破坏自洽性 fwd[i]+ret[i]=RTT_i。本测试故意让 min_rtt=2000µs 远小于
// 探针基线 6000µs，验证锚定仍取探针尺度（halfRef=3000µs）而非 min_rtt/2=1000µs。
func TestRttProbeRecomputeProbeScaledAnchor(t *testing.T) {
	// 真实（探针尺度，µs）：ref 对称 fwd=ret=3000；连接1 fwd=3000、ret=1000。
	// decay[(s,d)] = fwd_s + ret_d，换算成 ns（*1000）。
	dec := map[[2]uint32]uint64{
		{0, 0}: 6000 * 1000, // RTT(ref,ref)
		{1, 0}: 6000 * 1000, // fwd_1 + ret_0
		{0, 1}: 4000 * 1000, // fwd_0 + ret_1
	}
	minRtt := uint32(2000) // 物理地板，故意远小于探针基线
	b0 := &Backend{minRttCache: &minRtt}
	b1 := &Backend{minRttCache: &minRtt}
	s := &rttProbeScheduler{
		decay:     dec,
		lastDecay: make(map[[2]uint32]time.Time),
		refConn:   0,
		active:    []int{0, 1},
	}
	s.resolveConn = func(i int) *Backend {
		switch i {
		case 0:
			return b0
		case 1:
			return b1
		}
		return nil
	}
	s.recomputeAll()

	// halfRef=3000µs（探针基线/2）而非 min_rtt/2=1000µs。
	if got := b1.fwdOneWayUS.Load(); got != 3000 {
		t.Fatalf("fwd[1]=%d want 3000 (probe-scaled anchor, not min_rtt/2)", got)
	}
	if got := b1.retOneWayUS.Load(); got != 1000 {
		t.Fatalf("ret[1]=%d want 1000", got)
	}
	// 自洽性：fwd[1]+ret[1]=RTT_1=4000µs。
	if f, r := b1.fwdOneWayUS.Load(), b1.retOneWayUS.Load(); f+r != 4000 {
		t.Fatalf("self-consistency broken: fwd+ret=%d want 4000 (=RTT)", f+r)
	}
	// ref 自身锚定为 halfRef=3000µs（对称约定）。
	if got := b0.fwdOneWayUS.Load(); got != 3000 {
		t.Fatalf("ref fwd=%d want 3000", got)
	}
	if got := b0.retOneWayUS.Load(); got != 3000 {
		t.Fatalf("ref ret=%d want 3000", got)
	}
}

// TestDecomposeOneWayRankingImmuneToAsymmetry 验证相对分解的排序不受绝对单程
// 不对称影响：去直回绕（去程 30ms、回程 300ms）下，选路仍按相对序正确。
//
// 三条连接，ref=0。真实单程（完全不对称）：
//
//	conn0: F=30ms  B=300ms（去直回绕）
//	conn1: F=60ms  B=200ms
//	conn2: F=100ms B=150ms
//
// 跨路径探针测得 decay[(i,ref)]=F_i+B_ref、decay[(ref,i)]=F_ref+B_i。
// 相对分解应给出：去程排序 conn0<conn1<conn2，回程排序 conn2<conn1<conn0。
func TestDecomposeOneWayRankingImmuneToAsymmetry(t *testing.T) {
	ms := func(v uint64) uint64 { return v * 1_000_000 } // ms→ns
	// 真实单程（ns）。
	F := []uint64{ms(30), ms(60), ms(100)}
	B := []uint64{ms(300), ms(200), ms(150)}
	const ref = 0

	decay := map[[2]uint32]uint64{}
	// 自回包 + 跨路径矩阵（模拟探针 decayed-min 收敛到真实值）。
	for i := 0; i < 3; i++ {
		decay[[2]uint32{uint32(i), uint32(ref)}] = F[i] + B[ref]
		decay[[2]uint32{uint32(ref), uint32(i)}] = F[ref] + B[i]
	}
	halfRef := oneWayUS(decay[[2]uint32{uint32(ref), uint32(ref)}]) / 2
	if halfRef == 0 {
		halfRef = oneWayUS(ms(330)) / 2 // (30+300)/2
	}
	decay[[2]uint32{uint32(ref), uint32(ref)}] = F[ref] + B[ref]

	fwd, ret := decomposeOneWay(decay, []int{0, 1, 2}, ref, halfRef)

	// 去程：conn0 < conn1 < conn2（相对 ref）。
	if !(fwd[1] > fwd[0] && fwd[2] > fwd[1]) {
		t.Fatalf("forward ranking wrong: fwd=%v, want strictly increasing", fwd)
	}
	// 回程：conn2 < conn1 < conn0（相对 ref）。
	if !(ret[2] < ret[1] && ret[1] < ret[0]) {
		t.Fatalf("return ranking wrong: ret=%v, want strictly decreasing", ret)
	}
}
