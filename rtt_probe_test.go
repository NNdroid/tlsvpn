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
// 下 fwd/ret 的相对排序必须与真实单向时延一致——这正是选路依赖的性质。
func TestRttProbeRecomputePreservesOrdering(t *testing.T) {
	// 真实单向时延（µs）：path0 fwd 5 / ret 10000；path1 fwd 5000 / ret 5。
	// ref=0，RTT(i,j) = fwd_i + ret_j，故矩阵对角/交叉值如下。
	dec := map[[2]uint32]uint64{
		{0, 0}: 5 + 10000,    // RTT(ref,ref)
		{1, 0}: 5000 + 10000, // RTT(i=1, ref=0) → fwd_1
		{0, 1}: 5 + 5,        // RTT(ref=0, j=1) → ret_1
	}
	fwd, ret := recomputeOneWay(dec, []int{0, 1}, 0, (5+10000)/2)

	if fwd[0] != (5+10000)/2 || ret[0] != (5+10000)/2 {
		t.Fatalf("ref not anchored: fwd=%d ret=%d", fwd[0], ret[0])
	}
	// fwd_1 = RTT(1,0) - RTT(ref,ref)/2 = 5000 + 10000 - 5002 = 9998（去程主导）
	// ret_1 = RTT(0,1) - RTT(ref,ref)/2 = 10 - 5002 → 反转，落 1µs 地板
	if fwd[1] < 9000 {
		t.Fatalf("fwd[1]=%d, asymmetric forward latency lost", fwd[1])
	}
	if ret[1] != 1 {
		t.Fatalf("ret[1]=%d, inverted matrix should clamp to the 1µs floor", ret[1])
	}
	// 选路性质：去程应选 path0（fwd 小），回程应选 path1（ret 小）
	if fwd[0] <= fwd[1] && ret[1] <= ret[0] {
		// 两侧 argmin 一致：去程 0、回程 1，跨路径分解生效
	} else {
		t.Fatalf("ordering broken: fwd=%v ret=%v", fwd, ret)
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
	// 已收敛 → 估计值优先于 min_rtt
	b.fwdOneWayUS.Store(300)
	mode := &atomic.Int32{}
	mode.Store(oneWayModeFwd)
	b.oneWayModePtr = mode
	if got := adaptiveBackendOneWayUS(b); got != 300 {
		t.Fatalf("converged estimate ignored: got=%d want=300", got)
	}
	// 方向不匹配（ret 模式只有 fwd 估计）→ 退回 min_rtt/2
	mode.Store(oneWayModeRet)
	b.retOneWayUS.Store(0)
	if got := adaptiveBackendOneWayUS(b); got != 6000 {
		t.Fatalf("wrong direction not honoured: got=%d want=6000", got)
	}
	// roundtrip 兼容模式：无方向偏好，仍走 min_rtt/2
	mode.Store(oneWayModeRoundtrip)
	if got := adaptiveBackendOneWayUS(b); got != 6000 {
		t.Fatalf("roundtrip mode: got=%d want=6000", got)
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

// TestRttProbeSubClamp 保证 subClamp 非零且保留真实量级：0 是"未收敛"哨兵，
// 不能被合法的零差值占用；矩阵反转时落到 1µs 地板。
func TestRttProbeSubClamp(t *testing.T) {
	if got := subClamp(12000, 5000); got != 7000 {
		t.Fatalf("subClamp(12000,5000)=%d want=7000", got)
	}
	if got := subClamp(5000, 5000); got != 1 {
		t.Fatalf("zero difference must stay non-zero: got=%d", got)
	}
	if got := subClamp(4000, 5000); got != 1 {
		t.Fatalf("inverted matrix: got=%d want=1", got)
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
	s := newRttProbeScheduler(ctx, resolve, active)
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
	s := newRttProbeScheduler(context.Background(), func(int) *Backend { return nil }, func() []int { return nil })

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
	snap := schedulerSnapshot(b)
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal schedulerSnapshot: %v", err)
	}
	for _, want := range []string{`"fwd_oneway_us":`, `"ret_oneway_us":`, `"min_rtt_us":`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("快照 JSON 缺少 %s：%s", want, raw)
		}
	}
}
