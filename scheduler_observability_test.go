package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestSchedObservabilityEnvelopeExcluded 验证资格包络把离组内地板太远的路径排除
// 出候选集时，观测字段如实发布"包络外"而非笼统的 eligible=false。
// 这正是面板曾把"去程最快却待命"误读成选路 bug 的场景。
func TestSchedObservabilityEnvelopeExcluded(t *testing.T) {
	p := &AsyncPort{}
	fast := testAdaptiveBackend(10_000)
	slow := testAdaptiveBackend(26_000)
	fast.rateBytesPerSec.Store(20_000_000)
	slow.rateBytesPerSec.Store(20_000_000)

	if got := p.pickAdaptiveBackend([]*Backend{fast, slow}, 0, 8*1024); got != fast {
		t.Fatalf("got=%p want=%p", got, fast)
	}
	snapFast := schedulerSnapshot(fast)
	if !snapFast.Eligible {
		t.Fatalf("组内最快路径未被标为候选内: %+v", snapFast)
	}
	if !snapFast.RankKnown {
		t.Fatalf("候选内路径应发布排名键: %+v", snapFast)
	}
	if snapFast.GroupMinRttUS != 10_000 {
		t.Fatalf("组内 min_rtt 地板=%d want=10000", snapFast.GroupMinRttUS)
	}
	wantMax := uint64(10_000) + uint64(max(uint32(backendRTTHysteresisMin), 10_000/4))
	if snapFast.GroupMaxRttUS != wantMax {
		t.Fatalf("包络上限=%d want=%d", snapFast.GroupMaxRttUS, wantMax)
	}

	snapSlow := schedulerSnapshot(slow)
	if snapSlow.Eligible {
		t.Fatalf("包络外路径被标为候选内: %+v", snapSlow)
	}
	if snapSlow.ExcludeReason != "envelope_out" {
		t.Fatalf("排除原因=%q want=envelope_out", snapSlow.ExcludeReason)
	}
	if snapSlow.RankKnown || snapSlow.RankKeyUS != 0 {
		t.Fatalf("被排除路径不应残留排名键: %+v", snapSlow)
	}
	if snapSlow.NearState != "" {
		t.Fatalf("非 near 策略下不应发布 near 状态: %+v", snapSlow)
	}
}

// TestSchedObservabilityStalledExclusion 验证 stalled 路径的排除原因与包络外区分。
func TestSchedObservabilityStalledExclusion(t *testing.T) {
	p := &AsyncPort{}
	good := testAdaptiveBackend(10_000)
	bad := testAdaptiveBackend(10_000)
	bad.rateBytesPerSec.Store(20_000_000)
	good.rateBytesPerSec.Store(20_000_000)
	bad.stalled.Store(true)

	if got := p.pickAdaptiveBackend([]*Backend{bad, good}, 0, 8*1024); got != good {
		t.Fatalf("got=%p want=%p", got, good)
	}
	if snap := schedulerSnapshot(bad); snap.ExcludeReason != "stalled" || snap.Eligible {
		t.Fatalf("stalled 路径的排除原因=%q eligible=%v", snap.ExcludeReason, snap.Eligible)
	}
}

// TestSchedObservabilityDecisionRing 验证选路决策环在 run goroutine 内发布、
// API goroutine 经 schedDecisionSnapshot 读取，且同原因同路径不重复追加。
func TestSchedObservabilityDecisionRing(t *testing.T) {
	p := &AsyncPort{}
	backends := []*Backend{testAdaptiveBackend(10_000), testAdaptiveBackend(10_000)}
	for _, b := range backends {
		b.rateBytesPerSec.Store(20_000_000)
	}
	for i := 0; i < 5; i++ {
		if got := p.pickAdaptiveBackend(backends, 0, 8*1024); got == nil {
			t.Fatalf("第 %d 批选路返回 nil", i+1)
		}
	}
	ring := p.schedDecisionSnapshot()
	if len(ring) == 0 {
		t.Fatal("决策环为空")
	}
	if len(ring) > 1 {
		t.Fatalf("同一决策被重复追加 %d 条: %+v", len(ring), ring)
	}
	if ring[0].Reason != schedReasonRank0 {
		t.Fatalf("原因=%q want=%q", ring[0].Reason, schedReasonRank0)
	}
	if ring[0].Path < 0 || ring[0].Path >= len(backends) {
		t.Fatalf("路径下标=%d 越界", ring[0].Path)
	}
	if ring[0].AtMs == 0 {
		t.Fatal("缺少时间戳")
	}
	// 变更检测：把当前活跃路径调慢，粘滞保留应记为独立一条。
	p.routingAlgo.Store(routingAlgoCode(string(RoutingAlgoLatencySticky)))
	p.preferred.Store(backends[0])
	*backends[0].rttCache = 10_500
	*backends[0].minRttCache = 10_500
	for i := 0; i < 3; i++ {
		p.pickAdaptiveBackend(backends, 0, 8*1024)
	}
	ring2 := p.schedDecisionSnapshot()
	if len(ring2) < 2 {
		t.Fatalf("切换后决策环应有新条目: %+v", ring2)
	}
	if ring2[len(ring2)-1].Reason != schedReasonStickyHeld {
		t.Fatalf("末条原因=%q want=%q", ring2[len(ring2)-1].Reason, schedReasonStickyHeld)
	}
}

// TestSchedObservabilityStickyHeldFlag 验证粘滞保留在观测标志上留痕。
func TestSchedObservabilityStickyHeldFlag(t *testing.T) {
	p := &AsyncPort{}
	// a 是当前活跃路径但较慢：粘滞滞回应把它从 rank[0]=b 手里留住。
	a := testAdaptiveBackend(10_500)
	b := testAdaptiveBackend(10_000)
	a.rateBytesPerSec.Store(20_000_000)
	b.rateBytesPerSec.Store(20_000_000)
	p.routingAlgo.Store(routingAlgoCode(string(RoutingAlgoLatencySticky)))
	p.preferred.Store(a)
	backends := []*Backend{a, b}
	if got := p.pickAdaptiveBackend(backends, 0, 8*1024); got != a {
		t.Fatalf("粘滞带内应保留当前路径: got=%p want=%p", got, a)
	}
	if !schedulerSnapshot(a).StickyHeld {
		t.Fatalf("保留路径未标记粘滞: %+v", schedulerSnapshot(a))
	}
	if schedulerSnapshot(b).StickyHeld {
		t.Fatalf("非保留路径不应标记粘滞: %+v", schedulerSnapshot(b))
	}
}

// TestSchedObservabilityDecisionJSON 决策流水的 JSON 形态（前端按 reason token
// 映射 i18n 键 sched.reason.<token>）。
func TestSchedObservabilityDecisionJSON(t *testing.T) {
	p := &AsyncPort{}
	e := schedDecisionEntry{Reason: schedReasonRank0, Path: 0, AtMs: 1, Active: 1}
	p.decisionRing = append(p.decisionRing, e)
	b, err := json.Marshal(p.schedDecisionSnapshot())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"reason":"rank0"`) || !strings.Contains(string(b), `"active":1`) {
		t.Fatalf("决策 JSON 缺少字段: %s", b)
	}
}

// TestWebUISchedObservabilityContract 面板侧契约：调度单元格读排除原因/包络/排名
// 键/near 资格，i18n 五个 locale 字典都带对应键，index.html 有流水容器。
func TestWebUISchedObservabilityContract(t *testing.T) {
	app := readWebUIAsset(t, "webui/app.js")
	for _, want := range []string{
		"s.exclude_reason",
		"s.group_max_rtt_us",
		"s.rank_key_us",
		"s.near_state",
		"function schedulerTip(r)",
		"function renderSchedLog(data)",
		"function schedLogEntries(data)",
		"sched_log",
		"function schedExclReason(s)",
	} {
		if !strings.Contains(app, want) {
			t.Errorf("webui/app.js 缺少调度可观测片段 %q", want)
		}
	}
	css := readWebUIAsset(t, "webui/style.css")
	if !strings.Contains(css, ".slog-row") {
		t.Error("style.css 缺少决策流水行样式")
	}
	if !strings.Contains(readWebUIAsset(t, "webui/index.html"), `id="sched-log"`) {
		t.Error("index.html 缺少决策流水容器")
	}
	// 五个 locale 的 sched 块都要带新增键（zh-TW 由 clone 继承，不单独计数）。
	// 注意：不能用 `sched:\{active:[^}]*\}` 这类正则切块——sched 块内的占位符
	// （paths:'{a}/{n}'、excl_cmp:'...{a}...{b}'）自带 '}'，会把块提前截断。改用计数。
	i18n := readWebUIAsset(t, "webui/i18n.js")
	if got := strings.Count(i18n, "sched:{active:'"); got != 5 {
		t.Fatalf("sched 字典数量=%d want=5", got)
	}
	for _, want := range []string{
		"excl_envelope_out:'", "excl_cmp:'", "reason_sticky_held:'",
		"near_lenient:'", "log_line:'", "rank:'",
	} {
		if got := strings.Count(i18n, want); got != 5 {
			t.Errorf("i18n.js %s 出现 %d 次 want=5（五个 locale 各一份）", want, got)
		}
	}
}

// TestSchedConnJSONObservabilityFields 逐字段验证快照 JSON 契约：新增字段名必须
// 与前端读取的 scheduler.* 完全一致（漏一个就是面板静默失效）。
func TestSchedConnJSONObservabilityFields(t *testing.T) {
	b := testAdaptiveBackend(10_000)
	b.schedEnvMinRttUS.Store(10_000)
	b.schedEnvMaxRttUS.Store(12_500)
	b.rankKeyUS.Store(-3850)
	b.schedFlags.Store(schedExcludeNone | schedFlagRankKnown | schedFlagNearIn)
	b2 := testAdaptiveBackend(26_000)
	b2.schedEnvMinRttUS.Store(10_000)
	b2.schedEnvMaxRttUS.Store(12_500)
	b2.schedFlags.Store(schedExcludeEnvelopeOut)
	b3 := testAdaptiveBackend(10_000)
	b3.schedFlags.Store(schedFlagStickyHeld)
	b4 := testAdaptiveBackend(10_000)
	b4.schedFlags.Store(schedFlagNearLenient)
	b5 := testAdaptiveBackend(10_000)
	b5.schedFlags.Store(schedFlagNearIn)

	cases := []struct {
		name string
		snap schedulerConnJSON
		want string
	}{
		{"eligible", schedulerSnapshot(b), `"eligible":true`},
		{"group_min", schedulerSnapshot(b), `"group_min_rtt_us":10000`},
		{"group_max", schedulerSnapshot(b), `"group_max_rtt_us":12500`},
		{"rank_known", schedulerSnapshot(b), `"rank_known":true`},
		{"rank_key", schedulerSnapshot(b), `"rank_key_us":-3850`},
		{"excluded", schedulerSnapshot(b2), `"eligible":false`},
		{"exclude_reason", schedulerSnapshot(b2), `"exclude_reason":"envelope_out"`},
		{"sticky", schedulerSnapshot(b3), `"sticky_held":true`},
		{"near_lenient", schedulerSnapshot(b4), `"near_state":"lenient"`},
		{"near_in", schedulerSnapshot(b5), `"near_state":"in"`},
	}
	for _, tc := range cases {
		out, err := json.Marshal(tc.snap)
		if err != nil {
			t.Fatalf("%s: marshal: %v", tc.name, err)
		}
		if !strings.Contains(string(out), tc.want) {
			t.Errorf("%s: JSON 缺少 %s: %s", tc.name, tc.want, out)
		}
	}
}

// setFwdRank 给合成后端注入已收敛的去程读数（µs，有符号相对量）。
// 经 oneWayRankEncode 编码，与生产路径（rtt_probe 的 recomputeAll 发布点）同一口径。
func setFwdRank(b *Backend, rawUS int64) {
	b.fwdRankUS.Store(oneWayRankEncode(rawUS))
}

// schedEnvelopeFwdPort 构造已开启 fwd 资格门、窗口 ms 的端口，并把 backends 接到
// 它的一向时延模式上。oneWayModePtr 是 backendOneWayUS 选 fwd/ret 的唯一依据，
// 不接线则探针读数一律读不到（生产里由 Register*Backend 在注册后端时接线）。
func schedEnvelopeFwdPort(t *testing.T, ms int, backends ...*Backend) *AsyncPort {
	t.Helper()
	p := &AsyncPort{}
	p.SetSchedEnvelope(string(SchedEnvelopeFwd))
	p.SetSchedEnvelopeMs(ms)
	p.SetOneWayMode(oneWayModeFwd)
	for _, b := range backends {
		if b != nil {
			b.oneWayModePtr = &p.oneWayMode
		}
	}
	return p
}

// TestSchedEnvelopeFwdGate 验证 fwd 门按去程准入：一条"往返很慢但去程最快"的
// 极不对称路径，在 rtt 门下被方向盲的往返地板挡掉，在 fwd 门下应当准入。
// 这正是引入该选项的动机——两端各自按自己的发送方向设门。
func TestSchedEnvelopeFwdGate(t *testing.T) {
	a := testAdaptiveBackend(10_000) // 去程快、往返也快
	b := testAdaptiveBackend(26_000) // 往返很慢，但去程与 a 几乎相同
	a.rateBytesPerSec.Store(20_000_000)
	b.rateBytesPerSec.Store(20_000_000)
	setFwdRank(a, -400)
	setFwdRank(b, -350)

	// rtt 门（默认）：b 的往返 26ms 远超 a 的地板 10ms+滞回，被排除。
	prt := &AsyncPort{}
	if got := prt.pickAdaptiveBackend([]*Backend{a, b}, 0, 8*1024); got != a {
		t.Fatalf("rtt 门: got=%p want=%p", got, a)
	}
	if snap := schedulerSnapshot(b); snap.ExcludeReason != "envelope_out" || snap.Eligible {
		t.Fatalf("rtt 门下 b 应被排除: %+v", snap)
	}

	// fwd 门：两者去程读数相差不超过 20ms 窗口，b 应当准入候选集。
	p := schedEnvelopeFwdPort(t, 20, a, b)
	if got := p.pickAdaptiveBackend([]*Backend{a, b}, 0, 8*1024); got == nil {
		t.Fatal("fwd 门选路返回 nil")
	}
	snapB := schedulerSnapshot(b)
	if !snapB.Eligible {
		t.Fatalf("fwd 门下去程相近的路径被误排除: %+v", snapB)
	}
	if snapB.GroupFwdFloorUS != -400 {
		t.Fatalf("组内去程地板=%d want=-400", snapB.GroupFwdFloorUS)
	}
	if !snapB.FwdRankKnown || snapB.FwdRankUS != -350 {
		t.Fatalf("fwd 读数未发布: known=%v us=%d", snapB.FwdRankKnown, snapB.FwdRankUS)
	}
	// 地板是组内最小去程，即 a 的 -400。
	if snapA := schedulerSnapshot(a); snapA.GroupFwdFloorUS != -400 {
		t.Fatalf("a 侧地板=%d want=-400", snapA.GroupFwdFloorUS)
	}
}

// TestSchedEnvelopeFwdExcludesSlowFwd 验证 fwd 门真的会排除去程明显偏慢的路径，
// 而不是无条件放行——否则它就成了"永不排除"的洞。
func TestSchedEnvelopeFwdExcludesSlowFwd(t *testing.T) {
	fast := testAdaptiveBackend(10_000)
	slow := testAdaptiveBackend(10_000) // 往返相同，但去程慢 50ms
	fast.rateBytesPerSec.Store(20_000_000)
	slow.rateBytesPerSec.Store(20_000_000)
	setFwdRank(fast, -400)
	setFwdRank(slow, 49_600) // -400 + 50_000

	p := schedEnvelopeFwdPort(t, 20, fast, slow)
	p.pickAdaptiveBackend([]*Backend{fast, slow}, 0, 8*1024)
	snap := schedulerSnapshot(slow)
	if snap.Eligible {
		t.Fatalf("去程慢 50ms 的路径应被 fwd 门排除: %+v", snap)
	}
	if snap.ExcludeReason != "envelope_out" {
		t.Fatalf("排除原因=%q want=envelope_out", snap.ExcludeReason)
	}
}

// TestSchedEnvelopeFwdFallback 组内无任何已收敛去程读数时整体回退 rtt 门：
// 不能因为探针没收敛就空转（全部排除会退化成每批都 envelope_empty）。
func TestSchedEnvelopeFwdFallback(t *testing.T) {
	fast := testAdaptiveBackend(10_000)
	slow := testAdaptiveBackend(26_000)
	fast.rateBytesPerSec.Store(20_000_000)
	slow.rateBytesPerSec.Store(20_000_000)
	// 不注入 fwdRankUS：两者 backendOneWayUS 都未收敛 → 地板取不到。

	p := schedEnvelopeFwdPort(t, 20, fast, slow)
	if got := p.pickAdaptiveBackend([]*Backend{fast, slow}, 0, 8*1024); got != fast {
		t.Fatalf("回退 rtt 门后应仍选往返更快的: got=%p want=%p", got, fast)
	}
	// 回退后不应发布 fwd 地板（0=尚未建立），面板据此不显示去程比较式。
	if snap := schedulerSnapshot(slow); snap.GroupFwdFloorUS != 0 {
		t.Fatalf("回退 rtt 门不应发布去程地板: %d", snap.GroupFwdFloorUS)
	}
	if snap := schedulerSnapshot(fast); snap.GroupFwdFloorUS != 0 {
		t.Fatalf("回退 rtt 门不应发布去程地板: %d", snap.GroupFwdFloorUS)
	}
	// rtt 门的组包络照常发布，面板仍可读往返区间。
	if snap := schedulerSnapshot(fast); snap.GroupMinRttUS == 0 {
		t.Fatalf("回退 rtt 门后往返地板应仍发布: %+v", snap)
	}
}

// TestSchedEnvelopeFwdLenientUnconverged 探针未收敛的路径在 fwd 门下宽松放行，
// 与 near 窗口 parityNearState 的 bootstrap 契约一致：未收敛回退值是绝对内核
// 尺度，与已收敛探针的有符号相对量跨尺度比较会误判。
func TestSchedEnvelopeFwdLenientUnconverged(t *testing.T) {
	fast := testAdaptiveBackend(10_000)
	// cold 侧完成热身但探针未收敛（不注入 fwdRankUS）
	cold := testAdaptiveBackend(10_000)
	fast.rateBytesPerSec.Store(20_000_000)
	cold.rateBytesPerSec.Store(20_000_000)
	setFwdRank(fast, -400)

	p := schedEnvelopeFwdPort(t, 20, fast, cold)
	if got := p.pickAdaptiveBackend([]*Backend{fast, cold}, 0, 8*1024); got == nil {
		t.Fatal("选路返回 nil")
	}
	if snap := schedulerSnapshot(cold); !snap.Eligible {
		t.Fatalf("探针未收敛的路径应宽松放行: %+v", snap)
	}
}

// TestSchedEnvelopeConfigValidate fwd 门两个配置项的校验契约：合法值通过并生效，
// 非法枚举与越界窗口必须被拒（与 fec_near_window_ms 的既有契约同一风格）。
func TestSchedEnvelopeConfigValidate(t *testing.T) {
	old := &Config{}
	psk := strings.Repeat("a1", 32)
	valid := `{"mode":"client","addr":"1.2.3.4:4000","psk":"` + psk +
		`","sched_envelope":"fwd","sched_envelope_ms":35}`
	cfg, _, err := mergeAndValidateConfig(old, json.RawMessage(valid), false, nil, nil)
	if err != nil {
		t.Fatalf("合法 sched_envelope 应通过: %v", err)
	}
	if cfg.SchedEnvelope != string(SchedEnvelopeFwd) || cfg.SchedEnvelopeMs != 35 {
		t.Fatalf("字段未被设置: mode=%q ms=%d", cfg.SchedEnvelope, cfg.SchedEnvelopeMs)
	}

	if _, _, err := mergeAndValidateConfig(old, json.RawMessage(
		`{"mode":"client","addr":"1.2.3.4:4000","psk":"`+psk+`","sched_envelope":"bogus"}`), false, nil, nil); err == nil {
		t.Fatal("非法 sched_envelope 必须被拒绝")
	}
	// 0 = 未配置，applyDefaults 归一为默认 20ms 后才校验，故不属于越界；下界同理
	// （minMs-1 = 0 会被归一），只断言真越界的上界。
	bad := fmt.Sprintf(`{"mode":"client","addr":"1.2.3.4:4000","psk":"%s","sched_envelope_ms":%d}`, psk, schedEnvelopeMaxMs+1)
	if _, _, err := mergeAndValidateConfig(old, json.RawMessage(bad), false, nil, nil); err == nil {
		t.Errorf("越界 sched_envelope_ms=%d 必须被拒绝", schedEnvelopeMaxMs+1)
	}
}

// TestSchedEnvelopeDefaultIsRTT 默认（未配置）必须是 rtt 门：新选项上线不能改变
// 既有用户的选路行为。
func TestSchedEnvelopeDefaultIsRTT(t *testing.T) {
	old := &Config{}
	cfg, _, err := mergeAndValidateConfig(old, json.RawMessage(
		`{"mode":"client","addr":"1.2.3.4:4000","psk":"`+strings.Repeat("a1", 32)+`"}`), false, nil, nil)
	if err != nil {
		t.Fatalf("最小配置应通过: %v", err)
	}
	if cfg.SchedEnvelope != string(SchedEnvelopeRTT) {
		t.Fatalf("默认 sched_envelope=%q want=%q", cfg.SchedEnvelope, SchedEnvelopeRTT)
	}
	if cfg.SchedEnvelopeMs != schedEnvelopeDefaultMs {
		t.Fatalf("默认 sched_envelope_ms=%d want=%d", cfg.SchedEnvelopeMs, schedEnvelopeDefaultMs)
	}
}

// TestWebUISchedEnvelopeContract fwd 门在面板侧的契约：i18n 五语言各带包络维度
// 标签与 fwd 比较式，app.js 按 group_fwd_floor_us 走模式感知分支，配置键能出设置页。
func TestWebUISchedEnvelopeContract(t *testing.T) {
	i18n := readWebUIAsset(t, "webui/i18n.js")
	for _, want := range []string{"excl_cmp_fwd:'", "env_fwd:'", "sched_envelope:'", "sched_envelope_ms:'"} {
		if got := strings.Count(i18n, want); got != 5 {
			t.Errorf("i18n.js %s 出现 %d 次 want=5（五个 locale 各一份）", want, got)
		}
	}
	app := readWebUIAsset(t, "webui/app.js")
	for _, want := range []string{
		"group_fwd_floor_us",
		"excl_cmp_fwd",
		"env_fwd",
		"fwd_rank_known",
	} {
		if !strings.Contains(app, want) {
			t.Errorf("webui/app.js 缺少 fwd 门渲染片段 %q", want)
		}
	}
}
