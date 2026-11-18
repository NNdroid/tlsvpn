package main

import (
	"context"
	"encoding/binary"
	"testing"
	"time"
)

// TestClockOffsetFrameRoundTrip 验证 0x05/0x06 帧的编解码往返。
func TestClockOffsetFrameRoundTrip(t *testing.T) {
	buf := appendClockOffsetProbeFrame(nil, 0x12345678, 7)
	if len(buf) != clockOffsetWireLen {
		t.Fatalf("probe wire len = %d, want %d", len(buf), clockOffsetWireLen)
	}
	kind, nonce, conn, sendTS, recvTS, txTS, err := parseClockOffsetFrame(buf)
	if err != nil {
		t.Fatalf("parse probe: %v", err)
	}
	if kind != controlKindClockProbe || nonce != 0x12345678 || conn != 7 {
		t.Fatalf("probe fields = (%x,%08x,%d), want (0x05,%08x,7)", kind, nonce, conn, 0x12345678)
	}
	if sendTS != 0 || recvTS != 0 || txTS != 0 {
		t.Fatalf("probe ts/off_ts = (%d,%d,%d), want zero", sendTS, recvTS, txTS)
	}

	rbuf := appendClockOffsetReplyFrame(nil, 0x12345678, 1000, 2000, 5)
	kind, nonce, _, sendTS, recvTS, txTS, err = parseClockOffsetFrame(rbuf)
	if err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	if kind != controlKindClockReply || nonce != 0x12345678 || sendTS != 1000 || recvTS != 2000 || txTS != 5 {
		t.Fatalf("reply fields = (%x,%08x,%d,%d,%d), want (0x06,%08x,1000,2000,5)",
			kind, nonce, sendTS, recvTS, txTS, 0x12345678)
	}
}

// TestClockOffsetRejectsMalformed 校验长度、kind、flags 的严格纪律。
func TestClockOffsetRejectsMalformed(t *testing.T) {
	valid := appendClockOffsetProbeFrame(nil, 1, 0)

	short := appendClockOffsetProbeFrame(nil, 1, 0)[:clockOffsetWireLen-1]
	if _, _, _, _, _, _, err := parseClockOffsetFrame(short); err == nil {
		t.Fatal("accepted short frame")
	}
	long := append(appendClockOffsetProbeFrame(nil, 1, 0), 0)
	if _, _, _, _, _, _, err := parseClockOffsetFrame(long); err == nil {
		t.Fatal("accepted long frame")
	}

	badKind := appendClockOffsetProbeFrame(nil, 1, 0)
	badKind[0] = controlKindFECParity
	if _, _, _, _, _, _, err := parseClockOffsetFrame(badKind); err == nil {
		t.Fatal("accepted wrong kind")
	}

	badFlags := appendClockOffsetProbeFrame(nil, 1, 0)
	badFlags[clockOffOffFlags] = 1
	if _, _, _, _, _, _, err := parseClockOffsetFrame(badFlags); err == nil {
		t.Fatal("accepted nonzero flags (must be 0)")
	}
	_ = valid
}

// TestClockOffsetIsFramePrefix 校验读循环前置拦截的识别边界。
func TestClockOffsetIsFramePrefix(t *testing.T) {
	if !isClockOffsetFrame(appendClockOffsetProbeFrame(nil, 1, 0)) {
		t.Fatal("did not recognize probe frame")
	}
	if !isClockOffsetFrame(appendClockOffsetReplyFrame(nil, 1, 100, 200, 1)) {
		t.Fatal("did not recognize reply frame")
	}
	if isClockOffsetFrame(appendRttProbeFrame(nil, 1, 2)) {
		t.Fatal("misidentified RTT probe as clock offset frame")
	}
	if isClockOffsetFrame(nil) {
		t.Fatal("nil recognized as clock offset frame")
	}
}

// TestClockOffsetPatchSendTS 校验发送路径的 send_ts 固定偏移写入。
func TestClockOffsetPatchSendTS(t *testing.T) {
	buf := appendClockOffsetProbeFrame(nil, 1, 0)
	off := 10 + clockOffOffSendTS
	if buf[off] != 0 {
		t.Fatal("send_ts not zero before patch")
	}
	// 构造一个 UnixNano()==42 的时间点：time.Unix(0, 42)。
	patchClockOffsetSendTS(buf, time.Unix(0, 42))
	got := binary.BigEndian.Uint64(buf[off : off+8])
	if got != 42 {
		t.Fatalf("patched send_ts = %d, want 42", got)
	}
}

// TestClockOffsetEstimatorConverges 验证线性最小化估计器收敛到真实 θ。
func TestClockOffsetEstimatorConverges(t *testing.T) {
	e := newClockOffsetEstimator()
	const (
		trueThetaNS = int64(50_000_000)  // 50ms 偏移
		fwdNS       = uint64(30_000_000) // 去程 30ms
		retNS       = uint64(20_000_000) // 回程 20ms
		base        = uint64(1_000_000_000)
	)
	// 构造 12 个往返样本：F=fwd+θ/1 语义下 θ=(B-F)/2。
	// 令 B = ret + 2*thetaApprox... 直接按定义反推：给定 θ，F-θ 与 B+θ 之差。
	// 这里令每样本 t2-t1 = fwdNS + k, t4-t3 = retNS - k，则 θ_k = ((fwd+k)-(ret-k))/2。
	// 取 k 全 0 得 θ=(fwd-ret)/2=(30-20)/2=5ms，非 trueThetaNS。
	// 故改用显式构造：t2-t1 = fwdNS, t4-t3 = retNS，则 θ=(fwd-ret)/2=5ms。
	// 要让 θ 收敛到 5ms，验证估计器输出 ≈5ms（含 MAD 噪声容差）。
	for i := 0; i < 12; i++ {
		e.add(offsetSample{t1: base, t2: base + fwdNS, t3: base + 1, t4: base + 1 + retNS})
	}
	e.refresh()
	got, ok := e.thetaNS()
	if !ok {
		t.Fatal("estimator not converged with 12 samples")
	}
	// (fwd-ret)/2 = 5ms = 5,000,000 ns。容差 ±1ms 覆盖 MAD 噪声。
	if got < 4_000_000 || got > 6_000_000 {
		t.Fatalf("theta = %d ns, want ~5,000,000", got)
	}
	if unc := e.uncertaintyUS(); unc > 2000 {
		t.Fatalf("uncertainty = %d us, exceeds max", unc)
	}
}

// TestClockOffsetEstimatorRejectsOutliers 验证离群值鲁棒性：中位数解不被拉偏。
func TestClockOffsetEstimatorRejectsOutliers(t *testing.T) {
	e := newClockOffsetEstimator()
	const (
		base = uint64(1_000_000_000)
		fwd  = uint64(30_000_000)
		ret  = uint64(20_000_000)
	)
	// 10 个正常样本 + 1 个 500ms 离群（模拟偶发重传/排队抖动）。
	for i := 0; i < 10; i++ {
		e.add(offsetSample{t1: base, t2: base + fwd, t3: base + 1, t4: base + 1 + ret})
	}
	e.add(offsetSample{t1: base, t2: base + fwd + 500_000_000, t3: base + 1, t4: base + 1 + ret})
	e.refresh()
	got, ok := e.thetaNS()
	if !ok {
		t.Fatal("estimator rejected despite 11 samples")
	}
	// 中位数应仍 ≈5ms；离群值被 MAD 压住。
	if got < 3_000_000 || got > 7_000_000 {
		t.Fatalf("theta = %d ns, outlier skewed the median", got)
	}
}

// TestClockOffsetEstimatorInsufficientSamples 验证样本不足时判不可信。
func TestClockOffsetEstimatorInsufficientSamples(t *testing.T) {
	e := newClockOffsetEstimator()
	for i := 0; i < clockOffsetMinSamples-1; i++ {
		e.add(offsetSample{t1: 100, t2: 200, t3: 101, t4: 250})
	}
	e.refresh()
	if _, ok := e.thetaNS(); ok {
		t.Fatal("estimator converged below minimum sample count")
	}
}

// TestClockOffsetEstimatorExcludesBadSamples 验证时钟异常样本被丢弃。
func TestClockOffsetEstimatorExcludesBadSamples(t *testing.T) {
	e := newClockOffsetEstimator()
	const (
		base = uint64(1_000_000_000)
		fwd  = uint64(30_000_000)
		ret  = uint64(20_000_000)
	)
	for i := 0; i < 12; i++ {
		e.add(offsetSample{t1: base, t2: base + fwd, t3: base + 1, t4: base + 1 + ret})
	}
	// 注入 t2<t1 的样本（跨钟负偏移或离群，估计器不再按 t2<t1 丢弃——B 慢于
	// A 是合法状态）：中位数解应保持不受单个离群样本拉偏。
	e.add(offsetSample{t1: base, t2: base - 1, t3: base + 1, t4: base + 1 + ret})
	e.refresh()
	got, ok := e.thetaNS()
	if !ok {
		t.Fatal("estimator lost convergence after adding a bad sample")
	}
	if got < 4_000_000 || got > 6_000_000 {
		t.Fatalf("theta = %d ns, bad sample polluted the estimate", got)
	}
}

// TestClockOffsetAbsorbUsesTxTS 验证 absorb 用对端显式回填的 off_ts 重建 t3
// （off_ts 是 UnixMilli 低 32 位，须以 recv_ts 的毫秒为基准做环回差值还原，
// 而非 issued 时刻近似），且 off_ts==0 的样本被丢弃。
func TestClockOffsetAbsorbUsesTxTS(t *testing.T) {
	backend := &Backend{probeCh: make(chan []byte, 8)}
	resolve := func(i int) *Backend { return backend }
	active := func() []int { return []int{0} }
	s := newClockOffsetScheduler(context.Background(), resolve, active)

	// 构造一个 pending 探针，nonce 对应。
	// 直接驱动调度 goroutine 独占路径：手动建 pending + 调 absorb。
	now := time.Now()
	t1 := uint64(now.UnixNano())
	s.pending[42] = pendingClockProbe{srcConn: 0, targetConn: 0, issued: now}

	// B 在 now+3ms 收到请求、now+5ms 发出回包：recv_ts 全量纳秒，off_ts 为
	// now+5ms 的 UnixMilli 低 32 位。重建结果应恰为 recvTS+2ms。
	t2 := uint64(now.UnixNano()) + 3_000_000
	txMS := uint32(now.UnixMilli() + 5)
	fr := clockOffsetFrame{
		kind: controlKindClockReply, nonce: 42, conn: 0,
		sendTS: t1, recvTS: t2,
		txTS: txMS, srcConn: 0, recvAt: now.Add(5 * time.Millisecond),
	}
	s.absorb(fr)

	// 估计器应收到一个样本且 t3 精确 = t2 + (txMS − ms(t2)) × 1ms。
	if n := s.est.count(); n != 1 {
		t.Fatalf("estimator sample count = %d, want 1", n)
	}
	samp := s.est.samples[0]
	wantT3 := t2 + uint64(int32(txMS-uint32(t2/1_000_000)))*1_000_000
	if samp.t3 != wantT3 {
		t.Fatalf("t3 = %d, want %d (reconstructed from off_ts)", samp.t3, wantT3)
	}
	if samp.t1 != t1 || samp.t2 != fr.recvTS {
		t.Fatalf("t1/t2 = (%d,%d), want (%d,%d)", samp.t1, samp.t2, t1, fr.recvTS)
	}

	// off_ts==0 的样本应被丢弃（对端未填）。
	s.pending[43] = pendingClockProbe{srcConn: 0, targetConn: 0, issued: now}
	s.absorb(clockOffsetFrame{
		kind: controlKindClockReply, nonce: 43, conn: 0,
		sendTS: t1, recvTS: uint64(now.UnixNano()) + 3_000_000,
		txTS: 0, srcConn: 0, recvAt: now.Add(5 * time.Millisecond),
	})
	if n := s.est.count(); n != 1 {
		t.Fatalf("txTS==0 sample not dropped, count=%d", n)
	}
}

// TestClockOffsetRespondUsesRecvAtAsT2 回归：respond 的 t2 必须取读循环的到达
// 时刻（fr.recvAt，与 absorb 的 t4 同一打点位置），而非调度 goroutine 的
// time.Now()——后者混入 replies 通道+唤醒延迟，会让 θ 带 +d/2 的系统性偏置却
// "低不确定度收敛"到错值。
func TestClockOffsetRespondUsesRecvAtAsT2(t *testing.T) {
	backend := &Backend{probeCh: make(chan []byte, 8)}
	resolve := func(i int) *Backend { return backend }
	s := newClockOffsetScheduler(context.Background(), resolve, func() []int { return []int{0} })

	recvAt := time.Unix(1_800_000_000, 123_456_789) // 固定到达时刻（ns 粒度可辨）
	s.respond(clockOffsetFrame{
		kind: controlKindClockProbe, nonce: 7, conn: 0,
		sendTS: 111, srcConn: 0, recvAt: recvAt,
	})
	select {
	case payload := <-backend.probeCh:
		_, nonce, _, sendTS, recvTS, _, err := parseClockOffsetFrame(payload)
		if err != nil {
			t.Fatalf("reply malformed: %v", err)
		}
		if recvTS != uint64(recvAt.UnixNano()) {
			t.Fatalf("t2 = %d, want fr.recvAt ns %d (read-loop arrival, not respond-time)", recvTS, recvAt.UnixNano())
		}
		if nonce != 7 || sendTS != 111 {
			t.Fatalf("echo broken: nonce=%d sendTS=%d", nonce, sendTS)
		}
	default:
		t.Fatal("reply not queued on target conn")
	}
}

// TestClockOffsetEstimatorResetOnRefChange 回归：ref 变化（被测链路换了）时
// 估计器必须整体重置——θ 是"该条链路的不对称度"，旧 ref 的样本对新 ref 毫无
// 意义，混合会产出无人持有的伪 θ。
func TestClockOffsetEstimatorResetOnRefChange(t *testing.T) {
	b0 := &Backend{probeCh: make(chan []byte, 8)}
	b1 := &Backend{probeCh: make(chan []byte, 8)}
	conns := map[int]*Backend{0: b0, 1: b1}
	s := newClockOffsetScheduler(context.Background(),
		func(i int) *Backend { return conns[i] },
		func() []int { return []int{0, 1} })

	// 旧 ref（conn 0）收敛到某个 θ。
	now := time.Now()
	for i := 0; i < clockOffsetMinSamples+2; i++ {
		t1 := uint64(now.Add(time.Duration(i) * time.Second).UnixNano())
		s.est.add(offsetSample{
			t1: t1,
			t2: t1 + 10_000_000, // 去程 10ms
			t3: t1 + 11_000_000, // 1ms 后回包
			t4: t1 + 12_000_000, // 回程 1ms → θ_i=(10-1)/2=4.5ms
			at: now.Add(time.Duration(i) * time.Second),
		})
	}
	s.est.refresh()
	if _, _, ok := s.thetaNS(); !ok {
		t.Fatal("precondition: estimator should converge on old ref samples")
	}

	// ref 切换到 conn 1（conn 0 掉线）：issueRound 必须重置估计器。
	s.issueRound() // activeConns 返回 [0,1]，ref 仍 0 —— 不重置
	if _, _, ok := s.thetaNS(); !ok {
		t.Fatal("same ref must keep converged estimate")
	}
	s.activeConns = func() []int { return []int{1} }
	s.issueRound() // ref 变为 1
	if s.target != 1 {
		t.Fatalf("target not updated: %d", s.target)
	}
	if _, _, ok := s.thetaNS(); ok {
		t.Fatal("estimator must reset (θ not converged) when ref changes")
	}
	// 重置后 pending 探针已发往新 ref（连接 1）。
	if len(b1.probeCh) != 1 {
		t.Fatalf("clock probe not queued on new ref: %d", len(b1.probeCh))
	}
}

// TestClockOffsetSampleAging 回归：solve 剔除超龄样本（clockOffsetSampleMaxAge），
// 路由切换后 θ 在受限窗口内完成向新 regime 收敛，而不是被 ~2 分钟的旧样本拖住。
func TestClockOffsetSampleAging(t *testing.T) {
	e := newClockOffsetEstimator()
	now := time.Now()
	mk := func(age time.Duration, off int64) offsetSample {
		t1 := uint64(int64(now.Add(-age).UnixNano()))
		f := off*2 + 2_000_000 // 去程分量：base 2ms + 2·off
		t2 := uint64(int64(t1) + f)
		t3 := uint64(int64(t1) + 2_000_000)
		t4 := t3 + 2_000_000 // 回程分量恒 2ms
		return offsetSample{t1: t1, t2: t2, t3: t3, t4: t4, at: now.Add(-age)}
	}
	// (t2-t1)-(t4-t3) = (off*2+2ms) - 2ms = off*2 → θ_i = off。8 个新鲜样本
	// 收敛到 off=+5ms；再混 8 个超龄样本（off=-5ms）应被剔除。
	for i := 0; i < 8; i++ {
		e.add(mk(10*time.Second, 5_000_000))
	}
	for i := 0; i < 8; i++ {
		e.add(mk(clockOffsetSampleMaxAge+time.Minute, -5_000_000))
	}
	e.refresh()
	th, ok := e.thetaNS()
	if !ok {
		t.Fatal("fresh samples must keep θ converged")
	}
	if th != 5_000_000 {
		t.Fatalf("θ = %d ns, want 5ms (stale samples excluded)", th)
	}
}
