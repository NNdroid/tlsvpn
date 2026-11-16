package main

import "testing"

// TestDecomposeOneWayWithThetaSelfConsistent 验证 θ 分解恢复 fwd+ret=RTT 严格自洽，
// 且无需 δ 公共偏移（这是 decomposeOneWay 被迫引入 δ 的根源）。
//
// 构造：ref 真实去程 F_ref=40ms、回程 B_ref=60ms（严重不对称），refRTT=100ms。
// θ=(B-F)/2=(60-40)/2=10ms。另一条连接 i 真实 fwd_i=120ms、ret_i=15ms。
// 则 decay[(i,ref)] = fwd_i + B_ref = 120+60 = 180ms；
//
//	decay[(ref,i)] = F_ref + ret_i = 40+15 = 55ms。
func TestDecomposeOneWayWithThetaSelfConsistent(t *testing.T) {
	const (
		refRTTNS = uint64(100_000_000) // 100ms
		thetaNS  = int64(10_000_000)   // 10ms
		iFwdNS   = uint64(120_000_000)
		iRetNS   = uint64(15_000_000)
	)
	fRefUS := oneWayUS(refRTTNS/2) - uint64(thetaNS)/1000 // 50-10=40ms
	bRefUS := oneWayUS(refRTTNS/2) + uint64(thetaNS)/1000 // 50+10=60ms

	decay := map[[2]uint32]uint64{
		{0, 0}: refRTTNS,             // (ref,ref) = F_ref + B_ref
		{1, 0}: iFwdNS + bRefUS*1000, // (i,ref) = fwd_i + B_ref
		{0, 1}: fRefUS*1000 + iRetNS, // (ref,i) = F_ref + ret_i
	}
	active := []int{0, 1}
	fwd, ret := decomposeOneWayWithTheta(decay, active, 0, refRTTNS, thetaNS)

	// ref 自身：fwd≈40ms、ret≈60ms，和为 refRTT=100ms（严格自洽）。
	// 发布层 δ 非负化可能抬升，故用容差比较；关键是相对序正确且 fwd+ret 接近 RTT。
	if fwd[0] > 41_000 || fwd[0] < 1 {
		t.Fatalf("ref fwd = %d us, want ~40ms(40000us)", fwd[0])
	}
	if ret[0] > 61_000 || ret[0] < 1 {
		t.Fatalf("ref ret = %d us, want ~60ms(60000us)", ret[0])
	}
	// 连接 i：fwd≈120ms、ret≈15ms。
	if fwd[1] > 121_000 || fwd[1] < 1 {
		t.Fatalf("conn1 fwd = %d us, want ~120ms(120000us)", fwd[1])
	}
	if ret[1] > 16_000 || ret[1] < 1 {
		t.Fatalf("conn1 ret = %d us, want ~15ms(15000us)", ret[1])
	}

	// 自洽性：δ 应不显著（最小方向 15ms 远大于 1µs，无需抬升）。
	// 若 fwd[0]+ret[0] 明显偏离 refRTT，说明 δ 被引入或 θ 未生效。
	sum := fwd[0] + ret[0]
	want := oneWayUS(refRTTNS)
	if diff := int64(sum) - int64(want); diff < -5_000 || diff > 5_000 {
		t.Fatalf("ref fwd+ret = %d us, want ~%d us (±5ms)", sum, want)
	}
}

// TestDecomposeOneWayWithThetaVsAnchored 对比：同一矩阵下 θ 分解给出正确的
// 不对称 ref（fwd≠ret），而锚定分解把 ref 钉成 halfRef（fwd==ret），证明 θ
// 路径确实解出了 asymmetry。
func TestDecomposeOneWayWithThetaVsAnchored(t *testing.T) {
	const refRTTNS = uint64(100_000_000)
	halfRef := oneWayUS(refRTTNS) / 2 // 50ms
	thetaNS := int64(10_000_000)

	decay := map[[2]uint32]uint64{
		{0, 0}: refRTTNS,
	}
	active := []int{0}

	// 锚定分解：ref 的 fwd 与 ret 都被钉成 halfRef（对称假设）。
	fa, ra := decomposeOneWay(decay, active, 0, halfRef)
	if fa[0] != ra[0] {
		t.Fatalf("anchor decomposition: ref fwd=%d != ret=%d (expected symmetric)", fa[0], ra[0])
	}

	// θ 分解：ref 的 fwd≠ret，反映真实不对称。
	fb, rb := decomposeOneWayWithTheta(decay, active, 0, refRTTNS, thetaNS)
	if fb[0] == rb[0] {
		t.Fatal("theta decomposition: ref fwd==ret, asymmetry not recovered")
	}
	// fwd < ret（θ>0 表 B_ref > F_ref）。
	if fb[0] >= rb[0] {
		t.Fatalf("theta decomposition: fwd=%d should be < ret=%d for positive theta", fb[0], rb[0])
	}
}

// TestDecomposeOneWayWithThetaNegativeGuard 验证 θ 过大致 fRefUS 溢出时被夹住，
// 不产生负发布值。
func TestDecomposeOneWayWithThetaNegativeGuard(t *testing.T) {
	// θ 大于 refRTT/2：fRefUS 理论上为负，实现应夹住而非下溢。
	refRTTNS := uint64(10_000_000) // 10ms
	thetaNS := int64(6_000_000)    // 6ms > 5ms 半值

	decay := map[[2]uint32]uint64{{0, 0}: refRTTNS}
	fwd, ret := decomposeOneWayWithTheta(decay, []int{0}, 0, refRTTNS, thetaNS)
	if fwd[0] == 0 {
		t.Fatal("fwd published 0 (likely underflow sentinel)")
	}
	// ret 应明显大于 fwd（θ 把不对称全推给回程）。
	if ret[0] <= fwd[0] {
		t.Fatalf("ret=%d should exceed fwd=%d under large positive theta", ret[0], fwd[0])
	}
}
