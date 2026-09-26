package main

import "testing"

// TestPadStatsSnapshotOffModeReportsZero off 模式必须返回全零快照而不是 nil：
// 面板要显示 0.0%，把"填充已正确关闭"渲染成"未启用"会让人以为配置丢了。
// 这里显式清零计数：测试顺序不应决定快照内容。
func TestPadStatsSnapshotOffModeReportsZero(t *testing.T) {
	prev := setPadMode(padModeOff)
	defer setPadMode(prev)

	padWireC.v.Store(0)
	padPadC.v.Store(0)

	got := padStatsJSONPtr()
	if got == nil {
		t.Fatal("zero snapshot must not be nil")
	}
	if got.Mode != padModeOff || got.WireBytes != 0 || got.PadBytes != 0 || got.OverheadPct != 0 {
		t.Fatalf("off mode snapshot = %+v, want mode=off with all-zero counters", got)
	}

	// pad=0 的记账调用是空操作：心跳等空帧、off 模式下的整包都不该写计数器
	recordPadBytes(128, 0)
	if w, p := padStatsSnapshot(); w != 0 || p != 0 {
		t.Fatalf("recordPadBytes with pad=0 must be a no-op, got %d/%d", w, p)
	}
}

// TestSetPadModeResetsCountersOnChange 两种策略的线路长度分布完全不同，混在
// 一个累计里得到的"填充开销"既不代表旧策略也不代表新策略。
func TestSetPadModeResetsCountersOnChange(t *testing.T) {
	prev := padModeName()
	defer setPadMode(prev)

	setPadMode(padModeBucket)
	recordPadBytes(100, 40)
	if w, p := padStatsSnapshot(); w != 100 || p != 40 {
		t.Fatalf("after record = %d/%d, want 100/40", w, p)
	}

	if got := setPadMode(padModeOff); got != padModeOff {
		t.Fatalf("setPadMode(off) = %q, want %q", got, padModeOff)
	}
	if w, p := padStatsSnapshot(); w != 0 || p != 0 {
		t.Fatalf("strategy change must reset counters, got %d/%d", w, p)
	}

	// 设为同一个策略是空操作，不清零
	setPadMode(padModeBucket)
	recordPadBytes(100, 40)
	if got := setPadMode(padModeBucket); got != padModeBucket {
		t.Fatalf("setPadMode(bucket) = %q, want %q", got, padModeBucket)
	}
	if w, p := padStatsSnapshot(); w != 100 || p != 40 {
		t.Fatalf("idempotent setPadMode must not reset, got %d/%d", w, p)
	}

	if got := setPadMode("bogus"); got != padModeBucket {
		t.Fatalf("invalid mode must fall back to bucket, got %q", got)
	}
}

// TestAppendPaddedFrameReportsPad 记账移到 Write 成功之后之后，填充字节数只能
// 由成帧方自己报出来。1B 负载要补到 128B 的桶，117B 全是填充。
func TestAppendPaddedFrameReportsPad(t *testing.T) {
	prev := setPadMode(padModeBucket)
	defer setPadMode(prev)

	buf, pad := appendPaddedFrame(nil, VPNFrame{Seq: 1, Data: []byte("x")}, nil)
	if len(buf) != 128 {
		t.Fatalf("1B payload must land on the 128B bucket, got %d bytes", len(buf))
	}
	if pad != 117 {
		t.Fatalf("pad = %d, want 117 (128 - 10 header - 1 payload)", pad)
	}
	if uint64(pad) != uint64(len(buf))-11 {
		t.Fatalf("pad + header + payload must equal the record length: pad=%d len=%d", pad, len(buf))
	}

	setPadMode(padModeOff)
	buf, pad = appendPaddedFrame(nil, VPNFrame{Seq: 1, Data: []byte("xy")}, nil)
	if pad != 0 || len(buf) != 12 {
		t.Fatalf("off mode must add no padding: pad=%d len=%d", pad, len(buf))
	}
}
