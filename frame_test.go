package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

// TestFramePoolLengthInvariant 池缓冲的长度必须恒等于容量且等于所在分档。
//
// 历史上 putFrame 只按 cap 回收、原样入池：任何截断副本（frame[:66]）都会
// 带着旧 len 回到池里，下一个使用者按 len 使用时读到残值或直接越界。FEC
// 恢复的异或循环就是这一条路径把整个进程打崩的（线上报
// "index out of range [66] with length 66"）。
func TestFramePoolLengthInvariant(t *testing.T) {
	for _, s := range framePoolSizes {
		s := s
		t.Run(fmt.Sprintf("tier_%d", s), func(t *testing.T) {
			for i := 0; i < 8; i++ {
				b := getFrameAtLeast(s)
				if cap(b) != s || len(b) != s {
					t.Fatalf("分档 %d: 期望 len==cap==%d, got len=%d cap=%d", s, s, len(b), cap(b))
				}
				// 截断后归还：下一轮必须拿回完整长度，不能继承上一任的 len
				putFrame(b[:s/2])
				got := getFrameAtLeast(s)
				if cap(got) != s || len(got) != s {
					t.Fatalf("截断归还后分档 %d: 期望 len==cap==%d, got len=%d cap=%d",
						s, s, len(got), cap(got))
				}
			}
		})
	}
}

// TestFramePoolRecoversFromTruncatedReturn 线上崩溃的确切序列：getFrame() 取到
// 2048 档缓冲 → 截到 66 字节 → 归还 → 再取时必须拿到 len==cap==2048。
func TestFramePoolRecoversFromTruncatedReturn(t *testing.T) {
	putFrame(getFrame()[:66])

	b := getFrameAtLeast(1200) // 1200 落在 2048 档，与被污染的同一档
	if len(b) != 2048 || cap(b) != 2048 {
		t.Fatalf("期望 2048 档且 len==cap, got len=%d cap=%d", len(b), cap(b))
	}
}

// TestFramePoolAboveMaxTier 超出最大分档时直接分配，长度同样必须等于容量。
func TestFramePoolAboveMaxTier(t *testing.T) {
	want := framePoolSizes[len(framePoolSizes)-1] + 1
	b := getFrameAtLeast(want)
	if len(b) != want || cap(b) != want {
		t.Fatalf("超出最大分档时应 len==cap==%d, got len=%d cap=%d", want, len(b), cap(b))
	}
}

// TestFramePoolIgnoresOffTierBuffer 容量不命中任何分档的缓冲不入池，由 GC 回收。
func TestFramePoolIgnoresOffTierBuffer(t *testing.T) {
	putFrame(make([]byte, 66)) // 66 不在分档表内，不入池
	got := getFrameAtLeast(1)
	if cap(got) != 512 || len(got) != 512 {
		t.Fatalf("偏小缓冲不应污染 512 档, got len=%d cap=%d", len(got), cap(got))
	}
	putFrame(got)
	putFrame(nil) // nil 必须安全
}

// TestSetPadModeNormalizesCaseAndWhitespace 大小写/空白规范化：与 crypto.go
// encAlgoFromConfig 同型。"OFF"/" off " 此前被精确匹配静默回落为 bucket 填充，
// 必须同样规范化生效，且规范化改变入参时告警一次。
func TestSetPadModeNormalizesCaseAndWhitespace(t *testing.T) {
	prev := padModeName()
	defer setPadMode(prev)

	// 捕获告警：规范化发生时必须 log 一次警告。
	logs := captureWarnLogs(t)

	if got := setPadMode("OFF"); got != padModeOff {
		t.Fatalf("setPadMode(%q) = %q, want %q", "OFF", got, padModeOff)
	}
	if padModeName() != padModeOff {
		t.Fatalf("OFF 大写未生效: mode=%q", padModeName())
	}
	if got := setPadMode("  off  "); got != padModeOff {
		t.Fatalf("setPadMode(%q) = %q, want %q", "  off  ", got, padModeOff)
	}
	if !bytes.Contains([]byte(logs.String()), []byte("normalized")) {
		t.Fatalf("规范化未告警: %q", logs.String())
	}

	// 规范化值即返回值：调用方 ApplyConfig 的 actual != cfg.PadMode 约定不变。
	logs.Reset()
	if got := setPadMode(padModeOff); got != padModeOff {
		t.Fatalf("规范值不应触发告警路径: got=%q", got)
	}
	if logs.String() != "" {
		t.Fatalf("规范值不应告警: %q", logs.String())
	}

	// 非法值仍回落 bucket（既有契约），且 "BOGUS" 规范化后仍非法。
	if got := setPadMode("BOGUS"); got != padModeBucket {
		t.Fatalf("setPadMode(%q) = %q, want %q", "BOGUS", got, padModeBucket)
	}
	if padModeName() != padModeBucket {
		t.Fatalf("非法值应回落 bucket: mode=%q", padModeName())
	}
}

// TestFrameScannerBufferShrinksAfterJumbo 认证后收过 jumbo 帧会把扫描缓冲 cap
// 推到 ~100KB，只增不减就常驻到会话结束。缓冲排空后的整理点必须把 cap 缩回
// 16KB；缩回后正常收帧不受影响。
func TestFrameScannerBufferShrinksAfterJumbo(t *testing.T) {
	var in bytes.Buffer
	writeScannerFrame := func(seq uint32, data []byte) {
		var hdr [10]byte
		binary.BigEndian.PutUint32(hdr[0:4], uint32(len(data)))
		binary.BigEndian.PutUint16(hdr[4:6], 0)
		binary.BigEndian.PutUint32(hdr[6:10], seq)
		in.Write(hdr[:])
		in.Write(data)
	}

	payload := make([]byte, 100*1024)
	for i := range payload {
		payload[i] = byte(i)
	}
	writeScannerFrame(1, payload)

	fs := NewFrameScanner(&in)
	frame, seq, err := fs.ReadFrame()
	if err != nil || seq != 1 || !bytes.Equal(frame, payload) {
		t.Fatalf("jumbo 帧读取失败: err=%v seq=%d len=%d", err, seq, len(frame))
	}
	putFrame(frame)
	if cap(fs.buf) <= 64*1024 {
		t.Fatalf("前置条件失败: jumbo 未把缓冲 cap 推高 cap=%d", cap(fs.buf))
	}

	// 小帧触达"缓冲已排空"的整理点 → 缩容。
	small := make([]byte, 100)
	writeScannerFrame(2, small)
	frame, seq, err = fs.ReadFrame()
	if err != nil || seq != 2 || !bytes.Equal(frame, small) {
		t.Fatalf("小帧读取失败: err=%v seq=%d len=%d", err, seq, len(frame))
	}
	putFrame(frame)
	if cap(fs.buf) > 16*1024 {
		t.Fatalf("缓冲未缩容: cap=%d want<=16KB", cap(fs.buf))
	}

	// 缩容后继续收帧仍正常。
	writeScannerFrame(3, small)
	frame, seq, err = fs.ReadFrame()
	if err != nil || seq != 3 || !bytes.Equal(frame, small) {
		t.Fatalf("缩容后读取失败: err=%v seq=%d len=%d", err, seq, len(frame))
	}
	putFrame(frame)
}
