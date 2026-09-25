package main

import (
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


func TestTLSWriteBatchLimitByConnectionCount(t *testing.T) {
	tests := []struct {
		name  string
		conns int
		want  int
	}{
		{name: "legacy_unknown", conns: 0, want: maxTLSWriteBatchBytesMulti},
		{name: "single_path", conns: 1, want: maxTLSWriteBatchBytesSingle},
		{name: "two_paths", conns: 2, want: maxTLSWriteBatchBytesMulti},
		{name: "four_paths", conns: 4, want: maxTLSWriteBatchBytesMulti},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tlsWriteBatchLimit(tt.conns); got != tt.want {
				t.Fatalf("tlsWriteBatchLimit(%d)=%d, want %d", tt.conns, got, tt.want)
			}
		})
	}
}
