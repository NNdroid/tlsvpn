package main

import (
	"crypto/rand"
	"testing"
)

// 性能基准覆盖本轮新增的数据面路径：GCM 加解密、FEC 编解码恢复。
// 跑法：go test -bench=. -run='^$' -benchmem

func benchPayload() []byte {
	p := make([]byte, 1400)
	rand.Read(p)
	return p
}

func BenchmarkGCMSealOpen(b *testing.B) {
	salt := randomSalt()
	tx, _ := newGCMInnerCipher("bench_gcm", salt)
	rx, _ := newGCMInnerCipher("bench_gcm", salt)
	pt := benchPayload()
	region := make([]byte, len(pt)+gcmTagSize)

	b.SetBytes(int64(len(pt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(region, pt)
		tx.sealInPlace(region, len(pt), uint32(i)+1, uint32(len(region)))
		if _, err := rx.openInPlace(region, uint32(i)+1, uint32(len(region))); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFECEncode(b *testing.B) {
	// K=4、1400B 帧：覆盖异或累加 + 校验帧构建
	e := newFECEncoder(4, nil)
	pt := benchPayload()
	b.SetBytes(int64(len(pt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if par := e.add(VPNFrame{Seq: uint32(i%100000) + 1, Data: pt}); par != nil {
			putFrame(par)
			e.reset()
		}
	}
}

func BenchmarkFECEncodeRecover(b *testing.B) {
	// 全链路：每个 K=4 分组故意丢最后 1 帧，parity 到达后恢复。
	// 编码器始终看到完整 4 帧；解码器只看到前 3 帧，符合真实线路所有权。
	d := NewFECDecoder(4, nil, func(seq uint32, frame []byte) { putFrame(frame) })
	e := newFECEncoder(4, nil)
	pt := benchPayload()
	var seq uint32
	b.SetBytes(int64(len(pt)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var par []byte
		for j := 0; j < 4; j++ {
			seq++
			if p := e.add(VPNFrame{Seq: seq, Data: pt}); p != nil {
				par = p
			}
			if j != 3 {
				d.OnData(seq, pt)
			}
		}
		if par == nil {
			b.Fatal("expected parity frame")
		}
		// OnParity 只借用 payload；处理完成后才能把 parity 归还池。
		d.OnParity(par)
		putFrame(par)
	}
}
