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
	// 全链路：K 帧中丢 1 帧 → 校验帧到达 → 异或恢复
	// 每次迭代是一个全新分组（seq 递增），避免 done 缓存把开销变成缓存查找
	d := NewFECDecoder(4, nil, func(seq uint32, frame []byte) { putFrame(frame) })
	e := newFECEncoder(4, nil)
	pt := benchPayload()
	var seq uint32
	b.SetBytes(int64(len(pt)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var par []byte
		for j := 0; j < 4; j++ {
			seq++
			if j == 3 {
				continue // 组尾成员“丢失”
			}
			d.OnData(seq, pt)
		}
		// 组尾成员不喂 OnData，由编码器产出的校验帧恢复
		//（校验帧本身按发送侧语义生成，含该成员的异或贡献）
		if par = e.add(VPNFrame{Seq: seq + 1 - 4, Data: pt}); par == nil {
			// 用连续 4 个 add 的第 4 个产出校验帧：重新以该组 4 帧喂编码器
			for j := 0; j < 4; j++ {
				if p2 := e.add(VPNFrame{Seq: seq - 3 + uint32(j), Data: pt}); p2 != nil {
					par = p2
				}
			}
		}
		if par == nil {
			b.Fatal("expected parity frame")
		}
		putFrame(par)
		d.OnParity(par)
	}
}
