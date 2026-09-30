package main

import (
	"crypto/rand"
	"testing"
)

// 性能基准覆盖本轮新增的数据面路径：GCM 加解密、FEC 编解码恢复，以及
// AsyncPort 的 1/2 物理连接 × FEC off/on 分发矩阵。
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

func BenchmarkGCM128SealOpen(b *testing.B) {
	salt := randomSalt()
	tx, _ := newGCMInnerCipherForAlgo("bench_gcm128", salt, encAlgoGCM128)
	rx, _ := newGCMInnerCipherForAlgo("bench_gcm128", salt, encAlgoGCM128)
	pt := benchPayload()
	region := make([]byte, len(pt)+gcmTagSize)

	b.SetBytes(int64(len(pt)))
	b.ReportAllocs()
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

func drainBenchBackends(backends []*Backend) {
	for _, backend := range backends {
		for {
			select {
			case batch := <-backend.ch:
				n := vpnFrameBatchBytes(batch)
				backend.completeQueuedBytes(n)
				freeFrames(batch)
				putVPNFrameBatch(batch)
			default:
				goto nextBackend
			}
		}
	nextBackend:
	}
}

// BenchmarkAsyncPortDispatchFECMatrix 量化 single-path FEC fast bypass 的真实
// AsyncPort 热路径，而不是直接调用 fecEncoder。每轮 8×1400B = 11.2 KiB，接近
// streamTLSBatchSoftLimit；K=4 时多路径 FEC-on 每轮应生成 2 份 parity。
//
// 关键比较：
//   - 1conn/FEC_on vs 1conn/FEC_off：#68 fast bypass 应让两者尽量接近；
//   - 2conn/FEC_on vs 2conn/FEC_off：保留正常 XOR/parity 成本作为对照。
func BenchmarkAsyncPortDispatchFECMatrix(b *testing.B) {
	const (
		framesPerBatch = 8
		frameBytes     = 1400
		batchBytes     = framesPerBatch * frameBytes
	)

	cases := []struct {
		name  string
		paths int
		fec   bool
	}{
		{name: "1conn/FEC_off", paths: 1, fec: false},
		{name: "1conn/FEC_on", paths: 1, fec: true},
		{name: "2conn/FEC_off", paths: 2, fec: false},
		{name: "2conn/FEC_on", paths: 2, fec: true},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			p := &AsyncPort{
				parityScratch:    make([][]byte, 0, framesPerBatch/fecMinGroup),
				schedulerScratch: make([]backendCandidate, 0, tc.paths),
			}
			if tc.fec {
				p.encoder = newFECEncoder(4, nil)
			}

			backends := make([]*Backend, 0, tc.paths)
			rtts := make([]uint32, tc.paths)
			for i := 0; i < tc.paths; i++ {
				rtts[i] = uint32(1000 + i*100)
				backends = append(backends, &Backend{
					ch:       make(chan []VPNFrame, 32),
					rttCache: &rtts[i],
				})
			}
			p.backends = backends

			var seq uint32
			b.SetBytes(batchBytes)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var batch [framesPerBatch]VPNFrame
				for j := range batch {
					seq++
					frame := getFrameAtLeast(frameBytes)[:frameBytes]
					batch[j] = VPNFrame{Seq: seq, Data: frame}
				}
				p.dispatchBatch(batch[:], batchBytes)
				drainBenchBackends(backends)
			}
			b.StopTimer()

			if p.encoder != nil && b.N > 0 {
				b.ReportMetric(float64(p.encoder.ParitySent())/float64(b.N), "parity/op")
			}
		})
	}
}
