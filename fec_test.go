package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

// fecCollector 收集解码器恢复输出的帧
type fecCollector struct {
	mu     sync.Mutex
	seqs   []uint32
	frames [][]byte
	wg     sync.WaitGroup
}

func newFecCollector() (*fecCollector, func(seq uint32, frame []byte)) {
	c := &fecCollector{}
	return c, func(seq uint32, frame []byte) {
		c.mu.Lock()
		c.seqs = append(c.seqs, seq)
		c.frames = append(c.frames, append([]byte(nil), frame...))
		c.mu.Unlock()
		c.wg.Done()
	}
}

func (c *fecCollector) expect(n int) { c.wg.Add(n) }

func (c *fecCollector) waitDone(t *testing.T) {
	t.Helper()
	done := make(chan struct{})
	go func() { c.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("等待 FEC 恢复超时, 已恢复 %d 帧", len(c.seqs))
	}
}

// encodeGroup 已移至 cipher_test.go（依赖 cipher 类型）

func randomIntN(n int) int {
	return int(sha256.Sum256([]byte{byte(n)})[0]) % n
}

func TestFECEncoderParityLayout(t *testing.T) {
	e := newFECEncoder(4, nil)
	var par []byte
	for i := 0; i < 4; i++ {
		vf := VPNFrame{Seq: uint32(i + 1), Data: bytes.Repeat([]byte{byte(0x10 * (i + 1))}, 100)}
		if p := e.add(vf); p != nil {
			par = p
		}
	}
	if par == nil {
		t.Fatal("K=4 时第 4 帧应产出校验帧")
	}
	if par[0] != fecMagic {
		t.Fatalf("校验帧魔数应为 0xFE, got %02x", par[0])
	}
	if start := binary.BigEndian.Uint32(par[1:5]); start != 1 {
		t.Fatalf("组起点应为 1, got %d", start)
	}
	if par[5] != 4 {
		t.Fatalf("组大小应为 4, got %d", par[5])
	}
	// 成员长度字段：4×4B 全部为 100
	for i := 0; i < 4; i++ {
		if l := binary.BigEndian.Uint32(par[6+4*i : 10+4*i]); l != 100 {
			t.Fatalf("成员 %d 长度应为 100, got %d", i, l)
		}
	}
	// 校验载荷 = 成员异或：0x10^0x20^0x30^0x40 = 0x40
	want := byte(0x10 ^ 0x20 ^ 0x30 ^ 0x40)
	for _, b := range par[6+4*4:] {
		if b != want {
			t.Fatalf("校验载荷异或值应为 %02x, got %02x", want, b)
		}
	}
}

func TestFECEncoderPartialGroupNoParity(t *testing.T) {
	e := newFECEncoder(4, nil)
	for i := 0; i < 3; i++ {
		if p := e.add(VPNFrame{Seq: uint32(i + 1), Data: []byte("data")}); p != nil {
			t.Fatal("组未满不应产出校验帧")
		}
	}
}

func TestFECEncoderAccumulatorGrowth(t *testing.T) {
	// 组内后面的帧更长时，累加器扩容必须保留已有异或状态
	e := newFECEncoder(2, nil)
	first := bytes.Repeat([]byte{0x01}, 10)
	if p := e.add(VPNFrame{Seq: 1, Data: first}); p != nil {
		t.Fatal("组未满不应产出校验帧")
	}
	second := bytes.Repeat([]byte{0x02}, 300)
	par := e.add(VPNFrame{Seq: 2, Data: second})
	if par == nil {
		t.Fatal("组满应产出校验帧")
	}
	// 布局: 6B 描述 + 2×4B 长度 + 载荷；载荷前 10 字节: 0x01^0x02=0x03，
	// 其后: 0x00^0x02=0x02
	off := 6 + 2*4
	if par[off+0] != 0x03 || par[off+10] != 0x02 {
		t.Fatalf("扩容后异或状态错误: byte0=%02x byte10=%02x", par[off], par[off+10])
	}
}

func TestFECRoundTripNoLoss(t *testing.T) {
	c, out := newFecCollector()
	d := NewFECDecoder(4, nil, out)
	payloads := [][]byte{
		bytes.Repeat([]byte{0x01}, 40),
		bytes.Repeat([]byte{0x02}, 40),
		bytes.Repeat([]byte{0x03}, 40),
		bytes.Repeat([]byte{0x04}, 40),
	}
	parity := encodeGroup(4, nil, nil, 1, payloads)
	c.expect(0)
	for i, p := range payloads {
		d.OnData(uint32(i+1), p)
	}
	d.OnParity(parity)
	if len(c.seqs) != 0 {
		t.Fatalf("无丢失时解码器不应输出, got %v", c.seqs)
	}
}

func TestFECRecoverSingleLoss(t *testing.T) {
	c, out := newFecCollector()
	d := NewFECDecoder(4, nil, out)
	payloads := [][]byte{
		bytes.Repeat([]byte{0xAA}, 100),
		bytes.Repeat([]byte{0xBB}, 140),
		bytes.Repeat([]byte{0xCC}, 80),
		bytes.Repeat([]byte{0xDD}, 120),
	}
	parity := encodeGroup(4, nil, nil, 1, payloads)

	c.expect(1)
	d.OnData(1, payloads[0])
	d.OnData(3, payloads[2])
	d.OnData(4, payloads[3])
	d.OnParity(parity) // seq=2 丢失

	c.waitDone(t)
	if len(c.seqs) != 1 || c.seqs[0] != 2 {
		t.Fatalf("应恰好恢复 seq=2, got %v", c.seqs)
	}
	if !bytes.Equal(c.frames[0], payloads[1]) {
		t.Fatalf("恢复内容与原文不符: got %d bytes, want %d bytes", len(c.frames[0]), len(payloads[1]))
	}
}

func TestFECRecoverFirstFrameLoss(t *testing.T) {
	// 最难点：组首帧丢失 → 待定组起点被错误锚定在 seq=2，
	// 校验帧到达后必须通过碎片合并平移对齐
	c, out := newFecCollector()
	d := NewFECDecoder(4, nil, out)
	payloads := [][]byte{
		bytes.Repeat([]byte{0x01}, 50),
		bytes.Repeat([]byte{0x02}, 60),
		bytes.Repeat([]byte{0x03}, 70),
		bytes.Repeat([]byte{0x04}, 80),
	}
	parity := encodeGroup(4, nil, nil, 1, payloads)

	c.expect(1)
	d.OnData(2, payloads[1])
	d.OnData(3, payloads[2])
	d.OnData(4, payloads[3])
	d.OnParity(parity)

	c.waitDone(t)
	if len(c.seqs) != 1 || c.seqs[0] != 1 {
		t.Fatalf("应恢复组首帧 seq=1, got %v", c.seqs)
	}
	if !bytes.Equal(c.frames[0], payloads[0]) {
		t.Fatalf("恢复的组首帧内容不符")
	}
}

func TestFECUnrecoverableMultiLoss(t *testing.T) {
	c, out := newFecCollector()
	d := NewFECDecoder(4, nil, out)
	payloads := [][]byte{
		bytes.Repeat([]byte{0x0A}, 40),
		bytes.Repeat([]byte{0x0B}, 40),
		bytes.Repeat([]byte{0x0C}, 40),
		bytes.Repeat([]byte{0x0D}, 40),
	}
	parity := encodeGroup(4, nil, nil, 1, payloads)

	c.expect(0)
	d.OnData(2, payloads[1])
	d.OnData(4, payloads[3])
	d.OnParity(parity) // 同组丢 2 帧（seq=1,3）：不可恢复
	if len(c.seqs) != 0 {
		t.Fatalf("同组丢多帧不应有输出, got %v", c.seqs)
	}
	// 后续帧不受影响
	d.OnData(5, []byte("next group frame"))
}

func TestFECEncryptedRoundTrip(t *testing.T) {
	block, baseIV := getCipherContext("fec_enc_test")
	c, out := newFecCollector()
	d := NewFECDecoder(4, encIC(block, baseIV), out)
	payloads := [][]byte{
		bytes.Repeat([]byte{0x11}, 200),
		bytes.Repeat([]byte{0x22}, 200),
		bytes.Repeat([]byte{0x33}, 200),
		bytes.Repeat([]byte{0x44}, 200),
	}
	parity := encodeGroup(4, block, baseIV, 1, payloads)

	c.expect(1)
	d.OnData(1, payloads[0])
	d.OnData(2, payloads[1])
	d.OnData(3, payloads[2])
	d.OnParity(parity) // seq=4 丢失；解码器内部用 seq=start 解密校验载荷

	c.waitDone(t)
	if len(c.seqs) != 1 || c.seqs[0] != 4 {
		t.Fatalf("加密链路应恢复 seq=4, got %v", c.seqs)
	}
	if !bytes.Equal(c.frames[0], payloads[3]) {
		t.Fatalf("加密链路恢复内容不符")
	}
}

func TestFECDecoderDuplicateParity(t *testing.T) {
	// 多连接广播产生重复校验帧：首份恢复，其余必须被吸收
	c, out := newFecCollector()
	d := NewFECDecoder(4, nil, out)
	payloads := [][]byte{
		bytes.Repeat([]byte{0x01}, 30),
		bytes.Repeat([]byte{0x02}, 30),
		bytes.Repeat([]byte{0x03}, 30),
		bytes.Repeat([]byte{0x04}, 30),
	}
	parity := encodeGroup(4, nil, nil, 1, payloads)

	c.expect(1)
	d.OnData(1, payloads[0])
	d.OnData(2, payloads[1])
	d.OnData(4, payloads[3])
	d.OnParity(parity)
	c.waitDone(t)
	if len(c.seqs) != 1 {
		t.Fatalf("应恢复 1 帧, got %v", c.seqs)
	}
	d.OnParity(parity)
	d.OnParity(parity)
	if len(c.seqs) != 1 {
		t.Fatalf("重复校验帧不应再次输出, got %v", c.seqs)
	}
}

func TestFECDecoderLateMemberAfterRecovery(t *testing.T) {
	// 恢复后"丢失"帧又迟到（原帧其实只是延迟）：不得二次输出
	c, out := newFecCollector()
	d := NewFECDecoder(4, nil, out)
	payloads := [][]byte{
		bytes.Repeat([]byte{0x01}, 30),
		bytes.Repeat([]byte{0x02}, 30),
		bytes.Repeat([]byte{0x03}, 30),
		bytes.Repeat([]byte{0x04}, 30),
	}
	parity := encodeGroup(4, nil, nil, 1, payloads)

	c.expect(1)
	d.OnData(1, payloads[0])
	d.OnData(2, payloads[1])
	d.OnData(4, payloads[3])
	d.OnParity(parity)
	c.waitDone(t)

	// 迟到的原帧：组已终结，解码器忽略
	d.OnData(3, payloads[2])
	if len(c.seqs) != 1 {
		t.Fatalf("迟到原帧不应引发二次输出, got %v", c.seqs)
	}
}

func TestFECDecoderReset(t *testing.T) {
	c, out := newFecCollector()
	d := NewFECDecoder(4, nil, out)
	payloads := [][]byte{bytes.Repeat([]byte{0x01}, 30), bytes.Repeat([]byte{0x02}, 30)}
	parity := encodeGroup(2, nil, nil, 1, payloads)

	d.OnData(2, payloads[1])
	d.Reset()
	c.expect(0)
	d.OnParity(parity) // 旧会话的校验帧，Reset 后不应恢复
	if len(c.seqs) != 0 {
		t.Fatalf("Reset 后不应有输出, got %v", c.seqs)
	}
}

func TestFECStressConcurrentSingleLossPerGroup(t *testing.T) {
	// 确定性压测：K=8，每组恰好丢 1 帧，4 个"连接"乱序并发投递，
	// 广播校验帧后必须恢复全部丢失帧且内容逐字节一致
	const total = 2000
	const k = 8
	payloads := make([][]byte, total)
	for i := range payloads {
		n := 20 + randomIntN(1400)
		payloads[i] = make([]byte, n)
		rand.Read(payloads[i])
	}

	// 编码全部组
	e := newFECEncoder(k, nil)
	parities := make([][]byte, 0, total/k)
	for i := 0; i < total; i++ {
		if par := e.add(VPNFrame{Seq: uint32(i + 1), Data: payloads[i]}); par != nil {
			parities = append(parities, par)
		}
	}
	if len(parities) != total/k {
		t.Fatalf("应产出 %d 个校验帧, got %d", total/k, len(parities))
	}

	c, out := newFecCollector()
	d := NewFECDecoder(k, nil, out)

	// 每组丢第 4 帧（seq ≡ 4 mod 8）
	c.expect(total / k)
	var wgData sync.WaitGroup
	chunks := 4
	perChunk := (total + chunks - 1) / chunks
	for ch := 0; ch < chunks; ch++ {
		wgData.Add(1)
		go func(ch int) {
			defer wgData.Done()
			lo, hi := ch*perChunk, min((ch+1)*perChunk, total)
			for i := lo; i < hi; i++ {
				if i%k == k-1 {
					continue // 丢包
				}
				d.OnData(uint32(i+1), payloads[i])
			}
		}(ch)
	}
	wgData.Wait()
	// 广播校验帧（重复投递模拟多连接副本）
	for round := 0; round < 2; round++ {
		for _, p := range parities {
			d.OnParity(p)
		}
	}
	c.waitDone(t)

	if len(c.seqs) != total/k {
		t.Fatalf("应恢复全部 %d 个丢失帧, 实际 %d", total/k, len(c.seqs))
	}
	for i, s := range c.seqs {
		if s%k != 0 {
			t.Fatalf("恢复的 seq 应为组尾成员 (seq%%k==0), got %d", s)
		}
		if !bytes.Equal(c.frames[i], payloads[int(s)-1]) {
			t.Fatalf("恢复帧 seq=%d 内容不符", s)
		}
	}
}

func TestFECDecoderConcurrentSafety(t *testing.T) {
	// 并发 OnData/OnParity 的数据竞争由 -race 兜底；此处验证无死锁、无 panic
	c, out := newFecCollector()
	d := NewFECDecoder(4, nil, out)
	e := newFECEncoder(4, nil)
	var parities [][]byte
	payloads := make([][]byte, 400)
	for i := range payloads {
		payloads[i] = bytes.Repeat([]byte{byte(i)}, 50)
		if par := e.add(VPNFrame{Seq: uint32(i + 1), Data: payloads[i]}); par != nil {
			parities = append(parities, par)
		}
	}
	lost := 100 // 4 组 × 每组丢 1 帧
	c.expect(lost)
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; i < len(payloads); i += 4 {
				if i%4 == 3 {
					continue // 丢包
				}
				d.OnData(uint32(i+1), payloads[i])
				if (i/4)%2 == 0 {
					d.OnParity(parities[i/4])
				}
			}
		}(w)
	}
	wg.Wait()
	for _, p := range parities {
		d.OnParity(p)
	}
	c.waitDone(t)
	if len(c.seqs) != lost {
		t.Fatalf("应恢复 %d 帧, got %d", lost, len(c.seqs))
	}
}
