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

// partialGroupParity 手工构造一个只有 m<K 个成员的校验帧负载，载荷为
// members 的逐字节异或——载荷本身是自洽的，所以解码端拒绝它只能是因为
// 成员数与本地 K 不符，而不是内容有问题。
func partialGroupParity(start uint32, members [][]byte) []byte {
	maxLen := 0
	for _, p := range members {
		if len(p) > maxLen {
			maxLen = len(p)
		}
	}
	buf := make([]byte, 1+6+4*len(members)+maxLen)
	buf[0] = fecMagic
	binary.BigEndian.PutUint32(buf[1:5], start)
	buf[5] = byte(len(members))
	off := 6
	for _, p := range members {
		binary.BigEndian.PutUint32(buf[off:off+4], uint32(len(p)))
		off += 4
	}
	for _, p := range members {
		for j, b := range p {
			buf[off+j] ^= b
		}
	}
	return buf
}

// TestFECDecoderRejectsPartialGroup 锁定"永不接受不满 K 的分组"这条不变量：
// 解码端按 seq 算术对齐把数据帧归组，一旦接受 m<K 的分组，该 start 被标记
// 已终结，紧随其后的帧会全部被算进这个已终结组而整组丢弃（静默批量丢包）。
func TestFECDecoderRejectsPartialGroup(t *testing.T) {
	part := [][]byte{
		bytes.Repeat([]byte{0x01}, 16), bytes.Repeat([]byte{0x02}, 16),
		bytes.Repeat([]byte{0x03}, 16),
	}

	// (1) K=4 解码器收到 3 成员校验帧：整帧忽略，不输出
	none, outNone := newFecCollector()
	d4 := NewFECDecoder(4, nil, outNone)
	for i, p := range part {
		d4.OnData(uint32(i+1), p)
	}
	d4.OnParity(partialGroupParity(1, part))
	time.Sleep(5 * time.Millisecond)
	none.mu.Lock()
	n := len(none.seqs)
	none.mu.Unlock()
	if n != 0 {
		t.Fatalf("不满 K 的校验帧不应产生任何恢复输出, got %d", n)
	}

	// (2) 同一情形下分组未被终结：组状态仍在，正确校验帧到达即可恢复
	c2, out2 := newFecCollector()
	d4b := NewFECDecoder(4, nil, out2)
	p4 := append(append([][]byte(nil), part...), bytes.Repeat([]byte{0x04}, 16))
	for i, p := range p4[:3] {
		d4b.OnData(uint32(i+1), p)
	}
	d4b.OnParity(partialGroupParity(1, part)) // 应被忽略，不得终结分组
	c2.expect(1)
	d4b.OnParity(encodeGroup(4, nil, 1, p4))
	c2.waitDone(t)
	if len(c2.seqs) != 1 || c2.seqs[0] != 4 {
		t.Fatalf("忽略错误校验帧后分组应仍可恢复 seq=4, got %v", c2.seqs)
	}

	// (3) 同一载荷 + K=3 解码器：对齐一致，应当被接受。
	// 说明拒绝是"与本地 K 不符"导致的，而不是载荷本身有问题。
	c3, out3 := newFecCollector()
	d3 := NewFECDecoder(3, nil, out3)
	d3.OnData(1, part[0])
	d3.OnData(2, part[1])
	c3.expect(1)
	d3.OnParity(partialGroupParity(1, part))
	c3.waitDone(t)
	if len(c3.seqs) != 1 || c3.seqs[0] != 3 {
		t.Fatalf("K 对齐时应恢复 seq=3, got %v", c3.seqs)
	}
	if !bytes.Equal(c3.frames[0], part[2]) {
		t.Fatalf("恢复内容错误: % X", c3.frames[0])
	}

	// (4) 起点不是合法组起点（(start-1)%K != 0）的校验帧同样忽略
	bad, outBad := newFecCollector()
	dMis := NewFECDecoder(4, nil, outBad)
	dMis.OnData(1, bytes.Repeat([]byte{0x09}, 16))
	dMis.OnParity(partialGroupParity(2, part))
	time.Sleep(5 * time.Millisecond)
	bad.mu.Lock()
	nBad := len(bad.seqs)
	bad.mu.Unlock()
	if nBad != 0 {
		t.Fatalf("非法组起点的校验帧不应产生输出, got %d", nBad)
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
	parity := encodeGroup(4, nil, 1, payloads)
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
	parity := encodeGroup(4, nil, 1, payloads)

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
	parity := encodeGroup(4, nil, 1, payloads)

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
	parity := encodeGroup(4, nil, 1, payloads)

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
	c, out := newFecCollector()
	d := NewFECDecoder(4, encIC("fec_enc_psk"), out)
	payloads := [][]byte{
		bytes.Repeat([]byte{0x11}, 200),
		bytes.Repeat([]byte{0x22}, 200),
		bytes.Repeat([]byte{0x33}, 200),
		bytes.Repeat([]byte{0x44}, 200),
	}
	parity := encodeGroup(4, encIC("fec_enc_psk"), 1, payloads)

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
	parity := encodeGroup(4, nil, 1, payloads)

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
	parity := encodeGroup(4, nil, 1, payloads)

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

func TestFECDecoderPendingGroupsStayBounded(t *testing.T) {
	d := NewFECDecoder(4, nil, nil)
	payload := make([]byte, 128)

	// 每个组只送第一个成员，不送 parity，强制制造大量未完成组。
	for i := 0; i < fecMaxPendingGroups+128; i++ {
		seq := uint32(i*4 + 1)
		d.OnData(seq, payload)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if got := len(d.groups); got > fecMaxPendingGroups {
		t.Fatalf("pending groups=%d, want <=%d", got, fecMaxPendingGroups)
	}
	latest := uint32((fecMaxPendingGroups+127)*4 + 1)
	start := d.groupStartOf(latest)
	if _, ok := d.groups[start]; !ok {
		t.Fatalf("latest group %d was not retained after bounded eviction", start)
	}
}

func TestFECDecoderReset(t *testing.T) {
	c, out := newFecCollector()
	d := NewFECDecoder(4, nil, out)
	payloads := [][]byte{bytes.Repeat([]byte{0x01}, 30), bytes.Repeat([]byte{0x02}, 30)}
	parity := encodeGroup(2, nil, 1, payloads)

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

// TestFECProductionRecoveryRegression 线上崩溃的完整序列。
//
// 池缓冲被 FrameScanner 截到 66 字节后整块归还（len=66/cap=2048），随后一个
// K=4 组在 lens=[1100,1100,1200,1100] 下丢 seq=3：maxLen=1200 使校验帧载荷
// 取自同一个 2048 档，g.parity 的 len 停在 66，恢复循环遍历到 index 66 即
// panic —— "runtime error: index out of range [66] with length 66"，整条服务端
// 进程退出。该场景由两个改动共同兜住：池的长度不变量（主修）与 FEC 的防御性
// 长度检查（防止同类回归再变成进程崩溃）。
func TestFECProductionRecoveryRegression(t *testing.T) {
	c, out := newFecCollector()
	d := NewFECDecoder(4, nil, out)
	payloads := [][]byte{
		bytes.Repeat([]byte{0x01}, 1100),
		bytes.Repeat([]byte{0x02}, 1100),
		bytes.Repeat([]byte{0x03}, 1200),
		bytes.Repeat([]byte{0x04}, 1100),
	}
	parity := encodeGroup(4, nil, 1, payloads) // 先用干净的池生成校验帧

	// 投毒：与 frame.go 的 FrameScanner.ReadFrame 完全相同的动作——网络帧缓冲
	// 被截到 dataLen 后整块归还。必须放在 OnParity 之前：解码器取校验帧缓冲走
	// getFrameAtLeast(maxLen)，与 getFrame() 同属 2048 档，这样才能拿到 len=66/
	// cap=2048 的那块。放在 encodeGroup 之前是无效的——编码器会先消费掉它，测试
	// 就退化成只测正常路径。
	putFrame(getFrame()[:66])

	c.expect(1)
	d.OnData(1, payloads[0])
	d.OnData(2, payloads[1])
	d.OnData(4, payloads[3])
	d.OnParity(parity) // seq=3 丢失 → 由校验帧恢复

	c.waitDone(t)
	if len(c.seqs) != 1 || c.seqs[0] != 3 {
		t.Fatalf("应恰好恢复 seq=3, got %v", c.seqs)
	}
	if !bytes.Equal(c.frames[0], payloads[2]) {
		t.Fatalf("恢复内容与原文不符: got %d bytes, want %d bytes",
			len(c.frames[0]), len(payloads[2]))
	}
}

// TestFECDropsInconsistentParity 校验帧描述符与异或载荷不自洽（声明的成员
// 长度超过实际载荷长度）时整组静默丢弃并计入丢失，绝不 panic、绝不断连。
// 直接构造不自洽的组状态来锁定这条降级路径——它独立于池的行为，是错误帧
// 语义的一部分：FEC 失败只能表现为丢帧。
func TestFECDropsInconsistentParity(t *testing.T) {
	d := NewFECDecoder(4, nil, func(uint32, []byte) {})
	g := &fecGroupState{
		start:   1,
		k:       4,
		lens:    []int{1100, 1100, 1200, 1100}, // 描述符声称成员 2 长 1200
		gotMask: 0b1011,                        // 仅成员 2 缺失
		acc:     make([]byte, 1200),
		parity:  make([]byte, 66), // 实际载荷只有 66 字节 → 不自洽
	}
	d.groups[1] = g

	d.tryRecoverLocked(g) // 修复前在此 index out of range

	if !d.isDoneLocked(1) {
		t.Fatal("不自洽的组必须被终结")
	}
	if _, ok := d.groups[1]; ok {
		t.Fatal("终结后的组必须从 groups 移除")
	}
	if _, lost := d.FECStats(); lost != 1 {
		t.Fatalf("不自洽组应计入 1 帧丢失, got %d", lost)
	}
}

// TestFECDropsTruncatedParityThroughOnParity 不自洽载荷走完整 OnParity 入口
// （而非直接构造组状态）：载荷长度不足的校验帧必须在描述符自洽性校验处被
// 忽略，且不得终结分组——随后的正确校验帧仍应能恢复。
func TestFECDropsTruncatedParityThroughOnParity(t *testing.T) {
	payloads := [][]byte{
		bytes.Repeat([]byte{0x01}, 100),
		bytes.Repeat([]byte{0x02}, 140),
		bytes.Repeat([]byte{0x03}, 80),
		bytes.Repeat([]byte{0x04}, 120),
	}
	parity := encodeGroup(4, nil, 1, payloads)

	c, out := newFecCollector()
	d := NewFECDecoder(4, nil, out)
	d.OnData(1, payloads[0])
	d.OnData(2, payloads[1])
	d.OnData(4, payloads[3])

	// 把描述符里成员 1 的长度改成 4096（实际载荷只有 140）→ 自洽性校验失败
	truncated := make([]byte, len(parity))
	copy(truncated, parity)
	binary.BigEndian.PutUint32(truncated[6+4:10+4], 4096)
	d.OnParity(truncated)

	time.Sleep(5 * time.Millisecond)
	c.mu.Lock()
	n := len(c.seqs)
	c.mu.Unlock()
	if n != 0 {
		t.Fatalf("不自洽校验帧不应产生恢复输出, got %d", n)
	}

	c.expect(1)
	d.OnParity(parity) // 分组未被终结，正确校验帧仍应可恢复
	c.waitDone(t)
	if len(c.seqs) != 1 || c.seqs[0] != 3 {
		t.Fatalf("忽略不自洽帧后分组应仍可恢复 seq=3, got %v", c.seqs)
	}
}
