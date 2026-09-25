package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// ==========================================
// 工具函數測試 (Utility Functions)
// ==========================================

func TestFmtMAC(t *testing.T) {
	validMAC := macKey{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}
	expected := "00:1a:2b:3c:4d:5e"
	if res := fmtMAC(validMAC); res != expected {
		t.Errorf("fmtMAC 失敗，預期 %s，實際拿到 %s", expected, res)
	}
}

// ==========================================
// 握手输入校验（防日志伪造）
// ==========================================

func TestClientIDValidation(t *testing.T) {
	valid := []string{
		"123e4567-e89b-12d3-a456-426614174000",
		"123E4567-E89B-12D3-A456-426614174000", // 大写 hex 同样合法
	}
	for _, id := range valid {
		if !isValidClientID(id) {
			t.Errorf("合法 clientID %q 被误拒", id)
		}
	}
	invalid := []string{
		"", "", // 空串
		"g23e4567-e89b-12d3-a456-42661417400",           // 非 hex
		"123e4567_e89b-12d3-a456-426614174000",          // 连字符位置错
		"123e4567e89b12d3a4564266141740000",             // 缺连字符
		"123e4567-e89b-12d3-a456-42661417400",           // 长度差 1
		"123e4567-e89b-12d3-a456-4266141740000",         // 长度多 1
		"bad\nid-with-log-forging-attempt-xxxxxxxxxxxx", // 换行注入
	}
	for _, id := range invalid {
		if isValidClientID(id) {
			t.Errorf("非法 clientID %q 被误放行", id)
		}
	}
}

func TestMACStringValidation(t *testing.T) {
	if isValidMACString("") {
		t.Error("协议 v2 不允许空 MAC")
	}
	if !isValidMACString("00:1a:2b:3c:4d:5e") || !isValidMACString("00:1A:2B:3C:4D:5E") {
		t.Error("合法 MAC 被误拒")
	}
	for _, s := range []string{"00:00:00:00:00:00", "01:1a:2b:3c:4d:5e", "00:1a:2b:3c:4d", "00-1a-2b-3c-4d-5e", "zz:1a:2b:3c:4d:5e", "0:1a:2b:3c:4d:5e", "bad\nmac-xx"} {
		if isValidMACString(s) {
			t.Errorf("非法 MAC %q 被误放行", s)
		}
	}
	m, ok := parseMACKey("00:1a:2b:3c:4d:5e")
	if !ok || m != (macKey{0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e}) {
		t.Errorf("parseMACKey 解析错误: %v ok=%v", m, ok)
	}
}

func TestClientInstanceValidation(t *testing.T) {
	for _, s := range []string{"123e4567-e89b-12d3-a456-426614174000", "0123456789abcdef0123456789abcdef"} {
		if !isValidClientInstance(s) {
			t.Errorf("valid client instance rejected: %q", s)
		}
	}
	for _, s := range []string{"", "short", "123e4567-e89b-12d3-a456-426614174000\nforged", strings.Repeat("a", 65)} {
		if isValidClientInstance(s) {
			t.Errorf("invalid client instance accepted: %q", s)
		}
	}
}

// ==========================================
// VSwitch：源 MAC 归属校验 + 广播预算
// ==========================================

type stubPort struct {
	name   string
	frames chan []byte
}

func newStubPort(name string) *stubPort {
	return &stubPort{name: name, frames: make(chan []byte, 64)}
}

func (p *stubPort) ID() string { return p.name }
func (p *stubPort) WriteFrame(frame []byte) error {
	p.frames <- append([]byte(nil), frame...)
	return nil
}

func macFrame(dst, src macKey) []byte {
	f := make([]byte, 14)
	copy(f[0:6], dst[:])
	copy(f[6:12], src[:])
	return f
}

func TestVSwitchRejectsSpoofedSrcMAC(t *testing.T) {
	vs := NewVSwitch()
	macA := macKey{0xAA, 0, 0, 0, 0, 1}
	macB := macKey{0xBB, 0, 0, 0, 0, 2}
	registered := map[string]macKey{"A": macA, "B": macB}
	vs.validateMAC = func(srcPortID string, mac macKey) bool {
		reg, ok := registered[srcPortID]
		return !ok || reg == mac // 未登记端口放行（与服务端 MAC 为空放行语义一致）
	}
	pa, pb := newStubPort("A"), newStubPort("B")
	vs.AddPort(pa)
	vs.AddPort(pb)

	// 冒充：端口 A 声明 B 的 MAC —— 整帧丢弃，既不学习也不转发
	vs.ProcessFrame("A", macFrame(macB, macB))
	select {
	case f := <-pb.frames:
		t.Fatalf("冒充帧不应被转发, 收到 % X", f[:6])
	case <-time.After(50 * time.Millisecond):
	}
	if n := vs.spoofDrops.Load(); n != 1 {
		t.Fatalf("冒充计数应为 1, 实际 %d", n)
	}
	// 冒充不得污染学习表：B 的单播仍送达 B
	vs.ProcessFrame("A", macFrame(macA, macA)) // 正常帧，A→B
	vs.ProcessFrame("A", macFrame(macB, macA)) // A 发给 B
	select {
	case f := <-pb.frames:
		if !bytes.Equal(f[:6], macB[:]) {
			t.Fatalf("转发内容错误: % X", f[:6])
		}
	case <-time.After(time.Second):
		t.Fatal("合法单播未送达 B")
	}
}

func TestVSwitchOwnedUnicastTransfersBufferWithoutCopy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	vs := NewVSwitch()
	port := NewAsyncPort(ctx, "B")
	rtt := uint32(1000)
	backend := make(chan []VPNFrame, 4)
	port.RegisterBackend(backend, &rtt)
	defer port.UnregisterBackend(backend)
	defer port.Close()
	vs.AddPort(port)

	macB := macKey{0xBA, 0, 0, 0, 0, 2}
	macTap := macKey{0x02, 0, 0, 0, 0, 9}

	// 先让交换机学习 macB -> B。目标 MAC 未学习也没关系；这里只关心源学习。
	vs.ProcessFrame("B", macFrame(macTap, macB))

	raw := macFrame(macB, macTap)
	buf := getFrameAtLeast(len(raw))[:len(raw)]
	copy(buf, raw)
	ptr := &buf[0]

	vs.ProcessOwnedFrame(tapPortID, buf)

	select {
	case batch := <-backend:
		if len(batch) != 1 || len(batch[0].Data) != len(raw) {
			t.Fatalf("unexpected owned batch: %+v", batch)
		}
		if &batch[0].Data[0] != ptr {
			t.Fatal("owned TAP unicast payload was copied instead of transferred")
		}
		if !bytes.Equal(batch[0].Data, raw) {
			t.Fatal("owned TAP unicast payload changed")
		}
		freeFrames(batch)
		putVPNFrameBatch(batch)
	case <-time.After(time.Second):
		t.Fatal("owned TAP unicast was not delivered")
	}
}

func TestVSwitchFloodBudget(t *testing.T) {
	vs := NewVSwitch()
	vs.floodBurst = 2
	vs.floodRatePerSec = 0.001 // 测试期内不回充
	broadcast := macKey{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	unicastB := macKey{0xBA, 0, 0, 0, 0, 2} // 偶数首字节 = 单播 MAC（0xBB 的多播位会走洪泛）

	pa, pb := newStubPort("A"), newStubPort("B")
	vs.AddPort(pa)
	vs.AddPort(pb)

	// 前两帧在预算内送达 B，第三帧超预算丢弃
	vs.ProcessFrame("A", macFrame(broadcast, macKey{0xAA, 0, 0, 0, 0, 1}))
	vs.ProcessFrame("A", macFrame(broadcast, macKey{0xAA, 0, 0, 0, 0, 1}))
	vs.ProcessFrame("A", macFrame(broadcast, macKey{0xAA, 0, 0, 0, 0, 1}))
	got := 0
deadline:
	for {
		select {
		case <-pb.frames:
			got++
		default:
			break deadline
		}
	}
	time.Sleep(20 * time.Millisecond)
	select {
	case <-pb.frames:
		got++
	default:
	}
	if got != 2 {
		t.Fatalf("广播预算应为 2 帧, 实际送达 %d", got)
	}
	if n := vs.floodDrops.Load(); n != 1 {
		t.Fatalf("广播丢弃计数应为 1, 实际 %d", n)
	}

	// 单播不受广播预算影响：先让 B 发帧建立 macB→B 的学习表项，
	// 再从 A 发单播给 macB（此时预算已耗尽，走单播查找而非洪泛）
	vs.ProcessFrame("B", macFrame(macKey{0xAA, 0, 0, 0, 0, 1}, unicastB))
	select {
	case <-pa.frames:
	case <-time.After(time.Second):
		t.Fatal("B 的合法帧应送达 A")
	}
	vs.ProcessFrame("A", macFrame(unicastB, macKey{0xAA, 0, 0, 0, 0, 1}))
	select {
	case <-pb.frames:
	case <-time.After(time.Second):
		t.Fatal("单播不应受广播预算影响")
	}

	// 可信端口豁免预算
	vs.trustedPort = "TAP"
	tap := newStubPort("TAP")
	vs.AddPort(tap)
	for i := 0; i < 5; i++ {
		vs.ProcessFrame("TAP", macFrame(broadcast, macKey{0x00, 0, 0, 0, 0, 9}))
	}
	select {
	case <-pb.frames:
	case <-time.After(time.Second):
		t.Fatal("可信端口的广播不应被限速")
	}
}

func TestParseServerAddresses(t *testing.T) {
	raw := " 192.168.1.1:4000 ,  [::1]:4000, 10.0.0.1:4000  "
	expected := []string{"192.168.1.1:4000", "[::1]:4000", "10.0.0.1:4000"}
	res := parseServerAddresses(raw)

	if !reflect.DeepEqual(res, expected) {
		t.Errorf("parseServerAddresses 解析錯誤. 預期: %v, 實際: %v", expected, res)
	}

	emptyRes := parseServerAddresses("   ")
	if len(emptyRes) != 0 {
		t.Errorf("空字串應該解析為空切片，實際為: %v", emptyRes)
	}
}

func TestIncrementIP(t *testing.T) {
	ip := net.ParseIP("192.168.1.254").To4()
	incrementIP(ip)
	if ip.String() != "192.168.1.255" {
		t.Errorf("IP 遞增錯誤，預期 192.168.1.255，拿到 %s", ip.String())
	}

	incrementIP(ip)
	if ip.String() != "192.168.2.0" {
		t.Errorf("IP 遞增溢位處理錯誤，預期 192.168.2.0，拿到 %s", ip.String())
	}
}

// ==========================================
// 会话令牌与 PSK 失败限流测试
// ==========================================

func TestSessionToken(t *testing.T) {
	psk := "rotate_me_please"
	sessionID := "550e8400-e29b-41d4-a716-446655440000"

	tok := computeSessionToken(psk, sessionID)
	if tok == "" || len(tok) != 64 {
		t.Fatalf("令牌应为 64 位 hex，实际 %q", tok)
	}

	// 正确组合通过
	if !verifySessionToken(psk, sessionID, tok) {
		t.Error("合法令牌校验应通过")
	}
	// 会话 ID 被换（冒充别人的会话）必须失败
	if verifySessionToken(psk, "00000000-0000-0000-0000-000000000000", tok) {
		t.Error("不同会话 ID 的令牌校验应失败")
	}
	// PSK 被换（轮换后旧令牌）必须失败
	if verifySessionToken("another_psk", sessionID, tok) {
		t.Error("不同 PSK 的令牌校验应失败")
	}
	// 空令牌（旧版客户端）必须失败
	if verifySessionToken(psk, sessionID, "") {
		t.Error("空令牌校验应失败")
	}
	// 常量时间接口不应因空比较而 panic
	if verifySessionToken(psk, sessionID, "garbage") {
		t.Error("伪造令牌校验应失败")
	}
}

func TestPSKFailLimit(t *testing.T) {
	s := &Server{pskFail: make(map[string]*pskFailBucket)}

	remote := "203.0.113.7:44444"
	for i := 0; i <= pskFailLimit; i++ {
		exceeded := s.pskFailExceeded(remote)
		if i < pskFailLimit {
			if exceeded {
				t.Fatalf("第 %d 次失败不应超限", i+1)
			}
		} else {
			if !exceeded {
				t.Fatalf("第 %d 次失败应超限", i+1)
			}
		}
	}

	// 其他地址不受影响
	if s.pskFailExceeded("198.51.100.1:1") {
		t.Error("不同地址的失败计数应相互独立")
	}

	// 窗口过期后计数重置
	b := s.pskFail["203.0.113.7"]
	if b == nil {
		t.Fatal("PSK 失败预算必须按 IP 聚合，而不是按临时源端口分裂")
	}
	b.first = time.Now().Add(-2 * time.Minute)
	if s.pskFailExceeded(remote) {
		t.Error("窗口过期后应重新计数")
	}

	// 不同地址互不干扰：超限地址之外的新地址仍允许首次
	if len(s.pskFail) < 2 {
		t.Errorf("失败表应保留各地址条目，实际 %d", len(s.pskFail))
	}
	// 同一来源换端口仍共用预算，不能靠每次重连换临时端口绕过限制。
	for i := 0; i < pskFailLimit; i++ {
		_ = s.pskFailExceeded("192.0.2.9:" + fmt.Sprint(10000+i))
	}
	if !s.pskFailExceeded("192.0.2.9:20000") {
		t.Error("同一 IP 更换源端口不应重置 PSK 失败预算")
	}
}

// ==========================================
// 亂序重排緩衝區測試 (ReorderBuffer)
// ==========================================

func TestReorderBuffer(t *testing.T) {
	// 交付走独立协程（锁与系统调用解耦），所以回调在 Insert 返回之后才执行。
	// rec 用互斥锁保护：快照返回值供主协程读取，避免与交付协程的数据竞争。
	rec := &struct {
		mu     sync.Mutex
		output []uint32
	}{}
	rb := NewReorderBuffer(func(data []byte) {
		if len(data) == 0 {
			return
		}
		rec.mu.Lock()
		rec.output = append(rec.output, uint32(data[0]))
		rec.mu.Unlock()
	})
	snapshot := func() []uint32 {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return append([]uint32(nil), rec.output...)
	}
	clearRecord := func() {
		rec.mu.Lock()
		rec.output = nil
		rec.mu.Unlock()
	}
	// waitFor 等到输出恰好是 want（顺序与个数都一致）
	waitFor := func(t *testing.T, want []uint32, label string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if got := snapshot(); len(got) == len(want) {
				for i := range want {
					if got[i] != want[i] {
						t.Fatalf("%s 时第 %d 个输出应为 %d，实际 %d", label, i+1, want[i], got[i])
					}
				}
				return
			}
			time.Sleep(20 * time.Microsecond)
		}
		if got := snapshot(); len(got) != len(want) {
			t.Fatalf("%s 超时：預期 %d 个输出，實際 %v", label, len(want), got)
		}
	}

	// 模擬亂序封包到達
	// 順序應該是: 1, 2, 3, 4
	// 實際到達順序: 1, 4, 3, 2

	rb.Insert(1, []byte{1})
	// 到達 1 -> 應該輸出 [1]
	waitFor(t, []uint32{1}, "第一個包到達")

	rb.Insert(4, []byte{4})
	rb.Insert(3, []byte{3})
	// 到達 4, 3 -> 缺少 2，應該卡在緩衝區，輸出依然只有 [1]
	time.Sleep(10 * time.Millisecond)
	if got := snapshot(); len(got) != 1 {
		t.Fatalf("缺少 2，不應有新輸出, 實際: %v", got)
	}

	rb.Insert(2, []byte{2})
	// 到達 2 -> 缺口補齊，應該一口氣輸出 2, 3, 4
	waitFor(t, []uint32{1, 2, 3, 4}, "缺口補齊")

	// 測試丟棄過期包 (例如重傳了 2)
	clearRecord()
	rb.Insert(2, []byte{2})
	time.Sleep(10 * time.Millisecond)
	if got := snapshot(); len(got) != 0 {
		t.Fatalf("過期的包應該被丟棄，預期無輸出, 實際: %v", got)
	}
}

func TestReorderBufferGrowsForLargeMultipathSkew(t *testing.T) {
	delivered := make(chan byte, 4)
	rb := NewReorderBuffer(func(frame []byte) {
		if len(frame) > 0 {
			delivered <- frame[0]
		}
	})
	defer rb.Close()

	rb.Insert(1, []byte{1})
	select {
	case got := <-delivered:
		if got != 1 {
			t.Fatalf("first frame=%d, want 1", got)
		}
	case <-time.After(time.Second):
		t.Fatal("first frame not delivered")
	}

	// seq=4096 相对 expected=2 的偏斜为 4094，超过初始 2048 窗口。
	// 应按需扩容保留该帧，而不是静默丢弃。
	rb.Insert(4096, []byte{0x5a})
	rb.mu.Lock()
	window := len(rb.ring)
	rb.mu.Unlock()
	if window < 4096 {
		t.Fatalf("reorder window did not grow: %d", window)
	}

	select {
	case got := <-delivered:
		t.Fatalf("future frame delivered before gap timeout: %d", got)
	case <-time.After(reorderSkipDelay / 2):
	}

	select {
	case got := <-delivered:
		if got != 0x5a {
			t.Fatalf("post-timeout frame=%x, want 5a", got)
		}
	case <-time.After(reorderSkipDelay + time.Second):
		t.Fatal("far future frame was lost instead of retained")
	}

	stats := rb.Stats()
	if stats.SkippedFrames != 4094 {
		t.Fatalf("skipped=%d, want 4094", stats.SkippedFrames)
	}
}

// ==========================================
// 成幀與流式解析測試 (Frame & Scanner)
// ==========================================

func TestFrameScanner(t *testing.T) {
	// 模擬 TCP 連線的 Buffer
	tcpBuffer := new(bytes.Buffer)

	payload1 := []byte("VPN packet 1 data")
	payload2 := []byte("VPN packet 2 data with more content")

	// 產生並寫入兩筆 Frame (不加密)
	buf1 := appendPaddedFrame(getFrame()[:0], VPNFrame{Seq: 101, Data: payload1}, nil)
	tcpBuffer.Write(buf1)

	buf2 := appendPaddedFrame(getFrame()[:0], VPNFrame{Seq: 102, Data: payload2}, nil)
	tcpBuffer.Write(buf2)

	// 使用 Scanner 解析
	scanner := NewFrameScanner(tcpBuffer)

	// 讀取第一個 Frame
	parsedData1, seq1, err := scanner.ReadFrame()
	if err != nil {
		t.Fatalf("讀取 Frame 1 失敗: %v", err)
	}
	if seq1 != 101 {
		t.Errorf("預期 Seq 101, 實際拿到 %d", seq1)
	}
	if !bytes.Equal(parsedData1, payload1) {
		t.Errorf("預期 Data '%s', 實際拿到 '%s'", string(payload1), string(parsedData1))
	}

	// 讀取第二個 Frame
	parsedData2, seq2, err := scanner.ReadFrame()
	if err != nil {
		t.Fatalf("讀取 Frame 2 失敗: %v", err)
	}
	if seq2 != 102 {
		t.Errorf("預期 Seq 102, 實際拿到 %d", seq2)
	}
	if !bytes.Equal(parsedData2, payload2) {
		t.Errorf("預期 Data '%s', 實際拿到 '%s'", string(payload2), string(parsedData2))
	}

	// 讀取第三個 (應該為空或阻塞，這裡使用 timer 避免真阻塞)
	done := make(chan struct{})
	go func() {
		scanner.ReadFrame()
		close(done)
	}()

	select {
	case <-done:
		// EOF 是正常的
	case <-time.After(100 * time.Millisecond):
		// 阻塞代表沒資料了，這是預期的 Scanner 行為
	}
}

// TestFrameScannerMaxDataLen 锁定认证前首帧上限的语义：
// 超限的帧头直接报错（拒绝连接），不按声明长度扩容缓冲——否则 10 字节
// 帧头就能把每条预认证连接钉住 ~131KB 内存。
func TestFrameScannerMaxDataLen(t *testing.T) {
	mkStream := func(dataLen int) []byte {
		hdr := make([]byte, 10)
		binary.BigEndian.PutUint32(hdr[0:4], uint32(dataLen))
		binary.BigEndian.PutUint16(hdr[4:6], 0)
		binary.BigEndian.PutUint32(hdr[6:10], 1)
		return hdr
	}

	// 超过 maxHandshakeDataLen：立即报错且不分配大缓冲
	fs := NewFrameScanner(bytes.NewReader(mkStream(maxHandshakeDataLen + 1)))
	fs.SetMaxDataLen(maxHandshakeDataLen)
	if _, _, err := fs.ReadFrame(); err == nil {
		t.Fatal("超过认证前上限的帧应被拒绝")
	}
	if cap(fs.buf) > maxHandshakeDataLen*2 {
		t.Fatalf("拒绝帧不应把缓冲扩到 %.1fKB, 实际 cap=%d", float64(cap(fs.buf))/1024, cap(fs.buf))
	}

	// 认证后恢复全量上限：小于 maxWireDataLen 的大帧正常读取
	big := 20 * 1024
	stream := append(mkStream(big), make([]byte, big)...)
	fs2 := NewFrameScanner(bytes.NewReader(stream))
	fs2.SetMaxDataLen(maxHandshakeDataLen)
	fs2.SetMaxDataLen(maxWireDataLen) // 认证通过后放开
	frame, _, err := fs2.ReadFrame()
	if err != nil {
		t.Fatalf("放开上限后大帧应正常读取: %v", err)
	}
	if len(frame) != big {
		t.Fatalf("大帧长度不符: %d", len(frame))
	}

	// 默认上限为线路全量（不破坏既有行为）
	full := append(mkStream(maxWireDataLen), make([]byte, maxWireDataLen)...)
	fs3 := NewFrameScanner(bytes.NewReader(full))
	if _, _, err := fs3.ReadFrame(); err != nil {
		t.Fatalf("默认上限下全量帧应可读取: %v", err)
	}
}

// ==========================================
// 協議吞吐量基準測試 (Benchmark)
// ==========================================

type infiniteReader struct {
	data []byte
	pos  int
}

func (r *infiniteReader) Read(p []byte) (n int, err error) {
	n = copy(p, r.data[r.pos:])
	r.pos += n
	if r.pos >= len(r.data) {
		r.pos = 0
	}
	return n, nil
}

func BenchmarkProtocolThroughput(b *testing.B) {
	psk := "benchmark_secret_key"

	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i)
	}

	rx := mustGCM(psk, testGCMSalt)
	frameBuf := getFrame()[:0]
	frameBuf = appendPaddedFrame(frameBuf, VPNFrame{Seq: 1, Data: payload}, rx)

	reader := &infiniteReader{data: frameBuf}
	scanner := NewFrameScanner(reader)

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		data, seq, err := scanner.ReadFrame()
		if err != nil {
			b.Fatal(err)
		}
		// 模拟解密（含 GCM 标签校验）
		if _, err := rx.openInPlace(data, seq, uint32(len(data))); err != nil {
			b.Fatal(err)
		}
		putFrame(data)
	}
}
