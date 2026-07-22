package main

import (
	"bytes"
	"net"
	"reflect"
	"testing"
	"time"
)

// ==========================================
// 工具函數測試 (Utility Functions)
// ==========================================

func TestFmtMAC(t *testing.T) {
	validMAC := []byte{0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E}
	expected := "00:1a:2b:3c:4d:5e"
	if res := fmtMAC(validMAC); res != expected {
		t.Errorf("fmtMAC 失敗，預期 %s，實際拿到 %s", expected, res)
	}

	invalidMAC := []byte{0x00, 0x1A}
	if res := fmtMAC(invalidMAC); res != "invalid_mac" {
		t.Errorf("fmtMAC 應該要回傳 invalid_mac，實際拿到 %s", res)
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
// 加解密邏輯測試 (Cryptography)
// ==========================================

func TestXorCryptInPlace(t *testing.T) {
	psk := "my_super_secret_test_key"
	block, baseIV := getCipherContext(psk)

	originalData := []byte("hello world, this is a test payload!")
	data := make([]byte, len(originalData))
	copy(data, originalData)

	seq := uint32(12345)

	// 第一步：加密
	xorCryptInPlace(data, seq, block, baseIV)
	if bytes.Equal(data, originalData) {
		t.Fatal("資料加密後不應與原始資料相同")
	}

	// 第二步：解密 (再做一次 XOR)
	xorCryptInPlace(data, seq, block, baseIV)
	if !bytes.Equal(data, originalData) {
		t.Fatalf("解密失敗！預期: %s, 實際: %s", string(originalData), string(data))
	}
}

// ==========================================
// 去重器測試 (DeDuplicator)
// ==========================================

func TestDeDuplicator(t *testing.T) {
	d := NewDeDuplicator()

	// 測試 seq 0 (控制幀不參與去重)
	if d.IsDuplicate(0) {
		t.Error("Seq 0 不應該被標記為重複")
	}

	// 測試正常放入
	if d.IsDuplicate(100) {
		t.Error("Seq 100 第一次放入不應為重複")
	}

	// 測試重複檢查
	if !d.IsDuplicate(100) {
		t.Error("Seq 100 第二次放入應該被標記為重複")
	}

	if d.IsDuplicate(101) {
		t.Error("Seq 101 不應為重複")
	}

	// 測試 Reset
	d.Reset()
	if d.IsDuplicate(100) {
		t.Error("Reset 後，Seq 100 應該被視為新的包")
	}
}

// ==========================================
// 亂序重排緩衝區測試 (ReorderBuffer)
// ==========================================

func TestReorderBuffer(t *testing.T) {
	var output []uint32

	// 建立一個假的 callback，紀錄被按序輸出的 Seq
	rb := NewReorderBuffer(func(data []byte) {
		// 測試中我們把 Seq 放在 data 裡面的第一個 byte 方便驗證
		if len(data) > 0 {
			output = append(output, uint32(data[0]))
		}
	})

	// 模擬亂序封包到達
	// 順序應該是: 1, 2, 3, 4
	// 實際到達順序: 1, 4, 3, 2

	rb.Insert(1, []byte{1})
	// 到達 1 -> 應該立即輸出 [1]
	if len(output) != 1 || output[0] != 1 {
		t.Fatalf("預期輸出 [1], 實際: %v", output)
	}

	rb.Insert(4, []byte{4})
	rb.Insert(3, []byte{3})
	// 到達 4, 3 -> 缺少 2，應該卡在緩衝區，輸出依然只有 [1]
	if len(output) != 1 {
		t.Fatalf("缺少 2，不應有新輸出, 實際: %v", output)
	}

	rb.Insert(2, []byte{2})
	// 到達 2 -> 缺口補齊，應該一口氣輸出 2, 3, 4
	if len(output) != 4 || output[1] != 2 || output[2] != 3 || output[3] != 4 {
		t.Fatalf("預期輸出 [1 2 3 4], 實際: %v", output)
	}

	// 測試丟棄過期包 (例如重傳了 2)
	output = []uint32{} // 清空紀錄
	rb.Insert(2, []byte{2})
	if len(output) != 0 {
		t.Fatalf("過期的包應該被丟棄，預期無輸出, 實際: %v", output)
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
	buf1 := appendPaddedFrame(getFrame()[:0], VPNFrame{Seq: 101, Data: payload1}, nil, nil)
	tcpBuffer.Write(buf1)

	buf2 := appendPaddedFrame(getFrame()[:0], VPNFrame{Seq: 102, Data: payload2}, nil, nil)
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
	block, baseIV := getCipherContext(psk)

	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i)
	}

	frameBuf := getFrame()[:0]
	frameBuf = appendPaddedFrame(frameBuf, VPNFrame{Seq: 1, Data: payload}, block, baseIV)

	reader := &infiniteReader{data: frameBuf}
	scanner := NewFrameScanner(reader)

	b.SetBytes(int64(len(payload)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		data, seq, err := scanner.ReadFrame()
		if err != nil {
			b.Fatal(err)
		}
		// 模擬解密
		xorCryptInPlace(data, seq, block, baseIV)
		putFrame(data)
	}
}
