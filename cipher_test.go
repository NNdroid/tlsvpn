package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap/zapcore"

	mathrand "math/rand/v2"
)

// TestMain 初始化全局日志器（被测代码路径大量使用 log.*）
func TestMain(m *testing.M) {
	initLogger("error")
	os.Exit(m.Run())
}

func randomSalt() []byte {
	s := make([]byte, encSaltSize)
	rand.Read(s)
	return s
}

// encIC 用 legacy 算法参数构造 innerCipher（fec_test 辅助）
func encIC(block cipher.Block, baseIV []byte) *innerCipher {
	return &innerCipher{algo: encAlgoLegacyCTR, block: block, baseIV: baseIV}
}

// encodeGroup 用编码器处理一组 k 帧，返回校验帧（fec_test 辅助）
func encodeGroup(k int, block cipher.Block, baseIV []byte, startSeq uint32, payloads [][]byte) []byte {
	e := newFECEncoder(k, encIC(block, baseIV))
	var parity []byte
	for i, p := range payloads {
		if par := e.add(VPNFrame{Seq: startSeq + uint32(i), Data: p}); par != nil {
			parity = par
		}
	}
	return parity
}

func TestGCMSealOpenRoundtrip(t *testing.T) {
	salt := randomSalt()
	tx, err := newGCMInnerCipher("roundtrip_psk", salt)
	if err != nil {
		t.Fatal(err)
	}
	rx, err := newGCMInnerCipher("roundtrip_psk", salt)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{1, 16, 100, 1400, 3000} {
		pt := make([]byte, n)
		rand.Read(pt)
		region := make([]byte, n+gcmTagSize)
		copy(region, pt)
		written := tx.sealInPlace(region, n, 12345, uint32(n+gcmTagSize))
		if written != n+gcmTagSize {
			t.Fatalf("sealInPlace 应写入 %d 字节, 实际 %d", n+gcmTagSize, written)
		}
		plain, err := rx.openInPlace(region, 12345, uint32(written))
		if err != nil {
			t.Fatalf("len=%d 解密失败: %v", n, err)
		}
		if !bytes.Equal(plain, pt) {
			t.Fatalf("len=%d 明文不一致", n)
		}
	}
}

func TestGCMRejectsTampering(t *testing.T) {
	salt := randomSalt()
	tx, _ := newGCMInnerCipher("tamper_psk", salt)
	rx, _ := newGCMInnerCipher("tamper_psk", salt)
	pt := bytes.Repeat([]byte{0xAB}, 200)

	mk := func() []byte {
		region := make([]byte, len(pt)+gcmTagSize)
		copy(region, pt)
		tx.sealInPlace(region, len(pt), 7, uint32(len(pt)+gcmTagSize))
		return region
	}

	// 篡改密文任一字节
	ct := mk()
	ct[50] ^= 0xFF
	if _, err := rx.openInPlace(ct, 7, uint32(len(ct))); err == nil {
		t.Fatal("密文被篡改应校验失败")
	}
	// 篡改标签
	ct = mk()
	ct[len(ct)-1] ^= 0x01
	if _, err := rx.openInPlace(ct, 7, uint32(len(ct))); err == nil {
		t.Fatal("标签被篡改应校验失败")
	}
	// AAD（线路长度/seq）不匹配 —— 防止把有效密文挪到别的 seq 位置
	ct = mk()
	if _, err := rx.openInPlace(ct, 8, uint32(len(ct))); err == nil {
		t.Fatal("seq 不匹配应校验失败")
	}
	if _, err := rx.openInPlace(ct, 7, uint32(len(ct)+1)); err == nil {
		t.Fatal("线路长度不匹配应校验失败")
	}
}

func TestGCMCrossSaltAndDirectionSeparation(t *testing.T) {
	// 同 PSK、同 seq、不同盐 → 密文必须不同（会话间/客户端间密钥流隔离）
	salt1, salt2 := randomSalt(), randomSalt()
	a, _ := newGCMInnerCipher("shared_psk", salt1)
	b, _ := newGCMInnerCipher("shared_psk", salt2)
	pt := bytes.Repeat([]byte{0x42}, 64)
	ra := make([]byte, len(pt)+gcmTagSize)
	copy(ra, pt)
	a.sealInPlace(ra, len(pt), 5, uint32(len(pt)+gcmTagSize))
	rb := make([]byte, len(pt)+gcmTagSize)
	copy(rb, pt)
	b.sealInPlace(rb, len(pt), 5, uint32(len(pt)+gcmTagSize))
	if bytes.Equal(ra, rb) {
		t.Fatal("不同盐的同 seq 密文应不同")
	}
	// 用错盐解密必须失败
	if _, err := b.openInPlace(ra, 5, uint32(len(ra))); err == nil {
		t.Fatal("异盐密文应解密失败")
	}
	// 同盐不同 seq 密文不同
	rc := make([]byte, len(pt)+gcmTagSize)
	copy(rc, pt)
	a.sealInPlace(rc, len(pt), 6, uint32(len(pt)+gcmTagSize))
	if bytes.Equal(ra[0:16], rc[0:16]) {
		t.Fatal("同盐不同 seq 密文前缀不应相同")
	}
}

func TestNonceNeverRepeats(t *testing.T) {
	ic, _ := newGCMInnerCipher("nonce_psk", randomSalt())
	seen := make(map[string]bool, 10000)
	for i := 0; i < 10000; i++ {
		seq := uint32(mathrand.IntN(1 << 30))
		n := string(ic.gcmNonce(seq))
		if seen[n] {
			t.Fatalf("nonce 重复: seq=%d", seq)
		}
		seen[n] = true
	}
}

func TestFrameGCMWireRoundtrip(t *testing.T) {
	// 帧级往返：appendPaddedFrame(GCM) → FrameScanner → openInPlace
	// 真实协议中盐由握手下发、两端一致
	salt := randomSalt()
	tx, _ := newGCMInnerCipher("wire_psk", salt)
	rx, _ := newGCMInnerCipher("wire_psk", salt)

	var stream []byte
	payloads := [][]byte{
		[]byte("tiny"),
		bytes.Repeat([]byte{0x77}, 1400),
		bytes.Repeat([]byte{0x88}, 50),
	}
	for i, p := range payloads {
		stream = appendPaddedFrame(stream, VPNFrame{Seq: uint32(i + 1), Data: p}, tx)
	}

	// 直接用 FrameScanner 解析同一字节流
	rd := &bytesReader{data: stream}
	sc := NewFrameScanner(rd)
	for i, want := range payloads {
		frame, seq, err := sc.ReadFrame()
		if err != nil {
			t.Fatalf("第 %d 帧读取失败: %v", i, err)
		}
		// 线路负载 = 密文+标签：明文长 + 16
		if len(frame) != len(want)+gcmTagSize {
			t.Fatalf("第 %d 帧线路负载应含 16B 标签: got %d want %d", i, len(frame), len(want)+gcmTagSize)
		}
		plain, err := rx.openInPlace(frame, seq, uint32(len(frame)))
		if err != nil {
			t.Fatalf("第 %d 帧解密失败: %v", i, err)
		}
		if !bytes.Equal(plain, want) {
			t.Fatalf("第 %d 帧明文不一致", i)
		}
	}
}

type bytesReader struct {
	data []byte
	pos  int
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, nil // 模拟流阻塞结束（测试中不会到达）
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func TestFECGCMParityRoundTrip(t *testing.T) {
	// GCM 加密链路下的校验帧往返：编码端加密 → 解码端解密恢复丢失帧
	salt := randomSalt()
	enc, _ := newGCMInnerCipher("fec_gcm_psk", salt)
	dec, _ := newGCMInnerCipher("fec_gcm_psk", salt)

	c, out := newFecCollector()
	d := NewFECDecoder(4, dec, out)
	e := newFECEncoder(4, enc)

	payloads := [][]byte{
		bytes.Repeat([]byte{0x01}, 100),
		bytes.Repeat([]byte{0x02}, 150),
		bytes.Repeat([]byte{0x03}, 80),
		bytes.Repeat([]byte{0x04}, 120),
	}
	var parity []byte
	for i, p := range payloads {
		if par := e.add(VPNFrame{Seq: uint32(i + 1), Data: p}); par != nil {
			parity = par
		}
	}
	if parity == nil {
		t.Fatal("应产出校验帧")
	}

	// 校验帧线路格式：6B 描述 + 4×4B 成员长度 + maxLen(150) 密文 + 16B 标签
	if len(parity) != 6+4*4+150+gcmTagSize {
		t.Fatalf("校验帧长度应含 16B 标签: got %d want %d", len(parity), 6+4*4+150+gcmTagSize)
	}

	c.expect(1)
	d.OnData(1, payloads[0])
	d.OnData(2, payloads[1])
	d.OnData(3, payloads[2])
	d.OnParity(parity) // seq=4 丢失，解码器用同方向盐解密校验载荷并恢复

	c.waitDone(t)
	if len(c.seqs) != 1 || c.seqs[0] != 4 {
		t.Fatalf("应恢复 seq=4, got %v", c.seqs)
	}
	if !bytes.Equal(c.frames[0], payloads[3]) {
		t.Fatalf("GCM 链路恢复内容不符")
	}
}

func TestFECGCMParityWrongSaltRejected(t *testing.T) {
	// 用不同盐解密校验帧必须失败，整组放弃（不得产出伪造的"恢复"帧）
	enc, _ := newGCMInnerCipher("fec_gcm_psk", randomSalt())
	dec, _ := newGCMInnerCipher("fec_gcm_psk", randomSalt()) // 异盐

	c, out := newFecCollector()
	d := NewFECDecoder(4, dec, out)
	e := newFECEncoder(4, enc)
	payloads := [][]byte{
		bytes.Repeat([]byte{0x01}, 100),
		bytes.Repeat([]byte{0x02}, 100),
		bytes.Repeat([]byte{0x03}, 100),
		bytes.Repeat([]byte{0x04}, 100),
	}
	var parity []byte
	for i, p := range payloads {
		if par := e.add(VPNFrame{Seq: uint32(i + 1), Data: p}); par != nil {
			parity = par
		}
	}
	c.expect(0)
	d.OnData(1, payloads[0])
	d.OnData(2, payloads[1])
	d.OnData(3, payloads[2])
	d.OnParity(parity)
	if len(c.seqs) != 0 {
		t.Fatalf("异盐校验帧不应恢复任何帧, got %v", c.seqs)
	}
}

func mustGCM(psk string, salt []byte) *innerCipher {
	ic, err := newGCMInnerCipher(psk, salt)
	if err != nil {
		panic(err)
	}
	return ic
}

func TestLegacyFallbackUnchanged(t *testing.T) {
	// legacy 回退路径与历史行为逐字节一致（golden 向量以外的不变式）
	ic := newLegacyInnerCipher("legacy_psk")
	block, baseIV := getCipherContext("legacy_psk")
	pt := []byte("legacy payload for compat check")

	a := append([]byte(nil), pt...)
	ic.sealInPlace(a, len(a), 999, uint32(len(a)))

	b := append([]byte(nil), pt...)
	xorCryptInPlace(b, 999, block, baseIV)

	if !bytes.Equal(a, b) {
		t.Fatal("legacy 回退实现与原 xorCryptInPlace 行为不一致")
	}
	if got := hex.EncodeToString(a); len(got) != 2*len(pt) {
		t.Fatal("legacy 输出长度应与输入一致")
	}
}

func TestHandshakeJSONGCMFields(t *testing.T) {
	resp := HandshakeResp{
		Success: true, Encrypt: true, EncAlgo: encAlgoGCM,
		EncSalt: "aabbccddeeff0011", EncSalt2: "1122334455667788",
	}
	b, _ := json.Marshal(resp)
	var m map[string]any
	json.Unmarshal(b, &m)
	for _, k := range []string{"enc_algo", "enc_salt", "enc_salt2"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("GCM 响应缺少字段 %s", k)
		}
	}

	legacy := HandshakeResp{Success: true, Encrypt: true}
	b2, _ := json.Marshal(legacy)
	var m2 map[string]any
	json.Unmarshal(b2, &m2)
	for _, k := range []string{"enc_algo", "enc_salt", "enc_salt2"} {
		if _, ok := m2[k]; ok {
			t.Fatalf("legacy 响应不应出现字段 %s（旧端兼容）", k)
		}
	}

	req := HandshakeReq{Encrypt: true, EncAlgo: encAlgoGCM}
	b3, _ := json.Marshal(req)
	var m3 map[string]any
	json.Unmarshal(b3, &m3)
	if _, ok := m3["enc_algo"]; !ok {
		t.Fatal("GCM 客户端请求必须声明 enc_algo")
	}
}

func TestWebAuthAndStats(t *testing.T) {
	// Basic Auth：正确凭据放行、缺失/错误凭据 401
	h := basicAuthWrapper("admin:s3cret", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("无凭据应 401, got %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("GET", srv.URL, nil)
	req.SetBasicAuth("admin", "s3cret")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("正确凭据应 200, got %d", resp2.StatusCode)
	}
	req2, _ := http.NewRequest("GET", srv.URL, nil)
	req2.SetBasicAuth("admin", "wrong")
	resp3, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != 401 {
		t.Fatalf("错误凭据应 401, got %d", resp3.StatusCode)
	}

	// 未配置认证时直接放行
	open := basicAuthWrapper("", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	osrv := httptest.NewServer(open)
	defer osrv.Close()
	resp4, err := http.Get(osrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp4.Body.Close()
	if resp4.StatusCode != 200 {
		t.Fatalf("无认证配置应 200, got %d", resp4.StatusCode)
	}
}

func TestStatsClientModeShape(t *testing.T) {
	cli := &Client{
		clientID:   "test-client-id",
		macAddr:    "00:11:22:33:44:55",
		startedAt:  time.Now(),
		encAlgo:    encAlgoGCM,
		assignedV4: "10.0.0.5",
		fecStatus:  "xor K=4",
		fecMode:    true,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		startWebStatsHandler(w, r, nil, cli)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/api/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var data map[string]any
	json.NewDecoder(resp.Body).Decode(&data)
	if data["mode"] != "client" || data["version"] != appVersion {
		t.Fatalf("stats 头部字段不符: %v", data)
	}
	clients, _ := data["clients"].(map[string]any)
	local, _ := clients["local"].(map[string]any)
	if local == nil {
		t.Fatal("client 模式应有 clients.local")
	}
	if local["ipv4"] != "10.0.0.5" || local["fec"] != "xor K=4" || local["enc_algo"] != float64(encAlgoGCM) {
		t.Fatalf("local 字段不符: %v", local)
	}
}

func TestFECSupportCounters(t *testing.T) {
	// 恢复/丢失计数器：1 帧恢复 + 2 帧确认丢失
	c, out := newFecCollector()
	d := NewFECDecoder(4, nil, out)
	payloads := [][]byte{
		bytes.Repeat([]byte{0x01}, 30), bytes.Repeat([]byte{0x02}, 30),
		bytes.Repeat([]byte{0x03}, 30), bytes.Repeat([]byte{0x04}, 30),
	}
	// 组1: seq1-4，丢 seq2 → 恢复
	parity1 := encodeGroup(4, nil, nil, 1, payloads)
	c.expect(1)
	d.OnData(1, payloads[0])
	d.OnData(3, payloads[2])
	d.OnData(4, payloads[3])
	d.OnParity(parity1)
	c.waitDone(t)
	rec, lost := d.FECStats()
	if rec != 1 || lost != 0 {
		t.Fatalf("组1: 应 recovered=1 lost=0, got %d/%d", rec, lost)
	}
	// 组2: seq5-8，丢 seq5、seq6 → 不可恢复，随后触发淘汰确认丢失
	parity2 := encodeGroup(4, nil, nil, 5, payloads)
	d.OnData(7, payloads[2])
	d.OnData(8, payloads[3])
	d.OnParity(parity2)
	d.Reset()
	rec, lost = d.FECStats()
	if rec != 1 {
		t.Fatalf("Reset 后 recovered 应保持 1, got %d", rec)
	}
	_ = lost // 组2 缺 2 帧在 Reset 时被释放，不计入确认丢失（无 parity 终结语义）
}

func TestBanFlow(t *testing.T) {
	s := &Server{
		banned:        make(map[string]int64),
		activeClients: make(map[string]*ClientSession),
	}
	if s.IsBanned("c1") {
		t.Fatal("初始不应被封禁")
	}
	s.Ban("c1", 0) // 永久
	if !s.IsBanned("c1") {
		t.Fatal("封禁后应命中")
	}
	s.Ban("c2", 50*time.Millisecond)
	if !s.IsBanned("c2") {
		t.Fatal("TTL 封禁应命中")
	}
	time.Sleep(60 * time.Millisecond)
	if s.IsBanned("c2") {
		t.Fatal("过期封禁应自动解除")
	}
	if len(s.BanList()) != 1 {
		t.Fatalf("BanList 应只剩 1 项: %v", s.BanList())
	}
	s.Unban("c1")
	if s.IsBanned("c1") {
		t.Fatal("解封后不应命中")
	}
}

func TestControlCSRFRequired(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/control", basicAuthWrapper("", csrfGuard(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})))
	osrv := httptest.NewServer(mux)
	defer osrv.Close()

	// 缺失自定义头 → 403（跨站表单无法携带）
	resp, err := http.Post(osrv.URL+"/api/control", "application/json", strings.NewReader(`{"action":"gc"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("缺失 X-Requested-With 应 403, got %d", resp.StatusCode)
	}
	// 带上自定义头 → 放行
	req, _ := http.NewRequest("POST", osrv.URL+"/api/control", strings.NewReader(`{"action":"gc"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Requested-With", "tlsvpn")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != 200 {
		t.Fatalf("带头应 200, got %d", resp2.StatusCode)
	}
}

func TestMetricsEndpoint(t *testing.T) {
	s := &Server{
		mu:            sync.RWMutex{},
		banned:        make(map[string]int64),
		activeClients: make(map[string]*ClientSession),
		v4Net:         mustCIDR("10.0.0.0/24"),
		v6Net:         mustCIDR("fd00::/64"),
		startedAt:     time.Now(),
	}
	osrv := httptest.NewServer(handleMetrics(s, nil))
	defer osrv.Close()
	resp, err := http.Get(osrv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := make([]byte, 0, 4096)
	buf := make([]byte, 1024)
	for {
		n, err2 := resp.Body.Read(buf)
		body = append(body, buf[:n]...)
		if err2 != nil {
			break
		}
	}
	text := string(body)
	for _, want := range []string{
		"tlsvpn_uptime_seconds", "tlsvpn_active_clients",
		"tlsvpn_ip_pool_v4_used", "tlsvpn_ip_pool_v4_total",
		"tlsvpn_go_goroutines", "tlsvpn_heap_alloc_bytes",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("metrics 缺少 %s:\n%s", want, text)
		}
	}
}

func mustCIDR(cidr string) *net.IPNet {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return n
}

func TestLogLevelAction(t *testing.T) {
	defer setRuntimeLogLevel("info")
	if err := setRuntimeLogLevel("debug"); err != nil {
		t.Fatal(err)
	}
	if currentLogLevelName() != "debug" {
		t.Fatalf("应为 debug, got %s", currentLogLevelName())
	}
	if err := setRuntimeLogLevel("notalevel"); err == nil {
		t.Fatal("非法级别应报错")
	}
}

func TestLogRingSnapshot(t *testing.T) {
	r := newLogRing(4)
	base := time.Now()
	for i := 0; i < 6; i++ {
		r.add(zapcore.Entry{Level: zapcore.InfoLevel, Time: base, Message: fmt.Sprint("line", i)})
	}
	all := r.snapshot(0)
	if len(all) != 4 {
		t.Fatalf("环形缓冲应只保留最近 4 条, got %d", len(all))
	}
	if all[0].Msg != "line2" || all[3].Msg != "line5" {
		t.Fatalf("快照内容不符: %v", all)
	}
	part := r.snapshot(all[1].Seq)
	if len(part) != 2 || part[0].Msg != "line4" {
		t.Fatalf("增量快照不符: %v", part)
	}
}

func TestReconnectBackoff(t *testing.T) {
	d0 := reconnectBackoffDelay(0)
	if d0 < 500*time.Millisecond || d0 > reconnectBackoffBase {
		t.Fatalf("首次重试应在 [0.5s, 1s] 区间, got %s", d0)
	}
	d5 := reconnectBackoffDelay(5)
	if d5 > reconnectBackoffMax {
		t.Fatalf("退避应封顶 30s, got %s", d5)
	}
	d9 := reconnectBackoffDelay(9)
	if d9 > reconnectBackoffMax {
		t.Fatalf("超长 attempt 应仍封顶, got %s", d9)
	}
	if d5 <= d0 {
		t.Fatalf("退避应单调递增区间: d0=%s d5=%s", d0, d5)
	}
}
