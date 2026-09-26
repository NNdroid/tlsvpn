package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestWebStatsNewFieldsJSON 钉住新增观测字段的 JSON 键名与 omitempty 语义。
// 面板靠"字段缺席 = 平台不支持/未启用"来渲染缺位，指针字段一旦漏掉 omitempty，
// Windows 客户端就会看到一堆零值并误判成"数值为 0 的故障"；反过来 drop_breakdown
// 是非指针，必须无条件出现，否则前端要再加一层判空。
func TestWebStatsNewFieldsJSON(t *testing.T) {
	empty := WebStats{Mode: "server"}
	data, err := json.Marshal(empty)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)

	for _, key := range []string{
		"\"drop_breakdown\":", "\"global_tx_bytes\":", "\"global_rx_bytes\":",
		"\"global_tx_packets\":", "\"global_rx_packets\":",
		"\"reconnect_attempts\":", "\"live_conns\":",
	} {
		if !strings.Contains(s, key) {
			t.Errorf("absent-optional stats must still emit %s", key)
		}
	}
	for _, key := range []string{
		"\"protect\":", "\"pad\":", "\"sessions\":", "\"cert\":",
		"\"hooks\":", "\"routes\":", "\"tap_link\":", "\"cpu\":",
	} {
		if strings.Contains(s, key) {
			t.Errorf("nil %s must be omitted", strings.Trim(key, `":`))
		}
	}

	full := WebStats{
		Mode:            "server",
		DropBreakdown:   dropBreakdownJSON{Backpressure: 1, SpoofedSrc: 2, Broadcast: 3, Reorder: 4},
		Protect:         &protectStatsJSON{ConnsRejected: 5, TLSHandshakeFail: 6, FallbackHTTP: 7, Tarpit: 8, FECGroupRejected: 9},
		Pad:             &padStatsJSON{Mode: "off", WireBytes: 100, PadBytes: 10, OverheadPct: 10},
		Sessions:        &sessionsJSON{Active: 2, Max: 8},
		Cert:            &certInfoJSON{NotAfter: "2027-01-01T00:00:00Z", DaysLeft: 40, SelfSigned: true},
		Hooks:           &hookStatusJSON{Configured: true, UpPath: "up.sh", UpRan: true, UpOK: true, UpMs: 3},
		Routes:          &routeStateJSON{Rules: []string{"10.7.0.0/24 lookup 101"}, Routes: []string{"default via 1.2.3.4"}, AgeSec: 2},
		TapLink:         &tapLinkJSON{Up: true, MTU: 1500, RxPkts: 1, TxPkts: 2},
		CPU:             &cpuJSON{Percent: 12.5},
		GlobalTxPackets: 11, GlobalRxPackets: 12, ReconnectAttempts: 3, LiveConns: 4,
	}
	data, err = json.Marshal(full)
	if err != nil {
		t.Fatal(err)
	}
	s = string(data)
	for _, key := range []string{
		"\"protect\":", "\"pad\":", "\"sessions\":", "\"cert\":",
		"\"hooks\":", "\"routes\":", "\"tap_link\":", "\"cpu\":",
		"\"backpressure\":1", "\"spoofed_src\":2", "\"broadcast\":3", "\"reorder\":4",
		"\"conns_rejected\":5", "\"tls_handshake_fail\":6", "\"fallback_http\":7",
		"\"tarpit\":8", "\"fec_group_rejected\":9",
		"\"wire_bytes\":100", "\"pad_bytes\":10", "\"overhead_pct\":10",
		"\"active\":2", "\"max\":8",
		"\"not_after\":\"2027-01-01T00:00:00Z\"", "\"days_left\":40", "\"self_signed\":true",
		"\"configured\":true", "\"up_path\":\"up.sh\"", "\"up_ran\":true", "\"up_ok\":true", "\"up_ms\":3",
		"\"rules\":[\"10.7.0.0/24 lookup 101\"]", "\"age_sec\":2",
		"\"up\":true", "\"mtu\":1500", "\"rx_pkts\":1", "\"tx_pkts\":2",
		"\"percent\":12.5",
	} {
		if !strings.Contains(s, key) {
			t.Errorf("populated stats missing %s", key)
		}
	}
}

func TestPadOverhead(t *testing.T) {
	if padOverhead(0, 100) != 0 {
		t.Fatal("zero wire bytes must not divide by zero")
	}
	if padOverhead(100, 10) != 10 {
		t.Fatalf("padOverhead(100,10) = %v, want 10", padOverhead(100, 10))
	}
	if padOverhead(80, 20) != 25 {
		t.Fatalf("padOverhead(80,20) = %v, want 25", padOverhead(80, 20))
	}
}

// TestCertInfoSnapshot 证书有效期是"当天/7 天/30 天/已过期"四档告警的依据，
// 换算错一档就会让人忽略一个明天到期的证书。
func TestCertInfoSnapshot(t *testing.T) {
	old := serverCertExp.Load()
	defer serverCertExp.Store(old)

	serverCertExp.Store(nil)
	if certInfoSnapshot() != nil {
		t.Fatal("no loaded cert must yield nil")
	}

	serverCertExp.Store(&certExpiry{selfSigned: true})
	info := certInfoSnapshot()
	if info == nil || info.NotAfter != "" || info.DaysLeft != 0 || !info.SelfSigned {
		t.Fatalf("unparseable cert must stay zero: %+v", info)
	}

	serverCertExp.Store(&certExpiry{notAfter: time.Now().Add(36 * time.Hour), selfSigned: false})
	info = certInfoSnapshot()
	if info == nil || info.DaysLeft != 1 || !strings.HasSuffix(info.NotAfter, "Z") {
		t.Fatalf("expiry snapshot wrong: %+v", info)
	}

	serverCertExp.Store(&certExpiry{notAfter: time.Now().Add(-time.Hour), selfSigned: false})
	info = certInfoSnapshot()
	if info == nil || info.DaysLeft >= 0 {
		t.Fatalf("expired cert must be negative days_left: %+v", info)
	}
}

// TestServerPskFailSnapshotOrdering 失败次数多的排在前面，同级按地址排序——
// 面板直接当排行榜渲染，顺序错了第一名就不是威胁最大的那个地址。
func TestServerPskFailSnapshotOrdering(t *testing.T) {
	s := &Server{pskFail: map[string]*pskFailBucket{
		"1.1.1.1:443": {count: 3, first: time.Now()},
		"2.2.2.2:443": {count: 7, first: time.Now()},
		"3.3.3.3:443": {count: 7, first: time.Now()},
	}}
	out := s.pskFailSnapshot()
	if len(out) != 3 {
		t.Fatalf("len = %d, want 3", len(out))
	}
	if out[0].Remote != "2.2.2.2:443" || out[0].Count != 7 {
		t.Fatalf("top entry = %+v, want 2.2.2.2:443 count 7", out[0])
	}
	if out[1].Remote != "3.3.3.3:443" {
		t.Fatalf("tie must break by address: %+v", out[1])
	}
	if out[2].Count != 3 {
		t.Fatalf("bottom count = %d, want 3", out[2].Count)
	}
	for _, e := range out {
		if e.WindowSec < 0 {
			t.Fatalf("window_sec must be non-negative: %+v", e)
		}
	}

	if got := (&Server{}).pskFailSnapshot(); got != nil {
		t.Fatalf("empty table must return nil, got %v", got)
	}
}

// TestRouteStateSnapshotRequiresFwmark 无 fwmark 就没有"我们的"策略路由表；
// 服务器端不应把宿主机本地路由表当成自己的配置打出来。
func TestRouteStateSnapshotRequiresFwmark(t *testing.T) {
	for _, mark := range []int{0, -1} {
		if got := routeStateSnapshot(mark); got != nil {
			t.Fatalf("fwmark %d must yield nil, got %+v", mark, got)
		}
	}
}
