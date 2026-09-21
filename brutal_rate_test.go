package main

import (
	"bytes"
	"encoding/json"
	"testing"

	"go.uber.org/zap"
)

// TestNegotiateBrutalRates 锁定上下行速率的预算归属：下行必须受 brutalDown 约束、
// 上行必须受 brutalUp 约束。两个预算一旦写反，服务端就会拿自己的上行预算去限客户端
// 的下行，客户端面板随之出现"上行 125 Mbps 配 30 Mbps 上行总量"的矛盾读数。
//
// 刻意用不对称预算构造用例：上下行预算相等时，写反与否结果相同，这类 bug 测不出来。
func TestNegotiateBrutalRates(t *testing.T) {
	cases := []struct {
		name       string
		serverUp   uint64
		serverDown uint64
		cliTx      uint64
		cliRx      uint64
		wantSrvTx  uint64 // 服务端→客户端（下行），由服务端 socket 整形
		wantCliTx  uint64 // 客户端→服务端（上行），由客户端自己整形
	}{
		{"asym_budget_sides", 100, 1000, 7, 125, 125, 7},
		{"asym_budgets_reversed", 500, 30, 125, 7, 7, 125},
		{"symmetric_budgets", 500, 500, 7, 125, 125, 7},
		{"server_unlimited", 0, 0, 125, 7, 7, 125},
		{"client_wants_less_than_budget", 1000, 1000, 1, 1, 1, 1},
		{"client_requests_no_shaping", 1000, 1000, 0, 0, 1000, 1000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotSrvTx, gotCliTx := negotiateBrutalRates(tc.serverUp, tc.serverDown, tc.cliTx, tc.cliRx)
			if gotSrvTx != tc.wantSrvTx || gotCliTx != tc.wantCliTx {
				t.Fatalf("negotiateBrutalRates(serverUp=%d serverDown=%d cliTx=%d cliRx=%d) = (%d, %d), want (srvTx=%d, cliTx=%d)",
					tc.serverUp, tc.serverDown, tc.cliTx, tc.cliRx,
					gotSrvTx, gotCliTx, tc.wantSrvTx, tc.wantCliTx)
			}
		})
	}
}

// TestSendRespRateDirections 锁定握手响应里两个速率的方向：brutal_tx 是客户端视角的
// 上行、brutal_rx 是下行。服务端自己的 tx 是下行、不是上行——曾误按本端 tx/rx 填，
// 两端视角正好相反，面板表现为上行/下行整体对调。
func TestSendRespRateDirections(t *testing.T) {
	oldLog := log
	log = zap.NewNop().Sugar()
	defer func() { log = oldLog }()

	var buf bytes.Buffer
	// sendResp 内部吞掉写错误，所以这里靠下面的 ReadFrame 兜底：帧没写出来就读不到。
	(&Server{}).sendResp(&buf, true, "OK", "cid", "sid",
		"10.8.0.0/24", "fd00::/80",
		7, 125, // cliTx（上行）, srvTx（下行）
		false, 0, encAlgoGCM, "", "", "", true, 2, 3)

	// 走和客户端完全相同的读路径（client.go 的 handshake response 读取）
	scanner := NewFrameScanner(bytes.NewReader(buf.Bytes()))
	data, _, err := scanner.ReadFrame()
	if err != nil {
		t.Fatalf("读握手响应帧失败：%v", err)
	}
	var resp HandshakeResp
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("解析握手响应失败：%v", err)
	}
	if resp.BrutalTx != 7 {
		t.Errorf("brutal_tx = %d，应为 7（客户端上行）：上行/下行方向又被对调了", resp.BrutalTx)
	}
	if resp.BrutalRx != 125 {
		t.Errorf("brutal_rx = %d，应为 125（客户端下行）：上行/下行方向又被对调了", resp.BrutalRx)
	}
}

// TestConnsSummaryCountsHealthyConns 锁定每连接上行速率的统计口径：健康连接也要计入。
// 曾因为对 brutalErr=="" 的连接 continue，速率只从失败连接累加——全部连接生效时
// 面板的每连接上行速率永远是 "-"，只有整形挂掉才报得出数。
func TestConnsSummaryCountsHealthyConns(t *testing.T) {
	newClient := func(healthy bool) *Client {
		c := &Client{connsCount: 4, conns: map[int]*clientConnInfo{}}
		c.live.Store(&liveConfig{brutalUp: 30, brutalDown: 500, connsCount: 4})
		for i := 0; i < 4; i++ {
			ci := &clientConnInfo{}
			if !healthy {
				ci.brutalErr = "kernel has no 'brutal' congestion control"
			}
			c.conns[i] = ci
		}
		return c
	}

	st := newClient(true).connsSummary()
	if st.applied != 4 || st.total != 4 {
		t.Fatalf("健康连接统计错误：applied=%d total=%d", st.applied, st.total)
	}
	if st.minUp != 7 || st.maxUp != 7 {
		t.Errorf("4 条健康连接、上行总量 30 时每连接上行应为 7，实际 minUp=%d maxUp=%d",
			st.minUp, st.maxUp)
	}

	st = newClient(false).connsSummary()
	if st.applied != 0 {
		t.Errorf("全部失败时 applied 应为 0，实际 %d", st.applied)
	}
	if len(st.errs) != 1 {
		t.Fatalf("错误去重失效：errs=%v", st.errs)
	}
	if st.minUp != 7 || st.maxUp != 7 {
		t.Errorf("失败连接也应按配置给出每连接上行速率，实际 minUp=%d maxUp=%d",
			st.minUp, st.maxUp)
	}
}
