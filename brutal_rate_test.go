package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
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

// TestSendRespRateDirections 锁定握手响应里两个速率的方向：brutal_total_tx 是客户端
// 视角的上行、brutal_total_rx 是下行。服务端自己的 tx 是下行、不是上行——曾误按本端
// tx/rx 填，两端视角正好相反，面板表现为上行/下行整体对调。
func TestSendRespRateDirections(t *testing.T) {
	oldLog := log
	log = zap.NewNop().Sugar()
	defer func() { log = oldLog }()

	var buf bytes.Buffer
	if err := (&Server{}).sendResp(&buf, true, "OK", "cid", "sid",
		"10.8.0.0/24", "fd00::/80",
		true, 30, 500, // group 语义：客户端上行总量, 客户端下行总量
		false, 0, encAlgoGCM, "", "", "", true, 2, 3, nil); err != nil {
		t.Fatalf("发送握手响应失败：%v", err)
	}

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
	if resp.BrutalTotalTx != 30 {
		t.Errorf("brutal_total_tx = %d，应为 30（客户端上行）：上行/下行方向又被对调了", resp.BrutalTotalTx)
	}
	if resp.BrutalTotalRx != 500 {
		t.Errorf("brutal_total_rx = %d，应为 500（客户端下行）：上行/下行方向又被对调了", resp.BrutalTotalRx)
	}
	if !resp.BrutalGroups {
		t.Error("brutal_groups 应为 true：总速率字段依赖 group 语义才成立")
	}
}

type failingHandshakeWriter struct{}

func (failingHandshakeWriter) Write([]byte) (int, error) {
	return 0, errors.New("forced handshake write failure")
}

func TestSendRespPropagatesWriteFailure(t *testing.T) {
	oldLog := log
	log = zap.NewNop().Sugar()
	defer func() { log = oldLog }()

	err := (&Server{}).sendResp(failingHandshakeWriter{}, true, "OK", "cid", "sid",
		"10.8.0.0/24", "fd00::/80",
		false, 0, 0,
		false, 0, encAlgoNone, "", "", "", false, 2, 1, nil)
	if err == nil {
		t.Fatal("sendResp swallowed the handshake response write failure")
	}
	if !strings.Contains(err.Error(), "write handshake response") {
		t.Fatalf("unexpected sendResp error: %v", err)
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
			br := &brutalApplyResult{Attempted: true, Applied: healthy}
			if !healthy {
				br.Error = "kernel has no 'brutal' congestion control"
			}
			ci.brutal.Store(br)
			c.conns[i] = ci
		}
		return c
	}

	st := newClient(true).connsSummary()
	if st.applied != 4 || st.total != 4 {
		t.Fatalf("健康连接统计错误：applied=%d total=%d", st.applied, st.total)
	}
	if st.minUp != 7 || st.maxUp != 8 {
		t.Errorf("4 条健康连接、上行总量 30 时精确分配应为 7..8，实际 minUp=%d maxUp=%d",
			st.minUp, st.maxUp)
	}

	st = newClient(false).connsSummary()
	if st.applied != 0 {
		t.Errorf("全部失败时 applied 应为 0，实际 %d", st.applied)
	}
	if len(st.errs) != 1 {
		t.Fatalf("错误去重失效：errs=%v", st.errs)
	}
	if st.minUp != 7 || st.maxUp != 8 {
		t.Errorf("失败连接也应按配置给出精确的每连接上行范围，实际 minUp=%d maxUp=%d",
			st.minUp, st.maxUp)
	}
}

// TestSnapshotConnsCarriesNegotiatedRates 锁定客户端连接快照携带上下行速率——
// 面板逐连接 Brutal 列取的就是这两个字段。
//
// 曾因为 connSnapshot 根本没有速率字段、前端又对本地连接行硬编码 0，导致整形
// 明明生效（brutal_error 为空）面板却永远显示 "-"。速率取自 negInfo，是会话级
// （最近一次握手响应）的取值：服务端对每条物理连接各授各的，客户端只拿到握手
// 响应里那一份，所以同一会话的多条连接显示同一组数是预期行为，不是聚合错误。
func TestSnapshotConnsCarriesNegotiatedRates(t *testing.T) {
	newClient := func(setNeg bool) *Client {
		c := &Client{connsCount: 4, conns: map[int]*clientConnInfo{}}
		for i := 0; i < 4; i++ {
			// rttCache 是指针，生产里三处构造点都 new 了；这里不给就 nil deref。
			ci := &clientConnInfo{rttCache: new(uint32)}
			ci.brutal.Store(&brutalApplyResult{Attempted: true, Applied: true})
			c.conns[i] = ci
		}
		if setNeg {
			c.negInfo = &sessionNeg{TxRateMbps: 7, RxRateMbps: 125}
		}
		return c
	}

	got := newClient(true).snapshotConns()
	if len(got) != 4 {
		t.Fatalf("应有 4 条连接快照，实际 %d", len(got))
	}
	for i, s := range got {
		if s.BrutalTxMbps != 7 {
			t.Errorf("连接 %d 上行速率应为 7（服务端授予的上行），实际 %d", i, s.BrutalTxMbps)
		}
		if s.BrutalRxMbps != 125 {
			t.Errorf("连接 %d 下行速率应为 125（服务端授予的下行），实际 %d", i, s.BrutalRxMbps)
		}
		if !s.BrutalApplied {
			t.Errorf("连接 %d 无 brutalErr 应报告已生效", i)
		}
	}

	// 还没握手成功（negInfo 为 nil）时不给速率，面板就该显示 "-"
	zero := newClient(false).snapshotConns()
	if zero[0].BrutalTxMbps != 0 || zero[0].BrutalRxMbps != 0 {
		t.Errorf("未握手时速率应为 0，实际 %d/%d",
			zero[0].BrutalTxMbps, zero[0].BrutalRxMbps)
	}
}
