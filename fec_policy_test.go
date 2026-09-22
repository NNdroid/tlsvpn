package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// TestServerFecGroupPolicyDefaults 未配置时策略区间即协议边界，行为不变。
func TestServerFecGroupPolicyDefaults(t *testing.T) {
	cfg := &Config{Mode: "server", PSK: "fec-policy-psk", Tap: "mem", Addr: "127.0.0.1:0"}
	cfg.applyDefaults()
	if cfg.Server.FecGroupMin != fecMinGroup || cfg.Server.FecGroupMax != fecMaxGroup {
		t.Fatalf("默认策略区间应为 [%d,%d]，实际 [%d,%d]",
			fecMinGroup, fecMaxGroup, cfg.Server.FecGroupMin, cfg.Server.FecGroupMax)
	}
}

func TestValidateServerFecGroupPolicy(t *testing.T) {
	cases := []struct {
		name     string
		min, max int
		wantErr  bool
	}{
		{"区间内合法", 4, 8, false},
		{"min=max 合法", 4, 4, false},
		{"协议边界合法", fecMinGroup, fecMaxGroup, false},
		{"min 低于协议下限", 1, 8, true},
		{"min 为负", -1, 8, true},
		{"max 高于协议上限", 4, fecMaxGroup + 1, true},
		{"max 为 0 但未被默认填充", 4, 0, true},
		{"min 大于 max", 8, 4, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// 先跑默认填充（区间被填成协议边界），再把区间强制改成用例值，
			// 这样也能覆盖"配置里显式写了越界值"的情形
			cfg := &Config{Mode: "server", PSK: "fec-policy-psk", Addr: "0.0.0.0:4000",
				Server: ServerConfig{V4CIDR: "10.0.0.0/24", V6CIDR: "fd00::/64"}}
			cfg.applyDefaults()
			cfg.Server.FecGroupMin, cfg.Server.FecGroupMax = tc.min, tc.max
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("min=%d max=%d: 期望校验失败，实际通过", tc.min, tc.max)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("min=%d max=%d: 期望通过，实际 %v", tc.min, tc.max, err)
			}
		})
	}
}

// newFecPolicyServer 起一个只做握手验证的进程内 Server（mem tap）。
func newFecPolicyServer(t *testing.T, ctx context.Context, min, max int) *Server {
	t.Helper()
	cfg := &Config{Mode: "server", PSK: "fec-policy-psk", Tap: "mem", Addr: "127.0.0.1:0",
		Encrypt: false,
		Server: ServerConfig{V4CIDR: "10.0.0.0/24", V6CIDR: "fd00::/64",
			FecGroupMin: min, FecGroupMax: max}}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("server cfg: %v", err)
	}
	srv, err := newServerForTest(ctx, cfg)
	if err != nil {
		t.Fatalf("server init: %v", err)
	}
	return srv
}

// derivedClientID 复算服务端预期的 ClientID（server.go 的握手校验公式）。
func derivedClientID(mac, psk string) string {
	ns := uuid.NewMD5(uuid.NameSpaceURL, []byte("my_vpn_tunnel"))
	return uuid.NewSHA1(ns, []byte(mac+psk)).String()
}

// rawHandshake 用一条普通 TCP 连接直接喂握手帧给 handleConnection，返回握手响应。
// 不走自己的 Client：客户端发送前会把 fec_group 夹到协议范围，绕不过服务端策略闸。
func rawHandshake(t *testing.T, srv *Server, fec bool, k int) (*HandshakeResp, error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		c, err := l.(*net.TCPListener).AcceptTCP()
		if err != nil {
			return
		}
		accepted <- c
	}()

	client, err := net.DialTimeout("tcp", l.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	clientTCP := client.(*net.TCPConn)

	select {
	case srvConn := <-accepted:
		go srv.handleConnection(ctx, srvConn, srvConn)
	case <-time.After(2 * time.Second):
		t.Fatal("server did not accept")
	}

	req := HandshakeReq{
		ProtocolVersion: 2,
		ClientInstance:  "abcdefghijklmnop",
		ClientID:        derivedClientID("02:aa:bb:cc:dd:ee", "fec-policy-psk"),
		PSK:             hashPSK("fec-policy-psk"),
		MAC:             "02:aa:bb:cc:dd:ee",
		Padding:         strings.Repeat("a", 100),
		FEC:             fec,
		FecGroup:        k,
		Encrypt:         false,
		EncAlgo:         encAlgoNone,
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal req: %v", err)
	}
	if err := writeStreamFrame(clientTCP, data); err != nil {
		t.Fatalf("send req: %v", err)
	}

	scanner := NewFrameScanner(clientTCP)
	scanner.SetMaxDataLen(maxHandshakeDataLen)
	clientTCP.SetReadDeadline(time.Now().Add(3 * time.Second))
	respData, _, err := scanner.ReadFrame()
	clientTCP.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, err
	}
	var resp HandshakeResp
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// captureWarnLogs 把 warn 级日志收进缓冲，用于断言拒连**原因**（只断言
// "被拒"不够：PSK 错误等其它闸门也会以同样的 EOF 表现收场）。
// 参照 brutal_rate_test.go 的 log 替换模式。
func captureWarnLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	enc := zapcore.NewJSONEncoder(zapcore.EncoderConfig{
		MessageKey: "msg", TimeKey: zapcore.OmitKey, LevelKey: zapcore.OmitKey,
		NameKey: zapcore.OmitKey, CallerKey: zapcore.OmitKey,
		StacktraceKey: zapcore.OmitKey, FunctionKey: zapcore.OmitKey,
	})
	var buf bytes.Buffer
	old := log
	log = zap.New(zapcore.NewCore(enc, zapcore.AddSync(&buf), zapcore.WarnLevel)).Sugar()
	t.Cleanup(func() { log = old })
	return &buf
}

func TestServerRefusesFecGroupOutsidePolicy(t *testing.T) {
	logs := captureWarnLogs(t)

	cases := []struct {
		name    string
		fec     bool
		k       int
		wantErr bool
	}{
		{"低于政策下限被拒", true, 3, true},
		{"高于政策上限被拒", true, 9, true},
		{"远低于政策下限被拒", true, fecMinGroup, true},
		{"远高于协议上限被拒", true, fecMaxGroup * 1000, true},
		{"负数被拒", true, -3, true},
		// 政策区间内的端点与中间值
		{"下限通过", true, 4, false},
		{"上限通过", true, 8, false},
		{"区间中间值通过", true, 6, false},
		// fec=false 时 fec_group=0 合法，任何值都必须放行（否则非 FEC 握手全灭）
		{"未开 FEC 且 fec_group 为 0 放行", false, 0, false},
		{"未开 FEC 但 fec_group 越界仍放行", false, 999999, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// 每个用例独立起一个服务端：复用同一个 server 会让相邻用例落到
			// 同一 clientID 的会话复活路径上，拒连/协商结果彼此污染。
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			srv := newFecPolicyServer(t, ctx, 4, 8)
			logs.Reset()
			resp, err := rawHandshake(t, srv, tc.fec, tc.k)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("fec=%v fec_group=%d 应被拒绝，实际握手成功（fec_group=%d）",
						tc.fec, tc.k, resp.FecGroup)
				}
				// 断言是 FEC 策略闸门拒的，不是别的闸门顺带拒的（PSK 错误等也表现为 EOF）
				if !strings.Contains(logs.String(),
					fmt.Sprintf("fec_group=%d outside server policy", tc.k)) {
					t.Fatalf("fec=%v fec_group=%d 的拒绝原因应为 FEC 策略，实际日志: %s",
						tc.fec, tc.k, logs.String())
				}
				return
			}
			if err != nil {
				t.Fatalf("fec=%v fec_group=%d 应通过，实际被拒: %v", tc.fec, tc.k, err)
			}
			if !resp.Success {
				t.Fatalf("fec=%v fec_group=%d: success=false (msg=%q)", tc.fec, tc.k, resp.Message)
			}
			if tc.fec && resp.FecGroup != tc.k {
				t.Fatalf("fec_group 应原样协商为 %d，实际 %d", tc.k, resp.FecGroup)
			}
			if !tc.fec && resp.FecGroup != 0 {
				t.Fatalf("未请求 FEC 时 fec_group 应为 0，实际 %d", resp.FecGroup)
			}
		})
	}
}

// TestServerFecGroupPolicyHotReload 策略区间可热更，立即作用于新握手。
func TestServerFecGroupPolicyHotReload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := newFecPolicyServer(t, ctx, 4, 8)

	// 放宽到 [2,64] 前，K=2 仍被拒
	if _, err := rawHandshake(t, srv, true, 2); err == nil {
		t.Fatal("策略 [4,8] 下 fec_group=2 应被拒绝")
	}
	// 走面板同一条路径（合并 → 校验 → 热更）
	newCfg, needsRestart, err := mergeAndValidateConfig(srv.cfg.Load(),
		[]byte(`{"mode":"server","psk":"fec-policy-psk","tap":"mem","addr":"127.0.0.1:0",
			"server":{"v4_cidr":"10.0.0.0/24","v6_cidr":"fd00::/64",
				"fec_group_min":2,"fec_group_max":64}}`), true, srv, nil)
	if err != nil {
		t.Fatalf("hot cfg merge/validate: %v", err)
	}
	for _, f := range needsRestart {
		if strings.Contains(f, "fec_group") {
			t.Fatalf("FEC 策略应可热更，不应要求重启，needs_restart=%v", needsRestart)
		}
	}
	srv.ApplyConfig(newCfg)
	resp, err := rawHandshake(t, srv, true, 2)
	if err != nil {
		t.Fatalf("热更后 fec_group=2 应通过，实际被拒: %v", err)
	}
	if resp.FecGroup != 2 {
		t.Fatalf("热更后 fec_group 应为 2，实际 %d", resp.FecGroup)
	}
}
