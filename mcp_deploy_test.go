package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMCPDeployDefaultsAndPathGeneration(t *testing.T) {
	cfg := &Config{Web: WebConfig{MCP: MCPConfig{}}}
	cfg.applyDefaults()
	m := cfg.Web.MCP
	if m.Deploy != mcpDeployInternal {
		t.Fatalf("deploy=%q, want %q", m.Deploy, mcpDeployInternal)
	}
	if m.Path == "" || m.Path[0] != '/' || len(m.Path) != 21 {
		t.Fatalf("path=%q, want /<20 hex>", m.Path)
	}
	for _, c := range m.Path[1:] {
		if !isHexDigit(byte(c)) {
			t.Fatalf("path=%q contains non-hex char", m.Path)
		}
	}
	// 幂等：已生成不再改变
	before := m.Path
	cfg.applyDefaults()
	if cfg.Web.MCP.Path != before {
		t.Fatalf("path changed on second applyDefaults: %q -> %q", before, cfg.Web.MCP.Path)
	}
	// 两次实例生成不同（80 bit 熵，碰撞概率可忽略）
	other := &Config{Web: WebConfig{MCP: MCPConfig{}}}
	other.applyDefaults()
	if other.Web.MCP.Path == before {
		t.Fatalf("two generated paths collided: %q", before)
	}
}

func TestMCPPathValidation(t *testing.T) {
	for _, bad := range []string{"", "mcp", "//x", "/a//b", "/", "/a b", "/a\tb", "/a\nb", "/" + strings.Repeat("a", 128)} {
		if validMCPPath(bad) {
			t.Fatalf("validMCPPath(%q)=true, want false", bad)
		}
	}
	for _, good := range []string{"/a", "/a1b2c3", "/" + strings.Repeat("a", 127)} {
		if !validMCPPath(good) {
			t.Fatalf("validMCPPath(%q)=false, want true", good)
		}
	}
}

func TestMCPDeployAndPathValidation(t *testing.T) {
	if err := (MCPConfig{Deploy: "lan", Path: "/mcp"}).Validate(); err == nil {
		t.Fatal("invalid deploy must be rejected")
	}
	if err := (MCPConfig{Deploy: mcpDeployInternal}).Validate(); err == nil {
		t.Fatal("empty path must be rejected in Validate")
	}
	if err := (MCPConfig{Deploy: mcpDeployBoth, Path: "/abc123"}).Validate(); err != nil {
		t.Fatalf("valid both config rejected: %v", err)
	}
	if err := (MCPConfig{Deploy: mcpDeployInternal, Path: "/custom"}).Validate(); err != nil {
		t.Fatalf("valid internal custom path rejected: %v", err)
	}
}

func TestMCPPathMatchingAndDeployFaces(t *testing.T) {
	m := MCPConfig{Deploy: mcpDeployBoth, Path: "/secret"}
	if !m.matchesPath("/secret") || !m.matchesPath("/secret/") {
		t.Fatal("must match exact path and trailing slash")
	}
	if m.matchesPath("/secret2") || m.matchesPath("/mcp") || m.matchesPath("") {
		t.Fatal("must not match other paths, /mcp, or empty")
	}
	empty := MCPConfig{Deploy: mcpDeployInternal}
	if empty.matchesPath("/mcp") || empty.matchesPath("") {
		t.Fatal("empty path must not match anything, including /mcp")
	}
	if !m.deployAllowsPublic() || !m.deployAllowsInternal() {
		t.Fatal("both must allow both faces")
	}
	if !(MCPConfig{Deploy: mcpDeployPublic}.deployAllowsPublic()) || (MCPConfig{Deploy: mcpDeployPublic}.deployAllowsInternal()) {
		t.Fatal("public must allow public only")
	}
	if (MCPConfig{Deploy: mcpDeployInternal}.deployAllowsPublic()) || !(MCPConfig{Deploy: mcpDeployInternal}.deployAllowsInternal()) {
		t.Fatal("internal must allow internal only")
	}
}

func TestPublicMCPDispatcherRouting(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"tlsvpn-public-test","version":"1"}}}`

	run := func(deploy, path, reqPath string) (*httptest.ResponseRecorder, bool) {
		cfg := &Config{Web: WebConfig{MCP: MCPConfig{Deploy: deploy, Path: path, AuthMode: mcpAuthNone}}}
		mgr := NewWebManager(nil, nil, cfg, http.NewServeMux())
		d := &publicMCPDispatcher{w: mgr}
		req := httptest.NewRequest(http.MethodPost, "http://vpn.example"+reqPath, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		rr := httptest.NewRecorder()
		handled := d.serveMCPIfMatch(rr, req)
		return rr, handled
	}

	// both + 命中 path → MCP initialize 可达且被接管
	rr, handled := run(mcpDeployBoth, "/secret", "/secret")
	if !handled || rr.Code != http.StatusOK {
		t.Fatalf("both hit path handled=%v status=%d", handled, rr.Code)
	}
	// both + 不命中 → 未接管（403 诱饵由调用方维持）
	_, handled = run(mcpDeployBoth, "/secret", "/other")
	if handled {
		t.Fatal("both miss path must not dispatch")
	}
	// internal → 永不接管（公网面全 403）
	_, handled = run(mcpDeployInternal, "/secret", "/secret")
	if handled {
		t.Fatal("internal must not dispatch public MCP")
	}
	// public + 命中 → 接管
	_, handled = run(mcpDeployPublic, "/secret", "/secret")
	if !handled {
		t.Fatal("public hit path must dispatch")
	}
}

func TestMCPAccessRingAndMethodParsing(t *testing.T) {
	ring := newMCPAccessRing(3)
	ring.add(mcpAccessLine{Remote: "10.0.0.5", Method: "tools/call", Tool: "tlsvpn_status", Status: 200})
	ring.add(mcpAccessLine{Remote: "10.0.0.6", Method: "auth", Status: 401, Msg: "invalid token"})
	snap := ring.snapshot(0)
	if len(snap) != 2 || snap[0].Seq != 1 || snap[1].Seq != 2 {
		t.Fatalf("snapshot=%+v", snap)
	}
	if snap[0].Remote != "10.0.0.5" || snap[0].Tool != "tlsvpn_status" {
		t.Fatalf("unexpected line: %+v", snap[0])
	}
	// 增量续传
	inc := ring.snapshot(1)
	if len(inc) != 1 || inc[0].Seq != 2 {
		t.Fatalf("incremental snapshot=%+v", inc)
	}
	// 容量满丢最旧
	ring.add(mcpAccessLine{Method: "initialize"})
	ring.add(mcpAccessLine{Method: "tools/list"})
	got := ring.snapshot(0)
	if len(got) != 3 || got[0].Seq != 2 {
		t.Fatalf("capacity eviction got=%+v", got)
	}

	// mcpRequestMethod 解析 JSON-RPC 并恢复 Body
	req := httptest.NewRequest(http.MethodPost, "http://x/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"tlsvpn_status"}}`))
	method, tool := mcpRequestMethod(req)
	if method != "tools/call" || tool != "tlsvpn_status" {
		t.Fatalf("mcpRequestMethod=(%q,%q)", method, tool)
	}
	body, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(body), "tools/call") {
		t.Fatal("mcpRequestMethod did not restore request body")
	}
	// 非 tools/call 不设 tool
	req2 := httptest.NewRequest(http.MethodPost, "http://x/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	method, tool = mcpRequestMethod(req2)
	if method != "initialize" || tool != "" {
		t.Fatalf("mcpRequestMethod=(%q,%q), want (initialize,)", method, tool)
	}
}
