package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebMCPUsesWebAuthOnSameHandler(t *testing.T) {
	cfg := &Config{Web: WebConfig{Auth: "mcp-user:mcp-pass"}}
	mgr := NewWebManager(nil, nil, cfg, http.NewServeMux())
	h := mgr.auth(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("/mcp must be handled by MCP, not fall through to WebUI handler")
	})

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"tlsvpn-test","version":"1"}}}`

	unauthorized := httptest.NewRequest(http.MethodPost, "http://tlsvpn.local/mcp", strings.NewReader(body))
	unauthorized.Header.Set("Content-Type", "application/json")
	unauthorized.Header.Set("Accept", "application/json, text/event-stream")
	unauthorizedRR := httptest.NewRecorder()
	h(unauthorizedRR, unauthorized)
	if unauthorizedRR.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /mcp status=%d, want %d; body=%s", unauthorizedRR.Code, http.StatusUnauthorized, unauthorizedRR.Body.String())
	}
	if got := unauthorizedRR.Header().Get("WWW-Authenticate"); !strings.Contains(got, "tlsvpn-mcp") {
		t.Fatalf("WWW-Authenticate=%q, want tlsvpn-mcp realm", got)
	}

	authorized := httptest.NewRequest(http.MethodPost, "http://tlsvpn.local/mcp", strings.NewReader(body))
	authorized.Header.Set("Content-Type", "application/json")
	authorized.Header.Set("Accept", "application/json, text/event-stream")
	authorized.SetBasicAuth("mcp-user", "mcp-pass")
	authorizedRR := httptest.NewRecorder()
	h(authorizedRR, authorized)
	if authorizedRR.Code != http.StatusOK {
		t.Fatalf("authenticated /mcp status=%d, want 200; body=%s", authorizedRR.Code, authorizedRR.Body.String())
	}
	var response struct {
		Result struct {
			ServerInfo struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.Unmarshal(authorizedRR.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode initialize response: %v; body=%s", err, authorizedRR.Body.String())
	}
	if response.Result.ServerInfo.Name != "tlsvpn" {
		t.Fatalf("serverInfo.name=%q, want tlsvpn", response.Result.ServerInfo.Name)
	}
}

func TestMCPConfigRedactionKeepsOriginalSecrets(t *testing.T) {
	cfg := &Config{
		PSK:    "secret-psk",
		Socks5: "user:pass@127.0.0.1:1080",
		Web:    WebConfig{Auth: "admin:secret"},
	}
	got := mcpRedactedConfig(cfg)
	if got.PSK != "" || got.Socks5 != "" || got.Web.Auth != "" {
		t.Fatalf("MCP config must redact secrets: %+v", got)
	}
	if cfg.PSK != "secret-psk" || cfg.Socks5 == "" || cfg.Web.Auth != "admin:secret" {
		t.Fatal("redaction mutated live config")
	}
}

func TestMCPRangeAndLimitValidation(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"", "1h"},
		{"2m", "2m"},
		{"1H", "1h"},
		{"24h", "24h"},
	} {
		got, err := mcpRange(tc.in)
		if err != nil || got != tc.want {
			t.Fatalf("mcpRange(%q)=(%q,%v), want (%q,nil)", tc.in, got, err, tc.want)
		}
	}
	if _, err := mcpRange("7d"); err == nil {
		t.Fatal("unsupported MCP range must fail")
	}
	if got, err := mcpLimit(0); err != nil || got != 200 {
		t.Fatalf("mcpLimit(0)=(%d,%v), want (200,nil)", got, err)
	}
	if _, err := mcpLimit(1001); err == nil {
		t.Fatal("MCP limit above cap must fail")
	}
}
