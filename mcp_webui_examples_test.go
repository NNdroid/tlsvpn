package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMCPExamplesPanelEmbedded(t *testing.T) {
	h := webuiHandler()

	index := httptest.NewRecorder()
	h.ServeHTTP(index, httptest.NewRequest(http.MethodGet, "/", nil))
	if index.Code != http.StatusOK {
		t.Fatalf("GET / status=%d want=%d", index.Code, http.StatusOK)
	}
	if !strings.Contains(index.Body.String(), `<script src="mcp-examples.js"></script>`) {
		t.Fatal("dashboard does not load mcp-examples.js")
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/mcp-examples.js", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /mcp-examples.js status=%d want=%d", rr.Code, http.StatusOK)
	}
	body, err := io.ReadAll(rr.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)

	for _, want := range []string{
		"MCP configuration and connection examples",
		"MCP 配置与连接示例",
		"MCP 設定與連線範例",
		"MCP-Konfigurations- und Verbindungsbeispiele",
		"Exemples de configuration et de connexion MCP",
		"MCP 設定・接続例",
		"streamable-http",
		"/.well-known/oauth-protected-resource",
		"2025-06-18",
		"<MCP_BEARER_TOKEN>",
		"<MCP_API_KEY>",
		"<OAUTH_ACCESS_TOKEN>",
		"data-copy-target",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("mcp-examples.js missing %q", want)
		}
	}
}
