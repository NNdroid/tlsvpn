package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const mcpInitializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"tlsvpn-auth-test","version":"1"}}}`

func runMCPRequest(t *testing.T, mgr *WebManager, configure func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	h := mgr.auth(func(http.ResponseWriter, *http.Request) {
		t.Fatal("/mcp must not fall through to the dashboard handler")
	})
	req := httptest.NewRequest(http.MethodPost, "http://tlsvpn.local/mcp", strings.NewReader(mcpInitializeBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if configure != nil {
		configure(req)
	}
	rr := httptest.NewRecorder()
	h(rr, req)
	return rr
}

func TestMCPStaticCredentialVerifier(t *testing.T) {
	const secret = "mcp-super-secret-value"
	stored := normalizeMCPStaticCredential(secret)
	if !strings.HasPrefix(stored, mcpCredentialHashPrefix) {
		t.Fatalf("credential=%q, want sha256 verifier", stored)
	}
	if strings.Contains(stored, secret) {
		t.Fatal("stored verifier contains plaintext secret")
	}
	if normalizeMCPStaticCredential(stored) != stored {
		t.Fatal("credential normalization must be idempotent")
	}
	if !mcpCredentialMatches(secret, stored) {
		t.Fatal("correct plaintext did not match verifier")
	}
	if mcpCredentialMatches(secret+"x", stored) {
		t.Fatal("incorrect plaintext matched verifier")
	}
}

func TestMCPAuthDefaultsAndConfigPersistence(t *testing.T) {
	cfg := &Config{Web: WebConfig{MCP: MCPConfig{Credential: "do-not-persist-me"}}}
	cfg.applyDefaults()
	if cfg.Web.MCP.AuthMode != mcpAuthInheritWeb {
		t.Fatalf("auth_mode=%q, want %q", cfg.Web.MCP.AuthMode, mcpAuthInheritWeb)
	}
	if cfg.Web.MCP.APIKeyHeader != mcpDefaultAPIKeyHeader {
		t.Fatalf("api_key_header=%q, want %q", cfg.Web.MCP.APIKeyHeader, mcpDefaultAPIKeyHeader)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "do-not-persist-me") {
		t.Fatal("serialized config leaked plaintext MCP credential")
	}
	if !strings.Contains(string(data), mcpCredentialHashPrefix) {
		t.Fatal("serialized config is missing MCP credential verifier")
	}
}

func TestMCPBasicBearerAPIKeyAndNoneAuth(t *testing.T) {
	tests := []struct {
		name      string
		mcp       MCPConfig
		configure func(*http.Request)
	}{
		{
			name: "basic",
			mcp: MCPConfig{AuthMode: mcpAuthBasic, Username: "agent", Credential: normalizeMCPStaticCredential("basic-secret")},
			configure: func(r *http.Request) { r.SetBasicAuth("agent", "basic-secret") },
		},
		{
			name: "bearer",
			mcp: MCPConfig{AuthMode: mcpAuthBearer, Credential: normalizeMCPStaticCredential("bearer-secret")},
			configure: func(r *http.Request) { r.Header.Set("Authorization", "Bearer bearer-secret") },
		},
		{
			name: "api-key",
			mcp: MCPConfig{AuthMode: mcpAuthAPIKey, APIKeyHeader: "X-TLSVPN-Key", Credential: normalizeMCPStaticCredential("api-secret")},
			configure: func(r *http.Request) { r.Header.Set("X-TLSVPN-Key", "api-secret") },
		},
		{
			name: "none",
			mcp: MCPConfig{AuthMode: mcpAuthNone},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Web: WebConfig{Auth: "dashboard:secret", MCP: tc.mcp}}
			mgr := NewWebManager(nil, nil, cfg, http.NewServeMux())
			unauthorized := runMCPRequest(t, mgr, nil)
			if tc.name == "none" {
				if unauthorized.Code != http.StatusOK {
					t.Fatalf("none auth status=%d body=%s", unauthorized.Code, unauthorized.Body.String())
				}
				return
			}
			if unauthorized.Code != http.StatusUnauthorized {
				t.Fatalf("unauthenticated status=%d, want 401; body=%s", unauthorized.Code, unauthorized.Body.String())
			}
			authorized := runMCPRequest(t, mgr, tc.configure)
			if authorized.Code != http.StatusOK {
				t.Fatalf("authenticated status=%d, want 200; body=%s", authorized.Code, authorized.Body.String())
			}
		})
	}
}

func TestMCPAuthHotReloadWithoutListenerRestart(t *testing.T) {
	cfg := &Config{Web: WebConfig{Auth: "web-user:web-pass", MCP: MCPConfig{AuthMode: mcpAuthInheritWeb}}}
	mgr := NewWebManager(nil, nil, cfg, http.NewServeMux())

	first := runMCPRequest(t, mgr, func(r *http.Request) { r.SetBasicAuth("web-user", "web-pass") })
	if first.Code != http.StatusOK {
		t.Fatalf("inherited auth status=%d body=%s", first.Code, first.Body.String())
	}

	updated := &Config{Web: WebConfig{
		Auth: "web-user:web-pass",
		MCP: MCPConfig{AuthMode: mcpAuthBearer, Credential: normalizeMCPStaticCredential("rotated-token")},
	}}
	mgr.SetConfig(updated)

	oldCredential := runMCPRequest(t, mgr, func(r *http.Request) { r.SetBasicAuth("web-user", "web-pass") })
	if oldCredential.Code != http.StatusUnauthorized {
		t.Fatalf("old auth remained active after hot reload: status=%d", oldCredential.Code)
	}
	newCredential := runMCPRequest(t, mgr, func(r *http.Request) { r.Header.Set("Authorization", "Bearer rotated-token") })
	if newCredential.Code != http.StatusOK {
		t.Fatalf("new bearer auth status=%d body=%s", newCredential.Code, newCredential.Body.String())
	}
}

func TestMCPAuthValidation(t *testing.T) {
	badHeader := MCPConfig{AuthMode: mcpAuthAPIKey, APIKeyHeader: "Authorization", Credential: normalizeMCPStaticCredential("key")}
	if err := badHeader.Validate(); err == nil {
		t.Fatal("reserved API key header must be rejected")
	}
	badOAuth := MCPConfig{AuthMode: mcpAuthOAuthJWT, OAuth: MCPOAuthJWTConfig{
		JWKSURL: "http://example.com/jwks", Issuer: "https://issuer.example", Audience: "tlsvpn", Resource: "https://vpn.example/mcp",
	}}
	if err := badOAuth.Validate(); err == nil {
		t.Fatal("non-loopback HTTP JWKS URL must be rejected")
	}
}

func TestMCPOAuthJWTAndProtectedResourceMetadata(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "tlsvpn-test-key"
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{mcpRSAJWK(&privateKey.PublicKey, kid)}})
	}))
	defer jwks.Close()

	issuer := jwks.URL
	audience := "tlsvpn-mcp-test"
	resource := jwks.URL + "/mcp"
	cfg := &Config{Web: WebConfig{
		Auth: "dashboard:secret",
		MCP: MCPConfig{AuthMode: mcpAuthOAuthJWT, OAuth: MCPOAuthJWTConfig{
			JWKSURL: jwks.URL + "/jwks",
			Issuer: issuer,
			Audience: audience,
			Resource: resource,
			AuthorizationServers: []string{issuer},
			RequiredScopes: []string{"mcp:read"},
		}},
	}}
	if err := cfg.Web.MCP.Validate(); err != nil {
		t.Fatalf("valid OAuth configuration rejected: %v", err)
	}
	mgr := NewWebManager(nil, nil, cfg, http.NewServeMux())

	makeToken := func(scope string) string {
		t.Helper()
		claims := jwt.MapClaims{
			"iss": issuer,
			"aud": audience,
			"exp": time.Now().Add(5 * time.Minute).Unix(),
			"iat": time.Now().Add(-time.Second).Unix(),
			"scope": scope,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = kid
		signed, err := token.SignedString(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}

	good := runMCPRequest(t, mgr, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+makeToken("mcp:read other"))
	})
	if good.Code != http.StatusOK {
		t.Fatalf("OAuth-authenticated MCP status=%d body=%s", good.Code, good.Body.String())
	}

	missingScope := runMCPRequest(t, mgr, func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+makeToken("other"))
	})
	if missingScope.Code != http.StatusForbidden {
		t.Fatalf("missing-scope status=%d, want 403; body=%s", missingScope.Code, missingScope.Body.String())
	}
	if got := missingScope.Header().Get("WWW-Authenticate"); !strings.Contains(got, "insufficient_scope") || !strings.Contains(got, "resource_metadata") {
		t.Fatalf("OAuth challenge=%q", got)
	}

	h := mgr.auth(func(http.ResponseWriter, *http.Request) { t.Fatal("metadata must not fall through") })
	metadataReq := httptest.NewRequest(http.MethodGet, "http://tlsvpn.local/.well-known/oauth-protected-resource", nil)
	metadataRR := httptest.NewRecorder()
	h(metadataRR, metadataReq)
	if metadataRR.Code != http.StatusOK {
		t.Fatalf("metadata status=%d body=%s", metadataRR.Code, metadataRR.Body.String())
	}
	if metadataRR.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal("OAuth resource metadata must be cross-origin discoverable")
	}
	var metadata struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
		Scopes               []string `json:"scopes_supported"`
	}
	if err := json.Unmarshal(metadataRR.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Resource != resource || len(metadata.AuthorizationServers) != 1 || metadata.AuthorizationServers[0] != issuer || len(metadata.Scopes) != 1 || metadata.Scopes[0] != "mcp:read" {
		t.Fatalf("unexpected protected resource metadata: %+v", metadata)
	}
}
