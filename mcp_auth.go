package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	mcpAuthInheritWeb = "inherit_web"
	mcpAuthNone       = "none"
	mcpAuthBasic      = "basic"
	mcpAuthBearer     = "bearer"
	mcpAuthAPIKey     = "api_key"
	mcpAuthOAuthJWT   = "oauth_jwt"

	mcpCredentialHashPrefix = "sha256:"
	mcpDefaultAPIKeyHeader   = "X-API-Key"
	mcpJWKSMaxBytes          = 1 << 20
	mcpJWKSCacheTTL          = 10 * time.Minute
)

var errMCPInsufficientScope = errors.New("mcp oauth token has insufficient scope")

// MCPConfig controls authentication for /mcp. It deliberately lives under
// web.mcp because MCP shares the Web listener/TLS/port but can use a different
// authentication policy from the dashboard itself.
type MCPConfig struct {
	// AuthMode: inherit_web | none | basic | bearer | api_key | oauth_jwt.
	// Empty is backward-compatible and means inherit_web.
	AuthMode string `json:"auth_mode,omitempty"`
	// Username is only used by basic mode. The password/token/key itself is kept
	// in Credential and normalized to a non-replayable sha256 verifier on load/save.
	Username string `json:"username,omitempty"`
	// Credential accepts plaintext when initially configured from the WebUI JSON
	// editor. applyDefaults converts it to sha256:<hex> before it is persisted.
	Credential string `json:"credential,omitempty"`
	// APIKeyHeader is only used by api_key mode and defaults to X-API-Key.
	APIKeyHeader string `json:"api_key_header,omitempty"`
	OAuth        MCPOAuthJWTConfig `json:"oauth,omitempty"`
}

// MCPOAuthJWTConfig makes TLSVPN an OAuth/OIDC resource server for MCP. Access
// tokens are self-contained JWTs verified against the issuer's public JWKS, so
// no OAuth client secret needs to be stored in TLSVPN.
type MCPOAuthJWTConfig struct {
	JWKSURL              string   `json:"jwks_url,omitempty"`
	Issuer               string   `json:"issuer,omitempty"`
	Audience             string   `json:"audience,omitempty"`
	Resource             string   `json:"resource,omitempty"`
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
	RequiredScopes       []string `json:"required_scopes,omitempty"`
}

func normalizeMCPAuthMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return mcpAuthInheritWeb
	}
	return mode
}

func normalizeMCPStaticCredential(value string) string {
	if value == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(value), mcpCredentialHashPrefix) {
		return mcpCredentialHashPrefix + strings.ToLower(strings.TrimSpace(value[len(mcpCredentialHashPrefix):]))
	}
	sum := sha256.Sum256([]byte(value))
	return mcpCredentialHashPrefix + hex.EncodeToString(sum[:])
}

func validMCPStaticCredentialHash(value string) bool {
	if !strings.HasPrefix(value, mcpCredentialHashPrefix) {
		return false
	}
	raw := strings.TrimPrefix(value, mcpCredentialHashPrefix)
	if len(raw) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(raw)
	return err == nil
}

func mcpCredentialMatches(got, stored string) bool {
	stored = normalizeMCPStaticCredential(stored)
	if !validMCPStaticCredentialHash(stored) {
		return false
	}
	want, err := hex.DecodeString(strings.TrimPrefix(stored, mcpCredentialHashPrefix))
	if err != nil || len(want) != sha256.Size {
		return false
	}
	gotHash := sha256.Sum256([]byte(got))
	return subtle.ConstantTimeCompare(gotHash[:], want) == 1
}

func validHTTPHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		}
		return false
	}
	return true
}

func (c *MCPConfig) applyDefaults() {
	c.AuthMode = normalizeMCPAuthMode(c.AuthMode)
	if c.APIKeyHeader == "" {
		c.APIKeyHeader = mcpDefaultAPIKeyHeader
	} else {
		c.APIKeyHeader = http.CanonicalHeaderKey(strings.TrimSpace(c.APIKeyHeader))
	}
	if c.Credential != "" {
		c.Credential = normalizeMCPStaticCredential(c.Credential)
	}
	c.OAuth.JWKSURL = strings.TrimSpace(c.OAuth.JWKSURL)
	c.OAuth.Issuer = strings.TrimRight(strings.TrimSpace(c.OAuth.Issuer), "/")
	c.OAuth.Audience = strings.TrimSpace(c.OAuth.Audience)
	c.OAuth.Resource = strings.TrimSpace(c.OAuth.Resource)
	for i := range c.OAuth.AuthorizationServers {
		c.OAuth.AuthorizationServers[i] = strings.TrimRight(strings.TrimSpace(c.OAuth.AuthorizationServers[i]), "/")
	}
	if len(c.OAuth.AuthorizationServers) == 0 && c.OAuth.Issuer != "" {
		c.OAuth.AuthorizationServers = []string{c.OAuth.Issuer}
	}
	for i := range c.OAuth.RequiredScopes {
		c.OAuth.RequiredScopes[i] = strings.TrimSpace(c.OAuth.RequiredScopes[i])
	}
}

func (c MCPConfig) Validate() error {
	mode := normalizeMCPAuthMode(c.AuthMode)
	switch mode {
	case mcpAuthInheritWeb, mcpAuthNone:
		return nil
	case mcpAuthBasic:
		if strings.TrimSpace(c.Username) == "" {
			return fmt.Errorf("web.mcp.username is required for basic authentication")
		}
		if !validMCPStaticCredentialHash(normalizeMCPStaticCredential(c.Credential)) {
			return fmt.Errorf("web.mcp.credential is required for basic authentication")
		}
	case mcpAuthBearer:
		if !validMCPStaticCredentialHash(normalizeMCPStaticCredential(c.Credential)) {
			return fmt.Errorf("web.mcp.credential is required for bearer authentication")
		}
	case mcpAuthAPIKey:
		if !validHTTPHeaderName(strings.TrimSpace(c.APIKeyHeader)) {
			return fmt.Errorf("invalid web.mcp.api_key_header %q", c.APIKeyHeader)
		}
		if strings.EqualFold(c.APIKeyHeader, "Authorization") || strings.EqualFold(c.APIKeyHeader, "Cookie") || strings.EqualFold(c.APIKeyHeader, "Host") || strings.EqualFold(c.APIKeyHeader, "Content-Length") {
			return fmt.Errorf("web.mcp.api_key_header %q is reserved; use a dedicated header such as X-API-Key", c.APIKeyHeader)
		}
		if !validMCPStaticCredentialHash(normalizeMCPStaticCredential(c.Credential)) {
			return fmt.Errorf("web.mcp.credential is required for API key authentication")
		}
	case mcpAuthOAuthJWT:
		if err := c.OAuth.Validate(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid web.mcp.auth_mode %q (want inherit_web, none, basic, bearer, api_key or oauth_jwt)", c.AuthMode)
	}
	return nil
}

func (c MCPOAuthJWTConfig) Validate() error {
	if c.JWKSURL == "" {
		return fmt.Errorf("web.mcp.oauth.jwks_url is required for oauth_jwt authentication")
	}
	if c.Issuer == "" {
		return fmt.Errorf("web.mcp.oauth.issuer is required for oauth_jwt authentication")
	}
	if c.Audience == "" {
		return fmt.Errorf("web.mcp.oauth.audience is required for oauth_jwt authentication")
	}
	if c.Resource == "" {
		return fmt.Errorf("web.mcp.oauth.resource is required for oauth_jwt authentication")
	}
	for name, raw := range map[string]string{
		"jwks_url": c.JWKSURL,
		"issuer":   c.Issuer,
		"resource": c.Resource,
	} {
		if err := validateMCPHTTPSURL(raw); err != nil {
			return fmt.Errorf("invalid web.mcp.oauth.%s: %w", name, err)
		}
	}
	servers := c.AuthorizationServers
	if len(servers) == 0 {
		servers = []string{c.Issuer}
	}
	for _, raw := range servers {
		if err := validateMCPHTTPSURL(raw); err != nil {
			return fmt.Errorf("invalid web.mcp.oauth.authorization_servers entry %q: %w", raw, err)
		}
	}
	seen := map[string]struct{}{}
	for _, scope := range c.RequiredScopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			return fmt.Errorf("web.mcp.oauth.required_scopes must not contain empty values")
		}
		if strings.ContainsAny(scope, " \t\r\n") {
			return fmt.Errorf("invalid OAuth scope %q", scope)
		}
		if _, ok := seen[scope]; ok {
			return fmt.Errorf("duplicate OAuth scope %q", scope)
		}
		seen[scope] = struct{}{}
	}
	return nil
}

func validateMCPHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Scheme == "" {
		return fmt.Errorf("must be an absolute URL")
	}
	if u.User != nil {
		return fmt.Errorf("URL userinfo is not allowed")
	}
	if u.Fragment != "" {
		return fmt.Errorf("URL fragments are not allowed")
	}
	if strings.EqualFold(u.Scheme, "https") {
		return nil
	}
	if !strings.EqualFold(u.Scheme, "http") {
		return fmt.Errorf("scheme must be https (http is allowed only for loopback testing)")
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("plain HTTP is only allowed for loopback addresses")
}

func isMCPMetadataPath(path string) bool {
	return path == "/.well-known/oauth-protected-resource" || path == "/.well-known/oauth-protected-resource/mcp"
}

func mcpBearerToken(r *http.Request) (string, bool) {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(value) < len("Bearer ") || !strings.EqualFold(value[:len("Bearer")], "Bearer") || value[len("Bearer")] != ' ' {
		return "", false
	}
	token := strings.TrimSpace(value[len("Bearer "):])
	return token, token != ""
}

func (w *WebManager) serveMCP(rw http.ResponseWriter, r *http.Request) {
	cfg := w.Config()
	mode := normalizeMCPAuthMode(cfg.Web.MCP.AuthMode)
	var authErr error

	switch mode {
	case mcpAuthNone:
		// Explicitly unauthenticated MCP. The dashboard remains independently
		// protected by web.auth.
	case mcpAuthInheritWeb:
		expected := cfg.Web.Auth
		if expected != "" && !dashboardSessions.valid(dashboardSessionToken(r), expected) && !mcpBasicAuthValid(r, expected) {
			authErr = errors.New("invalid inherited Web credential")
		}
	case mcpAuthBasic:
		user, pass, ok := r.BasicAuth()
		if !ok || !constantTimeCredentialEqual(user, cfg.Web.MCP.Username) || !mcpCredentialMatches(pass, cfg.Web.MCP.Credential) {
			authErr = errors.New("invalid MCP basic credential")
		}
	case mcpAuthBearer:
		token, ok := mcpBearerToken(r)
		if !ok || !mcpCredentialMatches(token, cfg.Web.MCP.Credential) {
			authErr = errors.New("invalid MCP bearer token")
		}
	case mcpAuthAPIKey:
		header := cfg.Web.MCP.APIKeyHeader
		if header == "" {
			header = mcpDefaultAPIKeyHeader
		}
		if !mcpCredentialMatches(r.Header.Get(header), cfg.Web.MCP.Credential) {
			authErr = errors.New("invalid MCP API key")
		}
	case mcpAuthOAuthJWT:
		token, ok := mcpBearerToken(r)
		if !ok {
			authErr = fmt.Errorf("%w: bearer token is required", jwt.ErrTokenMalformed)
		} else {
			authErr = verifyMCPOAuthJWT(r.Context(), token, cfg.Web.MCP.OAuth)
		}
	default:
		authErr = fmt.Errorf("unsupported MCP authentication mode %q", mode)
	}

	if authErr != nil {
		w.writeMCPAuthError(rw, r, mode, authErr)
		return
	}
	if w.mcp == nil {
		http.NotFound(rw, r)
		return
	}
	w.mcp.ServeHTTP(rw, r)
}

func (w *WebManager) writeMCPAuthError(rw http.ResponseWriter, r *http.Request, mode string, authErr error) {
	status := http.StatusUnauthorized
	rw.Header().Set("Content-Type", "application/json")
	rw.Header().Set("Cache-Control", "no-store")

	switch mode {
	case mcpAuthInheritWeb, mcpAuthBasic:
		rw.Header().Set("WWW-Authenticate", `Basic realm="tlsvpn-mcp", charset="UTF-8"`)
	case mcpAuthBearer:
		rw.Header().Set("WWW-Authenticate", `Bearer realm="tlsvpn-mcp"`)
	case mcpAuthAPIKey:
		header := w.Config().Web.MCP.APIKeyHeader
		if header == "" {
			header = mcpDefaultAPIKeyHeader
		}
		rw.Header().Set("WWW-Authenticate", fmt.Sprintf(`ApiKey realm="tlsvpn-mcp", header=%q`, header))
	case mcpAuthOAuthJWT:
		scope := strings.Join(w.Config().Web.MCP.OAuth.RequiredScopes, " ")
		challenge := fmt.Sprintf(`Bearer resource_metadata=%q`, mcpMetadataURL(r))
		if errors.Is(authErr, errMCPInsufficientScope) {
			status = http.StatusForbidden
			challenge += `, error="insufficient_scope"`
		}
		if scope != "" {
			challenge += fmt.Sprintf(`, scope=%q`, scope)
		}
		rw.Header().Set("WWW-Authenticate", challenge)
	}

	rw.WriteHeader(status)
	if status == http.StatusForbidden {
		_, _ = rw.Write([]byte(`{"error":"insufficient_scope"}`))
	} else {
		_, _ = rw.Write([]byte(`{"error":"unauthorized"}`))
	}
}

func mcpRequestOrigin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func mcpMetadataURL(r *http.Request) string {
	return mcpRequestOrigin(r) + "/.well-known/oauth-protected-resource"
}

func (w *WebManager) serveMCPMetadata(rw http.ResponseWriter, r *http.Request) {
	cfg := w.Config().Web.MCP
	if normalizeMCPAuthMode(cfg.AuthMode) != mcpAuthOAuthJWT {
		http.NotFound(rw, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
		rw.Header().Set("Allow", "GET, HEAD, OPTIONS")
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rw.Header().Set("Access-Control-Allow-Origin", "*")
	rw.Header().Set("Cache-Control", "public, max-age=300")
	if r.Method == http.MethodOptions {
		rw.WriteHeader(http.StatusNoContent)
		return
	}
	servers := append([]string(nil), cfg.OAuth.AuthorizationServers...)
	if len(servers) == 0 && cfg.OAuth.Issuer != "" {
		servers = []string{cfg.OAuth.Issuer}
	}
	metadata := struct {
		Resource               string   `json:"resource"`
		AuthorizationServers   []string `json:"authorization_servers"`
		ScopesSupported        []string `json:"scopes_supported,omitempty"`
		BearerMethodsSupported []string `json:"bearer_methods_supported"`
	}{
		Resource:               cfg.OAuth.Resource,
		AuthorizationServers:   servers,
		ScopesSupported:        cfg.OAuth.RequiredScopes,
		BearerMethodsSupported: []string{"header"},
	}
	rw.Header().Set("Content-Type", "application/json")
	if r.Method == http.MethodHead {
		return
	}
	_ = json.NewEncoder(rw).Encode(metadata)
}

type mcpJWK struct {
	KTY string `json:"kty"`
	KID string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

type mcpJWKS struct {
	Keys []mcpJWK `json:"keys"`
}

type mcpJWKSCacheEntry struct {
	keys      map[string]any
	anonymous []any
	expires   time.Time
}

var mcpJWKSCache = struct {
	sync.Mutex
	entries map[string]mcpJWKSCacheEntry
}{entries: make(map[string]mcpJWKSCacheEntry)}

func fetchMCPJWKS(ctx context.Context, rawURL string, force bool) (mcpJWKSCacheEntry, error) {
	now := time.Now()
	mcpJWKSCache.Lock()
	if !force {
		if entry, ok := mcpJWKSCache.entries[rawURL]; ok && now.Before(entry.expires) {
			mcpJWKSCache.Unlock()
			return entry, nil
		}
	}
	mcpJWKSCache.Unlock()

	if err := validateMCPHTTPSURL(rawURL); err != nil {
		return mcpJWKSCacheEntry{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return mcpJWKSCacheEntry{}, err
	}
	req.Header.Set("Accept", "application/json")
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many JWKS redirects")
			}
			return validateMCPHTTPSURL(req.URL.String())
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return mcpJWKSCacheEntry{}, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return mcpJWKSCacheEntry{}, fmt.Errorf("fetch JWKS: HTTP %d", resp.StatusCode)
	}
	var set mcpJWKS
	dec := json.NewDecoder(io.LimitReader(resp.Body, mcpJWKSMaxBytes+1))
	if err := dec.Decode(&set); err != nil {
		return mcpJWKSCacheEntry{}, fmt.Errorf("decode JWKS: %w", err)
	}
	if len(set.Keys) == 0 {
		return mcpJWKSCacheEntry{}, fmt.Errorf("JWKS contains no keys")
	}
	entry := mcpJWKSCacheEntry{keys: make(map[string]any), expires: now.Add(mcpJWKSCacheTTL)}
	for _, jwk := range set.Keys {
		if jwk.Use != "" && jwk.Use != "sig" {
			continue
		}
		key, err := parseMCPJWK(jwk)
		if err != nil {
			continue
		}
		if jwk.KID == "" {
			entry.anonymous = append(entry.anonymous, key)
			continue
		}
		entry.keys[jwk.KID] = key
	}
	if len(entry.keys) == 0 && len(entry.anonymous) == 0 {
		return mcpJWKSCacheEntry{}, fmt.Errorf("JWKS contains no supported signature keys")
	}
	mcpJWKSCache.Lock()
	mcpJWKSCache.entries[rawURL] = entry
	mcpJWKSCache.Unlock()
	return entry, nil
}

func decodeMCPBase64URL(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(value)
}

func parseMCPJWK(jwk mcpJWK) (any, error) {
	switch jwk.KTY {
	case "RSA":
		nBytes, err := decodeMCPBase64URL(jwk.N)
		if err != nil || len(nBytes) == 0 {
			return nil, fmt.Errorf("invalid RSA modulus")
		}
		eBytes, err := decodeMCPBase64URL(jwk.E)
		if err != nil || len(eBytes) == 0 || len(eBytes) > 4 {
			return nil, fmt.Errorf("invalid RSA exponent")
		}
		e := 0
		for _, b := range eBytes {
			e = (e << 8) | int(b)
		}
		if e < 3 {
			return nil, fmt.Errorf("invalid RSA exponent")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
	case "EC":
		var curve elliptic.Curve
		switch jwk.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", jwk.Crv)
		}
		xb, errX := decodeMCPBase64URL(jwk.X)
		yb, errY := decodeMCPBase64URL(jwk.Y)
		if errX != nil || errY != nil || len(xb) == 0 || len(yb) == 0 {
			return nil, fmt.Errorf("invalid EC coordinates")
		}
		x, y := new(big.Int).SetBytes(xb), new(big.Int).SetBytes(yb)
		if !curve.IsOnCurve(x, y) {
			return nil, fmt.Errorf("EC point is not on curve")
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	case "OKP":
		if jwk.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve %q", jwk.Crv)
		}
		x, err := decodeMCPBase64URL(jwk.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 public key")
		}
		return ed25519.PublicKey(x), nil
	default:
		return nil, fmt.Errorf("unsupported JWK kty %q", jwk.KTY)
	}
}

func mcpJWTKeyCompatible(alg string, key any) bool {
	switch key.(type) {
	case *rsa.PublicKey:
		return strings.HasPrefix(alg, "RS") || strings.HasPrefix(alg, "PS")
	case *ecdsa.PublicKey:
		return strings.HasPrefix(alg, "ES")
	case ed25519.PublicKey:
		return alg == "EdDSA"
	default:
		return false
	}
}

func selectMCPJWTKey(ctx context.Context, token *jwt.Token, jwksURL string) (any, error) {
	kid, _ := token.Header["kid"].(string)
	selectKey := func(entry mcpJWKSCacheEntry) (any, bool) {
		if kid != "" {
			key, ok := entry.keys[kid]
			return key, ok
		}
		if len(entry.keys)+len(entry.anonymous) != 1 {
			return nil, false
		}
		for _, key := range entry.keys {
			return key, true
		}
		return entry.anonymous[0], true
	}

	entry, err := fetchMCPJWKS(ctx, jwksURL, false)
	if err != nil {
		return nil, err
	}
	key, ok := selectKey(entry)
	if !ok && kid != "" {
		entry, err = fetchMCPJWKS(ctx, jwksURL, true)
		if err != nil {
			return nil, err
		}
		key, ok = selectKey(entry)
	}
	if !ok {
		if kid == "" {
			return nil, fmt.Errorf("JWT has no kid and JWKS does not contain exactly one usable key")
		}
		return nil, fmt.Errorf("JWT kid %q not found in JWKS", kid)
	}
	if !mcpJWTKeyCompatible(token.Method.Alg(), key) {
		return nil, fmt.Errorf("JWT alg %q is incompatible with selected JWK", token.Method.Alg())
	}
	return key, nil
}

func verifyMCPOAuthJWT(ctx context.Context, tokenString string, cfg MCPOAuthJWTConfig) error {
	claims := jwt.MapClaims{}
	options := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}),
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(cfg.Issuer),
		jwt.WithAudience(cfg.Audience),
		jwt.WithLeeway(30 * time.Second),
	}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		return selectMCPJWTKey(ctx, token, cfg.JWKSURL)
	}, options...)
	if err != nil {
		return err
	}
	if !token.Valid {
		return errors.New("invalid OAuth JWT")
	}
	if len(cfg.RequiredScopes) == 0 {
		return nil
	}
	granted := extractMCPJWTScopes(claims)
	for _, required := range cfg.RequiredScopes {
		if _, ok := granted[required]; !ok {
			return fmt.Errorf("%w: missing %q", errMCPInsufficientScope, required)
		}
	}
	return nil
}

func extractMCPJWTScopes(claims jwt.MapClaims) map[string]struct{} {
	out := make(map[string]struct{})
	add := func(scope string) {
		for _, part := range strings.Fields(scope) {
			out[part] = struct{}{}
		}
	}
	for _, name := range []string{"scope", "scp"} {
		switch value := claims[name].(type) {
		case string:
			add(value)
		case []string:
			for _, scope := range value {
				add(scope)
			}
		case []any:
			for _, raw := range value {
				if scope, ok := raw.(string); ok {
					add(scope)
				}
			}
		}
	}
	return out
}

// mcpRSAJWK is shared with tests and intentionally small: it emits the public
// fields required by RFC 7517 for an RSA signing key.
func mcpRSAJWK(key *rsa.PublicKey, kid string) map[string]string {
	e := key.E
	var exponent []byte
	for e > 0 {
		exponent = append([]byte{byte(e)}, exponent...)
		e >>= 8
	}
	return map[string]string{
		"kty": "RSA",
		"kid": kid,
		"use": "sig",
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(exponent),
	}
}

func parseMCPPort(raw string) int {
	_, port, err := net.SplitHostPort(raw)
	if err != nil {
		return 0
	}
	p, _ := strconv.Atoi(port)
	return p
}
