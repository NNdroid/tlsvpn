# TLSVPN MCP server

The Go implementation exposes a Model Context Protocol (MCP) server through the **same HTTP server, listener, TLS configuration, bind policy, and port as the WebUI**.

If the WebUI is available at:

```text
https://10.0.0.1:8080/
```

then MCP is available at:

```text
https://10.0.0.1:8080/<web.mcp.path>
```

The endpoint path is not fixed to `/mcp`: it is configured under `web.mcp.path` and is generated randomly on first load (see [Deployment scope and path](#deployment-scope-and-path)). It is shared by the internal and public faces.

No second listener or MCP-specific port is opened.

## Transport

TLSVPN uses the official Go MCP SDK and Streamable HTTP transport.

- Endpoint: `/web.mcp.path` (random on first load, not `/mcp`)
- Transport: Streamable HTTP
- Server mode: stateless
- Response mode: JSON for request/response operations
- Maximum request body: 1 MiB
- HTTP request cancellation is propagated for protocol revisions that support it
- Both TLSVPN server mode and client mode expose MCP when `web.addr` enables the Web service

## Deployment scope and path

`web.mcp.deploy` selects which listener serves MCP. The internal face is the WebUI listener (`web.addr` + `web.cert`/`web.key`, optionally bound to the tunnel gateway IP with `web.bind: "tunnel"`). The public face is the VPN listener (`server.addr` + `server.cert`/`server.key`): its TLS post-handshake dispatch (currently a 403 nginx decoy) is extended to serve MCP **only** when the request path matches `web.mcp.path`, while every other path keeps the 403 decoy.

| `web.mcp.deploy` | Internal WebUI listener | Public VPN listener |
|---|---|---|
| `internal` (default) | MCP served | always 403 decoy |
| `public` | MCP not served (404 / normal Web handling) | MCP served on `path` |
| `both` | MCP served | MCP served on `path` |

### The path is part of the secret

`web.mcp.path` is a single path segment shared by both faces (for example `/a1b2c3d4e5f6a7b8c9d0`). It is **not** a well-known value:

- An empty `path` generates a random `/` + 20 hex characters (80 bits) on configuration load. It never falls back to `/mcp`.
- Treat the path as part of the endpoint secret. An attacker who learns it can at least probe the endpoint and attempt credential attacks, so rotate it immediately if it leaks (WebUI → Settings → MCP → *Randomize*, or set a fresh value and **Save & apply**).
- Validation rejects paths that do not start with `/`, contain `//`, are empty, exceed 128 characters, or contain whitespace/control characters.

The default `deploy` is `internal`: MCP is not exposed on the public VPN listener unless you explicitly choose `public` or `both`. The public face serves MCP only on the exact `path` (plus an optional trailing `/`); every other path on the VPN port continues to receive the 403 decoy, so the endpoint is not discoverable by scanning.

### OAuth metadata on the public face

When `web.mcp.auth_mode` is `oauth_jwt` and `deploy` is `public` or `both`, the OAuth Protected Resource Metadata endpoint (`/.well-known/oauth-protected-resource`) is also served on the public VPN listener, because OAuth discovery must be reachable at the resource server. The configured `web.mcp.oauth.resource` URL should point at the MCP endpoint (with the configured `path`).

### Warning: public deployment

`deploy: "public"` or `"both"` combined with `web.mcp.auth_mode: "none"` exposes an unauthenticated MCP server on the public VPN port. Do not use that combination outside an isolated trusted network. Even with authentication, prefer a strong mode (`bearer`, `api_key`, or `oauth_jwt`) and HTTPS.

## Authentication

MCP shares the Web listener and TLS settings, but its authentication policy is configured independently under `web.mcp`. The backward-compatible default is `inherit_web`.

### Supported modes

| `web.mcp.auth_mode` | Authentication | Typical client configuration |
|---|---|---|
| `inherit_web` | Reuse `web.auth`; dashboard cookie or HTTP Basic is accepted | Basic auth with the WebUI username/password |
| `basic` | Independent MCP username/password | HTTP Basic |
| `bearer` | Independent static bearer token | `Authorization: Bearer ...` |
| `api_key` | Independent API key in a configurable header | `X-API-Key: ...` by default |
| `oauth_jwt` | OAuth 2.x / OIDC resource-server mode; validates signed JWT access tokens with remote JWKS | `Authorization: Bearer <access-token>` |
| `none` | No MCP authentication | Development/trusted isolated networks only |

The dashboard itself continues to use `web.auth`; changing `web.mcp.auth_mode` does not weaken WebUI authentication.

### Configure from the WebUI

Open **Dashboard → Settings**. The JSON editor returned by `/api/config` contains the active `web.mcp` block. Change it and choose **Save & apply**.

MCP authentication is evaluated from the current `WebManager` configuration on every request, so changing Basic/Bearer/API-key/OAuth settings is hot-applied. The listener, port and TLS socket are not restarted merely because MCP credentials changed.

Example:

```json
{
  "web": {
    "addr": ":8080",
    "auth": "admin:strong-dashboard-password",
    "bind": "tunnel",
    "cert": "/etc/tlsvpn/web.crt",
    "key": "/etc/tlsvpn/web.key",
    "mcp": {
      "auth_mode": "bearer",
      "credential": "replace-with-a-long-random-token"
    }
  }
}
```

For `basic`, `bearer`, and `api_key`, plaintext `credential` values entered in the WebUI are normalized before persistence to a non-replayable value of the form:

```text
sha256:<64 hex characters>
```

The next WebUI load therefore shows the verifier, not the usable password/token/key. To rotate the credential, replace the verifier in the JSON editor with a new plaintext value and **Save & apply** again.

#### Independent Basic

```json
"mcp": {
  "auth_mode": "basic",
  "username": "mcp-agent",
  "credential": "a-long-random-password"
}
```

Client request:

```bash
curl -u 'mcp-agent:a-long-random-password' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}' \
  https://HOST:WEB_PORT/<PATH>
```

#### Static Bearer token

```json
"mcp": {
  "auth_mode": "bearer",
  "credential": "a-long-random-bearer-token"
}
```

Client request header:

```text
Authorization: Bearer a-long-random-bearer-token
```

#### API key header

```json
"mcp": {
  "auth_mode": "api_key",
  "api_key_header": "X-API-Key",
  "credential": "a-long-random-api-key"
}
```

Client request header:

```text
X-API-Key: a-long-random-api-key
```

`Authorization`, `Cookie`, `Host`, and `Content-Length` cannot be repurposed as the API-key header.

### OAuth / OIDC JWT access tokens

`oauth_jwt` turns TLSVPN into an OAuth/OIDC resource server. It does not issue tokens and does not store an IdP client secret. It validates incoming signed access-token JWTs against the configured public JWKS endpoint.

```json
"mcp": {
  "auth_mode": "oauth_jwt",
  "oauth": {
    "jwks_url": "https://login.example.com/.well-known/jwks.json",
    "issuer": "https://login.example.com",
    "audience": "tlsvpn-mcp",
    "resource": "https://vpn.example.com:8080/<PATH>",
    "authorization_servers": [
      "https://login.example.com"
    ],
    "required_scopes": [
      "mcp:read"
    ]
  }
}
```

`resource` must match the actual MCP endpoint, so it uses the configured `web.mcp.path` (the WebUI example fills it automatically).

Validation includes:

- JWT signature via JWKS, with key-id rotation support and bounded caching;
- `exp` is required;
- exact configured issuer;
- configured audience;
- optional required scopes from `scope` or `scp` claims;
- RSA PKCS#1/PSS, ECDSA, and Ed25519 signing keys;
- HTTPS-only issuer/JWKS/resource URLs, except loopback HTTP for local tests.

When OAuth mode is active, TLSVPN exposes MCP Protected Resource Metadata at:

```text
/.well-known/oauth-protected-resource
/.well-known/oauth-protected-resource/mcp
```

Unauthorized OAuth requests return a Bearer challenge containing the `resource_metadata` URL. Missing required scopes return HTTP 403 with `error="insufficient_scope"`.

### HTTPS requirement

Basic passwords, static bearer tokens, and API keys are bearer-like credentials on the wire. For a remotely reachable MCP endpoint, use HTTPS (`web.cert` + `web.key`) or expose the listener only through a trusted tunnel. Do not transmit them over plaintext HTTP on an untrusted network.

## Tools

### Read-only

| Tool | Purpose |
|---|---|
| `tlsvpn_status` | Complete live status snapshot used by the WebUI |
| `tlsvpn_connections` | Logical clients, physical connections, bans, MAC table and peer information |
| `tlsvpn_config_get` | Effective configuration with secrets redacted / static MCP credentials represented only by a SHA-256 verifier |
| `tlsvpn_diagnostics` | Diagnostic history for `2m`, `1h`, or `24h` |
| `tlsvpn_traffic` | Throughput/RTT trend for `2m`, `1h`, or `24h` |
| `tlsvpn_logs` | Incremental in-memory log ring using a sequence cursor |
| `tlsvpn_events` | Incremental lifecycle/administration events using a sequence cursor |
| `tlsvpn_config_validate` | Validate configuration and report restart-required fields without saving or applying |

Configuration responses redact PSK, `web.auth`, and SOCKS5 credentials. MCP static credentials are persisted and returned only as one-way SHA-256 verifiers; OAuth configuration contains public verification/discovery data only.

### Administration

| Tool | Mode | Effect |
|---|---|---|
| `tlsvpn_set_log_level` | both | Change runtime log level |
| `tlsvpn_force_reconnect` | client | Tear down tunnel connections and redial |
| `tlsvpn_kick_client` | server | Disconnect one active client session |
| `tlsvpn_ban_client` | server | Ban a client and disconnect it when active; `ttl_minutes=0` means permanent |
| `tlsvpn_unban_client` | server | Remove a client from the ban list |
| `tlsvpn_kick_all_clients` | server | Disconnect every active client session |
| `tlsvpn_gc` | both | Trigger Go memory reclamation |
| `tlsvpn_config_save` | both | Validate and atomically save config; optionally hot-apply supported settings |

Mode-specific tools return an MCP tool error when invoked in the wrong process mode.

Configuration writes intentionally reuse the same implementation as the WebUI configuration workflow:

1. merge redacted secrets with the current configuration;
2. validate the complete configuration;
3. normalize MCP static credentials to one-way verifiers;
4. calculate `needs_restart` fields;
5. atomically write the source JSON file; and
6. when `apply=true`, update the Web manager, traffic accounting, and the active server/client runtime configuration.

This prevents WebUI and MCP configuration semantics from diverging.

## Resources

The MCP server exposes dynamic JSON resources:

| URI | Contents |
|---|---|
| `tlsvpn://status` | Current complete status snapshot |
| `tlsvpn://connections` | Current connection/session state |
| `tlsvpn://config` | Current redacted configuration |
| `tlsvpn://diagnostics` | Current 1-hour diagnostic history |
| `tlsvpn://traffic` | Current 1-hour traffic/RTT history |

Resources are generated on read; they are not stale files or cached copies.

## Prompts

Three built-in prompts provide reusable operational workflows:

- `diagnose_tlsvpn` — evidence-driven troubleshooting from status, diagnostics, events and logs.
- `optimize_tlsvpn` — conservative throughput/latency/reliability/memory optimization, validating configuration before writes.
- `security_audit_tlsvpn` — read-only review of exposure, TLS/authentication, protection counters, bans and unexpected peers.

The prompts explicitly prefer read-only inspection and do not authorize disruptive actions by themselves.

## Recent MCP access log

Every MCP request (both faces) is recorded in a dedicated in-memory ring buffer (capacity 500, oldest dropped) and surfaced in the WebUI as a separate **MCP access** panel. It does not mix into the general event or log panels.

- Each entry records: sequence number, server time, remote host, JSON-RPC method (or `auth` for authentication failures), tool name for `tools/call`, HTTP status, duration in ms, and the error message when relevant.
- Authentication failures are recorded too (`method: "auth"`), so repeated credential/path probing is observable.
- Sources: the WebUI consumes the `mcp_logs` frame on the single `/api/stream` SSE channel (incremental via the `mcp_after` cursor); scripts/tests can use the compatibility endpoint `GET /api/mcp-logs?after=<seq>`.
- The buffer is in-memory only; long-term retention belongs to the process log file.

## Security model

MCP administration is intentionally equivalent in privilege to the existing authenticated Web control API. Anyone who can authenticate to MCP can invoke disruptive tools and can save the TLSVPN configuration.

Recommended deployment rules:

1. keep the dashboard protected with `web.auth`;
2. keep the default `web.mcp.deploy: "internal"` unless MCP must be reachable from outside the tunnel, and rotate `web.mcp.path` whenever it is exposed publicly or suspected leaked;
3. choose an MCP authentication mode appropriate for the client environment; prefer OAuth/OIDC for centrally managed remote deployments;
4. use HTTPS whenever the Web/MCP listener crosses an untrusted network;
5. prefer `web.bind: "tunnel"` when management should only be reachable through TLSVPN;
6. do not use `web.mcp.auth_mode: "none"` on a public or otherwise untrusted listener; and
7. use read-only MCP tools first and inspect `needs_restart` before applying configuration changes.
