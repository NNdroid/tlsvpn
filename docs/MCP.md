# TLSVPN MCP server

The Go implementation exposes a Model Context Protocol (MCP) server through the **same HTTP server, listener, TLS configuration, bind policy, and port as the WebUI**.

If the WebUI is available at:

```text
https://10.0.0.1:8080/
```

then MCP is available at:

```text
https://10.0.0.1:8080/mcp
```

No second listener or MCP-specific port is opened.

## Transport

TLSVPN uses the official Go MCP SDK and Streamable HTTP transport.

- Endpoint: `/mcp`
- Transport: Streamable HTTP
- Server mode: stateless
- Response mode: JSON for request/response operations
- Maximum request body: 1 MiB
- HTTP request cancellation is propagated for protocol revisions that support it
- Both TLSVPN server mode and client mode expose MCP when `web.addr` enables the Web service

The stateless transport follows the sessionless direction of newer MCP protocol revisions while retaining SDK compatibility with older supported MCP revisions.

## Authentication

MCP shares the WebUI authentication boundary.

When `web.auth` is empty, MCP is reachable without authentication wherever the Web listener is reachable. This is equivalent to the existing WebUI/API behavior and is **not recommended on an untrusted network**.

When `web.auth` is configured as `user:password`:

- an existing authenticated WebUI cookie session is accepted; and
- MCP clients may use HTTP Basic authentication with the same username and password.

For a remotely reachable MCP endpoint, use HTTPS (`web.cert` + `web.key`) or bind the Web service only to the tunnel interface. Basic credentials must not be sent over plaintext HTTP on an untrusted network.

Example initialization request:

```bash
curl -u 'admin:password' \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"initialize",
    "params":{
      "protocolVersion":"2025-06-18",
      "capabilities":{},
      "clientInfo":{"name":"curl","version":"1"}
    }
  }' \
  https://HOST:WEB_PORT/mcp
```

## Tools

### Read-only

| Tool | Purpose |
|---|---|
| `tlsvpn_status` | Complete live status snapshot used by the WebUI |
| `tlsvpn_connections` | Logical clients, physical connections, bans, MAC table and peer information |
| `tlsvpn_config_get` | Effective configuration with secrets redacted |
| `tlsvpn_diagnostics` | Diagnostic history for `2m`, `1h`, or `24h` |
| `tlsvpn_traffic` | Throughput/RTT trend for `2m`, `1h`, or `24h` |
| `tlsvpn_logs` | Incremental in-memory log ring using a sequence cursor |
| `tlsvpn_events` | Incremental lifecycle/administration events using a sequence cursor |
| `tlsvpn_config_validate` | Validate configuration and report restart-required fields without saving or applying |

`tlsvpn_config_get` and validation/save responses redact:

- PSK
- `web.auth`
- SOCKS5 credentials

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
3. calculate `needs_restart` fields;
4. atomically write the source JSON file; and
5. when `apply=true`, update the Web manager, traffic accounting, and the active server/client runtime configuration.

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

## Security model

MCP administration is intentionally equivalent in privilege to the existing authenticated Web control API. Anyone who can authenticate to MCP can invoke disruptive tools and can save the TLSVPN configuration.

Recommended deployment rules:

1. configure `web.auth`;
2. use HTTPS whenever the Web/MCP listener crosses an untrusted network;
3. prefer `web.bind: "tunnel"` when management should only be reachable through TLSVPN;
4. do not expose an unauthenticated Web/MCP port to the public Internet; and
5. use read-only MCP tools first and inspect `needs_restart` before applying configuration changes.
