# tlsvpn

A high-performance, stealthy Layer-2 VPN in Go. Ethernet frames travel over standard TCP + TLS, with optional inner AES-256-GCM encryption, XOR FEC, multipath MinRTT load balancing and TCP Brutal — built for stability and throughput on lossy or restricted networks.

## Features

- **HTTPS camouflage** — the tunnel looks like ordinary HTTPS (ALPN h2/http1.1). Non-VPN probes and bad PSKs land on a built-in Nginx-style page / tarpit.
- **Inner encryption** — `encrypt: true` adds AES-256-GCM inside the tunnel: per-session per-direction salts, `nonce = seq‖salt`, AAD-bound integrity. Old peers fall back to legacy AES-CTR automatically; `min_enc` enforces a floor.
- **XOR FEC** — one parity frame per K data frames (overhead ≈ 1/K) reconstructs any single lost frame; legacy duplication remains as the fallback.
- **Multipath** — multiple TCP links (multi-IP round-robin) with MinRTT routing and backpressure-aware path selection.
- **TCP Brutal** — maintains preset bandwidth under heavy packet loss (kernel `tcp_brutal` module required).
- **Layer-2 TAP** — ARP/DHCP/IPv6 all pass; static MAC/IP bindings; sharded MAC learning with anti-spoofing.
- **Web dashboard + `/metrics`** — live monitoring, client ban/kick, in-panel config editor with hot-apply; Prometheus text endpoint.

## Quick Start

Requires Go 1.26+ (build) and root + `/dev/net/tun` (run).

```bash
git clone https://github.com/NNdroid/tlsvpn.git
cd tlsvpn && go build -o tlsvpn .        # or: bash scripts/build.sh
```

Server and client are configured **only** through a JSON file:

```bash
cp config.server.json config.json        # or config.client.json
vi config.json                           # change psk (always!), addr, web.auth
sudo ./tlsvpn -c config.json
```

```bash
tlsvpn -print-config > config.json       # generate the full template instead
tlsvpn -h                                # shows only -c and -print-config
```

The command-line interface is exactly that: `-c` and `-print-config`. All tuning lives in the config file, which the dashboard's *Save & apply* edits in place — one source of truth, nothing to drift.

Minimal examples (full files ship in the repo root):

```json
{"mode": "server", "psk": "change-me", "addr": ":4000", "encrypt": true}
{"mode": "client", "psk": "change-me", "addr": "203.0.113.10:4000", "encrypt": true}
```

## Configuration Reference

Unknown fields are rejected (typo protection); omitted fields take the defaults below. `server.session_token` and `server.max_sessions` are JSON-only — there are no CLI flags at all.

### Top-level

| Field | Default | Description |
| --- | --- | --- |
| `mode` | (Required) | `server` or `client` |
| `psk` | (Warns) | Pre-shared key — the root of trust; change it |
| `addr` | `:4000` / (Required) | Server: listen address. Client: comma-separated target list for multipath |
| `tap` | `tap0` | TAP device name; `"mem"` = in-memory backend (CI/e2e) |
| `mac` | (Empty) | Pin the TAP interface MAC |
| `log_level` | `info` | `debug`/`info`/`warn`/`error`, switchable live |
| `encrypt` | `false` | Inner AES-256-GCM with per-session salts |
| `min_enc` | (Empty) | Strength floor: `ctr`/`gcm` — weaker negotiations are refused (needs `encrypt`) |
| `pad_mode` | `bucket` | Obfuscation padding: `bucket` (fixed length buckets, ~2% at MTU), `legacy` (random, 6–9× on small frames), `off` |
| `socks5` | (Empty) | Client: route all outbound sockets through a SOCKS5 proxy |
| `brutal` / `brutal_up` / `brutal_down` | `false` / `100` / `500` | TCP Brutal and its Mbps limits |

### `web` (dashboard off unless `addr` is set)

| Field | Default | Description |
| --- | --- | --- |
| `addr` | (Empty) | e.g. `:8080` |
| `bind` | `all` | `tunnel` = bind only the tunnel IPs (panel reachable exclusively from inside the VPN) |
| `auth` | (Empty) | Basic Auth `user:pass` — required outside loopback in practice |
| `cert` / `key` | (Empty) | HTTPS for the dashboard (pair) |

### `server`

| Field | Default | Description |
| --- | --- | --- |
| `v4_cidr` / `v6_cidr` | `10.0.0.0/24` / `fd00::/64` | Address pools handed to clients |
| `cert` / `key` | (Empty) | TLS pair; empty = self-signed, generated once and **persisted** so `cert_sha256` pinning survives restarts |
| `session_token` | `false` | Opt-in: re-attaching a live session requires a token delivered only inside that session's own TLS handshake — other PSK holders cannot hijack it |
| `max_sessions` | `1024` | Concurrent session cap; excess handshakes are tarpitted |

### `client`

| Field | Default | Description |
| --- | --- | --- |
| `conns` | `1` | Parallel TCP connections |
| `fec` / `fec_group` | `false` / `4` | XOR parity FEC (K = 2–64, overhead 1/K) |
| `sni` | `www.cloudflare.com` | Camouflage SNI |
| `insecure` | `false` | Skip TLS verification (prefer `cert_sha256`) |
| `cert_sha256` | (Empty) | Pin the server certificate fingerprint |
| `req_v4` / `req_v6` | (Empty) | Request specific tunnel IPs |
| `fwmark` | `0` | Policy routing mark for transparent-proxy setups |

## Dashboard & Metrics

Set `web.addr` to enable: live throughput chart, FEC/loss/drop counters, per-connection details and the MAC table, log tail with live level switching, client kick/ban, config editor with hot-apply (`needs_restart` is reported for fields that can't), zh-CN/en UI. Prometheus metrics at `/metrics` (authenticated like the rest of the panel). Security: Basic Auth, optional HTTPS, CSRF header guard on control actions.

## Notes

1. **Brutal** needs the `tcp_brutal` kernel module; **TAP** needs root (or `CAP_NET_ADMIN`).
2. **Certificate pinning**: the persisted self-signed cert logs its SHA-256 fingerprint at startup — pin it with `client.cert_sha256` (colon/case tolerant).
3. **Interop**: protocol extensions (`fec_group`, `enc_algo`, `enc_salt*`, `session_token`) are additive and negotiated — mixed old/new versions interoperate in fallback mode. The Rust implementation ([tlsvpn-rs](https://github.com/NNdroid/tlsvpn-rs)) shares this wire protocol.
4. **Client identity**: with `mac` empty the client generates a TAP MAC and persists it, together with the session token, in `<config>.state` (mode `0600`). This keeps the assigned tunnel IP stable across restarts and lets a restarted client rejoin its existing session instead of waiting out the old session's retention window. Delete the file to force a fresh identity.

---

*For educational and authorized network testing use only.*
