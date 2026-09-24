# tlsvpn

A high-performance, stealthy Layer-2 VPN in Go. Ethernet frames travel over standard TCP + TLS, with optional inner AES-256-GCM encryption, XOR FEC, multipath MinRTT load balancing and TCP Brutal — built for stability and throughput on lossy or restricted networks.

## Features

- **HTTPS camouflage** — the tunnel looks like ordinary HTTPS (ALPN h2/http1.1). Non-VPN probes and bad PSKs land on a built-in Nginx-style page / tarpit.
- **Inner encryption** — `encrypt: true` adds AES-256-GCM inside the tunnel: per-session/per-direction salts, separate data/FEC keys, `nonce = seq‖salt`, and AAD-bound integrity. There is exactly one inner algorithm and no weaker fallback: a peer that cannot negotiate GCM gets plaintext (TLS only).
- **XOR FEC** — one parity frame per K data frames, broadcast to every backend, reconstructs any single lost frame. The redundancy ratio is N/K with N links, so larger K is cheaper in bandwidth.
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
{"mode": "server", "psk": "GENERATE-A-UNIQUE-RANDOM-SECRET", "addr": ":4000", "encrypt": true}
{"mode": "client", "psk": "GENERATE-A-UNIQUE-RANDOM-SECRET", "addr": "203.0.113.10:4000", "encrypt": true}
```

## Configuration Reference

Unknown fields are rejected (typo protection); omitted fields take the defaults below. `server.session_token`, `server.max_sessions` and `server.fec_group_min`/`fec_group_max` are JSON-only — there are no CLI flags at all.

### Top-level

| Field | Default | Description |
| --- | --- | --- |
| `mode` | (Required) | `server` or `client` |
| `psk` | (Required) | High-entropy pre-shared key. Empty and known placeholder values are rejected |
| `addr` | `:4000` / (Required) | Server: listen address. Client: comma-separated target list for multipath |
| `tap` | `tap0` | TAP device name; `"mem"` = in-memory backend (CI/e2e) |
| `mac` | (Empty) | Pin the TAP interface MAC |
| `log_level` | `info` | `debug`/`info`/`warn`/`error`, switchable live |
| `up` / `down` | (Empty) | Absolute executable paths for process-level tunnel lifecycle hooks; changing either through the dashboard requires a restart |
| `encrypt` | `true` when omitted in JSON | Inner AES-256-GCM with per-session salts and separate data/FEC key domains |
| `min_enc` | (Empty) | Strength floor: `gcm` refuses peers that cannot negotiate GCM, `any`/empty sets no floor (needs `encrypt`) |
| `pad_mode` | `bucket` | Full-record padding: `bucket` maps every record to a fixed size with positive padding, and only `off` permits zero padding |
| `socks5` | (Empty) | Client: route all outbound sockets through a SOCKS5 proxy |
| `brutal` / `brutal_up` / `brutal_down` | `false` / `100` / `500` | TCP Brutal and its Mbps limits |

### `web` (dashboard off unless `addr` is set)

| Field | Default | Description |
| --- | --- | --- |
| `addr` | (Empty) | e.g. `:8080` |
| `bind` | `all` | `tunnel` = bind only the tunnel IPs (panel reachable exclusively from inside the VPN) |
| `auth` | (Required when enabled) | Basic Auth `user:pass`; known example credentials are rejected |
| `cert` / `key` | (Empty) | HTTPS pair; required when `bind=all` exposes a non-loopback listener |

### `server`

| Field | Default | Description |
| --- | --- | --- |
| `v4_cidr` / `v6_cidr` | `10.0.0.0/24` / `fd00::/64` | Address pools handed to clients |
| `cert` / `key` | (Empty) | TLS pair; empty = self-signed, generated once and **persisted** so `cert_sha256` pinning survives restarts |
| `session_token` | `false` | Resuming an existing session requires the per-session resume token. Off: `client_id`+PSK+MAC is enough to resume, so a PSK holder who knows the target MAC can impersonate that session (the id is derived from mac+psk). On: the token only ever crosses the session's own TLS connection, so a third party cannot obtain it. First connection is unaffected; flip both ends together |
| `max_sessions` | `1024` | Concurrent session cap; excess handshakes are tarpitted |
| `fec_group_min` / `fec_group_max` | `2` / `64` | Range of peer FEC group sizes K the server will accept. A handshake that requests FEC with K outside the range is **refused** (not clamped) — the peer chose its own coding parameter, and silently changing K would make it pay a different redundancy ratio unknowingly. Defaults are the protocol limits, so no extra limit applies unless configured. Direction: the parity is broadcast to all N backends, so the ratio is N/K — raising `min` (floor) bounds bandwidth usage, lowering `max` (ceiling) bounds the pending-frame buffer and recovery latency |

### `client`

| Field | Default | Description |
| --- | --- | --- |
| `conns` | `1` | Parallel TCP connections |
| `fec` / `fec_group` | `false` / `4` | XOR parity FEC (K = 2–64; the parity is broadcast to all N backends, so the redundancy ratio is N/K). Sent to the server, which may refuse an out-of-policy K (see `server.fec_group_min`/`_max`) |
| `sni` | `www.cloudflare.com` | Camouflage SNI |
| `insecure` | `false` | Skip TLS verification (prefer `cert_sha256`) |
| `cert_sha256` | (Empty) | Pin the server certificate fingerprint |
| `req_v4` / `req_v6` | (Empty) | Request specific tunnel IPs |
| `fwmark` | `0` | Policy routing mark for transparent-proxy setups; `0` disables the fwmark rule only — a non-empty `source_rules` still enables policy routing |
| `fwmark_priority` | `0` | `ip rule` priority (uint32); `0` = let the kernel assign one. Use it on machines that already run policy routing to make this client's rule win or lose |
| `extra_routes` | `[]` | Extra routes into the fwmark table, in iproute2 serialization form — one prefix plus an optional `dev`, e.g. `"fd99:10:5:8::/64 dev tap0"`. The address family is inferred from the prefix; with no `dev` the tunnel TAP is used. Validated when the config loads, not after the tunnel handshake |
| `source_rules` | `[]` | Policy-routing rules matched on the packet's **source prefix** instead of `SO_MARK`: each entry installs `ip rule from <from> table <table>` plus that table's default routes (from the gateways the server sends) and any `routes` you list. For traffic that has no socket to mark — forwarded packets on an NPT gateway, whose return flow must be pinned to the tunnel TAP. `from` may be a bare address (completed to a host route); `table` is mandatory, in `[1, 65535]` and not the reserved `253`/`254`/`255`; `priority` uint32, `0` = kernel-assigned. Validated when the config loads |

**Policy routing is owned by the process, not by systemd.** With a non-zero `fwmark` — or a non-empty `source_rules` — the client installs the `ip rule` entries and the routes itself, and removes everything it installed on exit. For the fwmark rule the table number is always equal to the fwmark value — `fwmark` `0x100` means table `256`; `source_rules` tables are whatever you configured and nothing derives them. It waits up to 30 s for the TAP to exist and be up before touching routing, so a network manager that creates the device later needs no separate ordering unit. Do **not** also keep an external drop-in doing the same work: two rules for one fwmark compete by priority, the kernel serves whichever wins, and each of them believes it owns the table.

### `up` / `down` lifecycle hooks

```json
{
  "up": "/etc/openvpn/up.sh",
  "down": "/etc/openvpn/down.sh"
}
```

Hooks are executed directly (never through `sh -c`), so the file needs a shebang and executable permission (`chmod 0755`). Paths must be absolute. Each hook has a 30-second timeout and runs with the configuration directory as its working directory. `up` runs once after the TAP addresses and built-in policy routing are ready; parallel TCP connections and short reconnects do not run it again. `down` runs once while the TAP still exists on graceful shutdown, and also rolls back a partially successful `up`. A failing `up` aborts startup; a failing `down` makes the process exit unsuccessfully. Hooks run with the same UID/capabilities as tlsvpn and are **not a sandbox**: only point them at administrator-controlled files. The inherited environment is reduced to a safe PATH/locale (plus required Windows system variables), so service credentials are not forwarded. The timeout terminates the immediate hook process, not an arbitrary descendant tree; hook scripts must supervise and clean up any children they create. `SIGKILL`, a kernel panic, or power loss cannot run cleanup code.

Scripts receive OpenVPN-style variables `script_type`, `dev`, `dev_type=tap`, `config`, `ifconfig_local`, `ifconfig_ipv6_local`, `route_vpn_gateway`, and `route_ipv6_gateway`. The unabridged values are also available as `TLSVPN_SCRIPT_TYPE`, `TLSVPN_MODE`, `TLSVPN_DEV`, `TLSVPN_CONFIG`, `TLSVPN_IPV4`, `TLSVPN_IPV6`, `TLSVPN_GATEWAY_V4`, and `TLSVPN_GATEWAY_V6`. The PSK is deliberately never exported.

## Dashboard & Metrics

Set `web.addr` to enable: live throughput chart, FEC/loss/drop counters, per-connection details (with each link's negotiated cipher, FEC group and whether TCP Brutal actually took effect on it) and the MAC table, log tail with live level switching, client kick/ban, config editor with hot-apply (`needs_restart` is reported for fields that can't), zh-CN/en UI.

The **Runtime status** tab shows what the process is really doing rather than what the config file says: the host and build (`os`/`arch`/Go version/CPU count/hostname/config path/version+uptime); the negotiated protocol (version, inner cipher, FEC group, padding mode, cipher floor, session token, and — on clients — the key epoch, the per-direction rates the server granted, and whether policy routing actually took effect or the exact `ip` error it hit); a TCP Brutal breakdown that separates *configured* Mbps from *kernel support* (current and available congestion controllers) and *per-connection applied/total*, listing the failure reason when shaping was skipped; the effective config snapshot (including the fwmark, its rule priority, the route table number, any extra routes and any source rules); and a restart banner when a hot-applied change needs a process restart. The theme follows the OS light/dark preference and can be pinned to either with a persisted choice.

Prometheus metrics at `/metrics` (authenticated like the rest of the panel). Security: Basic Auth, optional HTTPS, CSRF header guard on control actions.

## Notes

1. **Brutal** needs the `tcp_brutal` kernel module; **TAP** needs root (or `CAP_NET_ADMIN`).
2. **Certificate pinning**: the persisted self-signed cert logs its SHA-256 fingerprint at startup — pin it with `client.cert_sha256` (colon/case tolerant).
3. **Interop**: current Go and Rust builds share protocol v2 and byte-for-byte golden vectors (including data/FEC GCM domains). Upgrade both ends together — there is no backward compatibility by design: a server requires exactly protocol version 2, and a client rejects any other version in the handshake reply, so a mixed-version pair will not connect.
4. **Client identity**: with `mac` empty the client generates and persists a non-zero unicast MAC, session token, and session epoch in `<config>.state` (mode `0600`). A restarted client proves ownership, rotates salts/keys, closes half-open old links, and keeps its assigned tunnel IP. Delete the file to force a fresh identity.

---

*For educational and authorized network testing use only.*
