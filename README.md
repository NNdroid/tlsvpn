# tlsvpn

**tlsvpn** is a high-performance, high-stealth Layer 2 VPN tunnel written in Go. It transmits Ethernet frames over standard TCP TLS protocols and integrates multipath backup, FEC (Forward Error Correction), and TCP Brutal congestion control. It is purpose-built for extreme stability and connection acceleration in complex or restricted network environments.

## 🌟 Core Features

* **🛡️ Ultimate Camouflage**: Simulates standard HTTPS traffic with ALPN (h2/http1.1) support. When receiving non-VPN handshakes or invalid PSKs, it automatically falls back to a built-in Nginx camouflage page (Tarpan Tarpit).
* **🔐 Hardened Inner Encryption (Optional)**: With `encrypt: true`, payloads are additionally encrypted **inside** the TLS tunnel using AES-256-GCM with per-session random salts (separate salt per direction, nonce = seq‖salt) — providing integrity protection and immunity to keystream replay across sessions/restarts. Older peers automatically fall back to the legacy AES-CTR mode.
* **⚡ TCP Brutal Acceleration**: Integrates the TCP Brutal congestion control algorithm, forcefully maintaining preset bandwidth even in high packet-loss environments.
* **🔗 Multipath Dynamic Load Balancing**: Supports parallel transmission across multiple TCP connections.
    * **MinRTT Mode**: Automatically routes packets through the link with the lowest latency.
    * **FEC Redundancy Mode (XOR Parity)**: Every K data frames are accompanied by one XOR parity frame (overhead ≈ 1/K). Data frames are striped across links while the parity frame is broadcast to all of them, so any single lost frame is transparently reconstructed at the receiver. Legacy packet-duplication mode remains available as an automatic fallback when the peer does not support XOR FEC.
* **🌐 Multi-IP Link Backup**: Clients can connect to multiple server IPv4/IPv6 addresses simultaneously. It utilizes round-robin connection allocation for true physical path redundancy.
* **📦 Layer 2 Tunneling (TAP)**: Built on TAP virtual network interfaces, fully supporting all Layer 2 protocols including ARP, DHCP, and IPv6, alongside static MAC/IP bindings.
* **📊 Real-time Dashboard**: Built-in Web UI (optional) for real-time monitoring, log tailing, live log-level switching, client ban/kick management, and a Prometheus `/metrics` endpoint.
* **⚙️ Automated Routing**: Integrated policy routing (`fwmark`) auto-configuration, offering native support for transparent proxying setups.

---

## 🚀 Quick Start

### 1. Installation

Ensure you have Go 1.21+ installed, along with the necessary Linux headers for compilation.

```bash
git clone https://github.com/NNdroid/tlsvpn.git
cd tlsvpn
go build -o tlsvpn main.go
```

### 2. Server

Root privileges are required to create the TAP device. Copy the shipped example config, adjust `psk` (always!), and run:

```bash
cp config.server.json config.json
# edit config.json: change psk, set web.auth, optionally set server.cert/key
sudo ./tlsvpn -c config.json
```

The shipped `config.server.json` enables inner encryption, TCP Brutal and the web dashboard on `:8080` — a good starting point.

### 3. Client

```bash
cp config.client.json config.json
# edit config.json: change psk, set addr to your server, set client.cert_sha256
sudo ./tlsvpn -c config.json
```

The shipped `config.client.json` connects to two server addresses with 4 TCP links, XOR FEC (K=4) and Brutal — a good starting point for high availability.

### 4. JSON Config File

`-c config.json` makes the file the **single source of truth** — all other command-line flags are ignored. Unknown fields are rejected to catch typos; missing fields fall back to the same defaults documented below.

```bash
# Ready-made examples ship in the repo root — copy, edit, run (see above)

# Or generate the full template from the binary itself
./tlsvpn -print-config > config.json
```

`config.client.json` (shipped in the repo root):

```json
{
  "mode": "client",
  "psk": "change-me-please",
  "addr": "203.0.113.10:4000,[2001:db8::10]:4000",
  "encrypt": true,
  "brutal": true, "brutal_up": 100, "brutal_down": 500,
  "web": { "addr": ":8080", "auth": "admin:change-me" },
  "client": { "conns": 4, "fec": true, "fec_group": 4 }
}
```

`config.server.json` uses `"mode": "server"` with a `server` section (`v4_cidr`, `v6_cidr`, `cert`, `key`) instead of the `client` section. Full field-by-field reference below.

> When the server starts without `cert`/`key`, it generates a self-signed certificate **and persists it to disk** (`tlsvpn-selfsigned-cert.pem` / `tlsvpn-selfsigned-key.pem`), logging the SHA-256 fingerprint. Restarting reuses the same certificate, so `client.cert_sha256` pinning survives server restarts.

---

## 🛠️ Configuration Reference (JSON)

Values and defaults are identical whether you use the config file or the legacy command-line flags (appendix at the bottom). Nested sections are omitted entirely in the examples for modes that don't use them.

### 🟢 Global

| Field | Default | Description |
| --- | --- | --- |
| `mode` | (Required) | `server` or `client` |
| `psk` | `quic_secret` ⚠️ | Pre-shared key. The default is refused loud with a warning — always set your own |
| `addr` | server `0.0.0.0:4000` / client (Required) | **Server**: listen address. **Client**: target list, comma-separated for multi-IP round-robin (e.g. `1.2.3.4:4000,[2001:db8::1]:4000`) |
| `tap` | `tap0` | TAP device name. Special value `"mem"` uses an in-memory backend (CI/e2e only) |
| `mac` | (Empty) | Manually specify the TAP interface MAC address |
| `log_level` | `info` | `debug` / `info` / `warn` / `error` (switchable live from the dashboard) |
| `encrypt` | `false` | Inner AES-256-GCM payload encryption with per-session salts (legacy CTR fallback for old peers) |
| `brutal` | `false` | Enable TCP Brutal congestion control (requires the kernel `tcp_brutal` module) |
| `brutal_up` | `100` | Upload rate limit in Mbps |
| `brutal_down` | `500` | Download rate limit in Mbps |
| `socks5` | (Empty) | Client: route ALL outbound sockets through a SOCKS5 proxy, e.g. `127.0.0.1:1080` or `user:pass@host:port` |

### 🌐 web (Optional — dashboard is off unless `web.addr` is set)

| Field | Default | Description |
| --- | --- | --- |
| `addr` | (Empty) | Dashboard listen address (e.g. `:8080`). Empty = dashboard disabled |
| `auth` | (Empty) | Basic Auth as `user:pass`. Strongly recommended when binding a non-loopback address |
| `cert` / `key` | (Empty) | Serve the dashboard over HTTPS (both must be provided together) |

### 🔵 server (Server mode only)

| Field | Default | Description |
| --- | --- | --- |
| `v4_cidr` | `10.0.0.0/24` | IPv4 address pool for clients |
| `v6_cidr` | `fd00::/64` | IPv6 address pool for clients |
| `cert` / `key` | (Empty) | Custom TLS certificate pair. Empty = generate & persist a self-signed cert |

### 🟡 client (Client mode only)

| Field | Default | Description |
| --- | --- | --- |
| `conns` | `1` | Number of parallel TCP connections (multi-IP round-robin, MinRTT/FEC multipath) |
| `fec` | `false` | Enable FEC over multipath (XOR parity when the server supports it, else packet duplication) |
| `fec_group` | `4` | XOR FEC group size K (2–64); parity overhead is 1/K |
| `sni` | `www.cloudflare.com` | SNI domain used during the TLS handshake for camouflage |
| `insecure` | `false` | Skip server TLS certificate verification (prefer `cert_sha256` instead) |
| `cert_sha256` | (Empty) | Pin the server certificate by SHA-256 fingerprint (hex; colon-separated tolerated). Survives server restarts thanks to certificate persistence |
| `req_v4` / `req_v6` | (Empty) | Request a specific internal IPv4/IPv6 address |
| `fwmark` | `0` | Enable policy routing with the given fwmark (transparent proxies / traffic splitting) |

---

## 📈 Web Dashboard (Optional)

The dashboard is **off by default**. Enable it by setting `web.addr` (works for **both** server and client). Features include:

* **Throughput Chart**: A live up/down sparkline covering the last 120 seconds.
* **FEC & Loss Observability**: Parity frames sent, frames recovered by XOR FEC, frames confirmed lost, and queue-overflow drops.
* **Connection Details**: Per-physical-connection table (client: target/remote/RTT/retries/last error; server: per-connection RTT via kernel TCP_INFO), plus the MAC learning table and IP-pool usage.
* **Runtime Controls**: Live log-level switching, in-panel log tail (last 500 lines in memory), forced reconnect (client), manual GC.
* **Client Management**: Kick (closes physical TCP connections), ban with TTL or permanently (banned clients are routed to the tarpit), kick-all, unban — all effective immediately.
* **Prometheus Metrics**: `/metrics` endpoint (text format) for Grafana/Alertmanager integration.

Security: `web.auth` (Basic Auth), optional HTTPS via `web.cert`/`web.key`, and a CSRF header guard on all control actions.

## ⚠️ Important Notes

1. **Kernel Module**: If using Brutal mode, ensure the system kernel has the `tcp_brutal` congestion control module loaded.
2. **Permissions**: `/dev/net/tun` access is required, typically root.
3. **Certificate Pinning**: Without `cert`/`key`, the server generates a self-signed certificate and persists it to disk, logging its SHA-256 fingerprint. Pin it on clients via `client.cert_sha256`.
4. **Rust Peer Sync**: Handshake fields `fec_group`, `enc_algo`, `enc_salt`, `enc_salt2` are additive; older peers interoperate in fallback mode.

---

## 📎 Appendix: Legacy Command-Line Flags

All flags still work for quick one-liners; `-c config.json` overrides everything. Flag names map 1:1 to the JSON fields above (`-brutal-up` ↔ `brutal_up`, etc.).

```bash
# Server one-liner
sudo ./tlsvpn -mode server -psk "your_secret_key" -addr ":4000" -encrypt -brutal -web ":8080" -web-auth "admin:pass"

# Client one-liner
sudo ./tlsvpn -mode client -addr "1.1.1.1:4000,[::1]:4000" -psk "your_secret_key" \
  -conns 4 -fec -encrypt -brutal -brutal-down 500

# Shared flags: -psk -tap -mac -loglevel -encrypt -brutal -brutal-up -brutal-down -web -web-auth -web-cert -web-key
# Server only : -v4cidr -v6cidr -cert -key
# Client only : -conns -fec -fec-group -req-v4 -req-v6 -sni -insecure -cert-sha256 -fwmark -socks5
```

---

*Disclaimer: This project is for educational and authorized network testing purposes only.*
