# tlsvpn

**tlsvpn** is a high-performance, high-stealth Layer 2 VPN tunnel written in Go. It transmits Ethernet frames over standard TCP TLS protocols and integrates multipath backup, FEC (Forward Error Correction), and TCP Brutal congestion control. It is purpose-built for extreme stability and connection acceleration in complex or restricted network environments.

## 🌟 Core Features

* **🛡️ Ultimate Camouflage**: Simulates standard HTTPS traffic with ALPN (h2/http1.1) support. When receiving non-VPN handshakes or invalid PSKs, it automatically falls back to a built-in Nginx camouflage page (Tarpan Tarpit).
* **🔐 Hardened Inner Encryption (Optional)**: With `-encrypt`, payloads are additionally encrypted **inside** the TLS tunnel using AES-256-GCM with per-session random salts (separate salt per direction, nonce = seq‖salt) — providing integrity protection and immunity to keystream replay across sessions/restarts. Older peers automatically fall back to the legacy AES-CTR mode.
* **⚡ TCP Brutal Acceleration**: Integrates the TCP Brutal congestion control algorithm, forcefully maintaining preset bandwidth even in high packet-loss environments.
* **🔗 Multipath Dynamic Load Balancing**: Supports parallel transmission across multiple TCP connections.
    * **MinRTT Mode**: Automatically routes packets through the link with the lowest latency.
    * **FEC Redundancy Mode (XOR Parity)**: Every K data frames are accompanied by one XOR parity frame (overhead ≈ 1/K). Data frames are striped across links while the parity frame is broadcast to all of them, so any single lost frame is transparently reconstructed at the receiver. Legacy packet-duplication mode remains available as an automatic fallback when the peer does not support XOR FEC.
* **🌐 Multi-IP Link Backup**: Clients can connect to multiple server IPv4/IPv6 addresses simultaneously. It utilizes round-robin connection allocation for true physical path redundancy.
* **📦 Layer 2 Tunneling (TAP)**: Built on TAP virtual network interfaces, fully supporting all Layer 2 protocols including ARP, DHCP, and IPv6, alongside static MAC/IP bindings.
* **📊 Real-time Dashboard**: Built-in Web UI for real-time monitoring of speeds, traffic, TCP connections, and client status.
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

### 2. Server Deployment

Root privileges are required on the server to create the TAP device.

```bash
# Basic startup (listens on port 4000 across all interfaces)
sudo ./tlsvpn -mode server -psk "your_secret_key" -addr ":4000"

# Enable TCP Brutal acceleration and the Web Dashboard
sudo ./tlsvpn -mode server -psk "your_secret_key" -brutal -brutal-up 100 -web ":8080"

```

### 3. Client Connection

Root privileges are also required for the client.

```bash
# Single-link mode
sudo ./tlsvpn -mode client -addr "SERVER_IP:4000" -psk "your_secret_key"

# 🌐 High-Availability Multi-Link Mode (FEC Redundancy + Multi-IP Load Balancing)
# Connects to both IPv4 and IPv6 server addresses simultaneously, establishing 4 underlying TCP connections for extreme anti-interference capability.
sudo ./tlsvpn -mode client \
  -addr "1.1.1.1:4000,[2001:db8::1]:4000" \
  -conns 4 \
  -fec \
  -brutal -brutal-down 500

```

### 4. JSON Config File (Recommended)

For easier review and version control, run with a JSON config file — it becomes the **single source of truth** (all other flags are ignored):

```bash
# Ready-made examples ship in the repo root — copy, edit, run:
sudo ./tlsvpn -c config.client.json   # client side
sudo ./tlsvpn -c config.server.json   # server side

# Or generate the full template from the binary itself
./tlsvpn -print-config > config.json
```

`config.client.json` (shipped in the repo root; unknown fields are rejected to catch typos):

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

`config.server.json` uses `"mode": "server"` with a `server` section (`v4_cidr`, `v6_cidr`, `cert`, `key`) instead of the `client` section. All field names and defaults are documented in the flag tables below.

> When the server starts without `cert`/`key`, it generates a self-signed certificate **and persists it to disk** (`tlsvpn-selfsigned-cert.pem` / `tlsvpn-selfsigned-key.pem`), logging the SHA-256 fingerprint. Restarting reuses the same certificate, so `-cert-sha256` pinning on clients survives server restarts.

---

## 🛠️ Detailed Configuration Options

### 🟢 Global Options

| Flag | Default | Description |
| --- | --- | --- |
| `-mode` | (Required) | Running mode: `server` or `client` |
| `-addr` | `0.0.0.0:4000` | **Server**: Listen address (e.g., `:4000`) **Client**: Target address list, comma-separated for multi-IP round-robin |
| `-psk` | `quic_secret` | Pre-shared key for authentication |
| `-tap` | `tap0` | Name of the virtual Layer 2 TAP device to create/use |
| `-mac` | `(Empty)` | Manually specify the MAC address for the TAP interface |
| `-loglevel` | `info` | Logging verbosity (`debug`, `info`, `warn`, `error`) |
| `-web` | `(Empty)` | Optional: address to start the Web Dashboard on (e.g. `:8080`). Omit to disable |
| `-web-auth` | `(Empty)` | Basic Auth for the dashboard as `user:pass` (strongly recommended when `-web` binds a non-loopback address) |
| `-web-cert` | `(Empty)` | Optional: TLS certificate to serve the dashboard over HTTPS |
| `-web-key` | `(Empty)` | Optional: TLS key for the dashboard HTTPS listener |

### 🔵 Server Only

| Flag | Default | Description |
| --- | --- | --- |
| `-v4cidr` | `10.0.0.0/24` | IPv4 CIDR block allocated by the server |
| `-v6cidr` | `fd00::/64` | IPv6 CIDR block allocated by the server |
| `-cert` | `(Empty)` | Custom TLS certificate path (auto-generates self-signed if empty) |
| `-key` | `(Empty)` | Custom TLS private key path |

### 🟡 Client Only

| Flag | Default | Description |
| --- | --- | --- |
| `-req-v4` | `(Empty)` | Request a specific internal IPv4 address |
| `-req-v6` | `(Empty)` | Request a specific internal IPv6 address |
| `-conns` | `1` | Number of concurrent TCP connections for Load Balancing / Multipath |
| `-fec` | `false` | Enable FEC over Multipath (XOR parity when the server supports it, else packet duplication) |
| `-fec-group` | `4` | XOR FEC group size K (2–64); parity overhead is 1/K |
| `-sni` | `www.cloudflare.com` | SNI domain used during the TLS handshake for camouflage |
| `-insecure` | `false` | Skip server TLS certificate verification |
| `-cert-sha256` | `(Empty)` | Verify the server certificate using a SHA256 fingerprint (hex encoded) to prevent MITM attacks |
| `-fwmark` | `0` | Enable policy routing with a specific `fwmark` (useful for transparent proxies/traffic splitting) |

### ⚡ TCP Brutal Acceleration

| Flag | Default | Description |
| --- | --- | --- |
| `-brutal` | `false` | Enable TCP Brutal congestion control |
| `-brutal-up` | `100` | Local upload rate limit in Mbps |
| `-brutal-down` | `500` | Local download rate limit in Mbps |

---

## 📈 Web Dashboard (Optional)

The dashboard is **off by default**. Start it by passing `-web :8080` (works for **both** server and client). Configure `-web-auth user:pass` to protect it with Basic Auth, and optionally `-web-cert/-web-key` for HTTPS. Control actions are CSRF-protected. Features include:

* **Throughput Chart**: A live throughput sparkline covering the last 120 seconds.
* **Real-time Speeds**: Global and per-client instant upload/download bandwidth.
* **FEC & Loss Observability**: Parity frames sent, frames recovered by XOR FEC, frames confirmed lost, and queue-overflow drops.
* **Connection Details**: Per-physical-connection table (client: target/remote/RTT/retries/last error; server: per-connection RTT via kernel TCP_INFO), plus the MAC learning table and IP-pool usage.
* **Runtime Controls**: Live log-level switching (debug…error), in-panel log tail (last 500 lines kept in memory), forced reconnect (client), manual GC.
* **Client Management**: Kick (closes physical TCP connections), ban with TTL or permanently (banned clients are routed to the tarpit), kick-all, unban — all effective immediately.
* **Prometheus Metrics**: `/metrics` endpoint (text format) exposing uptime, goroutines, heap, throughput, FEC counters, IP-pool usage and reconnect counters for Grafana/Alertmanager integration.

## ⚠️ Important Notes

1. **Kernel Module**: If using the `-brutal` mode, ensure that your system kernel has been compiled with and loaded the `tcp_brutal` congestion control module.
2. **Permissions**: Ensure the system has access to `/dev/net/tun` before running. This typically requires `root` privileges.
3. **Security Warning**: Without `cert`/*`key`, the server generates a self-signed certificate and persists it to disk, logging its SHA-256 fingerprint. For absolute link security, pin it on clients with `cert_sha256` (config) or `-cert-sha256` (flags).

---

*Disclaimer: This project is for educational and authorized network testing purposes only.*
