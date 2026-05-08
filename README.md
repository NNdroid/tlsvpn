# tlsvpn

**tlsvpn** is a high-performance, high-stealth Layer 2 VPN tunnel written in Go. It transmits Ethernet frames over standard TCP TLS protocols and integrates multipath backup, FEC (Forward Error Correction), and TCP Brutal congestion control. It is purpose-built for extreme stability and connection acceleration in complex or restricted network environments.

## 🌟 Core Features

* **🛡️ Ultimate Camouflage**: Simulates standard HTTPS traffic with ALPN (h2/http1.1) support. When receiving non-VPN handshakes or invalid PSKs, it automatically falls back to a built-in Nginx camouflage page (Tarpan Tarpit).
* **⚡ TCP Brutal Acceleration**: Integrates the TCP Brutal congestion control algorithm, forcefully maintaining preset bandwidth even in high packet-loss environments.
* **🔗 Multipath Dynamic Load Balancing**: Supports parallel transmission across multiple TCP connections.
    * **MinRTT Mode**: Automatically routes packets through the link with the lowest latency.
    * **FEC Redundancy Mode**: Duplicates and sends packets across multiple links simultaneously, achieving zero-loss seamless failover using a custom high-speed deduplicator.
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

---

## 🛠️ Detailed Configuration Options

### 🟢 Global Options

| Flag | Default | Description |
| --- | --- | --- |
| `-mode` | (Required) | Running mode: `server` or `client` |
| `-addr` | `0.0.0.0:4000` | **Server**: Listen address (e.g., `:4000`) <br>

<br>**Client**: Target address list, comma-separated for multi-IP round-robin |
| `-psk` | `quic_secret` | Pre-shared key for authentication |
| `-tap` | `tap0` | Name of the virtual Layer 2 TAP device to create/use |
| `-mac` | `(Empty)` | Manually specify the MAC address for the TAP interface |
| `-loglevel` | `info` | Logging verbosity (`debug`, `info`, `warn`, `error`) |
| `-web` | `(Empty)` | Address to start the Web Dashboard on (e.g., `:8080`) |

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
| `-fec` | `false` | Enable Packet Duplication FEC (Forward Error Correction) over Multipath |
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

## 📈 Web Dashboard

If you start the server or client with the `-web :8080` flag, you can access the visual dashboard by opening `http://localhost:8080` in your browser. Features include:

* **Real-time Speeds**: Accurate tracking of global and per-client instant upload/download bandwidth.
* **Connection Details**: View MAC address bindings, allocated internal IPs, and the number of active TCP connections.
* **Access Control**: The server administrator can manually kick or disconnect abnormal clients directly from the panel.

## ⚠️ Important Notes

1. **Kernel Module**: If using the `-brutal` mode, ensure that your system kernel has been compiled with and loaded the `tcp_brutal` congestion control module.
2. **Permissions**: Ensure the system has access to `/dev/net/tun` before running. This typically requires `root` privileges.
3. **Security Warning**: The server randomly generates a self-signed certificate by default. For absolute link security, it is highly recommended that clients use the `-cert-sha256` flag to lock the server certificate fingerprint.

---

*Disclaimer: This project is for educational and authorized network testing purposes only.*
