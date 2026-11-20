# tlsvpn

A high-performance, stealthy Layer-2 VPN in Go. Ethernet frames travel over standard TCP + TLS, with optional authenticated inner AEAD, XOR FEC, multipath MinRTT load balancing and TCP Brutal — built for stability and throughput on lossy or restricted networks.

## Features

- **HTTPS camouflage** — the tunnel looks like ordinary HTTPS (ALPN h2/http1.1). Non-VPN probes and bad PSKs land on a built-in Nginx-style page / tarpit.
- **Inner encryption** — `encrypt: true` adds authenticated AEAD inside the tunnel: AES-256-GCM (`gcm256`, default), AES-128-GCM (`gcm128`), ChaCha20-Poly1305 (`chacha20`) or XChaCha20-Poly1305 (`xchacha20`). Data and FEC use separate keys and per-session/per-direction salts. AES-GCM/ChaCha20 use `seq(4BE) || salt(8B)` nonces; XChaCha20 derives a 20-byte nonce prefix from the session salt and appends `seq(4BE)`. AAD binds `dataLen(4BE) || seq(4BE)`, and all current algorithms use a 16-byte authentication tag. Peers must agree on the exact algorithm; there is no implicit downgrade.
- **XOR FEC** — one parity frame per K data frames reconstructs any single lost frame. The parity is sent once and rotated across healthy physical links, so redundancy is ≈1/K instead of N/K on N-link sessions.
- **Multipath** — multiple TCP links (multi-IP round-robin) with MinRTT routing and backpressure-aware path selection.
- **TCP Brutal** — maintains preset bandwidth under heavy packet loss (kernel `tcp_brutal` module required).
- **Layer-2 TAP** — ARP/DHCP/IPv6 all pass; static MAC/IP bindings; sharded MAC learning with anti-spoofing.
- **Web dashboard + `/metrics`** — live monitoring, client ban/kick, in-panel config editor with hot-apply; Prometheus text endpoint.
- **Server-observed TLS diagnostics** — every successful application handshake may include an optional `tls` summary containing the negotiated TLS version/cipher/ALPN/SNI plus the ordered ClientHello cipher, signature, group and ALPN features observed by the server. The client dashboard shows the resulting `tls-clienthello-v1` SHA-256. This project-specific digest filters GREASE and is deliberately labelled **not JA3/JA4** because the Go/Rust TLS APIs do not expose the complete raw extension order. It is diagnostic data, not an authentication identity; randoms, tickets, certificate bodies and key material are never returned.

## Quick Start

Requires Go 1.26.1+ (build) and root + `/dev/net/tun` (run).

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
tlsvpn -version                          # print the injected build/release version
tlsvpn -h                                # shows -c, -print-config and -version
```

Runtime configuration remains JSON-only. The bootstrap/query flags are `-c`, `-print-config`, and `-version` (Go's flag parser also accepts `--version`). All tuning lives in the config file, which the dashboard's *Save & apply* edits in place — one source of truth, nothing to drift.

Minimal examples (full files ship in the repo root):

```json
{"mode": "server", "psk": "GENERATE-A-UNIQUE-RANDOM-SECRET", "addr": ":4000", "encrypt": true}
{"mode": "client", "psk": "GENERATE-A-UNIQUE-RANDOM-SECRET", "addr": "203.0.113.10:4000", "encrypt": true}
```


## One-click installer

`scripts/install.sh` provides an English interactive wizard and a fully flag-driven mode for Debian, Ubuntu, Rocky/RHEL-family and Alpine Linux. It can install, upgrade, uninstall, roll back, show status and run daily maintenance. Server certificates can be issued by lego/ACME for either a DNS name or a public IP identifier, generated locally as self-signed certificates, or copied from an existing pair. Optional components include XanMod on supported Debian/Ubuntu x86_64 hosts, tcp-brutal DKMS and conservative network sysctl tuning.

```bash
sudo bash scripts/install.sh
sudo bash scripts/install.sh install --mode server --psk '...' --cert-mode lego \
  --cert-name vpn.example.com --email admin@example.com --daily-update yes
sudo bash scripts/install.sh install --mode server --psk '...' --cert-mode lego \
  --cert-name 203.0.113.10 --email admin@example.com
sudo bash scripts/install.sh install --mode client --server vpn.example.com:4000 --psk '...' \
  --tcp-brutal yes --optimize-kernel yes
sudo bash scripts/install.sh upgrade
sudo bash scripts/install.sh rollback
sudo bash scripts/install.sh uninstall --purge
```

The installer stores rollback snapshots under `/var/lib/tlsvpn-installer`, installs a systemd timer or Alpine daily periodic task when daily maintenance is enabled, and keeps optional kernel components non-fatal so a XanMod or tcp-brutal failure does not destroy an otherwise working TLSVPN installation. Use `scripts/install.sh help` for every flag.

## Configuration Reference

Unknown fields are rejected (typo protection); omitted fields take the defaults below. `server.max_sessions` and `server.fec_group_min`/`fec_group_max` are JSON-only — there are no CLI flags at all.

### Top-level

| Field | Default | Description |
| --- | --- | --- |
| `mode` | (Required) | `server` or `client` |
| `psk` | (Required) | High-entropy pre-shared key. Empty and known placeholder values are rejected |
| `addr` | `:4000` / (Required) | Server: listen address. Client: comma-separated target list for multipath |
| `tap` | `tap0` | TAP device name; `"mem"` = in-memory backend (CI/e2e) |
| `mac` | (Empty) | Pin the TAP interface MAC |
| `log_level` | `info` | `debug`/`info`/`warn`/`error`, switchable live |
| `up` / `down` | (Empty) | Absolute executable paths for process-level tunnel lifecycle hooks in self-managed mode; changing either requires restart |
| `encrypt` | `true` when omitted in JSON | Enable inner authenticated AEAD |
| `enc_algo` | `gcm256` | Inner AEAD: `gcm256` (AES-256-GCM, compatibility default), `gcm128`, `chacha20`, or `xchacha20`. Both peers must match exactly |
| `min_enc` | `gcm` when `encrypt=true` | Minimum inner-encryption policy. Omitted/empty normalizes to `gcm`; legacy name `gcm` means require a supported authenticated inner AEAD, while explicit `any` removes the floor. Requires `encrypt=true` |
| `pad_mode` | `bucket` | Full-record padding: `bucket` maps every record to a fixed size with positive padding, and only `off` permits zero padding |
| `socks5` | (Empty) | Client: route all outbound sockets through a SOCKS5 proxy |
| `brutal` / `brutal_up` / `brutal_down` | `false` / `100` / `500` | TCP Brutal and its Mbps limits |
| `traffic_days` | `30` | Daily traffic-accounting retention in local-calendar days (`1`–`3650`); hot-appliable from the dashboard |
| `traffic_file` | `tlsvpn-traffic.json` beside the config | Persistent daily-traffic store. When omitted, a config-file launch resolves this path next to the JSON config |
| `routing_algo` | `auto` | Multipath scheduler routing algorithm, hot-reloadable: `auto` (decayed-min forward floor + batch service time), `latency_strict`, `latency_sticky`, `min_rtt_strict`, `min_rtt_adaptive`, or `roundtrip_strict`. Applies to this end's egress (client uplink / server downlink) |
| `fec_strategy` | `auto` | FEC parity distribution strategy, hot-reloadable: `auto` (rotate parity across all healthy backends, avoid data paths) or `near` (only connections whose forward one-way latency is within `fec_near_window_ms` of the data path) |
| `fec_near_window_ms` | `10` | Near-strategy forward-latency window in milliseconds (`1`–`100`); hot-reloadable |

### `web` (dashboard off unless `addr` is set)

| Field | Default | Description |
| --- | --- | --- |
| `addr` | (Empty) | e.g. `:8080` |
| `bind` | `all` | `tunnel` = bind only the tunnel IPs (panel reachable exclusively from inside the VPN) |
| `auth` | (Required when enabled) | Dashboard login credential as `user:pass`; known example credentials are rejected. Successful login creates a server-side session cookie rather than leaving credentials in every browser request |
| `cert` / `key` | (Empty) | HTTPS pair; required when `bind=all` exposes a non-loopback listener |

### `server`

Session resume tokens are mandatory and always enabled. There is no `server.session_token` switch; legacy configs containing that key are accepted during upgrade but the value is ignored.

| Field | Default | Description |
| --- | --- | --- |
| `v4_cidr` / `v6_cidr` | `10.0.0.0/24` / `fd00::/64` | Address pools handed to clients |
| `cert` / `key` | (Empty) | TLS pair; empty = self-signed, generated once and **persisted** so `cert_sha256` pinning survives restarts |
| `max_sessions` | `1024` | Concurrent session cap; excess handshakes are tarpitted |
| `fec_group_min` / `fec_group_max` | `2` / `64` | Range of peer FEC group sizes K the server will accept. A handshake that requests FEC with K outside the range is **refused** (not clamped) — the peer chose its own coding parameter, and silently changing K would make it pay a different redundancy ratio unknowingly. Defaults are the protocol limits, so no extra limit applies unless configured. Direction: one parity copy is sent per K data frames and rotated across healthy backends, so the ratio is ≈1/K — raising `min` (floor) bounds bandwidth usage, lowering `max` (ceiling) bounds the pending-frame buffer and recovery latency |

### `client`

| Field | Default | Description |
| --- | --- | --- |
| `interface_manager` | `self` | L3 ownership: `self` keeps the normal Linux behavior; `netifd` is reserved for the OpenWrt protocol handler, where netifd owns addresses/routes/firewall lifecycle |
| `conns` | `1` | Parallel TCP connections |
| `fec` / `fec_group` | `false` / `4` | XOR parity FEC (K = 2–64; one parity copy is rotated across healthy backends, so redundancy is ≈1/K). Sent to the server, which may refuse an out-of-policy K (see `server.fec_group_min`/`_max`) |
| `sni` | `www.cloudflare.com` | Camouflage SNI |
| `insecure` | `false` | Skip TLS verification (prefer `cert_sha256`) |
| `cert_sha256` | (Empty) | Pin the server certificate fingerprint (64 hex). The client also records the actual server certificate SHA-256 it observes at handshake and exposes it per-connection as `cert_sha256` in the API/WebUI connection table and MCP `tlsvpn_connections` |
| `req_v4` / `req_v6` | (Empty) | Request specific tunnel IPs |
| `fwmark` | `0` | Policy routing mark for transparent-proxy setups; `0` disables the fwmark rule only — a non-empty `source_rules` still enables policy routing |
| `fwmark_priority` | `0` | `ip rule` priority (uint32); `0` = let the kernel assign one. Use it on machines that already run policy routing to make this client's rule win or lose |
| `extra_routes` | `[]` | Extra routes into the fwmark table, in iproute2 serialization form — one prefix plus an optional `dev`, e.g. `"fd99:10:5:8::/64 dev tap0"`. The address family is inferred from the prefix; with no `dev` the tunnel TAP is used. Validated when the config loads, not after the tunnel handshake |
| `source_rules` | `[]` | Policy-routing rules matched on the packet's **source prefix** instead of `SO_MARK`: each entry installs `ip rule from <from> table <table>` plus that table's default routes (from the gateways the server sends) and any `routes` you list. For traffic that has no socket to mark — forwarded packets on an NPT gateway, whose return flow must be pinned to the tunnel TAP. `from` may be a bare address (completed to a host route); `table` is mandatory, in `[1, 65535]` and not the reserved `253`/`254`/`255`; `priority` uint32, `0` = kernel-assigned. Validated when the config loads |

**Policy routing ownership depends on `client.interface_manager`.** In the default `self` mode, the process owns its `fwmark`/`source_rules` entries and route tables and removes everything it installed on exit. In `netifd` mode those fields are intentionally rejected: OpenWrt owns addresses, routes, metrics and firewall lifecycle, while TLSVPN only owns the TAP and data plane. Do not configure the same routes in both layers.

## OpenWrt / netifd protocol mode

The in-tree OpenWrt/netifd integration can expose a TLSVPN client as a native OpenWrt network interface. TLSVPN still creates the TAP and runs the TLS/FEC/multipath data plane, but it does **not** call `AddrReplace` or install policy-routing rules in this mode. Instead, fixed helpers under `/lib/netifd/` report the negotiated IPv4/IPv6 addresses and gateways to netifd.

The repository contains two OpenWrt package templates:

- `openwrt/package/tlsvpn`: builds the `tlsvpn` binary plus the `tlsvpn-proto` netifd handler.
- `openwrt/luci-proto-tlsvpn`: adds **Network → Interfaces → Protocol: TLSVPN** to LuCI.

A minimal UCI interface looks like:

```uci
config interface 'vpn'
        option proto 'tlsvpn'
        option server 'vpn.example.com:4000'
        option psk 'REPLACE-WITH-A-HIGH-ENTROPY-SECRET'
        option conns '4'
        option fec '1'
        option fec_group '4'
        option routing_algo 'auto'
        option sched_envelope 'rtt'
        option encrypt '1'
        option brutal '1'
        option brutal_up '100'
        option brutal_down '500'
        option web_enable '1'
        option web_addr ':8080'
        option web_bind 'tunnel'
        option web_auth 'admin:REPLACE-WITH-A-RANDOM-PASSWORD'
        option traffic_days '30'
        option defaultroute '1'
        option metric '10'
```

Every client-mode configuration knob that is legal under `client.interface_manager=netifd` is exposed through UCI and LuCI (which splits it into general, scheduling, dashboard, MCP and advanced tabs): transport identity (`server`/`psk`/`tap`/`mac`/`sni`/`cert_sha256`/`req_v4`/`req_v6`), inner encryption (`encrypt`/`enc_algo`/`min_enc`), padding, TCP Brutal, SOCKS5, multipath scheduling (`routing_algo`, `sched_envelope`, `sched_envelope_ms`, `sched_health_penalty_us`), FEC parity placement (`fec_strategy`, `fec_near_window_ms`), frame write priorities (`priority_control`, `priority_data`), the observation floor (`probe_min_half_rtt_us`), daily traffic accounting (`traffic_days`, `traffic_file`) and the dashboard with its MCP endpoint (`web_*`, `mcp_*`). Options the daemon rejects in netifd mode — `fwmark`, `fwmark_priority`, `extra_routes`, `source_rules`, `up`/`down` — are intentionally absent because netifd owns L3 routing and interface lifecycle. The proto handler mirrors the daemon's validation (ranges, cipher/encrypt consistency, fingerprint pinning, dashboard auth/TLS requirements) and reports `proto_notify_error` codes at `ifup` instead of letting the process die after start.

The generated JSON is stored in `/var/etc/tlsvpn-<interface>.json` with mode `0600` semantics and always sets `client.interface_manager` to `netifd`. In this mode `fwmark`, `extra_routes` and `source_rules` must remain disabled because netifd is the L3 owner.

Because that generated file lives on tmpfs and is rebuilt at every `ifup`, **UCI is the single source of truth on OpenWrt**: the dashboard's *Save & apply* hot-edits stay in effect only for the current process lifetime and are re-generated from UCI on the next interface restart or reboot — persist changes through LuCI/UCI. `traffic_file` defaults to `/etc/tlsvpn/tlsvpn-<interface>-traffic.json` so daily traffic statistics survive reboots (about one flash write per minute while traffic flows); point it at tmpfs such as `/var/etc/vpn-traffic.json` to keep them in RAM only. The dashboard binds tunnel IPs only by default (`web_bind='tunnel'`); `web_bind='all'` also exposes it on WAN and then requires `web_cert`/`web_key`, mirroring the daemon's own validation. An empty `web.mcp.path` is re-randomized by the daemon at every interface restart, so set `mcp_path` explicitly on routers where MCP clients are expected to reconnect.

For ad-hoc SDK work the package template follows `main`; reproducible release builds do not rely on that moving ref. `scripts/build_openwrt_apk.sh` injects the exact Git commit, source date and package version into the OpenWrt build, downloads the official SDK, verifies its SHA-256 checksum, installs only the Go packaging helper from the `packages` feed (the LuCI protocol package is static JavaScript and does not require the full `luci` feed), builds `tlsvpn`, `tlsvpn-proto` and `luci-proto-tlsvpn`, then collects the resulting APK files under `bin/openwrt/<target>-<subtarget>/`.

Example for the NanoPi R5S / Rockchip ARMv8 target:

```bash
OPENWRT_VERSION=25.12.6 \
OPENWRT_TARGET=rockchip \
OPENWRT_SUBTARGET=armv8 \
OPENWRT_INCLUDE_ARCH_INDEPENDENT=1 \
./scripts/build_openwrt_apk.sh
```

The release workflow runs the same script as a target matrix for x86/64, generic ARMv8/ARMv7, Rockchip ARMv8, MediaTek Filogic, ramips/mt7621, ath79/generic, qualcommax/ipq50xx and airoha/an7581+an7583. `tlsvpn-proto` and `luci-proto-tlsvpn` are architecture-independent, so the release exports them only once; the main `tlsvpn` APK is emitted per target/subtarget. Manual runs of `build_and_release.yml` build Actions artifacts without creating a Release, while a pushed `v*` tag builds all artifacts and publishes them to the corresponding GitHub Release.

### OpenWrt APK feed signing key

The OpenWrt 25.12 APK feed requires a stable, unencrypted OpenSSL **EC P-256** private/public key pair. Generate a dedicated pair once and keep the private key backed up securely:

```bash
umask 077

openssl ecparam \
  -name prime256v1 \
  -genkey \
  -noout \
  -out ~/.ssh/tlsvpn_openwrt_feed_private.pem

openssl ec \
  -in ~/.ssh/tlsvpn_openwrt_feed_private.pem \
  -pubout \
  -out ~/.ssh/tlsvpn_openwrt_feed_public.pem
```

Validate the private key and prove that the public key belongs to it:

```bash
openssl ec \
  -in ~/.ssh/tlsvpn_openwrt_feed_private.pem \
  -check \
  -noout

cmp \
  <(openssl ec -in ~/.ssh/tlsvpn_openwrt_feed_private.pem -pubout 2>/dev/null) \
  ~/.ssh/tlsvpn_openwrt_feed_public.pem
```

Encode the complete file contents, including the PEM header and footer:

```bash
base64 -w0 ~/.ssh/tlsvpn_openwrt_feed_private.pem
echo

base64 -w0 ~/.ssh/tlsvpn_openwrt_feed_public.pem
echo
```

Store the resulting values in the GitHub repository settings:

- Private-key Base64: Actions **Secret** `OPENWRT_FEED_SIGNING_KEY_B64`
- Public-key Base64: Actions **Variable** `OPENWRT_FEED_PUBLIC_KEY_B64`

Do **not** use keys created by `minisign -G`, `ssh-keygen`, or the legacy OpenWrt `usign` tool. Minisign uses its own Ed25519 key-file format; it is not interchangeable with the EC P-256 PEM key expected by the OpenWrt APK signing path. Keep Minisign keys for separate artifact signatures and use a dedicated pair for the APK feed.

Pull-request workflows intentionally cannot read the production private-key Secret and log that an ephemeral CI-only key pair is being used. To test the configured production key without publishing, manually run the `OpenWrt Custom Feed` workflow with `publish=false`. The trusted run must report `private_key_type=EC curve=prime256v1 pair_match=true` before it starts the SDK matrix.

The full feed layout, publication behavior and client setup are documented in [`docs/openwrt-customfeed.md`](docs/openwrt-customfeed.md).

### `up` / `down` lifecycle hooks

In the default self-managed mode, optional process-level hooks can run after tunnel networking is ready and during graceful cleanup:

```json
{
  "up": "/etc/openvpn/up.sh",
  "down": "/etc/openvpn/down.sh"
}
```

Hooks are executed directly (never through `sh -c`), so the file needs a shebang and executable permission. Paths must be absolute. Each hook has a 30-second timeout and runs with the configuration directory as its working directory. `up` runs once after TAP addresses and built-in policy routing are ready; parallel TCP connections and short reconnects do not run it again. `down` runs once while the TAP still exists on graceful shutdown and also rolls back a partially successful `up`. The inherited environment is reduced to a safe PATH/locale and the PSK is never exported.

Scripts receive OpenVPN-style variables `script_type`, `dev`, `dev_type=tap`, `config`, `ifconfig_local`, `ifconfig_ipv6_local`, `route_vpn_gateway`, and `route_ipv6_gateway`, plus the corresponding `TLSVPN_*` aliases.

When `client.interface_manager=netifd`, top-level `up`/`down` hooks are rejected. OpenWrt already owns interface lifecycle through netifd and the fixed TLSVPN helpers, so allowing a second lifecycle owner would make ordering and rollback ambiguous.

## Dashboard & Metrics

Set `web.addr` to enable: live throughput and daily-traffic views, FEC/loss/drop counters, per-connection details (with each link's negotiated cipher, FEC group and whether TCP Brutal actually took effect on it), the MAC table, log tail with live level switching, client kick/ban, config editor with hot-apply (`needs_restart` is reported for fields that can't), the current frame-format visualizer, local OS/architecture icons, a Model Context Protocol (MCP) administration server with independent authentication (`web.mcp.auth_mode`, default `inherit_web`) on a shared random-by-default endpoint path (`web.mcp.path`, never `/mcp`), a recent-MCP-access log panel, and zh-CN/zh-TW/en/de/fr/ja UI.

The **Runtime status** tab shows what the process is really doing rather than what the config file says: the host and build (`os`/`arch`/Go version/CPU count/hostname/config path/version+uptime); the negotiated protocol (version, inner cipher, FEC group, padding mode, cipher floor, session token, and — on clients — the key epoch, the per-direction rates the server granted, and whether policy routing actually took effect or the exact `ip` error it hit); a TCP Brutal breakdown that separates *configured* Mbps from *kernel support* (current and available congestion controllers) and *per-connection applied/total*, listing the failure reason when shaping was skipped; the effective config snapshot (including the fwmark, its rule priority, the route table number, any extra routes and any source rules); and a restart banner when a hot-applied change needs a process restart. The theme follows the OS light/dark preference and can be pinned to either with a persisted choice.

Prometheus metrics at `/metrics` are protected by the Web UI authentication gate. Security: `web.auth` backs the login flow, successful browser login uses an HttpOnly SameSite session cookie, mutating API calls require the CSRF header, and HTTPS is available through `web.cert`/`web.key`.

## WebUI documentation

- [Dashboard accounting](docs/WEBUI_METRICS.md)
- [Diagnostic charts](docs/WEBUI_CHARTS.md)
- [Observed Linux TCP state](docs/WEBUI_TCP.md)
- [MCP administration](docs/MCP.md)

## Notes

1. **Brutal** needs the `tcp_brutal` kernel module; **TAP** needs root (or `CAP_NET_ADMIN`).
2. **Certificate pinning**: the persisted self-signed cert logs its SHA-256 fingerprint at startup — pin it with `client.cert_sha256` (colon/case tolerant). On the client side the handshake also records the server certificate SHA-256 it actually observed, logs it per connection (`[Conn N] TLS server certificate SHA256: ...`) and exposes it as `cert_sha256` on each connection — visible in the WebUI connection table (and connection detail drawer) and via MCP `tlsvpn_connections`. The server exposes its own certificate fingerprint the same way.
3. **Interop**: current Go and Rust builds share protocol v4 and byte-for-byte golden vectors (including frame headers and data/FEC AEAD-domain vectors). The wire protocol supports the same four inner AEADs on both implementations. v4 binds the inner AEAD AAD to the frame header `padLen` (data frames) and to the FEC parity descriptor (parity frames). Upgrade both ends together — there is no backward compatibility by design: a server requires exactly protocol version 4, and a client rejects any other version in the handshake reply, so a mixed-version pair will not connect.
4. **Client identity**: with `mac` empty the client generates and persists a non-zero unicast MAC, session token, and session epoch in `<config>.state` (mode `0600`). A restarted client proves ownership, rotates salts/keys, closes half-open old links, and keeps its assigned tunnel IP. Delete the file to force a fresh identity.

---

*For educational and authorized network testing use only.*
