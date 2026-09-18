package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"go.uber.org/zap/zapcore"
)

// ======================= JSON 配置文件 =======================
//
// -c <path> 指定 JSON 配置文件后，文件即唯一配置来源（其余命令行标志被忽略），
// 便于 review 与版本管理。字段与命令行标志一一对应：
//
//	{
//	  "mode": "client",
//	  "psk": "change-me",
//	  "addr": "1.2.3.4:4000,[::1]:4000",
//	  "conns": 4, "fec": true, "fec_group": 4,
//	  "encrypt": true,
//	  "web": { "addr": ":8080", "auth": "admin:secret" }
//	}
//
// 未指定的字段取默认值；出现未知字段直接报错（防拼写错误静默失效）。

// Config 顶层配置
type Config struct {
	Mode       string       `json:"mode"`                // 必填：server | client
	PSK        string       `json:"psk"`                 // 预共享密钥
	Tap        string       `json:"tap,omitempty"`       // TAP 设备名（默认 tap0）
	Mac        string       `json:"mac,omitempty"`       // 手动指定 MAC
	Addr       string       `json:"addr"`                // server: 监听地址；client: 目标地址列表
	LogLevel   string       `json:"log_level,omitempty"` // 默认 info
	Encrypt    bool         `json:"encrypt,omitempty"`   // 内层加密（GCM 协商）
	MinEnc     string       `json:"min_enc,omitempty"`   // 最低内层加密强度：ctr | gcm（空=无下限）
	PadMode    string       `json:"pad_mode,omitempty"`  // 混淆填充：legacy | bucket | off（默认 bucket）
	Socks5     string       `json:"socks5,omitempty"`    // 全局 SOCKS5 出口（client）
	Brutal     bool         `json:"brutal,omitempty"`
	BrutalUp   uint64       `json:"brutal_up,omitempty"`   // Mbps
	BrutalDown uint64       `json:"brutal_down,omitempty"` // Mbps
	Web        WebConfig    `json:"web,omitempty"`
	Server     ServerConfig `json:"server,omitempty"`
	Client     ClientConfig `json:"client,omitempty"`

	// SourcePath 配置文件来源路径（-c 指定）；面板"保存配置"写回此文件。
	// 经命令行标志启动时为空，此时面板保存返回错误提示。
	SourcePath string `json:"-"`
}

// WebConfig Web 面板（可选，addr 留空则不启动）
type WebConfig struct {
	Addr string `json:"addr,omitempty"`
	Auth string `json:"auth,omitempty"` // user:pass
	Cert string `json:"cert,omitempty"` // HTTPS 证书（可选）
	Key  string `json:"key,omitempty"`  // HTTPS 私钥（可选）
	// Bind 面板监听位置：
	//   "tunnel" — 仅绑定隧道 IP（server 用网关 IP，client 用分配的 IP，
	//              IPv4+IPv6 各一个 listener），不占本机物理网卡端口，
	//              面板只有进入隧道才能访问；
	//   "all"    — 绑定全部接口（旧行为）。
	// 端口取自 Addr 的端口部分。
	Bind string `json:"bind,omitempty"` // 默认 all
}

// ServerConfig 服务端专属
type ServerConfig struct {
	V4CIDR string `json:"v4_cidr,omitempty"` // 默认 10.0.0.0/24
	V6CIDR string `json:"v6_cidr,omitempty"` // 默认 fd00::/64
	Cert   string `json:"cert,omitempty"`    // 留空则自动生成并持久化自签证书
	Key    string `json:"key,omitempty"`
	// SessionToken 要求重连接入既有会话时回带会话令牌。
	// 关闭（默认）时保持旧行为：clientID + PSK + MAC 即可重连，
	// 因此任何持密者只要知道目标 MAC 就能冒充既有会话（clientID 由 mac+psk 推导）。
	// 开启后：令牌只在会话自己的 TLS 连接内下发一次，第三方无法取得，
	// 冒充既有会话被拒。代价是旧版客户端无法重连既有会话（首次接入不受影响），
	// 升级需两端同版本同时打开。
	SessionToken bool `json:"session_token,omitempty"`
}

// ClientConfig 客户端专属
type ClientConfig struct {
	ReqV4      string `json:"req_v4,omitempty"`
	ReqV6      string `json:"req_v6,omitempty"`
	SNI        string `json:"sni,omitempty"` // 默认 www.cloudflare.com
	Insecure   bool   `json:"insecure,omitempty"`
	CertSHA256 string `json:"cert_sha256,omitempty"` // 证书指纹锁定
	Fwmark     int    `json:"fwmark,omitempty"`
	Conns      int    `json:"conns,omitempty"` // 默认 1
	FEC        bool   `json:"fec,omitempty"`
	FecGroup   int    `json:"fec_group,omitempty"` // 默认 4
}

// exampleConfigJSON -print-config 输出的模板（可直接改用）
const exampleConfigJSON = `{
  "mode": "client",
  "psk": "change-me-please",
  "addr": "203.0.113.10:4000,[2001:db8::10]:4000",
  "log_level": "info",
  "encrypt": true,
  "min_enc": "gcm",
  "pad_mode": "bucket",
  "brutal": true,
  "brutal_up": 100,
  "brutal_down": 500,
  "socks5": "",
  "tap": "tap0",
  "mac": "",
  "web": {
    "addr": ":8080",
    "auth": "admin:change-me",
    "cert": "",
    "key": ""
  },
  "client": {
    "conns": 4,
    "fec": true,
    "fec_group": 4,
    "sni": "www.cloudflare.com",
    "insecure": false,
    "cert_sha256": "",
    "req_v4": "",
    "req_v6": "",
    "fwmark": 0
  },
  "server": {
    "v4_cidr": "10.0.0.0/24",
    "v6_cidr": "fd00::/64",
    "cert": "",
    "key": "",
    "session_token": false
  }
}`

// loadConfigFile 读取并解析 JSON 配置（未知字段报错），不包含默认值填充。
func loadConfigFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	cfg := &Config{}
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %v", path, err)
	}
	return cfg, nil
}

// applyDefaults 填充未指定的默认值（与命令行标志默认值保持一致）
func (c *Config) applyDefaults() {
	if c.PSK == "" {
		c.PSK = "quic_secret"
	}
	if c.Tap == "" {
		c.Tap = "tap0"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.PadMode == "" {
		c.PadMode = padModeBucket // 小帧填充到固定长度桶，开销远低于 legacy
	}
	if c.BrutalUp == 0 {
		c.BrutalUp = 100
	}
	if c.BrutalDown == 0 {
		c.BrutalDown = 500
	}
	if c.Web.Bind == "" {
		c.Web.Bind = "all"
	}
	if c.Web.Bind != "all" && c.Web.Bind != "tunnel" {
		// 不在 Validate 报错——早期校验时 log 可能未初始化，统一在启动时检查
		c.Web.Bind = "all"
	}
	if c.Mode == "server" {
		if c.Addr == "" {
			c.Addr = "0.0.0.0:4000"
		}
		if c.Server.V4CIDR == "" {
			c.Server.V4CIDR = "10.0.0.0/24"
		}
		if c.Server.V6CIDR == "" {
			c.Server.V6CIDR = "fd00::/64"
		}
	}
	if c.Mode == "client" {
		if c.Client.SNI == "" {
			c.Client.SNI = "www.cloudflare.com"
		}
		if c.Client.Conns == 0 {
			c.Client.Conns = 1
		}
		if c.Client.FecGroup == 0 {
			c.Client.FecGroup = 4
		}
	}
}

// Validate 校验配置合法性。在 applyDefaults 之后调用。
func (c *Config) Validate() error {
	switch c.Mode {
	case "server", "client":
	case "":
		return fmt.Errorf("mode is required (server or client)")
	default:
		return fmt.Errorf("invalid mode %q (must be server or client)", c.Mode)
	}
	if c.Addr == "" {
		return fmt.Errorf("addr is required")
	}
	var l zapcore.Level
	if err := l.UnmarshalText([]byte(c.LogLevel)); err != nil {
		return fmt.Errorf("invalid log_level %q", c.LogLevel)
	}
	if err := ensureBasicAuthFormat(c.Web.Auth); err != nil {
		return err
	}
	if (c.Web.Cert == "") != (c.Web.Key == "") {
		return fmt.Errorf("web.cert and web.key must be provided together")
	}
	if c.PSK == "quic_secret" {
		log.Warnf("⚠️  PSK is the default value — change it via -psk or the config file!")
	}
	switch c.MinEnc {
	case "", "any", "ctr", "legacy", "gcm":
	default:
		return fmt.Errorf("invalid min_enc %q (want ctr, gcm or empty)", c.MinEnc)
	}
	switch c.PadMode {
	case padModeOff, padModeLegacy, padModeBucket:
	default:
		return fmt.Errorf("invalid pad_mode %q (want %s, %s or %s)",
			c.PadMode, padModeOff, padModeLegacy, padModeBucket)
	}
	if c.MinEnc != "" && !c.Encrypt {
		return fmt.Errorf("min_enc %q requires encrypt=true", c.MinEnc)
	}

	if c.Mode == "server" {
		for name, cidr := range map[string]string{"v4_cidr": c.Server.V4CIDR, "v6_cidr": c.Server.V6CIDR} {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("invalid server.%s %q: %v", name, cidr, err)
			}
		}
	}

	if c.Mode == "client" {
		if c.Client.Conns < 1 {
			return fmt.Errorf("client.conns must be >= 1")
		}
		if c.Client.FecGroup < fecMinGroup || c.Client.FecGroup > fecMaxGroup {
			return fmt.Errorf("client.fec_group must be in [%d, %d]", fecMinGroup, fecMaxGroup)
		}
		if c.Client.Fwmark < 0 {
			return fmt.Errorf("client.fwmark must be >= 0")
		}
		if c.Client.CertSHA256 != "" {
			cleaned := strings.ToLower(strings.ReplaceAll(c.Client.CertSHA256, ":", ""))
			if len(cleaned) != 64 {
				return fmt.Errorf("client.cert_sha256 must be 64 hex chars (sha256)")
			}
		}
	}
	return nil
}

// SaveConfigFile 把配置以缩进 JSON 写回来源文件（面板"保存配置"用）。
// 写入采用 临时文件 + rename 原子替换，避免半写状态损坏配置。
// SourcePath 为空（命令行标志启动）时返回错误。
func SaveConfigFile(cfg *Config) error {
	if cfg.SourcePath == "" {
		return fmt.Errorf("configuration was not loaded from a file; specify -c to enable saving")
	}
	cfg.applyDefaults()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %v", err)
	}
	data = append(data, '\n')
	tmp := cfg.SourcePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write temp config: %v", err)
	}
	if err := os.Rename(tmp, cfg.SourcePath); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replace config: %v", err)
	}
	return nil
}
