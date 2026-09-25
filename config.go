package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
	Mode     string `json:"mode"`                // 必填：server | client
	PSK      string `json:"psk"`                 // 预共享密钥
	Tap      string `json:"tap,omitempty"`       // TAP 设备名（默认 tap0）
	Mac      string `json:"mac,omitempty"`       // 手动指定 MAC
	Addr     string `json:"addr"`                // server: 监听地址；client: 目标地址列表
	LogLevel string `json:"log_level,omitempty"` // 默认 info
	Up       string `json:"up,omitempty"`        // 隧道就绪后执行一次（直接 exec，不经 shell）
	Down     string `json:"down,omitempty"`      // 进程退出/启动回滚时执行一次
	// 内层加密（GCM 协商）。刻意不带 omitempty：否则面板"保存配置"会丢掉
	// 显式的 false，下次重载又被默认值翻回 true。
	Encrypt    bool         `json:"encrypt"`
	MinEnc     string       `json:"min_enc,omitempty"`  // 最低内层加密强度：gcm（空/any=不设下限）
	PadMode    string       `json:"pad_mode,omitempty"` // 混淆填充：bucket | off（默认 bucket）
	Socks5     string       `json:"socks5,omitempty"`   // 全局 SOCKS5 出口（client）
	Brutal     bool         `json:"brutal,omitempty"`
	BrutalUp   uint64       `json:"brutal_up,omitempty"`   // Mbps
	BrutalDown uint64       `json:"brutal_down,omitempty"` // Mbps
	Web        WebConfig    `json:"web,omitempty"`
	Server     ServerConfig `json:"server,omitempty"`
	Client     ClientConfig `json:"client,omitempty"`

	// SourcePath 配置文件来源路径（-c 指定）；面板"保存配置"写回此文件。
	// 经命令行标志启动时为空，此时面板保存返回错误提示。
	SourcePath string `json:"-"`
	// EncryptPresent 标记配置文件里是否显式写了 encrypt。bool 无法自辨"字段
	// 缺失"与"显式 false"，靠这个标记让 loadConfigFile 能把"未写"当成开启处理。
	EncryptPresent bool `json:"-"`
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
	// MaxSessions 并发会话数上限（0 = 默认 1024）。v6 池在 /64 下实际不会
	// 枯竭，没有上限的话任何持 PSK 者轮换 MAC 即可无限创建会话（每会话
	// 3-4 个 goroutine + 4096 深发送队列 + 重排环形缓冲），直到 OOM。
	// 达到上限后新握手按认证失败处理（焦油坑）。可热更，作用于新会话。
	MaxSessions int `json:"max_sessions,omitempty"`
	// FecGroupMin/Max 是服务端接受的对端 FEC 分组大小 K 的区间。请求 FEC 而
	// K 越界的握手按请求形态错误拒连（不夹取、不降级，见 server.go 的拒连闸）。
	// 默认 [2, 64] = 协议允许范围，即默认不额外限制。
	// 方向注意：奇偶帧广播到全部 N 个后端，冗余开销是 N/K —— K 越大开销越小，
	// 所以限带宽要调高 min（地板），调低 max 限的是待收帧缓冲与恢复时延上限。
	FecGroupMin int `json:"fec_group_min,omitempty"`
	FecGroupMax int `json:"fec_group_max,omitempty"`
}

// ClientConfig 客户端专属
type ClientConfig struct {
	// InterfaceManager controls who owns L3 interface configuration.
	// "self" keeps the existing Linux behavior: tlsvpn brings the TAP up,
	// assigns tunnel addresses and manages policy routing itself.
	// "netifd" is for OpenWrt protocol-handler integration: tlsvpn still
	// creates and owns the TAP/data plane, while netifd owns addresses,
	// routes, metrics and firewall lifecycle through fixed helper scripts.
	InterfaceManager string `json:"interface_manager,omitempty"`
	ReqV4      string `json:"req_v4,omitempty"`
	ReqV6      string `json:"req_v6,omitempty"`
	SNI        string `json:"sni,omitempty"` // 默认 www.cloudflare.com
	Insecure   bool   `json:"insecure,omitempty"`
	CertSHA256 string `json:"cert_sha256,omitempty"` // 证书指纹锁定
	Fwmark     int    `json:"fwmark,omitempty"`
	// FwmarkPriority 是策略路由规则的优先级；0 = 交给内核分配（默认）。
	// 混有其他 ip rule 的机器上用它压住或抬高本项目的规则。
	FwmarkPriority int `json:"fwmark_priority,omitempty"`
	// ExtraRoutes 是 fwmark 表里除默认路由外的额外路由，语法取 iproute2 的序列化
	// 形式：单个前缀 + 可选 dev，例如 "fd99:10:5:8::/64 dev tap0"。地址族由前缀
	// 自动判定，无需再写 -4/-6；未写 dev 时默认走隧道网卡。配置加载期即校验。
	ExtraRoutes []string `json:"extra_routes,omitempty"`
	// SourceRules 按源地址前缀安装策略路由规则（ip rule from <from> table <table>）。
	//
	// 它和 Fwmark 匹配的东西根本不同：Fwmark 走 SO_MARK，只标记本进程自己写的包；
	// SourceRules 匹配包上的源地址，内核转发的流量同样命中。转发包没有任何 socket，
	// SO_MARK 碰不到它，所以"给 socket 打 mark"这条路对转发流量不适用，也只有
	// netfilter（nftables）能在 PREROUTING 给转发包注入 mark——SourceRules 按源
	// 前缀匹配，两者都不需要。
	//
	// 典型用途是 NPT 网关的回程路由：NPT 把内网地址翻译成公网前缀后，回程包的
	// 源地址就落在该公网前缀里（conntrack 的反向 NAT 在 PREROUTING 完成，早于
	// 路由决策），按源前缀即可把回程精确导向承载该前缀的接口。
	SourceRules []SourceRule `json:"source_rules,omitempty"`
	Conns       int          `json:"conns,omitempty"` // 默认 1
	FEC         bool         `json:"fec,omitempty"`
	FecGroup    int          `json:"fec_group,omitempty"` // 默认 4
}

// SourceRule 一条按源地址前缀匹配的策略路由规则。
type SourceRule struct {
	// From 源地址前缀，缺掩码时按主机路由补全（/32 或 /128）。
	From string `json:"from"`
	// Table 路由表号，必须显式给出。Fwmark 的表号等于 mark 值、不用填，这里没有
	// 可推导的来源，所以不允许省略。
	Table int `json:"table"`
	// Priority 规则优先级；0 = 交给内核分配。
	Priority int `json:"priority,omitempty"`
	// Routes 该表里除默认路由外的额外路由，语法同 ExtraRoutes。默认路由由程序
	// 按握手下发的网关自动写入，无需在这里重复声明。
	Routes []string `json:"routes,omitempty"`
}

// exampleConfigJSON -print-config 输出的模板（可直接改用）
const exampleConfigJSON = `{
  "mode": "client",
	  "psk": "REPLACE-WITH-A-RANDOM-SECRET",
  "addr": "203.0.113.10:4000,[2001:db8::10]:4000",
  "log_level": "info",
  "up": "",
  "down": "",
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
	    "auth": "admin:REPLACE-WITH-A-RANDOM-PASSWORD",
	    "bind": "tunnel",
    "cert": "",
    "key": ""
  },
  "client": {
    "interface_manager": "self",
    "conns": 4,
    "fec": true,
    "fec_group": 4,
    "sni": "www.cloudflare.com",
    "insecure": false,
    "cert_sha256": "",
    "req_v4": "",
    "req_v6": "",
		"fwmark": 0,
    "fwmark_priority": 0,
    "extra_routes": [],
    "source_rules": []
  },
  "server": {
    "v4_cidr": "10.0.0.0/24",
    "v6_cidr": "fd00::/64",
    "cert": "",
    "key": "",
    "max_sessions": 1024
  }
}`

// stripDeprecatedSessionTokenConfig removes the former server.session_token
// configuration switch before strict decoding. Session resume tokens are now a
// mandatory protocol property; the legacy key is accepted only so upgrades do
// not brick existing config files. Its value is intentionally ignored.
func stripDeprecatedSessionTokenConfig(data []byte) []byte {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return data
	}
	rawServer, ok := root["server"]
	if !ok {
		return data
	}
	var server map[string]json.RawMessage
	if err := json.Unmarshal(rawServer, &server); err != nil {
		return data
	}
	if _, ok := server["session_token"]; !ok {
		return data
	}
	delete(server, "session_token")
	cleanServer, err := json.Marshal(server)
	if err != nil {
		return data
	}
	root["server"] = cleanServer
	clean, err := json.Marshal(root)
	if err != nil {
		return data
	}
	return clean
}

// loadConfigFile 读取并解析 JSON 配置（未知字段报错），不包含默认值填充。
// 唯一例外是 encrypt：bool 无法自辨"字段缺失"与"显式 false"，而这里
// 是唯一还能看到原始 JSON 的地方，所以"未写按开启处理"的默认放在这里，
// 而不是放进共享的 applyDefaults。
func loadConfigFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %v", err)
	}
	decodeData := stripDeprecatedSessionTokenConfig(data)
	dec := json.NewDecoder(bytes.NewReader(decodeData))
	dec.DisallowUnknownFields()
	cfg := &Config{}
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %v", path, err)
	}
	var probe struct {
		Encrypt *bool `json:"encrypt"`
	}
	if json.Unmarshal(decodeData, &probe) == nil {
		cfg.EncryptPresent = probe.Encrypt != nil
		// 未写 encrypt 按开启处理：-print-config 模板一直输出 true，省略字段若仍
		// 按 bool 零值 false 处理，整条链路会静默跑明文，与模板读起来完全相反。
		// 只在这里默认，不进 applyDefaults——那是共享路径，按代码构造的
		// Config{Encrypt: false}（含测试与内嵌调用）不该被静默翻成加密。
		if probe.Encrypt == nil {
			cfg.Encrypt = true
		}
	}
	return cfg, nil
}

// applyDefaults 填充未指定的默认值（与命令行标志默认值保持一致）
func (c *Config) applyDefaults() {
	if c.Tap == "" {
		c.Tap = "tap0"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.PadMode == "" {
		c.PadMode = padModeBucket // 小帧填充到固定长度桶，额外线路开销远低于随机填充
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
	if c.Encrypt && c.MinEnc == "" {
		c.MinEnc = "gcm"
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
		if c.Server.MaxSessions == 0 {
			c.Server.MaxSessions = 1024
		}
		// 区间默认取协议边界，即未配置时不额外限制
		if c.Server.FecGroupMin == 0 {
			c.Server.FecGroupMin = fecMinGroup
		}
		if c.Server.FecGroupMax == 0 {
			c.Server.FecGroupMax = fecMaxGroup
		}
	}
	if c.Mode == "client" {
		if c.Client.InterfaceManager == "" {
			c.Client.InterfaceManager = "self"
		}
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
	if err := validateHookPath("up", c.Up); err != nil {
		return err
	}
	if err := validateHookPath("down", c.Down); err != nil {
		return err
	}
	if c.BrutalUp > maxBrutalRateMbps || c.BrutalDown > maxBrutalRateMbps {
		return fmt.Errorf("brutal_up/brutal_down must not exceed %d Mbps", maxBrutalRateMbps)
	}
	if c.Mode == "client" && c.Client.Conns > 1<<16 {
		return fmt.Errorf("client.conns must not exceed 65536")
	}
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
	psk := strings.TrimSpace(c.PSK)
	if psk == "" {
		return fmt.Errorf("psk is required; generate a high-entropy random secret")
	}
	switch strings.ToLower(psk) {
	case "quic_secret", "change-me", "change-me-please", "replace-with-a-random-secret":
		return fmt.Errorf("psk uses a known placeholder; replace it with a high-entropy random secret")
	}
	if c.Mac != "" && !isValidMACString(c.Mac) {
		return fmt.Errorf("invalid mac %q (want a non-zero unicast aa:bb:cc:dd:ee:ff address)", c.Mac)
	}
	var l zapcore.Level
	if err := l.UnmarshalText([]byte(c.LogLevel)); err != nil {
		return fmt.Errorf("invalid log_level %q", c.LogLevel)
	}
	if err := ensureBasicAuthFormat(c.Web.Auth); err != nil {
		return err
	}
	if strings.EqualFold(c.Web.Auth, "admin:change-me") || strings.EqualFold(c.Web.Auth, "admin:replace-with-a-random-password") {
		return fmt.Errorf("web.auth uses a known placeholder; replace it with a unique password")
	}
	if (c.Web.Cert == "") != (c.Web.Key == "") {
		return fmt.Errorf("web.cert and web.key must be provided together")
	}
	if c.Web.Bind != "all" && c.Web.Bind != "tunnel" {
		return fmt.Errorf("invalid web.bind %q (want all or tunnel)", c.Web.Bind)
	}
	if c.Web.Addr != "" && c.Web.Auth == "" {
		return fmt.Errorf("web.auth is required whenever the dashboard is enabled")
	}
	if c.Web.Addr != "" && c.Web.Bind == "all" && webAddrIsPublic(c.Web.Addr) {
		if c.Web.Cert == "" || c.Web.Key == "" {
			return fmt.Errorf("web.cert and web.key are required for a non-loopback dashboard listener")
		}
	}
	switch c.MinEnc {
	case "", "any", "gcm":
	default:
		return fmt.Errorf("invalid min_enc %q (want gcm, any or empty)", c.MinEnc)
	}
	switch c.PadMode {
	case padModeOff, padModeBucket:
	default:
		return fmt.Errorf("invalid pad_mode %q (want %s or %s)",
			c.PadMode, padModeOff, padModeBucket)
	}
	if c.MinEnc != "" && c.MinEnc != "any" && !c.Encrypt {
		return fmt.Errorf("min_enc %q requires encrypt=true", c.MinEnc)
	}

	if c.Mode == "server" {
		if c.Server.MaxSessions < 0 || c.Server.MaxSessions > 1<<20 {
			return fmt.Errorf("server.max_sessions %d out of range [0, 1048576]", c.Server.MaxSessions)
		}
		if c.Server.FecGroupMin < fecMinGroup || c.Server.FecGroupMin > fecMaxGroup {
			return fmt.Errorf("server.fec_group_min %d must be in [%d, %d]", c.Server.FecGroupMin, fecMinGroup, fecMaxGroup)
		}
		if c.Server.FecGroupMax < fecMinGroup || c.Server.FecGroupMax > fecMaxGroup {
			return fmt.Errorf("server.fec_group_max %d must be in [%d, %d]", c.Server.FecGroupMax, fecMinGroup, fecMaxGroup)
		}
		if c.Server.FecGroupMin > c.Server.FecGroupMax {
			return fmt.Errorf("server.fec_group_min %d must be <= fec_group_max %d", c.Server.FecGroupMin, c.Server.FecGroupMax)
		}
		for name, cidr := range map[string]string{"v4_cidr": c.Server.V4CIDR, "v6_cidr": c.Server.V6CIDR} {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("invalid server.%s %q: %v", name, cidr, err)
			}
		}
	}

	if c.Mode == "client" {
		switch c.Client.InterfaceManager {
		case "self", "netifd":
		default:
			return fmt.Errorf(
				"invalid client.interface_manager %q (want self or netifd)",
				c.Client.InterfaceManager,
			)
		}
		if c.Client.InterfaceManager == "netifd" &&
			(c.Client.Fwmark != 0 || len(c.Client.ExtraRoutes) != 0 || len(c.Client.SourceRules) != 0) {
			return fmt.Errorf(
				"client.interface_manager=netifd requires fwmark=0 and no extra_routes/source_rules; netifd must own OpenWrt routing",
			)
		}
		if c.Client.InterfaceManager == "netifd" && (c.Up != "" || c.Down != "") {
			return fmt.Errorf(
				"client.interface_manager=netifd does not allow top-level up/down hooks; netifd owns OpenWrt interface lifecycle",
			)
		}
		if c.Client.Conns < 1 {
			return fmt.Errorf("client.conns must be >= 1")
		}
		if c.Client.FecGroup < fecMinGroup || c.Client.FecGroup > fecMaxGroup {
			return fmt.Errorf("client.fec_group must be in [%d, %d]", fecMinGroup, fecMaxGroup)
		}
		if c.Client.Fwmark < 0 {
			return fmt.Errorf("client.fwmark must be >= 0")
		}
		// 优先级是 uint32；0 是"交给内核分配"的保留值，所以区间是 [0, 2^32)
		// ip rule 的 priority 是 uint32。负值不是合法的 uint32；上界不用
		// 裸 0xffffffff 常量（32 位平台上 int 只有 32 位，常量直接溢出），
		// 改用往返比较兜住两个方向。
		if c.Client.FwmarkPriority < 0 || int(uint32(c.Client.FwmarkPriority)) != c.Client.FwmarkPriority {
			return fmt.Errorf("client.fwmark_priority %d must be a uint32 in [0, 4294967295]", c.Client.FwmarkPriority)
		}
		if err := validateExtraRoutes(c.Client.ExtraRoutes); err != nil {
			return err
		}
		if err := validateSourceRules(c.Client.SourceRules); err != nil {
			return err
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

func validateHookPath(name, value string) error {
	if value == "" {
		return nil
	}
	if strings.IndexByte(value, 0) >= 0 || strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("%s hook path contains control characters", name)
	}
	// filepath.IsAbs follows the host OS, but config files are intentionally
	// portable. Accept POSIX absolute paths, Windows drive-rooted paths and UNC
	// paths regardless of which OS performs validation.
	isWindowsAbs := len(value) >= 3 &&
		((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) &&
		value[1] == ':' && (value[2] == '\\' || value[2] == '/')
	isUNC := strings.HasPrefix(value, "\\\\") || strings.HasPrefix(value, "//")
	if !filepath.IsAbs(value) && !strings.HasPrefix(value, "/") && !isWindowsAbs && !isUNC {
		return fmt.Errorf("%s hook must be an absolute executable path", name)
	}
	return nil
}

func webAddrIsPublic(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return true
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return true
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
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
