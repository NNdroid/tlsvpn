package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func rsaGenerateForTest() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

var randReaderForTest = rand.Reader

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hexEncodeToString(sum[:])
}

func hexEncodeToString(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexDigits[v>>4]
		out[i*2+1] = hexDigits[v&0x0f]
	}
	return string(out)
}

func colonHex(h string) string {
	if len(h) < 2 {
		return h
	}
	parts := make([]string, 0, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadConfigFileValid(t *testing.T) {
	p := writeTempConfig(t, `{
		"mode": "client",
		"psk": "my-secret",
		"addr": "1.2.3.4:4000",
		"encrypt": true,
		"web": {"addr": ":8080", "auth": "admin:pw"},
		"client": {"conns": 4, "fec": true, "fec_group": 8}
	}`)
	cfg, err := loadConfigFile(p)
	if err != nil {
		t.Fatal(err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.PSK != "my-secret" || cfg.Client.Conns != 4 || cfg.Client.FecGroup != 8 {
		t.Fatalf("字段解析不符: %+v", cfg)
	}
	if cfg.Client.SNI != "www.cloudflare.com" {
		t.Fatalf("SNI 默认值缺失: %s", cfg.Client.SNI)
	}
	if cfg.Web.Auth != "admin:pw" {
		t.Fatalf("web.auth 解析不符: %s", cfg.Web.Auth)
	}
}

func TestLoadConfigUnknownField(t *testing.T) {
	p := writeTempConfig(t, `{"mode":"client","addr":"1.2.3.4:4000","conns":2}`)
	// conns 在 client 子对象之下，顶层 conns 属未知字段
	_, err := loadConfigFile(p)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("未知字段应报错, got %v", err)
	}
}

func TestLoadConfigBadMode(t *testing.T) {
	p := writeTempConfig(t, `{"mode":"proxy","addr":"1.2.3.4:4000"}`)
	cfg, err := loadConfigFile(p)
	if err != nil {
		t.Fatal(err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err == nil {
		t.Fatal("非法 mode 应校验失败")
	}
}

func TestValidateServerBadCIDR(t *testing.T) {
	cfg := &Config{Mode: "server", PSK: "k", Addr: ":4000",
		Server: ServerConfig{V4CIDR: "not-a-cidr", V6CIDR: "fd00::/64"}}
	cfg.applyDefaults()
	if err := cfg.Validate(); err == nil {
		t.Fatal("非法 v4_cidr 应校验失败")
	}
}

func TestValidateWebAuthFormat(t *testing.T) {
	cfg := &Config{Mode: "client", PSK: "k", Addr: "1.2.3.4:4000",
		Web: WebConfig{Addr: ":8080", Auth: "no-colon-here"}}
	cfg.applyDefaults()
	if err := cfg.Validate(); err == nil {
		t.Fatal("无冒号的 web.auth 应校验失败")
	}
}

func TestValidateCertSHA256Length(t *testing.T) {
	cfg := &Config{Mode: "client", PSK: "k", Addr: "1.2.3.4:4000",
		Client: ClientConfig{CertSHA256: "aabb"}}
	cfg.applyDefaults()
	if err := cfg.Validate(); err == nil {
		t.Fatal("长度不足的 cert_sha256 应校验失败")
	}
	cfg.Client.CertSHA256 = strings.Repeat("ab", 32)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("64 位 hex 指纹应通过: %v", err)
	}
}

func TestExampleConfigParses(t *testing.T) {
	p := writeTempConfig(t, exampleConfigJSON)
	cfg, err := loadConfigFile(p)
	if err != nil {
		t.Fatalf("-print-config 模板必须始终可解析: %v", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("模板必须通过校验: %v", err)
	}
}

// TestRepoExampleConfigsValid 保证仓库根目录的示例配置与 schema 同步：
// 配置结构体字段变更而示例未跟时，本测试立即失败。
// 注意：不与 TestSelfSignedCertPersistence 并行——该测试会 os.Chdir，
// 而本测试依赖仓库根目录的相对路径。
func TestRepoExampleConfigsValid(t *testing.T) {
	for _, name := range []string{"config.server.json", "config.client.json"} {
		cfg, err := loadConfigFile(name)
		if err != nil {
			t.Errorf("%s 解析失败: %v", name, err)
			continue
		}
		cfg.applyDefaults()
		if err := cfg.Validate(); err != nil {
			t.Errorf("%s 校验失败: %v", name, err)
			continue
		}
		switch name {
		case "config.server.json":
			if cfg.Mode != "server" {
				t.Errorf("%s 的 mode 应为 server", name)
			}
		case "config.client.json":
			if cfg.Mode != "client" || cfg.Client.Conns < 1 {
				t.Errorf("%s 的 client 段不完整", name)
			}
		}
	}
}

func TestCertHashVerification(t *testing.T) {
	// 生成一张临时自签证书
	key, err := rsaGenerateForTest()
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "hash-test"}}
	der, err := x509.CreateCertificate(randReaderForTest, &tmpl, &tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256Hex(der)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	// 正确指纹（大小写不敏感）
	if err := verifyCertHash([][]byte{der}, strings.ToUpper(sum)); err != nil {
		t.Fatalf("正确指纹应通过: %v", err)
	}
	// 冒号分隔格式
	if err := verifyCertHash([][]byte{der}, colonHex(sum)); err != nil {
		t.Fatalf("冒号分隔指纹应通过: %v", err)
	}
	// 错误指纹必须失败（回归：sha256.New().Sum() 旧实现恒失败）
	if err := verifyCertHash([][]byte{der}, strings.Repeat("ab", 32)); err == nil {
		t.Fatal("错误指纹必须失败")
	}
	// 空证书链
	if err := verifyCertHash(nil, sum); err == nil {
		t.Fatal("空证书链应失败")
	}
	_ = certPEM
}

func TestSelfSignedCertPersistence(t *testing.T) {
	dir := t.TempDir()
	oldWd, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWd)

	c1 := getServerTLSConfig("", "")
	if len(c1.Certificates) == 0 {
		t.Fatal("证书链为空")
	}
	if _, err := os.Stat(selfSignedCertFile); err != nil {
		t.Fatalf("自签证书应持久化到磁盘: %v", err)
	}
	if _, err := os.Stat(selfSignedKeyFile); err != nil {
		t.Fatalf("自签私钥应持久化到磁盘: %v", err)
	}
	// 重启（再次调用）必须复用同一证书 —— 指纹锁定不因重启失效
	cfg2 := getServerTLSConfig("", "")
	if len(cfg2.Certificates) == 0 {
		t.Fatal("证书链为空")
	}
	fp1 := certFingerprintHex(c1.Certificates[0].Certificate[0])
	fp2 := certFingerprintHex(cfg2.Certificates[0].Certificate[0])
	if fp1 != fp2 {
		t.Fatalf("两次启动应复用同一张自签证书: %s != %s", fp1, fp2)
	}
}
