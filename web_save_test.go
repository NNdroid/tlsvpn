package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// startSaveHTTPHarness 起一个从 -c 文件加载配置的 Web 面板，完成登录，
// 返回带 cookie 的 client。用于回归 /api/control 的 save 语义。
func startSaveHTTPHarness(t *testing.T) (base, path string, client *http.Client) {
	return startSaveHTTPHarnessSrv(t, statsAuditServer())
}

// startSaveHTTPHarnessSrv 是 startSaveHTTPHarness 的变体：允许调用方注入一个
// 带 bootCfg 的真实 Server（模拟生产服务端），用于验证「服务端保存后刷新
// 返回新值」这一用户可感知的链路，而非仅用 bootCfg=nil 的测试替身。
func startSaveHTTPHarnessSrv(t *testing.T, srv *Server) (base, path string, client *http.Client) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "config.json")
	cfgJSON := `{
	  "mode": "server",
	  "psk": "test-only-high-entropy-secret-abcdefgh",
	  "addr": "127.0.0.1:4000",
	  "encrypt": true,
	  "enc_algo": "gcm256",
	  "routing_algo": "auto",
	  "fec_strategy": "auto",
	  "web": {"addr": "127.0.0.1:8080", "bind": "all", "auth": "admin:realpassword123"},
	  "server": {"v4_cidr": "10.0.0.0/24", "v6_cidr": "fd00::/64", "max_sessions": 1024}
	}`
	if err := os.WriteFile(path, []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfigFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.applyDefaults()
	cfg.SourcePath = path
	port := freePort(t)
	cfg.Web.Addr = fmt.Sprintf("127.0.0.1:%d", port)
	startWebServer(cfg.Web.Addr, srv, nil, "", "", "", cfg)
	waitListener(t, cfg.Web.Addr, 3*time.Second)
	base = cfg.Web.Addr

	jar, _ := cookiejar.New(nil)
	client = &http.Client{Timeout: 5 * time.Second, Jar: jar}
	loginBody, _ := json.Marshal(map[string]string{"username": "admin", "password": "realpassword123"})
	resp, err := client.Post("http://"+base+"/api/login", "application/json", strings.NewReader(string(loginBody)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("login failed: %d", resp.StatusCode)
	}
	return base, path, client
}

func getConfigFromPanel(t *testing.T, base string, client *http.Client) (int, string) {
	t.Helper()
	resp, err := client.Get("http://" + base + "/api/config")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(data)
}

func postControl(t *testing.T, base string, client *http.Client, action, postedCfg string) (int, string) {
	t.Helper()
	payload := fmt.Sprintf(`{"action":%q,"config":%s}`, action, postedCfg)
	req, _ := http.NewRequest(http.MethodPost, "http://"+base+"/api/control", strings.NewReader(payload))
	req.Header.Set("X-Requested-With", "tlsvpn")
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", action, err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(data)
}

// TestSaveReflectsInPanel 回归"保存了但没生效"：
// save（不 apply）后，GET /api/config 必须立即反映刚保存的值，
// 否则连续两次保存会以第一次保存前的旧配置为 base，静默回滚第一次的改动。
func TestSaveReflectsInPanel(t *testing.T) {
	base, _, client := startSaveHTTPHarness(t)

	// 改 brutal_up 100→200，只保存（不应用，避免重启数据面）
	code, body := postControl(t, base, client, "save",
		`{"mode":"server","psk":"test-only-high-entropy-secret-abcdefgh","addr":"127.0.0.1:4000","encrypt":true,"enc_algo":"gcm256","brutal_up":200,"web":{"addr":"127.0.0.1:8080","bind":"all"}}`)
	if code != http.StatusOK {
		t.Fatalf("save returned %d: %s", code, body)
	}

	// 面板编辑器（GET /api/config）必须看到 200，而不是旧的 100
	code, body = getConfigFromPanel(t, base, client)
	if code != http.StatusOK {
		t.Fatalf("GET /api/config returned %d: %s", code, body)
	}
	if !strings.Contains(body, `"brutal_up": 200`) {
		t.Errorf("save 后 GET /api/config 未反映新值（用户会以为保存失败）:\n%s", body)
	}
}

// TestSaveReflectsInPanelWithBootCfg 直接覆盖用户可感知的「服务端修改后保存、
// 刷新仍是旧值」场景：用带 bootCfg 的真实 Server（非 bootCfg=nil 的测试替身）
// 启动面板，保存 brutal_up 100→200，GET /api/config 必须返回 200，绝不能回滚成
// 启动值 100。此前 TestSaveReflectsInPanel 只用 statsAuditServer()（bootCfg=nil），
// 无法暴露 bootCfg 非空时 NeedsRestart 参与计算对保存链路的任何影响。
func TestSaveReflectsInPanelWithBootCfg(t *testing.T) {
	// 启动时配置（bootCfg）：applyDefaults 会把未写的 brutal_up 归一到 100
	dir := t.TempDir()
	bootPath := filepath.Join(dir, "boot.json")
	bootJSON := `{
	  "mode": "server",
	  "psk": "test-only-high-entropy-secret-abcdefgh",
	  "addr": "127.0.0.1:4000",
	  "encrypt": true,
	  "enc_algo": "gcm256",
	  "web": {"addr": "127.0.0.1:8080", "bind": "all", "auth": "admin:realpassword123"},
	  "server": {"v4_cidr": "10.0.0.0/24", "v6_cidr": "fd00::/64", "max_sessions": 1024}
	}`
	if err := os.WriteFile(bootPath, []byte(bootJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	bootCfg, err := loadConfigFile(bootPath)
	if err != nil {
		t.Fatal(err)
	}
	bootCfg.applyDefaults()
	if bootCfg.BrutalUp != 100 {
		t.Fatalf("bootCfg.brutal_up = %d, want 100 (applyDefaults 归一)", bootCfg.BrutalUp)
	}
	srv := statsAuditServer()
	srv.bootCfg = bootCfg

	base, _, client := startSaveHTTPHarnessSrv(t, srv)

	// 保存 brutal_up 100→200（仅保存，不热应用）
	code, body := postControl(t, base, client, "save",
		`{"mode":"server","psk":"test-only-high-entropy-secret-abcdefgh","addr":"127.0.0.1:4000","encrypt":true,"enc_algo":"gcm256","brutal_up":200,"web":{"addr":"127.0.0.1:8080","bind":"all"}}`)
	if code != http.StatusOK {
		t.Fatalf("save returned %d: %s", code, body)
	}

	// 刷新 GET /api/config：必须看到 200，绝不能回滚成启动值 100
	code, body = getConfigFromPanel(t, base, client)
	if code != http.StatusOK {
		t.Fatalf("GET /api/config returned %d: %s", code, body)
	}
	if !strings.Contains(body, `"brutal_up": 200`) {
		t.Errorf("带 bootCfg 的服务端 save 后 GET 未返回新值（刷新仍是旧值）:\n%s", body)
	}
	if strings.Contains(body, `"brutal_up": 100`) {
		t.Errorf("带 bootCfg 的服务端 save 后 GET 回滚成启动值 100（刷新显示旧值）:\n%s", body)
	}
}

// TestSaveStatsReflectsNewValue 回归「仅保存后状态卡回显旧值」：
// 带 bootCfg 的真实服务端仅保存 brutal_up 100→200 后，/api/stats 的 cfg.brutal_up
// 必须显示 200（与设置页 /api/config 一致），绝不能仍显示数据面生效值 100。
// 此前 stats.Cfg 读 s.cfg（仅保存不更新），导致设置页新值、状态卡旧值不一致。
func TestSaveStatsReflectsNewValue(t *testing.T) {
	dir := t.TempDir()
	bootPath := filepath.Join(dir, "boot.json")
	bootJSON := `{
	  "mode": "server",
	  "psk": "test-only-high-entropy-secret-abcdefgh",
	  "addr": "127.0.0.1:4000",
	  "encrypt": true,
	  "enc_algo": "gcm256",
	  "web": {"addr": "127.0.0.1:8080", "bind": "all", "auth": "admin:realpassword123"},
	  "server": {"v4_cidr": "10.0.0.0/24", "v6_cidr": "fd00::/64", "max_sessions": 1024}
	}`
	if err := os.WriteFile(bootPath, []byte(bootJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	bootCfg, err := loadConfigFile(bootPath)
	if err != nil {
		t.Fatal(err)
	}
	bootCfg.applyDefaults()
	srv := statsAuditServer()
	srv.bootCfg = bootCfg

	base, _, client := startSaveHTTPHarnessSrv(t, srv)

	// 仅保存 brutal_up 100→200
	code, body := postControl(t, base, client, "save",
		`{"mode":"server","psk":"test-only-high-entropy-secret-abcdefgh","addr":"127.0.0.1:4000","encrypt":true,"enc_algo":"gcm256","brutal_up":200,"web":{"addr":"127.0.0.1:8080","bind":"all"}}`)
	if code != http.StatusOK {
		t.Fatalf("save returned %d: %s", code, body)
	}

	// GET /api/stats：状态卡 cfg.brutal_up 必须反映新值 200
	resp, err := client.Get("http://" + base + "/api/stats")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/stats returned %d: %s", resp.StatusCode, string(data))
	}
	var stats struct {
		Cfg struct {
			BrutalUp uint64 `json:"brutal_up"`
		} `json:"cfg"`
	}
	if err := json.Unmarshal(data, &stats); err != nil {
		t.Fatalf("decode /api/stats: %v: %s", err, string(data))
	}
	if stats.Cfg.BrutalUp != 200 {
		t.Errorf("仅保存后状态卡 cfg.brutal_up = %d, want 200（回显旧值，与设置页不一致）", stats.Cfg.BrutalUp)
	}
}

// TestSaveTwiceDoesNotRollback 回归配置丢失：
// 第一次保存 A 字段，第二次（面板从运行态读到的内容）改 B 字段，
// A 字段必须仍在磁盘上，不能被回滚成启动值。
func TestSaveTwiceDoesNotRollback(t *testing.T) {
	base, path, client := startSaveHTTPHarness(t)

	// 面板两次保存都用 GET /api/config 的输出为 base：第一次改 brutal_up=200，
	// 第二次在面板看到的内容上改 brutal_down=600。第二次提交必须仍然携带
	// brutal_up=200，否则磁盘上第一次的改动会被回滚成启动值 100。
	baseCfg := `{"mode":"server","psk":"test-only-high-entropy-secret-abcdefgh","addr":"127.0.0.1:4000","encrypt":true,"enc_algo":"gcm256","web":{"addr":"127.0.0.1:8080","bind":"all"}}`
	code, body := postControl(t, base, client, "save", baseCfg[:1]+"\"brutal_up\":200,"+baseCfg[1:])
	if code != http.StatusOK {
		t.Fatalf("save #1: %d %s", code, body)
	}
	// 面板读到运行态后改 brutal_down
	code, body = getConfigFromPanel(t, base, client)
	if code != http.StatusOK {
		t.Fatalf("GET after save #1: %d", code)
	}
	full := body
	if !strings.Contains(full, `"brutal_up": 200`) {
		t.Errorf("save #1 后 GET 未含 brutal_up=200（会导致第二次保存回滚）:\n%s", full)
	}
	// 把 GET 输出替换成带 brutal_down 的版本：直接解析再改回更贴近面板行为
	var got map[string]any
	if err := json.Unmarshal([]byte(full), &got); err != nil {
		t.Fatalf("GET body 不是合法 JSON: %v", err)
	}
	got["brutal_down"] = 600
	second, _ := json.Marshal(got)
	code, body = postControl(t, base, client, "save", string(second))
	if code != http.StatusOK {
		t.Fatalf("save #2: %d %s", code, body)
	}
	saved, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(saved), `"brutal_up": 200`) {
		t.Errorf("第一次保存的 brutal_up=200 被回滚（配置丢失）:\n%s", saved)
	}
	if !strings.Contains(string(saved), `"brutal_down": 600`) {
		t.Errorf("第二次保存的 brutal_down=600 未落盘:\n%s", saved)
	}
}

// TestSaveEndToEndUserFlow 完整模拟用户在设置页的真实操作序列，逐环节断言：
//  1. GET /api/config 作为编辑 base（用户从设置页读到现有配置）
//  2. 改 brutal_up 后 save，GET /api/config 立即回显新值（设置页不旧值）
//  3. 同时 GET /api/stats 的 cfg 也回显新值（状态卡与设置页一致，不分裂）
//  4. 重新 GET /api/config 作为 base（模拟用户刷新后继续编辑），改另一个字段
//     再 save，第一次的改动必须仍在（不静默回滚），且设置页/状态卡都回显新值
func TestSaveEndToEndUserFlow(t *testing.T) {
	dir := t.TempDir()
	bootPath := filepath.Join(dir, "boot.json")
	bootJSON := `{
	  "mode": "server",
	  "psk": "test-only-high-entropy-secret-abcdefgh",
	  "addr": "127.0.0.1:4000",
	  "encrypt": true,
	  "enc_algo": "gcm256",
	  "brutal_up": 100,
	  "web": {"addr": "127.0.0.1:8080", "bind": "all", "auth": "admin:realpassword123"},
	  "server": {"v4_cidr": "10.0.0.0/24", "v6_cidr": "fd00::/64", "max_sessions": 1024}
	}`
	if err := os.WriteFile(bootPath, []byte(bootJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	bootCfg, err := loadConfigFile(bootPath)
	if err != nil {
		t.Fatal(err)
	}
	bootCfg.applyDefaults()
	srv := statsAuditServer()
	srv.bootCfg = bootCfg
	base, _, client := startSaveHTTPHarnessSrv(t, srv)

	// 1) 用户从设置页读到现有配置（作为编辑 base）
	code, body := getConfigFromPanel(t, base, client)
	if code != http.StatusOK {
		t.Fatalf("GET /api/config #1: %d %s", code, body)
	}
	editor := map[string]any{}
	if err := json.Unmarshal([]byte(body), &editor); err != nil {
		t.Fatalf("设置页 GET 不是合法 JSON: %v: %s", err, body)
	}

	// 2) 改 brutal_up 100→200，仅保存
	editor["brutal_up"] = 200
	first, _ := json.Marshal(editor)
	code, body = postControl(t, base, client, "save", string(first))
	if code != http.StatusOK {
		t.Fatalf("save #1: %d %s", code, body)
	}

	// 设置页回显：GET /api/config 立即返回 200（不旧值 100）
	code, body = getConfigFromPanel(t, base, client)
	if code != http.StatusOK {
		t.Fatalf("GET /api/config #2: %d", code)
	}
	if !strings.Contains(body, `"brutal_up": 200`) {
		t.Errorf("保存后设置页未回显 brutal_up=200（仍是旧值）:\n%s", body)
	}

	// 3) 状态卡回显：GET /api/stats 的 cfg.brutal_up 也必须是 200（与设置页一致）
	resp, err := client.Get("http://" + base + "/api/stats")
	if err != nil {
		t.Fatal(err)
	}
	statsBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/stats: %d %s", resp.StatusCode, string(statsBody))
	}
	var stats struct {
		Cfg struct {
			BrutalUp uint64 `json:"brutal_up"`
		} `json:"cfg"`
	}
	if err := json.Unmarshal(statsBody, &stats); err != nil {
		t.Fatalf("decode /api/stats: %v", err)
	}
	if stats.Cfg.BrutalUp != 200 {
		t.Errorf("保存后状态卡 cfg.brutal_up = %d, want 200（状态卡与设置页分裂）", stats.Cfg.BrutalUp)
	}

	// 4) 用户刷新设置页（重新 GET 作为 base），改另一个字段 brutal_down，再保存；
	//    第一次的 brutal_up=200 必须仍在（不静默回滚）
	code, body = getConfigFromPanel(t, base, client)
	if code != http.StatusOK {
		t.Fatalf("GET /api/config #3: %d", code)
	}
	editor2 := map[string]any{}
	if err := json.Unmarshal([]byte(body), &editor2); err != nil {
		t.Fatalf("设置页刷新 GET 不是合法 JSON: %v", err)
	}
	editor2["brutal_down"] = 600
	second, _ := json.Marshal(editor2)
	code, body = postControl(t, base, client, "save", string(second))
	if code != http.StatusOK {
		t.Fatalf("save #2: %d %s", code, body)
	}

	// 最终设置页回显：brutal_up 仍 200，brutal_down 已 600
	code, body = getConfigFromPanel(t, base, client)
	if code != http.StatusOK {
		t.Fatalf("GET /api/config #4: %d", code)
	}
	if !strings.Contains(body, `"brutal_up": 200`) {
		t.Errorf("第二次保存后 brutal_up=200 被回滚（配置丢失）:\n%s", body)
	}
	if !strings.Contains(body, `"brutal_down": 600`) {
		t.Errorf("第二次保存后 brutal_down=600 未回显:\n%s", body)
	}

	// 最终状态卡：brutal_up 仍 200（与设置页一致）
	resp, err = client.Get("http://" + base + "/api/stats")
	if err != nil {
		t.Fatal(err)
	}
	statsBody, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err := json.Unmarshal(statsBody, &stats); err != nil {
		t.Fatalf("decode /api/stats #2: %v", err)
	}
	if stats.Cfg.BrutalUp != 200 {
		t.Errorf("第二次保存后状态卡 cfg.brutal_up = %d, want 200", stats.Cfg.BrutalUp)
	}
}

// TestSaveMCPCredentialSetEcho 回归"MCP 凭据保存不上"（用户感知）：
// 凭据保存链路本身是通的（toEditor→POST→后端保留），但 GET /api/config 对
// credential 脱敏且不提供任何"已配置"信号，面板状态永远显示"尚未配置静态
// 凭据"——保存成功也像失败。修复：GET 派生 credential_set 布尔（校验器任何
// 前缀都可对弱口令离线爆破，布尔量零验证面），面板据此显示已配置。
// 本测试钉住整条链路：
//  1. 提交明文凭据 → GET credential 脱敏为空 + credential_set=true；
//  2. credential_set 是派生量：不落盘、面板回传被清除；
//  3. 二次不带凭据保存（保留语义）→ 凭据仍配置（credential_set 仍 true），
//     文件里的 credential 保持 sha256: 归一形态不被面板回传污染。
func TestSaveMCPCredentialSetEcho(t *testing.T) {
	base, path, client := startSaveHTTPHarness(t)

	// 1) 提交明文凭据（Bearer 模式）
	code, body := postControl(t, base, client, "save",
		`{"mode":"server","psk":"test-only-high-entropy-secret-abcdefgh","addr":"127.0.0.1:4000","encrypt":true,"enc_algo":"gcm256","web":{"addr":"127.0.0.1:8080","bind":"all","auth":"admin:realpassword123","mcp":{"auth_mode":"bearer","deploy":"public","credential":"my-mcp-bearer-token"}}}`)
	if code != http.StatusOK {
		t.Fatalf("save with credential returned %d: %s", code, body)
	}

	// GET：credential 脱敏为空、credential_set=true
	code, body = getConfigFromPanel(t, base, client)
	if code != http.StatusOK {
		t.Fatalf("GET after save returned %d: %s", code, body)
	}
	var cfg struct {
		Web struct {
			MCP struct {
				Credential    string `json:"credential"`
				CredentialSet bool   `json:"credential_set"`
			} `json:"mcp"`
		} `json:"web"`
	}
	if err := json.Unmarshal([]byte(body), &cfg); err != nil {
		t.Fatalf("decode GET /api/config: %v: %s", err, body)
	}
	if cfg.Web.MCP.Credential != "" {
		t.Errorf("credential must stay redacted in GET, got %q", cfg.Web.MCP.Credential)
	}
	if !cfg.Web.MCP.CredentialSet {
		t.Errorf("credential_set must be true after saving a credential (面板据此显示已配置):\n%s", body)
	}

	// 2) credential_set 是派生量：绝不落盘
	fileData, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(fileData), "credential_set") {
		t.Errorf("credential_set must never be persisted to the config file:\n%s", fileData)
	}
	if !strings.Contains(string(fileData), `"credential": "sha256:`) {
		t.Errorf("persisted credential must be the normalized sha256 verifier:\n%s", fileData)
	}

	// 3) 面板回传 credential_set:true（模拟 GET 回显后再保存）+ 空凭据：
	//    不得 400、派生量被清除、凭据保留语义生效（credential_set 仍 true）。
	code, body = postControl(t, base, client, "save",
		`{"mode":"server","psk":"test-only-high-entropy-secret-abcdefgh","addr":"127.0.0.1:4000","encrypt":true,"enc_algo":"gcm256","web":{"addr":"127.0.0.1:8080","bind":"all","auth":"admin:realpassword123","mcp":{"auth_mode":"bearer","deploy":"public","credential_set":true}}}`)
	if code != http.StatusOK {
		t.Fatalf("save echoing credential_set returned %d: %s", code, body)
	}
	code, body = getConfigFromPanel(t, base, client)
	if code != http.StatusOK {
		t.Fatalf("GET after second save returned %d: %s", code, body)
	}
	if err := json.Unmarshal([]byte(body), &cfg); err != nil {
		t.Fatalf("decode GET /api/config (2nd): %v: %s", err, body)
	}
	if !cfg.Web.MCP.CredentialSet {
		t.Errorf("credential_set must stay true after a keep-credential save (凭据被清掉=保存不上):\n%s", body)
	}
}
