package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestWebUIMCPSettingsSync 用 node 执行 testdata 的 webui-mcp-settings.test.js，
// 验证 webui/mcp-settings.js 的「JSON 编辑器 ↔ MCP 面板」同步：
//   - fromEditor 从顶层 cfg.web.mcp 填 MCP 面板（path/auth_mode/deploy/api_key_header）；
//   - JSON 编辑器 input 事件 → fromEditor 回填 MCP 面板（回归：此前无 editor
//     input 监听，用户直接在 cfg-editor 改 web.mcp.* 时 MCP 面板停在旧值，
//     造成「渲染旧值、JSON 新值」分裂）；
//   - saveConfig 保存后（无论是否热应用）都回填 fromEditor。
//
// 这是「设置页输入框与 JSON 编辑器分裂」的 MCP 面板侧回归：scheduler-settings
// 已覆盖调度面板，这里覆盖 MCP 认证面板。node 脚本放 testdata/（不进生产二进制）。
func TestWebUIMCPSettingsSync(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed; skipping WebUI MCP-settings DOM test")
	}
	out, err := exec.Command("node", "testdata/webui-mcp-settings.test.js").CombinedOutput()
	if err != nil {
		t.Fatalf("mcp-settings DOM test failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ALL PASS") {
		t.Fatalf("mcp-settings DOM test did not pass:\n%s", out)
	}
}
