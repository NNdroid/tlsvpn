package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestWebUISchedulerSettingsTopLevelAccess 用 node 执行 testdata 的
// webui-scheduler-settings.test.js，验证 webui/scheduler-settings.js 的 fromEditor
// 读**顶层** routing_algo / fec_strategy / fec_near_window_ms（迁移后位置），
// toEditor 写顶层而非旧 client 块。这是配置迁移的 WebUI 侧回归：若 JS 仍读
// cfg.client 块，DOM 下拉框会为空，测试失败。
// 注意：node 脚本放 testdata/（go:embed webui 不会把它打进生产二进制）。
func TestWebUISchedulerSettingsTopLevelAccess(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed; skipping WebUI scheduler-settings DOM test")
	}
	out, err := exec.Command("node", "testdata/webui-scheduler-settings.test.js").CombinedOutput()
	if err != nil {
		t.Fatalf("scheduler-settings DOM test failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ALL PASS") {
		t.Fatalf("scheduler-settings DOM test did not pass:\n%s", out)
	}
}
