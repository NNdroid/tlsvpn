package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestWebUIDropdownSyncOnProgrammaticWrite 用 node 执行 testdata 的
// webui-dropdown-sync.test.js，验证 app.js 自定义下拉对 programmatic
// select.value 赋值的视图同步：
//
//  1. 自定义下拉按钮文案只在原生 change 事件上同步，而 loadConfig 后
//     scheduler-settings 的 fromEditor 对 select.value 做 programmatic 赋值
//     （不派发 change），按钮文案停在构建时的默认值——线上故障为
//     「/api/config 返回 latency_sticky/near/fwd，调度设置下拉显示
//     auto/auto/rtt，而 near/fwd 条件字段与数值输入框都正确」。
//  2. 修复：app.js 在 HTMLSelectElement.prototype 上劫持 value setter，
//     任何来源的赋值都自动 syncSelect；未注册的 select 零开销。
//
// 测试按真实时序加载 app.js + scheduler-settings.js 两个真实脚本
// （syncSelects 先按默认值构建文案 → wrapped loadConfig 注入配置 →
// fromEditor 赋值），断言按钮文案跟随。node 脚本放 testdata/
// （go:embed webui 不会把它打进生产二进制）。
func TestWebUIDropdownSyncOnProgrammaticWrite(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not installed; skipping WebUI dropdown-sync DOM test")
	}
	out, err := exec.Command("node", "testdata/webui-dropdown-sync.test.js").CombinedOutput()
	if err != nil {
		t.Fatalf("dropdown-sync DOM test failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ALL PASS") {
		t.Fatalf("dropdown-sync DOM test did not pass:\n%s", out)
	}
}
