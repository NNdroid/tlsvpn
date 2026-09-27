package main

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// 面板静态资源独立存放在 webui/ 目录并在编译期整目录嵌入二进制，
// 运行期零外部依赖。app.js 由 dashboard_script_test.go 做词法级守护，
// 改动主脚本前先跑那组测试。frameviz.js 独立加载，避免把协议示意逻辑
// 混入已经很大的主面板脚本。
//
//go:embed webui
var webuiFS embed.FS

// webuiHandler 服务内嵌面板资源。资产随二进制发布、URL 不带版本号，
// 统一 no-store：升级后浏览器不能还拿旧面板去打新 API。
func webuiHandler() http.Handler {
	sub, err := fs.Sub(webuiFS, "webui")
	if err != nil {
		panic(err) // embed 路径是编译期常量，出错只能说明实现写错了
	}
	fileServer := http.FileServer(http.FS(sub))

	// index.html 保持原文件简单；在响应时插入独立的帧格式可视化脚本。
	// 这样无需复制主面板的 I18N/状态逻辑，也不会改变 app.js 的加载顺序。
	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		panic(err)
	}
	indexHTML := strings.Replace(string(index), "</body>", "<script src=\"frameviz.js\"></script>\n</body>", 1)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// FileServer 会对目录生成列表页；面板只允许根页面和具名静态资产。
		if strings.HasSuffix(r.URL.Path, "/") && r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Path == "/" || r.URL.Path == "/index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(indexHTML))
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}
