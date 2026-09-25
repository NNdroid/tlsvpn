package main

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// 面板静态资源独立存放在 webui/ 目录（index.html / style.css / app.js），
// 编译期整目录嵌入二进制，运行期零外部依赖。目录里的文件由
// dashboard_script_test.go 做词法级守护，改动 JS 前先跑那组测试。
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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// FileServer 会对目录生成列表页；面板只该暴露三个具名文件
		if strings.HasSuffix(r.URL.Path, "/") && r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		fileServer.ServeHTTP(w, r)
	})
}
