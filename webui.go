package main

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

// 面板静态资源独立存放在 webui/ 目录并在编译期整目录嵌入二进制，
// 运行期零外部依赖。app.js 由 dashboard_script_test.go 做词法级守护，
// 改动主脚本前先跑那组测试。附加功能保持独立脚本，避免继续膨胀主脚本。
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

	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		panic(err)
	}
	indexHTML := string(index)
	// WebUI 主文件仍以 zh-CN 为 canonical key set；繁中 locale 在 app.js
	// 执行后克隆同一棵 key tree，因此新增 key 不会因两份手写字典而漏翻。
	indexHTML = strings.Replace(indexHTML,
		`<button data-v="zh-CN" onclick="setLang('zh-CN')">中文</button>`,
		`<button data-v="zh-CN" onclick="setLang('zh-CN')">简中</button>
        <button data-v="zh-TW" onclick="setLang('zh-TW')">繁中</button>`, 1)
	indexHTML = strings.Replace(indexHTML, "</body>",
		"<script src=\"zh-tw.js\"></script>\n<script src=\"frameviz.js\"></script>\n<script src=\"frameviz-zh-tw.js\"></script>\n</body>", 1)

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
