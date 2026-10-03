package main

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed webui
var webuiFS embed.FS

func webuiHandler() http.Handler {
	sub, err := fs.Sub(webuiFS, "webui")
	if err != nil { panic(err) }
	fileServer := http.FileServer(http.FS(sub))
	index, err := fs.ReadFile(sub, "index.html")
	if err != nil { panic(err) }
	login, err := fs.ReadFile(sub, "login.html")
	if err != nil { panic(err) }
	indexHTML := string(index)
	indexHTML = strings.Replace(indexHTML,
		`<button data-v="zh-CN" onclick="setLang('zh-CN')">中文</button>`,
		`<button data-v="zh-CN" onclick="setLang('zh-CN')">简中</button>
        <button data-v="zh-TW" onclick="setLang('zh-TW')">繁中</button>`, 1)
	indexHTML = strings.Replace(indexHTML, "</body>",
		"<script src=\"frameviz.js\"></script>\n<script src=\"metrics.js\"></script>\n<script src=\"stream.js\"></script>\n<script src=\"mcp-settings.js\"></script>\n</body>", 1)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") && r.URL.Path != "/" { http.NotFound(w, r); return }
		w.Header().Set("Cache-Control", "no-store")
		switch r.URL.Path {
		case "/", "/index.html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(indexHTML))
			return
		case "/login", "/login.html":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write(login)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}
