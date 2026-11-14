package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// mcpAccessLine 是 WebUI"近期 MCP 访问日志"面板与 SSE 通道共用的记录。
// 与 logLine/evtJSON 同构：seq 单调递增供断线增量续传，内存只留最近 cap 条，
// 长期留痕归日志文件，内存不能随进程运行时长线性增长。
type mcpAccessLine struct {
	Seq    uint64 `json:"seq"`
	Time   string `json:"time"`
	Remote string `json:"remote,omitempty"`
	Level  string `json:"level"` // info | warn | error
	Method string `json:"method,omitempty"`
	Tool   string `json:"tool,omitempty"`
	Status int    `json:"status,omitempty"`
	DurMs  int64  `json:"dur_ms,omitempty"`
	Msg    string `json:"msg,omitempty"`
}

type mcpAccessRing struct {
	mu    sync.Mutex
	seq   uint64
	lines []mcpAccessLine
	cap   int
}

func newMCPAccessRing(capacity int) *mcpAccessRing {
	return &mcpAccessRing{cap: capacity}
}

// add 追加一条访问日志。满则丢最旧；seq 在此统一编号。
func (r *mcpAccessRing) add(line mcpAccessLine) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	line.Seq = r.seq
	if line.Time == "" {
		line.Time = time.Now().Format("15:04:05.000")
	}
	r.lines = append(r.lines, line)
	if len(r.lines) > r.cap {
		r.lines = r.lines[len(r.lines)-r.cap:]
	}
}

// snapshot 返回 seq 大于 after 的记录，供面板首次打开或断线重连补齐空档。
func (r *mcpAccessRing) snapshot(after uint64) []mcpAccessLine {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []mcpAccessLine{}
	for _, l := range r.lines {
		if l.Seq > after {
			out = append(out, l)
		}
	}
	return out
}

// mcpAccess 进程内唯一实例（容量 500，与 evBus/logRing 同量级）。
var mcpAccess = newMCPAccessRing(500)

// mcpRemoteHost 提取 RemoteAddr 的主机部分（去端口），供访问日志审计"谁在访问"。
func mcpRemoteHost(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// mcpRequestMethod best-effort 解析 JSON-RPC 请求体，提取 method 与
// tools/call 的工具名。读取后恢复 Body，让 MCP handler 能再次读取。
// 解析失败返回空（不阻断请求）。
func mcpRequestMethod(r *http.Request) (method, tool string) {
	if r.Body == nil {
		return "", ""
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		return "", ""
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	var msg struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if json.Unmarshal(body, &msg) != nil || msg.Method == "" {
		return "", ""
	}
	method = msg.Method
	if method == "tools/call" {
		tool = msg.Params.Name
	}
	return method, tool
}

// mcpStatusWriter 捕获 MCP handler 实际写出的 HTTP 状态码，供访问日志记录。
// 透传 Flusher（Streamable HTTP 可能用 SSE 流式响应）。
type mcpStatusWriter struct {
	http.ResponseWriter
	status int
}

func (w *mcpStatusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *mcpStatusWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

func (w *mcpStatusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
