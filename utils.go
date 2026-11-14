package main

import (
	"crypto/rand"
	"fmt"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

// fmtMAC 格式化 6 字节 MAC。入参为定长数组（VSwitch MAC 表的 key 形式），
// 避免每帧在 []byte 与 string 之间做转换拷贝。
func fmtMAC(mac macKey) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// parseMACKey 解析 "aa:bb:cc:dd:ee:ff"（大小写不敏感）为定长 MAC。
// 解析失败返回 false，调用方按无 MAC 处理。
func parseMACKey(s string) (macKey, bool) {
	var m macKey
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return m, false
	}
	for i, p := range parts {
		if len(p) != 2 {
			return m, false
		}
		b, err := strconv.ParseUint(p, 16, 8)
		if err != nil {
			return m, false
		}
		m[i] = byte(b)
	}
	return m, true
}

// isValidClientID 校验 clientID 为标准 UUID 形态（8-4-4-4-12，hex + 连字符）。
// clientID 由请求方自报并大量进入日志：不校验格式的话，换行注入可以伪造
// 日志行（日志聚合/告警按行解析时被注入伪事件）。
func isValidClientID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !isHexDigit(byte(c)) {
				return false
			}
		}
	}
	return true
}

// isValidMACString 要求可用于远端端口归属的非空单播 MAC。
func isValidMACString(s string) bool {
	m, ok := parseMACKey(s)
	if !ok || m == (macKey{}) {
		return false
	}
	return m[0]&1 == 0
}

// isValidClientInstance 限制握手日志与会话密钥代际标识。Go 客户端使用
// UUID，Rust 客户端使用 32 位 hex；共同闭集只需要 ASCII 字母数字与连字符。
func isValidClientInstance(s string) bool {
	if len(s) < 16 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-') {
			return false
		}
	}
	return true
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// hashPSK 将明文 PSK 转换为 SHA256 防止明文传输
type PrefixConn struct {
	net.Conn
	prefix []byte
}

// Unwrap exposes the underlying transport so socket-level optimizations such
// as TCP_MAXSEG/TCP_CORK can reach the real *net.TCPConn through PrefixConn.
func (c *PrefixConn) Unwrap() net.Conn { return c.Conn }

func (c *PrefixConn) Read(p []byte) (n int, err error) {
	if len(c.prefix) > 0 {
		n = copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

type singleConnListener struct {
	conn net.Conn
	done chan struct{}
}

func (s *singleConnListener) Accept() (net.Conn, error) {
	select {
	case <-s.done:
		return nil, net.ErrClosed
	default:
		close(s.done)
		return s.conn, nil
	}
}
func (s *singleConnListener) Close() error   { return nil }
func (s *singleConnListener) Addr() net.Addr { return s.conn.LocalAddr() }

// publicMCPDispatcher 让 VPN 公网 listener 的 TLS 后分派能按需暴露 MCP。
// 只持 WebManager：每次请求实时读当前配置的 deploy/path/auth_mode，
// 配置热更即时生效，无需单独 atomic 快照。
type publicMCPDispatcher struct {
	w *WebManager
}

// serveMCPIfMatch 在命中配置路径时接管请求并返回 true；否则返回 false，
// 调用方维持原有的 403 nginx 诱饵。deploy=internal 时一律 false（不暴露）。
func (d *publicMCPDispatcher) serveMCPIfMatch(rw http.ResponseWriter, r *http.Request) bool {
	if d == nil || d.w == nil {
		return false
	}
	cfg := d.w.Config().Web.MCP
	if !cfg.deployAllowsPublic() {
		return false
	}
	if cfg.matchesPath(r.URL.Path) {
		d.w.serveMCP(rw, r)
		return true
	}
	if isMCPMetadataPath(r.URL.Path) && normalizeMCPAuthMode(cfg.AuthMode) == mcpAuthOAuthJWT {
		d.w.serveMCPMetadata(rw, r)
		return true
	}
	return false
}

func serveFallbackHTTP(conn net.Conn, alpn string, mcp *publicMCPDispatcher) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if mcp.serveMCPIfMatch(w, r) {
			return
		}
		w.Header().Set("Server", "nginx")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(403)
		w.Write([]byte(`<html><head><title>403 Forbidden</title></head><body><center><h1>403 Forbidden</h1></center><hr><center>nginx</center></body></html>`))
	})
	if alpn == "h2" {
		srv := &http2.Server{IdleTimeout: 60 * time.Second}
		srv.ServeConn(conn, &http2.ServeConnOpts{Handler: handler})
	} else {
		l := &singleConnListener{conn: conn, done: make(chan struct{})}
		srv := &http.Server{Handler: handler, IdleTimeout: 60 * time.Second}
		srv.Serve(l)
	}
}

func camouflageProbe(conn net.Conn) {
	protectTarpit.Add(1)
	defer conn.Close()
	junkBuf := getFrame()
	defer putFrame(junkBuf)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		if _, err := conn.Read(junkBuf); err != nil {
			return
		}
		time.Sleep(time.Duration(mathrand.IntN(150)+50) * time.Millisecond)
		fakePayloadLen := mathrand.IntN(300) + 100
		fakeFrame := getFrameAtLeast(fakePayloadLen + 2)[:fakePayloadLen+2]
		fakeFrame[0] = 0x00
		fakeFrame[1] = byte(fakePayloadLen)
		rand.Read(fakeFrame[2:])
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, err := conn.Write(fakeFrame)
		putFrame(fakeFrame)
		if err != nil {
			return
		}
	}
}
