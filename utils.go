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

// isValidMACString 校验自报 MAC 的形态（允许为空 = 客户端未上报）。
func isValidMACString(s string) bool {
	if s == "" {
		return true
	}
	_, ok := parseMACKey(s)
	return ok
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// hashPSK 将明文 PSK 转换为 SHA256 防止明文传输
type PrefixConn struct {
	net.Conn
	prefix []byte
}

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

func serveFallbackHTTP(conn net.Conn, alpn string) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
