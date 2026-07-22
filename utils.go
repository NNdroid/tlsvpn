package main

import (
	"crypto/rand"
	"fmt"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

func fmtMAC(mac []byte) string {
	if len(mac) != 6 {
		return "invalid_mac"
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
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
		fakeFrame := getFrame()[:fakePayloadLen+2]
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
