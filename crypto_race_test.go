package main

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestConcurrentSelfSignedGenerationConsistent 模拟全新 checkout（无预置证书）下
// e2e 夹具的并发首启：server 监听 goroutine 与客户端指纹辅助函数同时
// getServerTLSConfig("","")。修复前两者各自 rsa.GenerateKey 会生成不同证书，
// 后到者 pin 到的全局指纹与服务端所持证书不一致 → 握手持续失败
// （CI group G 首测 "tunnel did not come up"）。证书路径是相对 CWD 的常量，
// 因此 chdir 到空临时目录即可复现"无预置证书"。
func TestConcurrentSelfSignedGenerationConsistent(t *testing.T) {
	dir := t.TempDir()
	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(oldWd) }()

	const n = 16
	var wg sync.WaitGroup
	fps := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := getServerTLSConfig("", "")
			if len(c.Certificates) == 0 {
				t.Errorf("call %d: no certificate in config", i)
				return
			}
			fps[i] = certFingerprintHex(c.Certificates[0].Certificate[0])
		}(i)
	}
	wg.Wait()

	for i := 1; i < n; i++ {
		if fps[i] != fps[0] {
			t.Fatalf("concurrent callers observed different certs: %s vs %s", fps[i], fps[0])
		}
	}
	if got := serverCertFingerprint(); got != fps[0] {
		t.Fatalf("global fingerprint %s != served cert %s", got, fps[0])
	}
	if _, err := tls.LoadX509KeyPair(filepath.Join(dir, "tlsvpn-selfsigned-cert.pem"),
		filepath.Join(dir, "tlsvpn-selfsigned-key.pem")); err != nil {
		t.Fatalf("disk key/cert pair is a mixed (corrupt) pair: %v", err)
	}
}
