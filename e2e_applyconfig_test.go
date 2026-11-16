package main

import (
	"bytes"
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// applyConfigPingHarness 建立 conns=2+FEC 隧道，注入 ping 观测回复，返回窗口函数。
// 用于在 ApplyConfig 前后分别测 ping 是否通。
func applyConfigPingHarness(t *testing.T, h *perfHarness) (pingWindow func(label string, count int) int) {
	t.Helper()
	replyCh := make(chan uint32, 4096)
	var seen sync.Map
	h.srvTap.SetOnWrite(func(b []byte) {
		if len(b) >= 14 && bytes.Equal(b[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}) {
			go func() {
				rev := append([]byte(nil), b...)
				copy(rev[0:6], b[6:12])
				copy(rev[6:12], b[0:6])
				h.cliTap.Write(rev)
			}()
		}
	})
	h.cliTap.SetOnWrite(func(b []byte) {
		if len(b) >= 14+20+4 {
			seq := binary.BigEndian.Uint32(b[14+20 : 14+20+4])
			if _, ok := seen.Load(seq); ok {
				select {
				case replyCh <- seq:
				default:
				}
			}
		}
	})
	return func(label string, count int) int {
		replies := 0
		for i := 0; i < count; i++ {
			seq := uint32(i + 1)
			seen.Store(seq, time.Now())
			payload := make([]byte, 100)
			binary.BigEndian.PutUint32(payload[0:4], seq)
			h.tapWriter(buildEthFrame(seq, payload))
			time.Sleep(10 * time.Millisecond)
		}
		deadline := time.After(4 * time.Second)
		for replies < count {
			select {
			case <-replyCh:
				replies++
			case <-deadline:
				goto out
			}
		}
	out:
		t.Logf("%s: %d/%d replies", label, replies, count)
		return replies
	}
}

// runApplyConfigPingSubtest 建立 harness，测基线 ping，ApplyConfig(mutate) 后重连，再测 ping。
func runApplyConfigPingSubtest(t *testing.T, name string, mutate func(cfg *Config)) {
	t.Run(name, func(t *testing.T) {
		h := startPerfHarness(t, 2, true, true)
		defer h.stop()
		time.Sleep(500 * time.Millisecond)

		newCfg := &Config{
			Mode: "client", PSK: "test-only-high-entropy-secret", Tap: "mem", Addr: h.srvAddr,
			Mac: "02:00:00:00:00:02", Encrypt: true,
			RoutingAlgo: "auto", FecStrategy: "auto", FecNearWindowMs: 10,
			Client: ClientConfig{
				Conns: 2, FEC: true, FecGroup: 4, Insecure: true, CertSHA256: e2eServerCertFingerprint(),
			},
		}
		newCfg.applyDefaults()
		if mutate != nil {
			mutate(newCfg)
		}
		if err := newCfg.Validate(); err != nil {
			t.Fatalf("mutated cfg invalid: %v", err)
		}

		ping := applyConfigPingHarness(t, h)
		if base := ping("baseline", 20); base == 0 {
			t.Fatal("baseline ping lost BEFORE ApplyConfig — harness broken")
		}
		t.Logf("calling ApplyConfig (%s)...", name)
		h.cli.ApplyConfig(newCfg)
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if atomic.LoadInt32(&h.cli.liveConns) >= 1 {
				time.Sleep(300 * time.Millisecond)
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		post := ping("after-apply", 20)
		if post == 0 {
			t.Fatalf("REPRODUCED (%s): ping fully lost after ApplyConfig", name)
		}
		if post < 19 {
			t.Logf("partial loss (%s): %d/20", name, post)
		}
	})
}

func TestE2EApplyConfigSchedulerHotReload(t *testing.T) {
	runApplyConfigPingSubtest(t, "scheduler-fields-only", func(cfg *Config) {
		cfg.RoutingAlgo = "auto"
		cfg.FecStrategy = "auto"
		cfg.FecNearWindowMs = 10
	})
	runApplyConfigPingSubtest(t, "routing-algo-nondefault", func(cfg *Config) {
		cfg.RoutingAlgo = "latency_strict"
	})
	runApplyConfigPingSubtest(t, "fec-strategy-near", func(cfg *Config) {
		cfg.FecStrategy = "near"
	})
	runApplyConfigPingSubtest(t, "handshake-fields-fec-off", func(cfg *Config) {
		cfg.Client.FEC = false
	})
}
