package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestClientStatePath(t *testing.T) {
	if got := clientStatePath(&Config{}); got != "" {
		t.Errorf("无 SourcePath 时应不持久化，得到 %q", got)
	}
	want := filepath.FromSlash("cfg.json.state")
	if got := clientStatePath(&Config{SourcePath: "cfg.json"}); got != want {
		t.Errorf("clientStatePath = %q, want %q", got, want)
	}
}

func TestGenerateTapMAC(t *testing.T) {
	for i := 0; i < 50; i++ {
		s, err := generateTapMAC()
		if err != nil {
			t.Fatalf("generateTapMAC: %v", err)
		}
		mac, err := net.ParseMAC(s)
		if err != nil {
			t.Fatalf("生成结果不是合法 MAC %q: %v", s, err)
		}
		if len(mac) != 6 {
			t.Fatalf("MAC 长度 %d，应为 6", len(mac))
		}
		if mac[0]&0x01 != 0 {
			t.Errorf("MAC %s 置了组播位，不是单播地址", s)
		}
		if mac[0]&0x02 == 0 {
			t.Errorf("MAC %s 未置本地管理位", s)
		}
	}
	// 稳定性要求是"同一份状态文件 → 同一个 MAC"，随机性本身不要求唯一，
	// 但 50 次全同几乎不可能，顺带挡住生成器退化成常量。
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		s, err := generateTapMAC()
		if err != nil {
			t.Fatalf("generateTapMAC: %v", err)
		}
		seen[s] = true
	}
	if len(seen) < 10 {
		t.Errorf("生成器退化为常量：50 次只产出 %d 个不同 MAC", len(seen))
	}
}

func TestClientStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json.state")

	in := &clientState{
		ClientID:     "11111111-2222-3333-4444-555555555555",
		MAC:          "02:aa:bb:cc:dd:ee",
		SessionID:    "99999999-8888-7777-6666-555555555555",
		SessionToken: "deadbeef",
	}
	if err := saveClientState(path, in); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("原子写入后应无残留临时文件，stat err=%v", err)
	}
	out, err := loadClientState(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if *out != *in {
		t.Errorf("往返不一致：\n  in  %+v\n  out %+v", in, out)
	}
}

func TestLoadClientStateMissingAndCorrupt(t *testing.T) {
	dir := t.TempDir()

	st, err := loadClientState(filepath.Join(dir, "不存在.state"))
	if err != nil || st != nil {
		t.Errorf("文件不存在应返回 (nil, nil)，得到 (%+v, %v)", st, err)
	}
	st, err = loadClientState("")
	if err != nil || st != nil {
		t.Errorf("空路径应返回 (nil, nil)，得到 (%+v, %v)", st, err)
	}

	corrupt := filepath.Join(dir, "坏.state")
	if err := os.WriteFile(corrupt, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write corrupt: %v", err)
	}
	if st, err := loadClientState(corrupt); err == nil || st != nil {
		t.Errorf("损坏文件应返回错误，得到 (%+v, %v)", st, err)
	}
}

// TestClientStateOnlyPersistsWhenMACApplies 校验 applyTapMac 的守卫：
// 未显式配置 MAC 时生成并落盘；显式配置时不落盘（配置即事实来源）。
func TestClientStateOnlyPersistsWhenMACApplies(t *testing.T) {
	if !netlinkTunnelSupported() {
		t.Skip("隧道网卡配置在非 Linux 平台不可用")
	}

	dir := t.TempDir()
	statePath := filepath.Join(dir, "config.json.state")

	// 显式配置 MAC：不应写入状态文件
	st := &clientState{}
	applyTapMac("", "02:00:00:00:00:aa", statePath, st)
	if st.MAC != "" {
		t.Errorf("显式配置 MAC 时不应落盘，st.MAC=%q", st.MAC)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Errorf("显式配置 MAC 时不应创建状态文件，stat err=%v", err)
	}

	// tap 名为空时 setTapMac 必然失败：MAC 不得落盘（否则下次重启会用到
	// 一个实际没设置成功的地址）
	st = &clientState{}
	applyTapMac("", "", statePath, st)
	if st.MAC != "" {
		t.Errorf("setTapMac 失败时不应落盘，st.MAC=%q", st.MAC)
	}
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Errorf("setTapMac 失败时不应创建状态文件，stat err=%v", err)
	}
}

// TestPersistSessionState 校验会话身份落盘的绑定语义。
func TestPersistSessionState(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "config.json.state")

	// 无状态文件路径（进程内测试）：不落盘
	c := &Client{clientID: "cid-A", stateFile: ""}
	c.persistSessionState("sess-1", "tok-1")
	if _, err := os.Stat(statePath); !os.IsNotExist(err) {
		t.Errorf("stateFile 为空时不应创建文件，stat err=%v", err)
	}

	c = &Client{clientID: "cid-A", stateFile: statePath, state: &clientState{MAC: "02:00:00:00:00:01"}}
	c.persistSessionState("sess-1", "tok-1")
	st, err := loadClientState(statePath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if st.ClientID != "cid-A" || st.SessionID != "sess-1" || st.SessionToken != "tok-1" {
		t.Errorf("落盘内容不符: %+v", st)
	}
	if st.MAC != "02:00:00:00:00:01" {
		t.Errorf("落盘应保留 MAC，得到 %q", st.MAC)
	}

	// clientID 变化（MAC/PSK 改配置）时旧令牌按绑定校验不沿用
	c2 := &Client{clientID: "cid-B", stateFile: statePath, state: st}
	c2.persistSessionState("sess-2", "tok-2")
	st2, err := loadClientState(statePath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if st2.ClientID != "cid-B" || st2.SessionID != "sess-2" || st2.SessionToken != "tok-2" {
		t.Errorf("clientID 变化后应整体重写身份，得到 %+v", st2)
	}
}
