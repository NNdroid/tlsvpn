package main

import (
	"crypto/rand"
	"encoding/json"
	"net"
	"os"
)

// clientState 是客户端落盘的进程身份：TAP MAC、会话 ID、会话令牌。
// MAC 派生 clientID，clientID 决定服务端会话与分配的隧道 IP。三者跨进程
// 稳定之后，客户端被杀或崩溃重启才能无缝接回原会话，而不是等 120 秒僵尸
// 会话过期才自然恢复连通。
type clientState struct {
	ClientID     string `json:"client_id"`
	MAC          string `json:"mac,omitempty"`
	SessionID    string `json:"session_id,omitempty"`
	SessionToken string `json:"session_token,omitempty"`
	SessionEpoch uint64 `json:"session_epoch,omitempty"`
}

// clientStatePath 状态文件紧随配置文件（<config>.state）。未从文件加载配置
// （进程内测试）时不持久化。
func clientStatePath(cfg *Config) string {
	if cfg.SourcePath == "" {
		return ""
	}
	return cfg.SourcePath + ".state"
}

func loadClientState(path string) (*clientState, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	st := &clientState{}
	if err := json.Unmarshal(data, st); err != nil {
		return nil, err
	}
	return st, nil
}

// saveClientState 原子写入状态文件。权限 0600：内容含会话令牌，令牌与 PSK
// 共同构成"持密者也不能冒充在线会话"的防御，泄露等同削弱会话隔离。
func saveClientState(path string, st *clientState) error {
	if path == "" || st == nil {
		return nil
	}
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// generateTapMAC 生成随机 MAC：清掉组播位、置本地管理位，保证是合法单播地址。
func generateTapMAC() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[0] = (b[0] & 0xfe) | 0x02
	return net.HardwareAddr(b).String(), nil
}
