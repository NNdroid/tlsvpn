package main

import (
	"bufio"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
)

// PeerInfo 是握手阶段交换的诊断元数据。它只用于可观测性/版本诊断，
// 绝不能参与认证或授权判定；对端可以自行伪造这些字段。
type PeerInfo struct {
	Implementation string `json:"implementation,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
	OS             string `json:"os,omitempty"`
	OSVersion      string `json:"os_version,omitempty"`
	Kernel         string `json:"kernel,omitempty"`
	Arch           string `json:"arch,omitempty"`
	Version        string `json:"version,omitempty"`
	GitCommit      string `json:"git_commit,omitempty"`
	BuildTime      string `json:"build_time,omitempty"`
}

const peerInfoFieldMax = 256

var (
	peerInfoOnce  sync.Once
	peerInfoLocal PeerInfo
)

func localPeerInfo() *PeerInfo {
	peerInfoOnce.Do(func() { peerInfoLocal = collectPeerInfo() })
	p := peerInfoLocal
	return &p
}

func collectPeerInfo() PeerInfo {
	host, _ := os.Hostname()
	p := PeerInfo{
		Implementation: "go",
		Hostname:       host,
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		Version:        appVersion,
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		p.OSVersion = readOSReleasePrettyName("/etc/os-release")
		p.Kernel = readTrimmedFile("/proc/sys/kernel/osrelease")
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if p.Version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			p.Version = bi.Main.Version
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				p.GitCommit = s.Value
			case "vcs.time":
				p.BuildTime = s.Value
			}
		}
	}
	return normalizePeerInfo(&p)
}

// normalizePeerInfo 在信任边界裁剪对端自报字段，避免异常大的字符串长期挂在
// logical session 上。nil 表示旧版本对端未提供 metadata。
func normalizePeerInfo(in *PeerInfo) PeerInfo {
	if in == nil {
		return PeerInfo{}
	}
	return PeerInfo{
		Implementation: trimPeerField(in.Implementation),
		Hostname:       trimPeerField(in.Hostname),
		OS:             trimPeerField(in.OS),
		OSVersion:      trimPeerField(in.OSVersion),
		Kernel:         trimPeerField(in.Kernel),
		Arch:           trimPeerField(in.Arch),
		Version:        trimPeerField(in.Version),
		GitCommit:      trimPeerField(in.GitCommit),
		BuildTime:      trimPeerField(in.BuildTime),
	}
}

func trimPeerField(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > peerInfoFieldMax {
		v = v[:peerInfoFieldMax]
	}
	return v
}

func readTrimmedFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readOSReleasePrettyName(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if !strings.HasPrefix(line, "PRETTY_NAME=") {
			continue
		}
		v := strings.TrimPrefix(line, "PRETTY_NAME=")
		v = strings.Trim(v, "\"")
		return strings.TrimSpace(v)
	}
	return ""
}

func peerInfoEmpty(p PeerInfo) bool {
	return p == (PeerInfo{})
}

// remotePeerInfoSnapshot returns a copy so WebUI serialization never races a reconnect.
func (c *Client) remotePeerInfoSnapshot() *PeerInfo {
	c.sessionMu.Lock()
	p := c.peerInfo
	c.sessionMu.Unlock()
	if peerInfoEmpty(p) {
		return nil
	}
	return &p
}
