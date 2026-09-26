package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const (
	hookTimeout   = 30 * time.Second
	hookOutputCap = 64 * 1024
)

// HookEnv is the stable process-lifecycle information exported to up/down
// scripts.  The lower-case names mirror the most useful OpenVPN variables;
// the TLSVPN_* aliases avoid ambiguity in scripts shared by several VPNs.
type HookEnv struct {
	Mode      string
	Dev       string
	Config    string
	IPv4      string
	IPv6      string
	GatewayV4 string
	GatewayV6 string
}

type hookCommandRunner func(path, workDir string, env []string) (string, error)

// LifecycleHooks executes each hook at most once.  A client with several
// physical connections calls Up concurrently after handshakes; sync.Once makes
// that a single logical tunnel event instead of one event per TCP connection.
type LifecycleHooks struct {
	upPath   string
	downPath string
	run      hookCommandRunner

	upOnce   sync.Once
	downOnce sync.Once
	mu       sync.Mutex
	active   bool
	env      HookEnv
	upErr    error
	downErr  error
	// 面板可见的最后一次执行结果：过去只有日志，面板不知道 up 钩子跑成功没有
	upInfo   hookRunInfo
	downInfo hookRunInfo
}

// hookRunInfo 单次钩子执行的结果。耗时与错误原文都只保留给运维看的信息。
type hookRunInfo struct {
	ran bool
	ok  bool
	ms  int64
	out string
	err error
}

func NewLifecycleHooks(upPath, downPath string) *LifecycleHooks {
	return newLifecycleHooksWithRunner(upPath, downPath, runHookCommand)
}

func newLifecycleHooksWithRunner(upPath, downPath string, run hookCommandRunner) *LifecycleHooks {
	return &LifecycleHooks{upPath: upPath, downPath: downPath, run: run}
}

func (h *LifecycleHooks) Configured() bool { return h.upPath != "" || h.downPath != "" }

func (h *LifecycleHooks) Activate(env HookEnv) {
	h.mu.Lock()
	h.active = true
	h.env = env
	h.mu.Unlock()
}

// Up marks the logical tunnel active and invokes the configured up hook.  Even
// a failed up attempt is considered active so Down can roll back partial work.
func (h *LifecycleHooks) Up(env HookEnv) error {
	h.upOnce.Do(func() {
		h.Activate(env)
		if h.upPath == "" {
			return
		}
		info := h.runRecorded("up", h.upPath, hookWorkDir(env.Config), hookEnvironment("up", env))
		h.mu.Lock()
		h.upInfo = info
		h.upErr = info.err
		h.mu.Unlock()
		if info.out != "" && log != nil {
			log.Infof("up hook output: %s", info.out)
		}
	})
	return h.upErr
}

// Down invokes the configured down hook once, using the exact environment
// snapshot that activated the tunnel.  It intentionally uses a fresh timeout,
// not the already-cancelled process context.
func (h *LifecycleHooks) Down() error {
	h.downOnce.Do(func() {
		h.mu.Lock()
		active, env := h.active, h.env
		h.mu.Unlock()
		if !active || h.downPath == "" {
			return
		}
		info := h.runRecorded("down", h.downPath, hookWorkDir(env.Config), hookEnvironment("down", env))
		h.mu.Lock()
		h.downInfo = info
		h.downErr = info.err
		h.mu.Unlock()
		if info.out != "" && log != nil {
			log.Infof("down hook output: %s", info.out)
		}
	})
	return h.downErr
}

// runRecorded 执行钩子并记录面板可见的结果（成功与否、耗时、错误原文）。
// 返回值同时保留输出用于日志，err 为 nil 表示退出码为 0 且未超时。
func (h *LifecycleHooks) runRecorded(kind, path, workDir string, env []string) hookRunInfo {
	start := time.Now()
	out, err := h.run(path, workDir, env)
	info := hookRunInfo{ran: true, ok: err == nil, ms: time.Since(start).Milliseconds(), out: out}
	if err != nil {
		info.err = hookError(kind, path, out, err)
	}
	return info
}

// Status 供面板显示钩子的配置与最近一次执行结果。失败细节只保留错误字符串，
// 脚本参数与配置路径不含密钥，可以直接展示。
func (h *LifecycleHooks) Status() *hookStatusJSON {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.upPath == "" && h.downPath == "" {
		return nil
	}
	out := &hookStatusJSON{
		Configured: h.Configured(),
		UpPath:     h.upPath,
		DownPath:   h.downPath,
		UpRan:      h.upInfo.ran,
		UpOK:       h.upInfo.ok,
		UpMs:       h.upInfo.ms,
		UpErr:      hookErrText(h.upInfo),
		DownRan:    h.downInfo.ran,
		DownOK:     h.downInfo.ok,
		DownMs:     h.downInfo.ms,
		DownErr:    hookErrText(h.downInfo),
	}
	return out
}

// hookErrText 把钩子错误压成面板可显示的一行；成功时返回空串。
func hookErrText(info hookRunInfo) string {
	if info.err == nil {
		return ""
	}
	return info.err.Error()
}

func hookWorkDir(configPath string) string {
	if configPath == "" {
		return ""
	}
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return ""
	}
	return filepath.Dir(abs)
}

func hookEnvironment(scriptType string, env HookEnv) []string {
	values := []string{
		"script_type=" + scriptType,
		"dev=" + env.Dev,
		"dev_type=tap",
		"config=" + env.Config,
		"ifconfig_local=" + stripCIDR(env.IPv4),
		"ifconfig_ipv6_local=" + stripCIDR(env.IPv6),
		"route_vpn_gateway=" + env.GatewayV4,
		"route_ipv6_gateway=" + env.GatewayV6,
		"TLSVPN_SCRIPT_TYPE=" + scriptType,
		"TLSVPN_MODE=" + env.Mode,
		"TLSVPN_DEV=" + env.Dev,
		"TLSVPN_CONFIG=" + env.Config,
		"TLSVPN_IPV4=" + env.IPv4,
		"TLSVPN_IPV6=" + env.IPv6,
		"TLSVPN_GATEWAY_V4=" + env.GatewayV4,
		"TLSVPN_GATEWAY_V6=" + env.GatewayV6,
	}
	return append(baseHookEnvironment(), values...)
}

func baseHookEnvironment() []string {
	if runtime.GOOS != "windows" {
		return []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	}
	// Windows programs commonly require SystemRoot; keep only non-secret
	// process-discovery and temporary-directory values instead of inheriting the
	// service's entire credential-bearing environment.
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	out := []string{
		"SystemRoot=" + root,
		"WINDIR=" + root,
		"PATH=" + filepath.Join(root, "System32") + ";" + root,
		"PATHEXT=.COM;.EXE;.BAT;.CMD",
	}
	for _, key := range []string{"TEMP", "TMP"} {
		if value, ok := os.LookupEnv(key); ok {
			out = append(out, key+"="+value)
		}
	}
	return out
}

func stripCIDR(s string) string {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i]
	}
	return s
}

func hookError(kind, path, output string, err error) error {
	if output == "" {
		return fmt.Errorf("%s hook %s failed: %w", kind, path, err)
	}
	return fmt.Errorf("%s hook %s failed: %w (output: %s)", kind, path, err, output)
}

func runHookCommand(path, workDir string, env []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hookTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path)
	cmd.Env = env
	cmd.WaitDelay = 2 * time.Second
	if workDir != "" {
		cmd.Dir = workDir
	}
	var output cappedBuffer
	output.limit = hookOutputCap
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("timed out after %s", hookTimeout)
	}
	return strings.TrimSpace(output.String()), err
}

// cappedBuffer preserves enough diagnostics for operators while continuing to
// accept writes, so a noisy child cannot block on a full pipe or exhaust RAM.
type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if remain := b.limit - b.Len(); remain > 0 {
		if len(p) > remain {
			p = p[:remain]
		}
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}
