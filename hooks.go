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
		out, err := h.run(h.upPath, hookWorkDir(env.Config), hookEnvironment("up", env))
		if err != nil {
			h.upErr = hookError("up", h.upPath, out, err)
			return
		}
		if out != "" && log != nil {
			log.Infof("up hook output: %s", out)
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
		out, err := h.run(h.downPath, hookWorkDir(env.Config), hookEnvironment("down", env))
		if err != nil {
			h.downErr = hookError("down", h.downPath, out, err)
			return
		}
		if out != "" && log != nil {
			log.Infof("down hook output: %s", out)
		}
	})
	return h.downErr
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
