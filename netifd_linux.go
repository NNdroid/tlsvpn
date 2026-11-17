//go:build linux
// +build linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"
)

const (
	netifdUpHelper   = "/lib/netifd/tlsvpn-up"
	netifdDownHelper = "/lib/netifd/tlsvpn-down"
)

func runNetifdHelper(path string, extraEnv ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, path)
	cmd.Env = append(os.Environ(), extraEnv...)
	// 超时后 CommandContext 只杀直接子进程；helper 脚本派生的孙进程会继承
	// CombinedOutput 的管道导致 Read 永久阻塞。WaitDelay 到点后放弃管道并
	// 收尾，与 hooks.go 的 runHookCommand 保持一致。
	cmd.WaitDelay = 2 * time.Second
	output, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("%s timed out", path)
	}
	if err != nil {
		return fmt.Errorf("%s failed: %w: %s", path, err, string(output))
	}
	return nil
}

func netifdLinkUp(iface, device, v4, v6, gw4, gw6 string) error {
	return runNetifdHelper(
		netifdUpHelper,
		"TLSVPN_NETIFD_INTERFACE="+iface,
		"TLSVPN_DEVICE="+device,
		"TLSVPN_IPV4="+v4,
		"TLSVPN_IPV6="+v6,
		"TLSVPN_GW4="+gw4,
		"TLSVPN_GW6="+gw6,
	)
}

func netifdLinkDown(iface, device string) error {
	return runNetifdHelper(
		netifdDownHelper,
		"TLSVPN_NETIFD_INTERFACE="+iface,
		"TLSVPN_DEVICE="+device,
	)
}
