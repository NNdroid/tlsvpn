package main

import (
    "os"
    "strings"
    "testing"
)

func TestInstallScriptContract(t *testing.T) {
    b, err := os.ReadFile("scripts/install.sh")
    if err != nil { t.Fatal(err) }
    s := string(b)
    wants := []string{
        `REPO="NNdroid/tlsvpn"`,
        `tlsvpn_linux_amd64`, `tlsvpn_linux_386`, `tlsvpn_linux_arm64`,
        `tlsvpn_linux_arm64_v8.2`, `tlsvpn_linux_arm`, `tlsvpn_linux_mipsle`, `tlsvpn_linux_mips`,
        `install|upgrade|uninstall|rollback|maintenance|status|help`,
        `--cert-mode lego|self-signed|existing`, `--profile shortlived`,
        `--renew-days 2`, `--renew-days 30`, `lego migrate --path`,
        `OnCalendar=daily`, `/etc/periodic/daily/tlsvpn-maintenance`,
        `--xanmod yes|no`, `--tcp-brutal yes|no`, `--optimize-kernel yes|no`,
        `"traffic_days": 30`, `"traffic_file": "$traffic"`,
        `debian|ubuntu`, `rocky|rhel|almalinux|centos|fedora`, `alpine`,
        `Type "back" at any prompt`, `ROLLBACK_ON_ERROR="yes"`,
        `web_addr_is_loopback`, `Client --web-bind all is only supported with a loopback`,
        `Would install daily TLSVPN maintenance task`, `mkdir -p "$INSTALL_DIR" "$STATE_DIR"`,
    }
    for _, want := range wants {
        if !strings.Contains(s, want) { t.Fatalf("install.sh missing %q", want) }
    }
    for _, bad := range []string{`NNdroid/tlsvpn-rs`, `tlsvpn-rs installer`, `"workers"`, `"mtu"`, `unknown-linux-musl`, `--cert-mode lego|self-signed|existing|none`} {
        if strings.Contains(s, bad) { t.Fatalf("install.sh still contains Rust-only marker %q", bad) }
    }
}
