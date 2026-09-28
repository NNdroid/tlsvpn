#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

bash -n scripts/install.sh

help="$(bash scripts/install.sh help)"
for needle in \
  "install       Install TLSVPN" \
  "upgrade       Upgrade the TLSVPN binary" \
  "uninstall     Remove TLSVPN-managed files" \
  "rollback      Restore the newest" \
  "maintenance   Renew certificates" \
  "status        Show installation" \
  "--arch auto|amd64|386|arm64|arm64-v8.2|arm|armv7|mipsle|mips" \
  "--cert-mode lego|self-signed|existing" \
  "XanMod" \
  "tcp-brutal" \
  "--optimize-kernel yes|no"; do
  grep -Fq -- "$needle" <<<"$help"
done

if grep -Fq -- "--cert-mode lego|self-signed|existing|none" <<<"$help"; then
  echo "server help must not advertise the unusable cert-mode none" >&2
  exit 1
fi

grep -Fq 'REPO="NNdroid/tlsvpn"' scripts/install.sh
for asset in \
  tlsvpn_linux_amd64 tlsvpn_linux_386 tlsvpn_linux_arm64 \
  tlsvpn_linux_arm64_v8.2 tlsvpn_linux_arm tlsvpn_linux_mipsle tlsvpn_linux_mips; do
  grep -Fq "$asset" scripts/install.sh
done

grep -Fq 'LEGO_ARGS=(run --path' scripts/install.sh
grep -Fq -- '--profile shortlived' scripts/install.sh
grep -Fq -- '--renew-days 2' scripts/install.sh
grep -Fq -- '--renew-days 30' scripts/install.sh
grep -Fq 'lego migrate --path' scripts/install.sh
grep -Fq 'OnCalendar=daily' scripts/install.sh
grep -Fq 'RandomizedDelaySec=45m' scripts/install.sh
grep -Fq 'HyNetworks/tcp-brutal/master/scripts/install_dkms.sh' scripts/install.sh
grep -Fq 'http://deb.xanmod.org' scripts/install.sh
grep -Fq '"traffic_days": 30' scripts/install.sh
grep -Fq '"traffic_file": "$traffic"' scripts/install.sh
grep -Fq '"interface_manager": "self"' scripts/install.sh
grep -Fq 'web_addr_is_loopback' scripts/install.sh
grep -Fq 'Would install daily TLSVPN maintenance task' scripts/install.sh
grep -Fq 'mkdir -p "$INSTALL_DIR" "$STATE_DIR"' scripts/install.sh
grep -Fq 'os_id="$(. /etc/os-release; printf' scripts/install.sh
grep -Fq 'Invalid TLSVPN release tag:' scripts/install.sh
grep -Fq 'systemctl cat tlsvpn.service' scripts/install.sh
if grep -Fxq '  . /etc/os-release' scripts/install.sh; then
  echo "installer must not source /etc/os-release into its global namespace" >&2
  exit 1
fi

for forbidden in 'NNdroid/tlsvpn-rs' 'unknown-linux-musl' '"workers"' '"mtu"'; do
  if grep -Fq "$forbidden" scripts/install.sh; then
    echo "Go installer contains forbidden Rust-only marker: $forbidden" >&2
    exit 1
  fi
done

if bash scripts/install.sh help --definitely-invalid >/dev/null 2>&1; then
  echo "unknown flag unexpectedly succeeded" >&2
  exit 1
fi

echo "installer checks passed"
