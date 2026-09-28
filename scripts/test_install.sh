#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

bash -n scripts/install.sh

help="$(bash scripts/install.sh help)"
for needle in \
  "install       Install TLSVPN" \
  "upgrade       Upgrade the TLSVPN binary" \
  "uninstall     Remove installer-managed TLSVPN files" \
  "rollback      Restore the newest backup" \
  "maintenance   Renew lego certificates" \
  "status        Show installation" \
  "arm64-v8.2" \
  "lego|self-signed|existing|none" \
  "XanMod" \
  "TCP Brutal" \
  "optimize-kernel"; do
  grep -Fq "$needle" <<<"$help"
done

grep -Fq 'REPO="NNdroid/tlsvpn"' scripts/install.sh
grep -Fq 'tlsvpn_linux_amd64' scripts/install.sh
grep -Fq 'tlsvpn_linux_arm64_v8.2' scripts/install.sh
grep -Fq 'tlsvpn_linux_arm' scripts/install.sh
grep -Fq 'args=(run --accept-tos' scripts/install.sh
grep -Fq -- '--profile shortlived' scripts/install.sh
grep -Fq 'lego migrate --path' scripts/install.sh
grep -Fq 'RandomizedDelaySec=1h' scripts/install.sh
grep -Fq 'https://tcp.hy2.sh/' scripts/install.sh
grep -Fq 'http://deb.xanmod.org' scripts/install.sh
grep -Fq '"traffic_days": 30' scripts/install.sh
grep -Fq '"interface_manager": "self"' scripts/install.sh
grep -Fq 'S_RELEASE_TAG=' scripts/install.sh

if grep -Fq -- '--workers' scripts/install.sh; then
  echo "Go installer must not expose the Rust-only --workers option" >&2
  exit 1
fi

if bash scripts/install.sh help --definitely-invalid >/dev/null 2>&1; then
  echo "unknown flag unexpectedly succeeded" >&2
  exit 1
fi

echo "installer checks passed"
