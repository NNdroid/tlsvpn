from pathlib import Path

p = Path('scripts/install.sh')
s = p.read_text()
old = '''  # shellcheck disable=SC1091
  . /etc/os-release
  DISTRO="${ID:-unknown}"
  DISTRO_LIKE="${ID_LIKE:-}"
'''
new = '''  # Read os-release in a subshell so keys such as VERSION= cannot clobber
  # installer options like --version/latest.
  local os_id os_id_like
  os_id="$(. /etc/os-release; printf '%s' "${ID:-unknown}")"
  os_id_like="$(. /etc/os-release; printf '%s' "${ID_LIKE:-}")"
  DISTRO="$os_id"
  DISTRO_LIKE="$os_id_like"
'''
assert s.count(old) == 1, f'detect_platform source block count={s.count(old)}'
s = s.replace(old, new)
old = '''  [[ -n "$RELEASE_TAG" ]] || die "Could not resolve a TLSVPN release tag."
  [[ "$RELEASE_TAG" == v* ]] || RELEASE_TAG="v$RELEASE_TAG"
  release_arch
'''
new = '''  [[ -n "$RELEASE_TAG" ]] || die "Could not resolve a TLSVPN release tag."
  [[ "$RELEASE_TAG" == v* ]] || RELEASE_TAG="v$RELEASE_TAG"
  [[ "$RELEASE_TAG" =~ ^v[0-9A-Za-z][0-9A-Za-z._+-]*$ ]] || die "Invalid TLSVPN release tag: $RELEASE_TAG"
  release_arch
'''
assert s.count(old) == 1, f'resolve_release block count={s.count(old)}'
s = s.replace(old, new)
old = '''start_service() {
  [[ "$NO_START" == "yes" ]] && return 0
  if [[ "$INIT_SYSTEM" == "systemd" ]]; then run systemctl restart tlsvpn.service;
  else run rc-service tlsvpn restart; fi
}
'''
new = '''start_service() {
  [[ "$NO_START" == "yes" ]] && return 0
  if [[ "$INIT_SYSTEM" == "systemd" ]]; then
    # A failed fresh install or a rollback after uninstall may legitimately have
    # no service unit to restart. Do not turn recovery into a second error.
    if [[ ! -e "$SYSTEMD_SERVICE" ]] && ! systemctl cat tlsvpn.service >/dev/null 2>&1; then return 0; fi
    run systemctl restart tlsvpn.service
  else
    [[ -e "$OPENRC_SERVICE" ]] || return 0
    run rc-service tlsvpn restart
  fi
}
'''
assert s.count(old) == 1, f'start_service block count={s.count(old)}'
s = s.replace(old, new)
p.write_text(s)

p = Path('scripts/test_install.sh')
s = p.read_text()
anchor = '''grep -Fq 'mkdir -p "$INSTALL_DIR" "$STATE_DIR"' scripts/install.sh
'''
addition = '''grep -Fq 'mkdir -p "$INSTALL_DIR" "$STATE_DIR"' scripts/install.sh
grep -Fq 'os_id="$(. /etc/os-release; printf' scripts/install.sh
grep -Fq 'Invalid TLSVPN release tag:' scripts/install.sh
grep -Fq 'systemctl cat tlsvpn.service' scripts/install.sh
if grep -Fxq '  . /etc/os-release' scripts/install.sh; then
  echo "installer must not source /etc/os-release into its global namespace" >&2
  exit 1
fi
'''
assert s.count(anchor) == 1
s = s.replace(anchor, addition)
p.write_text(s)

p = Path('installer_script_test.go')
s = p.read_text()
anchor = '''        `Would install daily TLSVPN maintenance task`, `mkdir -p "$INSTALL_DIR" "$STATE_DIR"`,
'''
replacement = '''        `Would install daily TLSVPN maintenance task`, `mkdir -p "$INSTALL_DIR" "$STATE_DIR"`,
        `os_id="$(. /etc/os-release; printf`, `Invalid TLSVPN release tag:`, `systemctl cat tlsvpn.service`,
'''
assert s.count(anchor) == 1
s = s.replace(anchor, replacement)
anchor = '''    for _, bad := range []string{`NNdroid/tlsvpn-rs`, `tlsvpn-rs installer`, `"workers"`, `"mtu"`, `unknown-linux-musl`, `--cert-mode lego|self-signed|existing|none`} {
'''
replacement = '''    if strings.Contains(s, "\\n  . /etc/os-release\\n") {
        t.Fatal("install.sh must not source /etc/os-release into the global installer namespace")
    }
    for _, bad := range []string{`NNdroid/tlsvpn-rs`, `tlsvpn-rs installer`, `"workers"`, `"mtu"`, `unknown-linux-musl`, `--cert-mode lego|self-signed|existing|none`} {
'''
assert s.count(anchor) == 1
s = s.replace(anchor, replacement)
p.write_text(s)
