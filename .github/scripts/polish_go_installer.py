from pathlib import Path

p = Path('scripts/install.sh')
s = p.read_text()


def one(old, new):
    global s
    n = s.count(old)
    if n != 1:
        raise SystemExit(f'expected one match, got {n}: {old[:100]!r}')
    s = s.replace(old, new, 1)


# Server installation always needs one of the usable certificate choices.
one('--cert-mode lego|self-signed|existing|none', '--cert-mode lego|self-signed|existing')
one('    none) die "Server mode requires a TLS certificate; use lego, self-signed, or existing." ;;\n', '')

# Prevent generating a client config that Go itself rejects: this installer does
# not provision a separate client-dashboard certificate for a public bind=all.
needle = '''validate_common() {
  [[ "$WEB_BIND" == "all" || "$WEB_BIND" == "tunnel" ]] || die "--web-bind must be all or tunnel"
  [[ "$ACME_CHALLENGE" == "http" || "$ACME_CHALLENGE" == "tls" ]] || die "--acme-challenge must be http or tls"
'''
replacement = '''web_addr_is_loopback() {
  local a="$1"
  [[ -z "$a" || "$a" == 127.* || "$a" == localhost:* || "$a" == "[::1]:"* || "$a" == ::1:* ]]
}

validate_common() {
  [[ "$WEB_BIND" == "all" || "$WEB_BIND" == "tunnel" ]] || die "--web-bind must be all or tunnel"
  [[ "$ACME_CHALLENGE" == "http" || "$ACME_CHALLENGE" == "tls" ]] || die "--acme-challenge must be http or tls"
  if [[ "$MODE" == "client" && "$WEB_BIND" == "all" ]] && ! web_addr_is_loopback "$WEB_ADDR"; then
    die "Client --web-bind all is only supported with a loopback --web-addr; use --web-bind tunnel for a remotely reachable dashboard."
  fi
'''
one(needle, replacement)

# install_tlsvpn_binary can also be called by upgrade if the state directory was
# manually deleted; recreate it before writing installed-version.
one('''  mkdir -p "$INSTALL_DIR"
  install -m 0755 "$tmp" "$INSTALL_DIR/$PROGRAM.new"''', '''  mkdir -p "$INSTALL_DIR" "$STATE_DIR"
  install -m 0755 "$tmp" "$INSTALL_DIR/$PROGRAM.new"''')

# Make --dry-run avoid /etc temp-file writes as well as the final mutations.
one('''write_systemd_service() {
  cat >"$SYSTEMD_SERVICE.tmp" <<EOF''', '''write_systemd_service() {
  if [[ "$DRY_RUN" == "yes" ]]; then info "Would write $SYSTEMD_SERVICE"; return 0; fi
  cat >"$SYSTEMD_SERVICE.tmp" <<EOF''')
one('''write_openrc_service() {
  cat >"$OPENRC_SERVICE.tmp" <<EOF''', '''write_openrc_service() {
  if [[ "$DRY_RUN" == "yes" ]]; then info "Would write $OPENRC_SERVICE"; return 0; fi
  cat >"$OPENRC_SERVICE.tmp" <<EOF''')
one('''write_daily_task() {
  if [[ "$DAILY_UPDATE" != "yes" ]]; then remove_daily_task; return; fi
  if [[ "$INIT_SYSTEM" == "systemd" ]]; then''', '''write_daily_task() {
  if [[ "$DAILY_UPDATE" != "yes" ]]; then remove_daily_task; return; fi
  if [[ "$DRY_RUN" == "yes" ]]; then info "Would install daily TLSVPN maintenance task"; return 0; fi
  if [[ "$INIT_SYSTEM" == "systemd" ]]; then''')
one('''apply_kernel_tuning() {
  [[ "$KERNEL_TUNING" == "yes" ]] || return 0
  local bbr=""''', '''apply_kernel_tuning() {
  [[ "$KERNEL_TUNING" == "yes" ]] || return 0
  if [[ "$DRY_RUN" == "yes" ]]; then info "Would write $SYSCTL_FILE and apply network kernel tuning"; return 0; fi
  local bbr=""''')

# Avoid creating a temporary file just to report a tcp-brutal dry run.
one('''  info "Installing tcp-brutal with the upstream DKMS installer"
  local tmp; tmp="$(mktemp)"
  if [[ "$DRY_RUN" == "yes" ]]; then printf '[DRY-RUN] upstream tcp-brutal installer\\n'; rm -f "$tmp"; return 0; fi''', '''  info "Installing tcp-brutal with the upstream DKMS installer"
  if [[ "$DRY_RUN" == "yes" ]]; then printf '[DRY-RUN] upstream tcp-brutal installer\\n'; return 0; fi
  local tmp; tmp="$(mktemp)"''')

p.write_text(s)

# Extend the static contract test with the audited safety guarantees.
tp = Path('installer_script_test.go')
t = tp.read_text()
t = t.replace(
    '`--cert-mode lego|self-signed|existing|none`, `--profile shortlived`,',
    '`--cert-mode lego|self-signed|existing`, `--profile shortlived`,',
    1,
)
t = t.replace(
    '        `Type "back" at any prompt`, `ROLLBACK_ON_ERROR="yes"`,\n',
    '        `Type "back" at any prompt`, `ROLLBACK_ON_ERROR="yes"`,\n'
    '        `web_addr_is_loopback`, `Client --web-bind all is only supported with a loopback`,\n'
    '        `Would install daily TLSVPN maintenance task`, `mkdir -p "$INSTALL_DIR" "$STATE_DIR"`,\n',
    1,
)
t = t.replace(
    'for _, bad := range []string{`NNdroid/tlsvpn-rs`, `tlsvpn-rs installer`, `"workers"`, `"mtu"`, `unknown-linux-musl`} {',
    'for _, bad := range []string{`NNdroid/tlsvpn-rs`, `tlsvpn-rs installer`, `"workers"`, `"mtu"`, `unknown-linux-musl`, `--cert-mode lego|self-signed|existing|none`} {',
    1,
)
tp.write_text(t)
