from pathlib import Path


def replace_one(path, old, new):
    p = Path(path)
    s = p.read_text()
    n = s.count(old)
    if n != 1:
        raise SystemExit(f"{path}: expected exactly one match, got {n}: {old[:120]!r}")
    p.write_text(s.replace(old, new, 1))

# Go CLI: expose the already-injected appVersion without introducing a second
# version source. Go's flag package accepts both -version and --version.
replace_one(
    "main.go",
    '''\tconfigPath := flag.String("c", "", "Path to JSON config file (required)")\n\tprintConfig := flag.Bool("print-config", false, "Print an example JSON config and exit")\n\tflag.Parse()\n\n\tif *printConfig {''',
    '''\tconfigPath := flag.String("c", "", "Path to JSON config file (required)")\n\tprintConfig := flag.Bool("print-config", false, "Print an example JSON config and exit")\n\tprintVersion := flag.Bool("version", false, "Print version and exit")\n\tflag.Parse()\n\n\tif *printVersion {\n\t\tfmt.Println(appVersion)\n\t\treturn\n\t}\n\n\tif *printConfig {''')
replace_one(
    "main.go",
    '''\t// 配置唯一来源是 JSON 文件：-c 指定路径，-print-config 输出可编辑模板。\n\t// 旧的命令行参数面已整体移除——两套入口必然漂移，且面板 save_apply 写回\n\t// 的也是同一份 JSON（字段参考见 README）。''',
    '''\t// 运行时配置唯一来源仍是 JSON 文件：-c 指定路径，-print-config 输出可编辑模板。\n\t// -version/--version 只查询构建版本，不引入第二套配置入口。旧的调参命令行\n\t// 面已整体移除——两套入口必然漂移，且面板 save_apply 写回的也是同一份 JSON。''')
replace_one(
    "main.go",
    '''\t\tfmt.Fprintln(os.Stderr, "generate a template with: tlsvpn -print-config")''',
    '''\t\tfmt.Fprintln(os.Stderr, "generate a template with: tlsvpn -print-config")\n\t\tfmt.Fprintln(os.Stderr, "show build version with: tlsvpn -version")''')
replace_one(
    "main.go",
    '''\t\tfmt.Fprintln(os.Stderr, "Usage: tlsvpn -c config.json   (-print-config for a template)")''',
    '''\t\tfmt.Fprintln(os.Stderr, "Usage: tlsvpn -c config.json   (-print-config template, -version build version)")''')

# The installer can now ask the installed binary directly. Keep the state-file
# fallback so rollback / old release installs remain compatible.
replace_one(
    "scripts/install.sh",
    '''random_secret() {\n  if have openssl; then openssl rand -hex 32; else od -An -N32 -tx1 /dev/urandom | tr -d ' \\n'; fi\n}\n\nrelease_arch() {''',
    '''random_secret() {\n  if have openssl; then openssl rand -hex 32; else od -An -N32 -tx1 /dev/urandom | tr -d ' \\n'; fi\n}\n\nbinary_version() {\n  local bin="${1:-$INSTALL_DIR/$PROGRAM}"\n  [[ -x "$bin" ]] || return 1\n  "$bin" -version 2>/dev/null | head -n1\n}\n\ninstalled_version() {\n  local v=""\n  v="$(binary_version 2>/dev/null || true)"\n  if [[ -z "$v" && -r "$STATE_DIR/installed-version" ]]; then v="$(cat "$STATE_DIR/installed-version")"; fi\n  printf '%s' "$v"\n}\n\nrelease_arch() {''')
replace_one(
    "scripts/install.sh",
    '''  local before=""\n  [[ -r "$STATE_DIR/installed-version" ]] && before="$(cat "$STATE_DIR/installed-version")"\n  install_tlsvpn_binary''',
    '''  local before=""\n  before="$(installed_version)"\n  install_tlsvpn_binary''')
replace_one(
    "scripts/install.sh",
    '''  local installed="" latest=""\n  [[ -r "$STATE_DIR/installed-version" ]] && installed="$(cat "$STATE_DIR/installed-version")"\n  latest="$(latest_release_tag || true)"''',
    '''  local installed="" latest=""\n  installed="$(installed_version)"\n  latest="$(latest_release_tag || true)"''')
replace_one(
    "scripts/install.sh",
    '''  if [[ -x "$INSTALL_DIR/$PROGRAM" ]]; then printf 'TLSVPN binary: %s\\n' "$INSTALL_DIR/$PROGRAM"; else printf 'TLSVPN binary: not installed\\n'; fi\n  [[ -r "$STATE_DIR/installed-version" ]] && printf 'Installed release: %s\\n' "$(cat "$STATE_DIR/installed-version")"''',
    '''  if [[ -x "$INSTALL_DIR/$PROGRAM" ]]; then printf 'TLSVPN binary: %s\\n' "$INSTALL_DIR/$PROGRAM"; else printf 'TLSVPN binary: not installed\\n'; fi\n  local installed="$(installed_version)"\n  [[ -n "$installed" ]] && printf 'Installed release: %s\\n' "$installed"''')

# README audit: CLI surface and actual go.mod floor.
replace_one("README.md", "Requires Go 1.26+ (build)", "Requires Go 1.26.1+ (build)")
replace_one(
    "README.md",
    '''tlsvpn -print-config > config.json       # generate the full template instead\ntlsvpn -h                                # shows only -c and -print-config''',
    '''tlsvpn -print-config > config.json       # generate the full template instead\ntlsvpn -version                          # print the injected build/release version\ntlsvpn -h                                # shows -c, -print-config and -version''')
replace_one(
    "README.md",
    '''The command-line interface is exactly that: `-c` and `-print-config`. All tuning lives in the config file, which the dashboard's *Save & apply* edits in place — one source of truth, nothing to drift.''',
    '''Runtime configuration remains JSON-only. The bootstrap/query flags are `-c`, `-print-config`, and `-version` (Go's flag parser also accepts `--version`). All tuning lives in the config file, which the dashboard's *Save & apply* edits in place — one source of truth, nothing to drift.''')

# CI: verify the version is the exact ldflags-injected value and both spellings work.
replace_one(
    ".github/workflows/go.yml",
    '''    - name: Build\n      run: go build -v ./...\n\n    - name: Test interop probe''',
    '''    - name: Build\n      run: go build -v ./...\n\n    - name: Verify version CLI\n      run: |\n        go build -ldflags "-X main.appVersion=ci-version-test" -o /tmp/tlsvpn-version-test .\n        test "$(/tmp/tlsvpn-version-test -version)" = "ci-version-test"\n        test "$(/tmp/tlsvpn-version-test --version)" = "ci-version-test"\n\n    - name: Test interop probe''')

# Persist a lightweight source contract so a future README/CLI drift is caught by go test.
Path("version_cli_test.go").write_text(r'''package main

import (
    "flag"
    "os"
    "strings"
    "testing"
)

func TestVersionFlagAndDocsContract(t *testing.T) {
    if flag.Lookup("version") == nil {
        t.Fatal("-version flag is not registered")
    }
    readme, err := os.ReadFile("README.md")
    if err != nil { t.Fatal(err) }
    s := string(readme)
    for _, want := range []string{"tlsvpn -version", "`-version`", "Go 1.26.1+"} {
        if !strings.Contains(s, want) { t.Fatalf("README missing %q", want) }
    }
    installer, err := os.ReadFile("scripts/install.sh")
    if err != nil { t.Fatal(err) }
    if !strings.Contains(string(installer), "binary_version()") {
        t.Fatal("installer does not query the binary version")
    }
}
''')
