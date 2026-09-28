from pathlib import Path

p = Path("scripts/install.sh")
s = p.read_text()
replacements = {
'''  "web": {"addr":"$(json_escape "$WEB_ADDR")","bind":"$(json_escape "$WEB_BIND")","auth":"$webauth","cert":"$cert","key":"$key"},''': '''  "web": {
    "addr": "$(json_escape "$WEB_ADDR")",
    "bind": "$(json_escape "$WEB_BIND")",
    "auth": "$webauth",
    "cert": "$cert",
    "key": "$key"
  },''',
'''  "server": {"v4_cidr":"10.0.0.0/24","v6_cidr":"fd00::/64","cert":"$cert","key":"$key","max_sessions":1024,"fec_group_min":2,"fec_group_max":64},''': '''  "server": {
    "v4_cidr": "10.0.0.0/24",
    "v6_cidr": "fd00::/64",
    "cert": "$cert",
    "key": "$key",
    "max_sessions": 1024,
    "fec_group_min": 2,
    "fec_group_max": 64
  },''',
'''  "client": {"interface_manager":"self","conns":1,"fec":false,"fec_group":4,"sni":"www.cloudflare.com","insecure":false,"cert_sha256":"","req_v4":"","req_v6":"","fwmark":0,"fwmark_priority":0,"extra_routes":[],"source_rules":[]}''': '''  "client": {
    "interface_manager": "self",
    "conns": 1,
    "fec": false,
    "fec_group": 4,
    "sni": "www.cloudflare.com",
    "insecure": false,
    "cert_sha256": "",
    "req_v4": "",
    "req_v6": "",
    "fwmark": 0,
    "fwmark_priority": 0,
    "extra_routes": [],
    "source_rules": []
  }''',
'''  "web": {"addr":"$(json_escape "$WEB_ADDR")","bind":"$(json_escape "$WEB_BIND")","auth":"$webauth","cert":"","key":""},''': '''  "web": {
    "addr": "$(json_escape "$WEB_ADDR")",
    "bind": "$(json_escape "$WEB_BIND")",
    "auth": "$webauth",
    "cert": "",
    "key": ""
  },''',
'''  "server": {"v4_cidr":"10.0.0.0/24","v6_cidr":"fd00::/64","cert":"","key":"","max_sessions":1024,"fec_group_min":2,"fec_group_max":64},''': '''  "server": {
    "v4_cidr": "10.0.0.0/24",
    "v6_cidr": "fd00::/64",
    "cert": "",
    "key": "",
    "max_sessions": 1024,
    "fec_group_min": 2,
    "fec_group_max": 64
  },''',
'''  "client": {"interface_manager":"self","conns":4,"fec":true,"fec_group":4,"sni":"www.cloudflare.com","insecure":false,"cert_sha256":"","req_v4":"","req_v6":"","fwmark":0,"fwmark_priority":0,"extra_routes":[],"source_rules":[]}''': '''  "client": {
    "interface_manager": "self",
    "conns": 4,
    "fec": true,
    "fec_group": 4,
    "sni": "www.cloudflare.com",
    "insecure": false,
    "cert_sha256": "",
    "req_v4": "",
    "req_v6": "",
    "fwmark": 0,
    "fwmark_priority": 0,
    "extra_routes": [],
    "source_rules": []
  }''',
}
for old, new in replacements.items():
    n = s.count(old)
    if n != 1:
        raise SystemExit(f"expected exactly one match, got {n}: {old[:80]!r}")
    s = s.replace(old, new, 1)
p.write_text(s)

Path("installer_config_format_test.go").write_text(r'''package main

import (
    "os"
    "strings"
    "testing"
)

func TestInstallerWritesReadableJSON(t *testing.T) {
    data, err := os.ReadFile("scripts/install.sh")
    if err != nil {
        t.Fatal(err)
    }
    s := string(data)
    for _, compact := range []string{
        `"web": {"addr":`,
        `"server": {"v4_cidr":`,
        `"client": {"interface_manager":`,
    } {
        if strings.Contains(s, compact) {
            t.Fatalf("installer still emits compact JSON object %q", compact)
        }
    }
    for _, pretty := range []string{
        `"web": {` + "\n" + `    "addr":`,
        `"server": {` + "\n" + `    "v4_cidr":`,
        `"client": {` + "\n" + `    "interface_manager":`,
    } {
        if !strings.Contains(s, pretty) {
            t.Fatalf("installer missing pretty JSON layout %q", pretty)
        }
    }
}
''')
