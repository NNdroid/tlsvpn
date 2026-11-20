package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

const (
	openWrtProtoShPath   = "openwrt/package/tlsvpn/files/lib/netifd/proto/tlsvpn.sh"
	openWrtLuciProtoPath = "openwrt/luci-proto-tlsvpn/htdocs/luci-static/resources/protocol/tlsvpn.js"
	openWrtLuciMakePath  = "openwrt/luci-proto-tlsvpn/Makefile"
)

func readRepoFileForTest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestOpenWrtProtoScriptCoversAllClientConfigFields asserts that the netifd
// proto handler registers every client-mode UCI option and emits the matching
// JSON field. interface_manager=netifd forbids fwmark/extra_routes/source_rules
// and up/down hooks, so those must stay absent (the daemon rejects them).
func TestOpenWrtProtoScriptCoversAllClientConfigFields(t *testing.T) {
	script := readRepoFileForTest(t, openWrtProtoShPath)

	registered := []struct {
		name string
		typ  string
	}{
		{"server", "string"}, {"psk", "string"}, {"tap", "string"},
		{"mac", "string"}, {"tunlink", "string"}, {"sni", "string"},
		{"cert_sha256", "string"}, {"req_v4", "string"}, {"req_v6", "string"},
		{"enc_algo", "string"}, {"min_enc", "string"}, {"pad_mode", "string"},
		{"socks5", "string"}, {"log_level", "string"},
		{"conns", "int"}, {"fec_group", "int"},
		{"brutal_up", "int"}, {"brutal_down", "int"},
		{"fec", "boolean"}, {"encrypt", "boolean"}, {"insecure", "boolean"}, {"brutal", "boolean"},
		{"routing_algo", "string"}, {"sched_envelope", "string"},
		{"sched_envelope_ms", "int"}, {"sched_health_penalty_us", "int"},
		{"fec_strategy", "string"}, {"fec_near_window_ms", "int"},
		{"priority_control", "int"}, {"priority_data", "int"},
		{"probe_min_half_rtt_us", "int"},
		{"traffic_days", "int"}, {"traffic_file", "string"},
		{"web_addr", "string"}, {"web_bind", "string"}, {"web_auth", "string"},
		{"web_cert", "string"}, {"web_key", "string"}, {"web_behind_proxy", "boolean"},
		{"mcp_auth_mode", "string"}, {"mcp_username", "string"}, {"mcp_credential", "string"},
		{"mcp_api_key_header", "string"}, {"mcp_path", "string"},
		{"mcp_jwks_url", "string"}, {"mcp_issuer", "string"}, {"mcp_audience", "string"},
		{"mcp_resource", "string"}, {"mcp_authorization_servers", "string"},
		{"mcp_required_scopes", "string"},
	}
	for _, f := range registered {
		want := "proto_config_add_" + f.typ + " \"" + f.name + "\""
		if !strings.Contains(script, want) {
			t.Errorf("proto handler does not register %s", want)
		}
	}

	// UCI option → emitted JSON snippet (nested web/mcp objects use renamed keys).
	emitted := map[string]string{
		"server":                  `json_add_string addr "$resolved_server"`,
		"psk":                     `json_add_string psk "$psk"`,
		"tap":                     `json_add_string tap "$tap"`,
		"mac":                     `json_add_string mac "$mac"`,
		// tunlink is consumed netifd-side as the host-dependency interface.
		"tunlink":                 `proto_add_host_dependency "$interface" "$ip" "$tunlink"`,
		"sni":                     `json_add_string sni "$sni"`,
		"cert_sha256":             `json_add_string cert_sha256 "$cert_sha256"`,
		"req_v4":                  `json_add_string req_v4 "$req_v4"`,
		"req_v6":                  `json_add_string req_v6 "$req_v6"`,
		"enc_algo":                `json_add_string enc_algo "$enc_algo"`,
		"min_enc":                 `json_add_string min_enc "$min_enc"`,
		"pad_mode":                `json_add_string pad_mode "$pad_mode"`,
		"socks5":                  `json_add_string socks5 "$resolved_socks5"`,
		"log_level":               `json_add_string log_level "$log_level"`,
		"conns":                   `json_add_int conns "$conns"`,
		"fec_group":               `json_add_int fec_group "$fec_group"`,
		"brutal_up":               `json_add_int brutal_up "$brutal_up"`,
		"brutal_down":             `json_add_int brutal_down "$brutal_down"`,
		"fec":                     `json_add_boolean fec "$fec"`,
		"encrypt":                 `json_add_boolean encrypt "$encrypt"`,
		"insecure":                `json_add_boolean insecure "$insecure"`,
		"brutal":                  `json_add_boolean brutal "$brutal"`,
		"routing_algo":            `json_add_string routing_algo "$routing_algo"`,
		"sched_envelope":          `json_add_string sched_envelope "$sched_envelope"`,
		"sched_envelope_ms":       `json_add_int sched_envelope_ms "$sched_envelope_ms"`,
		"sched_health_penalty_us": `json_add_int sched_health_penalty_us "$sched_health_penalty_us"`,
		"fec_strategy":            `json_add_string fec_strategy "$fec_strategy"`,
		"fec_near_window_ms":      `json_add_int fec_near_window_ms "$fec_near_window_ms"`,
		"priority_control":        `json_add_int priority_control "$priority_control"`,
		"priority_data":           `json_add_int priority_data "$priority_data"`,
		"probe_min_half_rtt_us":   `json_add_int probe_min_half_rtt_us "$probe_min_half_rtt_us"`,
		"traffic_days":            `json_add_int traffic_days "$traffic_days"`,
		"traffic_file":            `json_add_string traffic_file "$traffic_file"`,
		"web_addr":                `json_add_string addr "$web_addr"`,
		"web_bind":                `json_add_string bind "$web_bind"`,
		"web_auth":                `json_add_string auth "$web_auth"`,
		"web_cert":                `json_add_string cert "$web_cert"`,
		"web_key":                 `json_add_string key "$web_key"`,
		"web_behind_proxy":        `json_add_boolean behind_proxy 1`,
		"mcp_auth_mode":           `json_add_string auth_mode "$mcp_auth_mode"`,
		"mcp_username":            `json_add_string username "$mcp_username"`,
		"mcp_credential":          `json_add_string credential "$mcp_credential"`,
		"mcp_api_key_header":      `json_add_string api_key_header "$mcp_api_key_header"`,
		"mcp_path":                `json_add_string path "$mcp_path"`,
		"mcp_jwks_url":            `json_add_string jwks_url "$mcp_jwks_url"`,
		"mcp_issuer":              `json_add_string issuer "$mcp_issuer"`,
		"mcp_audience":            `json_add_string audience "$mcp_audience"`,
		"mcp_resource":            `json_add_string resource "$mcp_resource"`,
		"mcp_authorization_servers": `json_add_array authorization_servers`,
		"mcp_required_scopes":       `json_add_array required_scopes`,
	}
	for _, f := range registered {
		snippet, ok := emitted[f.name]
		if !ok {
			t.Fatalf("test table missing emitted snippet for %s", f.name)
		}
		if !strings.Contains(script, snippet) {
			t.Errorf("proto handler does not emit %s (%q)", f.name, snippet)
		}
	}
}

func TestOpenWrtProtoScriptStructureAndValidation(t *testing.T) {
	script := readRepoFileForTest(t, openWrtProtoShPath)

	required := []string{
		// netifd ownership contract stays intact
		`json_add_string interface_manager netifd`,
		`proto_run_command "$interface" /usr/bin/tlsvpn -c "$config"`,
		// web/mcp/oauth object nesting
		`json_add_object web`,
		`json_add_object mcp`,
		`json_add_object oauth`,
		// tunnel-only bind is the OpenWrt-safe default for the dashboard
		`[ -n "$web_bind" ] || web_bind=tunnel`,
		// per-interface persistent daily-traffic store (survives reboots,
		// unlike the tmpfs-generated config next to which the daemon would
		// otherwise default traffic_file)
		`traffic_file="/etc/tlsvpn/tlsvpn-$interface-traffic.json"`,
		// the daemon does not create the traffic_file parent directory
		`mkdir -p "$(dirname "$traffic_file")"`,
		// UCI list options are read shape-agnostically: JSON arrays (LuCI
		// DynamicList via netifd) via json_get_values, hand-written comma
		// scalars via json_get_var
		`json_get_type type "$name"`,
		`json_get_values values "$name"`,
		// early validation error codes (proto_notify_error instead of a
		// post-start log.Fatalf from the daemon)
		"PSK_TOO_SHORT", "INVALID_LOG_LEVEL", "INVALID_PAD_MODE",
		"ENC_ALGO_REQUIRES_ENCRYPT", "MIN_ENC_REQUIRES_ENCRYPT",
		"INVALID_ENC_ALGO", "INVALID_MIN_ENC",
		"INVALID_CONNS", "INVALID_FEC_GROUP", "INVALID_BRUTAL_RATE",
		"INSECURE_NEEDS_CERT_SHA256", "INVALID_CERT_SHA256",
		"INVALID_ROUTING_ALGO", "INVALID_SCHED_ENVELOPE",
		"INVALID_SCHED_ENVELOPE_MS", "INVALID_SCHED_HEALTH_PENALTY",
		"INVALID_FEC_STRATEGY", "INVALID_FEC_NEAR_WINDOW",
		"INVALID_FRAME_PRIORITY", "INVALID_PROBE_MIN_HALF_RTT",
		"INVALID_TRAFFIC_DAYS", "INVALID_WEB_BIND", "WEB_AUTH_REQUIRED",
		"INVALID_WEB_AUTH", "WEB_TLS_PAIR_REQUIRED", "WEB_TLS_REQUIRED_FOR_BIND_ALL",
		"INVALID_MCP_AUTH_MODE", "MCP_USERNAME_REQUIRED", "MCP_CREDENTIAL_REQUIRED",
		"MCP_OAUTH_FIELDS_REQUIRED", "INVALID_MCP_PATH",
	}
	for _, want := range required {
		if !strings.Contains(script, want) {
			t.Errorf("proto handler is missing required contract %q", want)
		}
	}

	// Ranges mirror config.go Validate(); keep them in lockstep.
	for _, rangeCheck := range []string{
		`"$conns" 1 65536`,
		`"$fec_group" 2 64`,
		`"$brutal_up" 0 1000000`,
		`"$brutal_down" 0 1000000`,
		`"$sched_envelope_ms" 1 500`,
		`"$sched_health_penalty_us" 0 60000`,
		`"$fec_near_window_ms" 1 100`,
		`"$priority_control" 0 10`,
		`"$priority_data" 0 10`,
		`"$probe_min_half_rtt_us" 0 3600000`,
		`"$traffic_days" 1 3650`,
	} {
		if !strings.Contains(script, rangeCheck) {
			t.Errorf("proto handler is missing range check %q", rangeCheck)
		}
	}

	// netifd owns L3 routing and lifecycle: these must never appear.
	for _, banned := range []string{"fwmark", "extra_routes", "source_rules"} {
		if strings.Contains(script, banned) {
			t.Errorf("proto handler must not reference %q in netifd mode", banned)
		}
	}
}

// TestOpenWrtLuciAndProtoOptionsStayInSync asserts every UCI option registered
// by the netifd proto handler has a LuCI form option, and that the only
// LuCI-only option is the web_enable flag gating the dashboard tab.
func TestOpenWrtLuciAndProtoOptionsStayInSync(t *testing.T) {
	script := readRepoFileForTest(t, openWrtProtoShPath)
	js := readRepoFileForTest(t, openWrtLuciProtoPath)

	shellReg := regexp.MustCompile(`proto_config_add_(?:string|int|boolean) "([a-z0-9_]+)"`)
	jsOpt := regexp.MustCompile(`s\.taboption\('(?:[^']+)',\s*(?:form\.[A-Za-z]+|widgets\.[A-Za-z]+),\s*'([a-z0-9_]+)'`)

	shellNames := map[string]bool{}
	for _, m := range shellReg.FindAllStringSubmatch(script, -1) {
		shellNames[m[1]] = true
	}
	jsNames := map[string]bool{}
	for _, m := range jsOpt.FindAllStringSubmatch(js, -1) {
		jsNames[m[1]] = true
	}

	for name := range shellNames {
		if !jsNames[name] {
			t.Errorf("LuCI form is missing UCI option %q registered by the proto handler", name)
		}
	}
	for name := range jsNames {
		if !shellNames[name] && name != "web_enable" {
			t.Errorf("LuCI option %q is not registered by the proto handler", name)
		}
	}
}

// TestOpenWrtLuciDynamicListForMcpOauthLists asserts the two MCP oauth list
// options use native UCI lists in LuCI (form.DynamicList) instead of
// comma-joined strings; the proto handler reads both blob shapes.
func TestOpenWrtLuciDynamicListForMcpOauthLists(t *testing.T) {
	js := readRepoFileForTest(t, openWrtLuciProtoPath)
	for _, name := range []string{"mcp_authorization_servers", "mcp_required_scopes"} {
		if !strings.Contains(js, "form.DynamicList, '"+name+"'") {
			t.Errorf("LuCI option %q should use form.DynamicList (native UCI list)", name)
		}
	}
	if n := strings.Count(js, "form.DynamicList"); n != 2 {
		t.Errorf("expected exactly 2 DynamicList options in the protocol JS, found %d", n)
	}
}

// TestOpenWrtLuciPoFilesCoverEveryJsLiteral parses every _('...') literal in
// the protocol JavaScript and requires it to appear as a msgid in each of the
// five translation catalogs, with no stale leftovers and no duplicates.
func TestOpenWrtLuciPoFilesCoverEveryJsLiteral(t *testing.T) {
	js := readRepoFileForTest(t, openWrtLuciProtoPath)

	literalRe := regexp.MustCompile(`_\('((?:[^'\\]|\\.)*)'\)`)
	seen := map[string]bool{}
	var literals []string
	for _, m := range literalRe.FindAllStringSubmatch(js, -1) {
		id := strings.ReplaceAll(m[1], `\'`, `'`)
		if !seen[id] {
			seen[id] = true
			literals = append(literals, id)
		}
	}
	if len(literals) < 100 {
		t.Fatalf("expected ~100 translatable literals in the protocol JS, found %d", len(literals))
	}

	msgidRe := regexp.MustCompile(`^msgid "((?:[^"\\]|\\.)*)"$`)
	langs := []string{"de", "fr", "ja", "zh_Hans", "zh_Hant"}
	for _, lang := range langs {
		po := readRepoFileForTest(t, "openwrt/luci-proto-tlsvpn/po/"+lang+"/tlsvpn.po")
		set := map[string]bool{}
		dup := map[string]int{}
		for _, line := range strings.Split(po, "\n") {
			line = strings.TrimRight(line, "\r")
			if m := msgidRe.FindStringSubmatch(line); m != nil {
				dup[m[1]]++
				if m[1] != "" {
					set[m[1]] = true
				}
			}
		}
		for _, id := range literals {
			if !set[id] {
				t.Errorf("po/%s/tlsvpn.po is missing msgid %q", lang, id)
			}
		}
		for id := range set {
			if !seen[id] {
				t.Errorf("po/%s/tlsvpn.po has stale msgid not present in the JS: %q", lang, id)
			}
		}
		for id, n := range dup {
			if n > 1 {
				t.Errorf("po/%s/tlsvpn.po repeats msgid %q %d times (msgfmt would fail)", lang, id, n)
			}
		}
	}

	makefile := readRepoFileForTest(t, openWrtLuciMakePath)
	for _, lang := range langs {
		if !strings.Contains(makefile, "LUCI_LANG."+lang+":=") {
			t.Errorf("LuCI Makefile does not declare LUCI_LANG.%s", lang)
		}
	}
}
