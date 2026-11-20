'use strict';
'require form';
'require network';
'require uci';
'require tools.widgets as widgets';

return network.registerProtocol('tlsvpn', {
	getI18n: function() {
		return _('TLSVPN');
	},

	getIfname: function() {
		var configured = uci.get('network', this.sid, 'tap');
		if (configured)
			return configured;

		var name = 'tvpn-' + this.sid;
		return name.substring(0, 15);
	},

	getPackageName: function() {
		return 'tlsvpn-proto';
	},

	isFloating: function() {
		return true;
	},

	isVirtual: function() {
		return true;
	},

	getDevices: function() {
		return null;
	},

	containsDevice: function(ifname) {
		return network.getIfnameOf(ifname) == this.getIfname();
	},

	renderFormOptions: function(s) {
		var o;

		s.tab('general', _('General Settings'));
		s.tab('scheduling', _('Multipath Scheduling'));
		s.tab('dashboard', _('Web Dashboard'));
		s.tab('mcp', _('MCP Server'));
		s.tab('advanced', _('Advanced Settings'));

		/* ---- general: transport endpoint, identity, TLS trust ---- */

		o = s.taboption('general', form.Value, 'server',
			_('TLSVPN server'),
			_('One or more host:port endpoints separated by commas. Every endpoint is pinned to the pre-tunnel routing domain to prevent recursive routing.'));
		o.placeholder = 'vpn.example.com:4000';
		o.rmempty = false;

		o = s.taboption('general', form.Value, 'psk', _('Pre-shared key'),
			_('At least 16 bytes of high-entropy random secret. Known placeholder values are rejected.'));
		o.password = true;
		o.rmempty = false;

		o = s.taboption('general', form.Value, 'tap', _('Tunnel device'),
			_('Optional TAP device name. Linux interface names are limited to 15 characters.'));
		o.placeholder = this.getIfname();
		o.datatype = 'maxlength(15)';

		o = s.taboption('general', widgets.NetworkSelect, 'tunlink',
			_('Underlying network'),
			_('Optional network used to reach the TLS transport endpoints. Leave empty to use normal routing.'));
		o.nocreate = true;
		o.rmempty = true;

		o = s.taboption('general', form.Value, 'sni', _('Camouflage SNI'),
			_('Hostname presented in the TLS ClientHello instead of the real endpoint.'));
		o.placeholder = 'www.cloudflare.com';

		o = s.taboption('general', form.Value, 'cert_sha256', _('Server certificate SHA-256'),
			_('64 hex characters, colons tolerated. Pins the server certificate instead of trusting CAs.'));
		o.placeholder = '0123456789abcdef...';

		o = s.taboption('general', form.Flag, 'insecure',
			_('Skip TLS certificate verification'),
			_('Requires the certificate SHA-256 fingerprint: the tunnel refuses to start with neither CA verification nor a pinned fingerprint.'));
		o.default = o.disabled;

		/* ---- scheduling: multipath egress and FEC parity placement ---- */

		o = s.taboption('scheduling', form.ListValue, 'routing_algo',
			_('Multipath routing algorithm'),
			_('How egress picks among parallel paths. Hot-reloadable; applies to this end only (client uplink / server downlink).'));
		o.value('auto', _('Auto (default)'));
		o.value('latency_strict', _('Latency strict'));
		o.value('latency_sticky', _('Latency sticky'));
		o.value('min_rtt_strict', _('Min-RTT strict'));
		o.value('min_rtt_adaptive', _('Min-RTT adaptive'));
		o.value('roundtrip_strict', _('Round-trip strict'));
		o.default = 'auto';

		o = s.taboption('scheduling', form.ListValue, 'sched_envelope',
			_('Candidate envelope metric'),
			_('Which latency dimension admits a path into the egress candidate set. Hot-reloadable.'));
		o.value('rtt', _('Round-trip kernel min-RTT (default)'));
		o.value('fwd', _('Forward one-way latency'));
		o.default = 'rtt';

		o = s.taboption('scheduling', form.Value, 'sched_envelope_ms',
			_('Forward admission window (ms)'),
			_('Paths whose forward latency is within this window of the group minimum are admitted (1-500 ms).'));
		o.datatype = 'and(uinteger,min(1),max(500))';
		o.default = '20';
		o.depends('sched_envelope', 'fwd');

		o = s.taboption('scheduling', form.Value, 'sched_health_penalty_us',
			_('Path health penalty (µs)'),
			_('Ranking penalty in microseconds per probe timeout or retransmission window; 0 disables health penalties.'));
		o.datatype = 'and(uinteger,min(0),max(60000))';
		o.default = '2000';

		o = s.taboption('scheduling', form.ListValue, 'fec_strategy',
			_('FEC parity strategy'),
			_('Where XOR parity frames are sent. Hot-reloadable.'));
		o.value('auto', _('Auto (rotate healthy backends)'));
		o.value('near', _('Near (paths close to data)'));
		o.default = 'auto';

		o = s.taboption('scheduling', form.Value, 'fec_near_window_ms',
			_('FEC near window (ms)'),
			_('Forward one-way latency window that qualifies a path to receive parity copies (1-100 ms).'));
		o.datatype = 'and(uinteger,min(1),max(100))';
		o.default = '10';
		o.depends('fec_strategy', 'near');

		/* ---- dashboard: web panel, /metrics and MCP listener ---- */

		o = s.taboption('dashboard', form.Flag, 'web_enable',
			_('Enable web dashboard'),
			_('Runs the dashboard, /metrics and the MCP endpoint inside this tunnel process.'));
		o.default = o.disabled;

		o = s.taboption('dashboard', form.Value, 'web_addr',
			_('Dashboard listen address'),
			_('Port binding such as :8080. The panel is reachable over the tunnel IP (or the LAN with firewall rules).'));
		o.placeholder = ':8080';
		o.rmempty = false;
		o.depends('web_enable', '1');

		o = s.taboption('dashboard', form.ListValue, 'web_bind',
			_('Dashboard bind scope'),
			_('Tunnel-only never touches physical NICs. All binds every interface including WAN and requires a TLS certificate pair.'));
		o.value('tunnel', _('Tunnel IPs only (recommended)'));
		o.value('all', _('All interfaces'));
		o.default = 'tunnel';
		o.depends('web_enable', '1');

		o = s.taboption('dashboard', form.Value, 'web_auth',
			_('Dashboard login (user:password)'),
			_('Known example credentials are rejected.'));
		o.password = true;
		o.rmempty = false;
		o.depends('web_enable', '1');

		o = s.taboption('dashboard', form.Value, 'web_cert',
			_('Dashboard TLS certificate'),
			_('Required together with the private key; mandatory when binding all interfaces publicly.'));
		o.rmempty = true;
		o.depends('web_enable', '1');

		o = s.taboption('dashboard', form.Value, 'web_key',
			_('Dashboard TLS private key'),
			_('Required together with the certificate.'));
		o.password = true;
		o.rmempty = true;
		o.depends('web_enable', '1');

		o = s.taboption('dashboard', form.Flag, 'web_behind_proxy',
			_('Behind TLS-terminating reverse proxy'),
			_('Declare that a reverse proxy terminates HTTPS in front of the plain-HTTP dashboard; session cookies are then always marked Secure.'));
		o.default = o.disabled;
		o.depends('web_enable', '1');

		/* ---- mcp: independent auth policy on the shared dashboard port ---- */

		o = s.taboption('mcp', form.ListValue, 'mcp_auth_mode',
			_('MCP authentication mode'),
			_('The MCP admin endpoint shares the dashboard port but can use its own authentication policy.'));
		o.value('inherit_web', _('Inherit dashboard login'));
		o.value('none', _('No authentication'));
		o.value('basic', _('HTTP Basic'));
		o.value('bearer', _('Bearer token'));
		o.value('api_key', _('API key header'));
		o.value('oauth_jwt', _('OAuth 2.0 JWT'));
		o.default = 'inherit_web';
		o.depends('web_enable', '1');

		o = s.taboption('mcp', form.Value, 'mcp_username', _('MCP username'));
		o.rmempty = false;
		o.depends('mcp_auth_mode', 'basic');

		o = s.taboption('mcp', form.Value, 'mcp_credential', _('MCP credential'),
			_('Plaintext here is normalized to a non-replayable SHA-256 verifier by the daemon.'));
		o.password = true;
		o.rmempty = false;
		o.depends('mcp_auth_mode', 'basic');
		o.depends('mcp_auth_mode', 'bearer');
		o.depends('mcp_auth_mode', 'api_key');

		o = s.taboption('mcp', form.Value, 'mcp_api_key_header', _('MCP API key header'));
		o.placeholder = 'X-API-Key';
		o.rmempty = true;
		o.depends('mcp_auth_mode', 'api_key');

		o = s.taboption('mcp', form.Value, 'mcp_path', _('MCP endpoint path'),
			_('Fixed secret path such as /a1b2c3d4e5f6. Set it explicitly on a router: an empty path is re-randomized at every interface restart and breaks clients.'));
		o.rmempty = true;
		o.depends('web_enable', '1');

		o = s.taboption('mcp', form.Value, 'mcp_jwks_url', _('MCP JWKS URL'),
			_('Public key set of the OAuth issuer; must be an absolute https URL.'));
		o.rmempty = false;
		o.depends('mcp_auth_mode', 'oauth_jwt');

		o = s.taboption('mcp', form.Value, 'mcp_issuer', _('MCP OAuth issuer'),
			_('Absolute https URL of the token issuer.'));
		o.rmempty = false;
		o.depends('mcp_auth_mode', 'oauth_jwt');

		o = s.taboption('mcp', form.Value, 'mcp_audience', _('MCP OAuth audience'),
			_('Audience claim this tunnel expects in access tokens.'));
		o.rmempty = false;
		o.depends('mcp_auth_mode', 'oauth_jwt');

		o = s.taboption('mcp', form.Value, 'mcp_resource', _('MCP OAuth resource'),
			_('Resource indicator URI of this MCP endpoint.'));
		o.rmempty = false;
		o.depends('mcp_auth_mode', 'oauth_jwt');

		o = s.taboption('mcp', form.DynamicList, 'mcp_authorization_servers', _('MCP authorization servers'),
			_('OAuth authorization server URLs, one entry per server. Empty falls back to the issuer.'));
		o.placeholder = 'https://idp.example.com';
		o.rmempty = true;
		o.depends('mcp_auth_mode', 'oauth_jwt');

		o = s.taboption('mcp', form.DynamicList, 'mcp_required_scopes', _('MCP required scopes'),
			_('OAuth scope names, one entry per scope.'));
		o.placeholder = 'vpn.read';
		o.rmempty = true;
		o.depends('mcp_auth_mode', 'oauth_jwt');

		/* ---- advanced: crypto detail, Brutal, priorities, accounting ---- */

		o = s.taboption('advanced', form.Value, 'req_v4',
			_('Requested tunnel IPv4'));
		o.datatype = 'cidr4';
		o.rmempty = true;

		o = s.taboption('advanced', form.Value, 'req_v6',
			_('Requested tunnel IPv6'));
		o.datatype = 'cidr6';
		o.rmempty = true;

		o = s.taboption('advanced', form.Value, 'mac', _('TAP MAC address'));
		o.datatype = 'macaddr';
		o.rmempty = true;

		o = s.taboption('advanced', form.Value, 'conns',
			_('Parallel connections'));
		o.datatype = 'and(uinteger,min(1),max(65536))';
		o.default = '1';

		o = s.taboption('advanced', form.Flag, 'fec', _('XOR FEC'));
		o.default = o.disabled;

		o = s.taboption('advanced', form.Value, 'fec_group',
			_('FEC group size'));
		o.datatype = 'and(uinteger,min(2),max(64))';
		o.default = '4';
		o.depends('fec', '1');

		o = s.taboption('advanced', form.Flag, 'encrypt',
			_('Inner AEAD encryption'));
		o.default = o.enabled;

		o = s.taboption('advanced', form.ListValue, 'enc_algo',
			_('Inner cipher'));
		o.value('gcm256', _('AES-256-GCM (default)'));
		o.value('gcm128', _('AES-128-GCM (faster)'));
		o.value('chacha20', _('ChaCha20-Poly1305'));
		o.value('xchacha20', _('XChaCha20-Poly1305'));
		o.default = 'gcm256';
		o.depends('encrypt', '1');

		o = s.taboption('advanced', form.ListValue, 'min_enc',
			_('Minimum inner encryption'));
		o.value('gcm', _('Require authenticated AEAD'));
		o.value('any', _('Allow TLS-only fallback'));
		o.default = 'gcm';
		o.depends('encrypt', '1');

		o = s.taboption('advanced', form.ListValue, 'pad_mode',
			_('Padding mode'));
		o.value('bucket', _('Bucket'));
		o.value('off', _('Off'));
		o.default = 'bucket';

		o = s.taboption('advanced', form.Flag, 'brutal',
			_('TCP Brutal'));
		o.default = o.disabled;

		o = s.taboption('advanced', form.Value, 'brutal_up',
			_('Brutal upload rate (Mbps)'));
		o.datatype = 'and(uinteger,min(0),max(1000000))';
		o.default = '100';
		o.depends('brutal', '1');

		o = s.taboption('advanced', form.Value, 'brutal_down',
			_('Brutal download rate (Mbps)'));
		o.datatype = 'and(uinteger,min(0),max(1000000))';
		o.default = '500';
		o.depends('brutal', '1');

		o = s.taboption('advanced', form.Value, 'socks5', _('SOCKS5 proxy'),
			_('Route all outbound sockets through this SOCKS5 proxy. Accepted forms: host:port, user:pass@host:port, socks5://... and socks5h://...'));
		o.placeholder = '127.0.0.1:1080';
		o.rmempty = true;

		o = s.taboption('advanced', form.Value, 'priority_control',
			_('Control frame write priority'),
			_('0-10, higher is written earlier on the same physical link. Control frames are heartbeats, RTT probes and FEC control.'));
		o.datatype = 'and(uinteger,min(0),max(10))';
		o.default = '7';

		o = s.taboption('advanced', form.Value, 'priority_data',
			_('Data frame write priority'),
			_('0-10, higher is written earlier. Defaults put control (7) above data (5); raise data above control for throughput-first behavior.'));
		o.datatype = 'and(uinteger,min(0),max(10))';
		o.default = '5';

		o = s.taboption('advanced', form.Value, 'probe_min_half_rtt_us',
			_('Probe half-RTT floor (µs)'),
			_('Physical lower bound for one-way latency decomposition; diagnostics only.'));
		o.datatype = 'and(uinteger,min(0),max(3600000))';
		o.default = '1000';

		o = s.taboption('advanced', form.Value, 'traffic_days',
			_('Daily traffic retention (days)'),
			_('How many local-calendar days of per-day traffic to keep. Hot-appliable from the dashboard.'));
		o.datatype = 'and(uinteger,min(1),max(3650))';
		o.default = '30';

		o = s.taboption('advanced', form.Value, 'traffic_file',
			_('Traffic statistics file'),
			_('Persistent JSON store for daily traffic. Empty defaults to /etc/tlsvpn/tlsvpn-<iface>-traffic.json, which survives reboots but writes to flash about once a minute while traffic flows; set a tmpfs path such as /var/etc/vpn-traffic.json to keep statistics in RAM only.'));
		o.rmempty = true;

		o = s.taboption('advanced', form.ListValue, 'log_level', _('Log level'));
		o.value('debug', 'DEBUG');
		o.value('info', 'INFO');
		o.value('warn', 'WARN');
		o.value('error', 'ERROR');
		o.default = 'info';
	}
});
