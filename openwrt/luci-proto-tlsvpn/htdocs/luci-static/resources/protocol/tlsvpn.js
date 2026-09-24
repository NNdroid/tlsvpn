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

		o = s.taboption('general', form.Value, 'server',
			_('TLSVPN server'),
			_('One or more host:port endpoints separated by commas. Every endpoint is pinned to the pre-tunnel routing domain to prevent recursive routing.'));
		o.placeholder = 'vpn.example.com:4000';
		o.rmempty = false;

		o = s.taboption('general', form.Value, 'psk', _('Pre-shared key'));
		o.password = true;
		o.rmempty = false;

		o = s.taboption('general', form.Value, 'tap', _('Tunnel device'),
			_('Optional TAP device name. Linux interface names are limited to 15 characters.'));
		o.placeholder = this.getIfname();
		o.datatype = 'uciname';

		o = s.taboption('general', widgets.NetworkSelect, 'tunlink',
			_('Underlying network'),
			_('Optional network used to reach the TLS transport endpoints. Leave empty to use normal routing.'));
		o.nocreate = true;
		o.rmempty = true;

		o = s.taboption('general', form.Value, 'sni', _('Camouflage SNI'));
		o.placeholder = 'www.cloudflare.com';

		o = s.taboption('general', form.Value, 'cert_sha256',
			_('Server certificate SHA-256'));
		o.placeholder = '0123456789abcdef...';

		o = s.taboption('general', form.Flag, 'insecure',
			_('Skip TLS certificate verification'));
		o.default = o.disabled;

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
			_('Inner AES-256-GCM encryption'));
		o.default = o.enabled;

		o = s.taboption('advanced', form.ListValue, 'min_enc',
			_('Minimum inner encryption'));
		o.value('gcm', _('Require GCM'));
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
		o.datatype = 'uinteger';
		o.default = '100';
		o.depends('brutal', '1');

		o = s.taboption('advanced', form.Value, 'brutal_down',
			_('Brutal download rate (Mbps)'));
		o.datatype = 'uinteger';
		o.default = '500';
		o.depends('brutal', '1');

		o = s.taboption('advanced', form.Value, 'socks5', _('SOCKS5 proxy'));
		o.placeholder = '127.0.0.1:1080';
		o.rmempty = true;

		o = s.taboption('advanced', form.ListValue, 'log_level', _('Log level'));
		o.value('debug', 'DEBUG');
		o.value('info', 'INFO');
		o.value('warn', 'WARN');
		o.value('error', 'ERROR');
		o.default = 'info';
	}
});
