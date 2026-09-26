const I18N={
'zh-CN':{kpi:{active:'活跃客户端/设备',tcp:'TCP 连接',tx:'总发送',rx:'总接收',uptime:'运行时长',version:'版本',gc:'立即回收',fec:'FEC 恢复 / 确认丢失',parity:'校验帧',overhead:'FEC 开销',pps:'包速率',cpu:'进程 CPU',cores:'核数:',dropped:'丢帧(队列)',reorder:'重排跳过',mem:'内存',goroutines:'Goroutines:',pool:'IPv4 地址池',v6used:'IPv6 已分配:'},
 chart:{title:'吞吐趋势',win:'(近 120 秒)',r2m:'2 分钟',r1h:'1 小时',r24h:'24 小时'},legend:{up:'上行',down:'下行',rtt:'RTT（均）'},
	tab:{clients:'客户端',conns:'连接明细',macs:'MAC 表',bans:'封禁',traffic:'流量',status:'运行状态',logs:'日志',settings:'设置'},
 tr:{today_up:'今日上行',today_down:'今日下行',today_total:'今日合计',daily:'每日流量',up:'上行',down:'下行',total:'合计',date:'日期',caption:'近 {n} 天',empty:'暂无按日统计数据',client:'客户端',all:'全部'},
 th:{id:'ID',v4:'IPv4',v6:'IPv6',mac:'MAC',tcp:'TCP',tx:'TX (发)',rx:'RX (收)',txs:'↑ 速率',rxs:'↓ 速率',fec:'FEC',enc:'加密',brutal:'Brutal',ops:'操作',kick:'踢出',ban:'封禁',unban:'解封',owner:'客户端',target:'目标',remote:'对端',state:'状态',rtt:'RTT',retries:'重试',age:'在线',epoch:'密钥代际',sni:'SNI',err:'最近错误'},
 m:{port:'端口',seen:'最近活跃'},bans:{id_ph:'ClientID（可短前缀）',min_ph:'分钟（留空=永久）',add:'封禁',refresh:'刷新',left:'剩余'},
 logs:{level:'级别',autoscroll:'自动滚动',clear:'清屏',download:'下载日志'},
 ui:{cancel:'取消',confirm:'确认'},goto:{traffic:'查看流量明细',logs:'查看错误日志'},menu_tip:'更多选项',no_logs:'暂无日志',page:{showing:'显示 {a}–{b} / 共 {n} 条',of:'第 {x} / {y} 页',prev:'上一页',next:'下一页',size:'{n} 条 / 页',all:'全部'},
 unauth:{title:'需要访问凭据',hint:'面板启用了访问控制（-web-auth user:pass）。请用 http://user:pass@host:port/ 形式的地址打开，或在浏览器弹出的认证框中输入凭据。'},
 toast:{kick:'已强制断开客户端',ban:'已封禁客户端',unban:'已解除封禁',gc:'已触发 GC',reconnect:'已触发重连',loglevel:'日志级别已更新',saved:'配置已保存',applied:'配置已保存并应用',fail:'操作失败',need_id:'请输入 ClientID',clear:'日志已清空',download:'日志已导出'},
 filter_ph:'输入关键字过滤…',filter_none:'无匹配结果',filter_clear:'清除过滤',filter_tip:'按 / 快速聚焦',no_clients:'暂无客户端',no_conns:'无连接',no_macs:'尚未学习到 MAC',no_bans:'无封禁记录',srv_only:'仅服务端模式提供',
 perm:'永久',confirm_kick:'确定要强制断开该客户端吗？',confirm_ban:'确定封禁该客户端吗？',need_id:'请输入 ClientID',
 st:{up:'up',connecting:'connecting',skip:'未生效'},
 badge:{dup:'复制',off:'关闭',ctr:'CTR',plain:'明文'},
 u:{day:'天',hour:'时',min:'分',sec:'秒'},updated:'更新于 {n}',footer:'数据每 {n} 秒刷新',refresh_tip:'刷新间隔',
	tls_http:'HTTP（建议启用 HTTPS）',mode_local:'本机',theme_tip:'主题（跟随系统）',theme:{sys:'Auto',light:'Light',dark:'Dark'},
 ov:{alerts:'异常提醒',none:'没有异常',alerts_off:'异常提醒已关闭',alerts_n:'{n} 项',pad_kpi:'填充开销',pad_wire:'填充后线路字节',pad_bytes:'填充字节',pad_pct:'填充占比',protect:'防护路径',sessions:'会话水位',reconnect:'重连尝试',prot:{off:'未启用',n:'{n} 项',conns:'并发上限拒绝',tls:'TLS 握手失败',fallback:'落到伪装站点',tarpit:'焦油坑（延迟探测）',fec:'FEC 分组超限拒绝',psk:'PSK 失败排行',psk_empty:'无 PSK 失败记录',window:'窗口'},hooks:'up/down 钩子',routes:'策略路由（内核实际状态）',tap:'TAP 链路层',routes_n:'{n} 条',rules_n:'{n} 条规则',routes_n2:'{n} 条路由',age:'快照 {n}s',no_data:'当前平台不支持或未配置',not_applied:'未启用',hook:{up:'up 钩子',down:'down 钩子',ran:'执行成功',fail:'执行失败',never:'尚未执行',ms:'耗时',out:'输出',err:'错误'},route:{rules:'ip rule',routes:'ip route',table:'路由表',age:'快照'},link:{up:'UP 状态',mtu:'MTU',rx:'RX 字节 / 包',tx:'TX 字节 / 包',errs:'RX / TX 错误',drops:'RX / TX 丢弃'},err_tls:'TLS 握手失败 {n}',err_fb:'非隧道流量 {n}',err_tarpit:'焦油坑 {n}',err_prot:'防护拒绝 {n}',err_drop:'丢帧 {n}',err_tap:'TAP 写失败 {n}',err_bp:'队列溢出',err_spoof:'伪造源 MAC',err_bcast:'泛洪超限',err_reord:'乱序缓冲溢出',err_fec:'FEC 丢失 {n}',err_rec:'FEC 恢复 {n}',err_pool:'地址池 {n}',err_sess:'会话 {n}',err_cpu:'进程 CPU {n}',err_pad:'填充开销 {n}',err_cert:'证书 {n}',err_cert_ok:'证书 {n} 天后到期',err_cert_bad:'证书已过期',err_reconn:'重连 {n}',err_neg:'策略路由未生效',err_nosess:'会话数触顶',err_hookup:'up 钩子失败',err_hookdown:'down 钩子失败',err_psk:'PSK 失败 {n}',export:'导出 CSV',export_done:'已导出 CSV',no_table:'暂无数据可导出',rtt:'RTT 统计',q:'质量指标',avg:'平均',p95:'P95',mx:'最大',mn:'最小',drop_pct:'丢帧率',avgpkt:'平均包大小',fec_eff:'FEC 效率',rtt_n:'{n} 条连接',avg_rtt:'平均 {n} ms',p95_rtt:'P95 {n} ms'},
 cfgk:{insecure:'跳过证书校验（不安全）',cert_sha256:'证书指纹锁定',sni:'伪装 SNI',req_v4:'请求的 IPv4',req_v6:'请求的 IPv6',interface_manager:'接口管理方式',hooks_up:'up 钩子',hooks_down:'down 钩子',traffic_days:'流量统计保留天数',traffic_file:'流量统计文件',mode:'运行模式',encrypt:'内层加密',enc_algo:'内层算法',min_enc:'最低加密要求',pad_mode:'填充模式',brutal:'TCP Brutal',brutal_up:'上行总量 (Mbps)',brutal_down:'下行总量 (Mbps)',socks5:'SOCKS5 代理',fec:'FEC',fec_group:'FEC 分组',fec_group_min:'FEC 分组下限',fec_group_max:'FEC 分组上限',log_level:'日志级别',conns:'并发连接数',tap:'TAP 设备',mac:'MAC 地址',addr:'服务端地址',web_addr:'面板监听',web_auth:'面板认证',web_bind:'面板绑定地址',web_https:'面板 HTTPS',encrypt_psk:'PSK 已配置',session_encrypt:'会话加密',max_sessions:'最大会话数',v4_cidr:'IPv4 网段',v6_cidr:'IPv6 网段',gw_v4:'IPv4 网关',gw_v6:'IPv6 网关',fwmark:'策略路由 fwmark',fwmark_priority:'规则优先级',fwmark_table:'路由表号',extra_routes:'额外路由',source_rules:'按源前缀路由'},
 stt:{title:'运行状态',host:'宿主与进程',negt:'协议协商结果',brutal:'TCP Brutal 明细',cfg:'生效配置快照',
   restart:'以下字段已修改，需要重启进程才能生效：',norestart:'无字段需要重启生效',noneg:'尚未与对端完成握手',
   noerr:'全部生效',kern_yes:'内核已支持',kern_no:'内核不支持',
   sys:{os:'操作系统',arch:'CPU 架构',go:'Go 版本',cpu:'CPU 核数',cpu_use:'进程 CPU 占用',cert:'服务端证书',host:'主机名',cfgpath:'配置文件',ver:'程序版本',load:'负载 (1/5/15 分)',mem:'物理内存',fd:'打开文件数',gc:'GC 次数 / 暂停'},
	  neg:{proto:'协议版本',fec:'FEC',grp:'FEC 分组',enc:'内层加密',pad:'填充模式',minenc:'最低加密要求',stoken:'Session Token',epoch:'密钥代际',tx:'客户端 → 服务端（上行）',rx:'服务端 → 客户端（下行）',prroute:'策略路由生效',tlsfp:'最近连接 ClientHello 指纹（非 JA3/JA4）',tlsver:'TLS 协商版本',tlscipher:'TLS 协商套件',tlsalpn:'TLS ALPN',tlssni:'TLS SNI',tlsoffer:'ClientHello 特征数'},
   brut:{en:'开关',up:'上行总量',down:'下行总量',kern:'内核支持',cur:'当前拥塞控制',avail:'可用拥塞控制',applied:'已生效 / 总数',perconn:'每连接速率',errs:'失败原因',off:'未启用'},
   yes:'是',no:'否'},
 set:{hint:'编辑 JSON 配置。保存：写回配置文件；保存并应用：写回并立即热更运行参数（列出的字段需重启生效）。',
   load:'重新加载',save:'保存',apply:'保存并应用',saved:'已保存',applied:'已保存并应用',restart_nr:'需重启生效:',loaded_err:'加载失败:'}},
'en':{kpi:{active:'Active clients',tcp:'TCP connections',tx:'Total sent',rx:'Total received',uptime:'Uptime',version:'Version',gc:'GC now',fec:'FEC recovered / confirmed lost',parity:'Parity frames',dropped:'Dropped (queue)',reorder:'Reorder skipped',mem:'Memory',goroutines:'Goroutines:',pool:'IPv4 pool',v6used:'IPv6 allocated:',pps:'Packet rate',cpu:'Process CPU',cores:'Cores:',overhead:'FEC overhead'},
 chart:{title:'Throughput',win:'(last 120s)',r2m:'2 min',r1h:'1 h',r24h:'24 h'},legend:{up:'Up',down:'Down',rtt:'RTT (avg)'},
	tab:{clients:'Clients',conns:'Connections',macs:'MAC table',bans:'Bans',traffic:'Traffic',status:'Runtime status',logs:'Logs',settings:'Settings'},
 tr:{today_up:'Up today',today_down:'Down today',today_total:'Total today',daily:'Daily traffic',up:'Up',down:'Down',total:'Total',date:'Date',caption:'Last {n} days',empty:'No daily traffic data yet',client:'Client',all:'All'},
 th:{id:'ID',v4:'IPv4',v6:'IPv6',mac:'MAC',tcp:'TCP',tx:'TX',rx:'RX',txs:'↑ Rate',rxs:'↓ Rate',fec:'FEC',enc:'Encrypt',brutal:'Brutal',ops:'Actions',kick:'Kick',ban:'Ban',unban:'Unban',owner:'Client',target:'Target',remote:'Remote',state:'State',rtt:'RTT',retries:'Retries',age:'Uptime',epoch:'Epoch',sni:'SNI',err:'Last error'},
 m:{port:'Port',seen:'Last seen'},bans:{id_ph:'ClientID (short prefix ok)',min_ph:'Minutes (empty = permanent)',add:'Ban',refresh:'Refresh',left:'Remaining'},
 logs:{level:'Level',autoscroll:'Auto scroll',clear:'Clear',download:'Download'},
 ui:{cancel:'Cancel',confirm:'Confirm'},goto:{traffic:'Open traffic detail',logs:'Open error logs'},menu_tip:'More options',no_logs:'No log lines yet',page:{showing:'Showing {a}–{b} of {n}',of:'Page {x} of {y}',prev:'Previous',next:'Next',size:'{n} per page',all:'All'},
 unauth:{title:'Authentication required',hint:'Dashboard authentication is enabled (-web-auth user:pass). Open the panel with credentials in the address, e.g. http://user:pass@host:port/, or answer the browser prompt.'},
 toast:{kick:'Client force-disconnected',ban:'Client banned',unban:'Ban lifted',gc:'GC triggered',reconnect:'Reconnect triggered',loglevel:'Log level updated',saved:'Config saved',applied:'Config saved & applied',fail:'Action failed',need_id:'Please enter a ClientID',clear:'Logs cleared',download:'Logs exported'},
 filter_ph:'Type to filter…',filter_none:'No matches',filter_clear:'Clear filter',filter_tip:'Press / to focus',no_clients:'No clients yet',no_conns:'No connections',no_macs:'No MACs learned yet',no_bans:'No banned clients',srv_only:'Server mode only',
 perm:'Permanent',confirm_kick:'Force-disconnect this client?',confirm_ban:'Ban this client?',need_id:'Please enter a ClientID',
 st:{up:'up',connecting:'connecting',skip:'Skipped'},
 badge:{dup:'Dup',off:'Off',ctr:'CTR',plain:'Plain'},
 u:{day:'d',hour:'h',min:'m',sec:'s'},updated:'Updated at {n}',footer:'Refreshing every {n}s',refresh_tip:'Refresh interval',
	tls_http:'HTTP (HTTPS recommended)',mode_local:'local',theme_tip:'Theme (follow system)',theme:{sys:'Auto',light:'Light',dark:'Dark'},
 ov:{alerts:'Anomalies',none:'Nothing unusual',alerts_off:'Anomaly alerts off',alerts_n:'{n} issue(s)',pad_kpi:'Padding overhead',pad_wire:'Padded wire bytes',pad_bytes:'Padding bytes',pad_pct:'Padding share',protect:'Protection paths',sessions:'Session water level',reconnect:'Reconnect attempts',prot:{off:'Not enabled',n:'{n} items',conns:'Concurrent-limit rejects',tls:'TLS handshake failures',fallback:'Fallback to camouflage site',tarpit:'Tarpit (slow probes)',fec:'FEC group out of range',psk:'PSK failure leaderboard',psk_empty:'No PSK failures',window:'window'},hooks:'up/down hooks',routes:'Policy routing (actual kernel state)',tap:'TAP link layer',routes_n:'{n} entries',rules_n:'{n} rules',routes_n2:'{n} routes',age:'snapshot {n}s',no_data:'Not supported on this platform or not configured',not_applied:'Not enabled',hook:{up:'up hook',down:'down hook',ran:'ran ok',fail:'failed',never:'not run yet',ms:'elapsed',out:'output',err:'error'},route:{rules:'ip rule',routes:'ip route',table:'Route table',age:'snapshot'},link:{up:'UP state',mtu:'MTU',rx:'RX bytes / pkts',tx:'TX bytes / pkts',errs:'RX / TX errors',drops:'RX / TX drops'},err_tls:'TLS handshake failures {n}',err_fb:'Non-tunnel traffic {n}',err_tarpit:'Tarpit {n}',err_prot:'Protection rejects {n}',err_drop:'Frames dropped {n}',err_tap:'TAP write failures {n}',err_bp:'queue overflow',err_spoof:'spoofed src MAC',err_bcast:'flood budget exceeded',err_reord:'reorder buffer overflow',err_fec:'FEC lost {n}',err_rec:'FEC recovered {n}',err_pool:'Address pool {n}',err_sess:'Sessions {n}',err_cpu:'Process CPU {n}',err_pad:'Padding overhead {n}',err_cert:'Certificate {n}',err_cert_ok:'Certificate expires in {n} days',err_cert_bad:'Certificate expired',err_reconn:'Reconnects {n}',err_neg:'Policy routing not applied',err_nosess:'Session limit reached',err_hookup:'up hook failed',err_hookdown:'down hook failed',err_psk:'PSK failures {n}',export:'Export CSV',export_done:'CSV exported',no_table:'Nothing to export yet',rtt:'RTT stats',q:'Quality',avg:'Avg',p95:'P95',mx:'Max',mn:'Min',drop_pct:'Drop rate',avgpkt:'Avg packet size',fec_eff:'FEC efficiency',rtt_n:'{n} conns',avg_rtt:'avg {n} ms',p95_rtt:'P95 {n} ms'},
 cfgk:{insecure:'Skip cert verification (unsafe)',cert_sha256:'Pinned cert fingerprint',sni:'Camouflage SNI',req_v4:'Requested IPv4',req_v6:'Requested IPv6',interface_manager:'Interface manager',hooks_up:'up hook',hooks_down:'down hook',traffic_days:'Traffic retention days',traffic_file:'Traffic stats file',mode:'Mode',encrypt:'Inner cipher',enc_algo:'Inner algorithm',min_enc:'Minimum cipher',pad_mode:'Padding mode',brutal:'TCP Brutal',brutal_up:'Upstream total (Mbps)',brutal_down:'Downstream total (Mbps)',socks5:'SOCKS5 proxy',fec:'FEC',fec_group:'FEC group',fec_group_min:'FEC group floor',fec_group_max:'FEC group ceiling',log_level:'Log level',conns:'Concurrent conns',tap:'TAP device',mac:'MAC address',addr:'Server address',web_addr:'Dashboard listen',web_auth:'Dashboard auth',web_bind:'Dashboard bind',web_https:'Dashboard HTTPS',encrypt_psk:'PSK configured',session_encrypt:'Session encryption',max_sessions:'Max sessions',v4_cidr:'IPv4 CIDR',v6_cidr:'IPv6 CIDR',gw_v4:'IPv4 gateway',gw_v6:'IPv6 gateway',fwmark:'Policy routing fwmark',fwmark_priority:'Rule priority',fwmark_table:'Route table',extra_routes:'Extra routes',source_rules:'Source rules'},
 stt:{title:'Runtime status',host:'Host & process',negt:'Negotiated protocol',brutal:'TCP Brutal detail',cfg:'Effective config snapshot',
   restart:'These fields changed and require a process restart:',norestart:'Nothing pending restart',noneg:'Handshake with peer not completed yet',
   noerr:'All applied',kern_yes:'Kernel supported',kern_no:'Not supported by kernel',
   sys:{os:'OS',arch:'CPU arch',go:'Go version',cpu:'CPU cores',cpu_use:'Process CPU',cert:'Server certificate',host:'Hostname',cfgpath:'Config file',ver:'App version',load:'Load (1/5/15 min)',mem:'Physical memory',fd:'Open files',gc:'GC count / pause'},
	  neg:{proto:'Protocol version',fec:'FEC',grp:'FEC group',enc:'Inner cipher',pad:'Padding mode',minenc:'Minimum cipher',stoken:'Session token',epoch:'Key epoch',tx:'Client → server (uplink)',rx:'Server → client (downlink)',prroute:'Policy routing applied',tlsfp:'Latest connection ClientHello fingerprint (not JA3/JA4)',tlsver:'Negotiated TLS version',tlscipher:'Negotiated TLS cipher',tlsalpn:'TLS ALPN',tlssni:'TLS SNI',tlsoffer:'ClientHello feature counts'},
   brut:{en:'Enabled',up:'Upstream total',down:'Downstream total',kern:'Kernel support',cur:'Current CC',avail:'Available CC',applied:'Applied / total',perconn:'Per-conn rate',errs:'Failure reasons',off:'Not enabled'},
   yes:'yes',no:'no'},
 set:{hint:'Edit the JSON config. Save: write back to the config file. Save & apply: write back and hot-apply runtime parameters (listed fields require a restart).',
   load:'Reload',save:'Save',apply:'Save & apply',saved:'Saved',applied:'Saved & applied',restart_nr:'Needs restart:',loaded_err:'Load failed:'}},
'de':{kpi:{active:'Aktive Clients',tcp:'TCP-Verbindungen',tx:'Gesendet',rx:'Empfangen',uptime:'Laufzeit',version:'Version',gc:'GC ausführen',fec:'FEC wiederhergestellt / verloren',parity:'Paritätsframes',dropped:'Verworfen (Queue)',reorder:'Reorder übersprungen',mem:'Speicher',goroutines:'Goroutines:',pool:'IPv4-Pool',v6used:'IPv6 zugewiesen:',pps:'Paktrate',cpu:'Prozess-CPU',cores:'Kerne:',overhead:'FEC-Overhead'},
 chart:{title:'Durchsatz',win:'(letzte 120 s)',r2m:'2 Min',r1h:'1 Std',r24h:'24 Std'},legend:{up:'Uplink',down:'Downlink',rtt:'RTT (Ø)'},
 tab:{clients:'Clients',conns:'Verbindungen',macs:'MAC-Tabelle',bans:'Sperren',traffic:'Traffic',status:'Laufzeitstatus',logs:'Protokolle',settings:'Einstellungen'},
 th:{id:'ID',v4:'IPv4',v6:'IPv6',mac:'MAC',tcp:'TCP',tx:'TX (S)',rx:'RX (E)',txs:'↑ Rate',rxs:'↓ Rate',fec:'FEC',enc:'Verschlüsselung',brutal:'Brutal',ops:'Aktionen',kick:'Trennen',ban:'Sperren',unban:'Entsperren',owner:'Client',target:'Ziel',remote:'Gegenstelle',state:'Status',rtt:'RTT',retries:'Wiederholungen',age:'Online',epoch:'Schlüssel-Epoche',sni:'SNI',err:'Letzter Fehler'},
 m:{port:'Port',seen:'Zuletzt aktiv'},bans:{id_ph:'ClientID (Präfix ok)',min_ph:'Minuten (leer = dauerhaft)',add:'Sperren',refresh:'Aktualisieren',left:'Restlaufzeit'},
 logs:{level:'Level',autoscroll:'Auto-Scroll',clear:'Leeren',download:'Download'},
 ui:{cancel:'Abbrechen',confirm:'Bestätigen'},goto:{traffic:'Traffic-Details öffnen',logs:'Fehlerprotokoll öffnen'},menu_tip:'Weitere Optionen',no_logs:'Keine Protokolleinträge',page:{showing:'{a}–{b} von {n} Einträgen',of:'Seite {x} von {y}',prev:'Zurück',next:'Weiter',size:'{n} pro Seite',all:'Alle'},
 unauth:{title:'Anmeldedaten erforderlich',hint:'Der Panelzugriff ist geschützt (-web-auth user:pass). Öffne das Panel mit Anmeldedaten in der Adresse, z. B. http://user:pass@host:port/, oder gib sie im Browserhinweis ein.'},
 toast:{kick:'Client getrennt',ban:'Client gesperrt',unban:'Sperre aufgehoben',gc:'GC ausgelöst',reconnect:'Neuverbindung ausgelöst',loglevel:'Log-Level aktualisiert',saved:'Konfiguration gespeichert',applied:'Gespeichert & angewendet',fail:'Aktion fehlgeschlagen',need_id:'Bitte ClientID eingeben',clear:'Protokolle geleert',download:'Protokoll exportiert'},
 filter_ph:'Zum Filtern eingeben…',filter_none:'Keine Treffer',filter_clear:'Filter löschen',filter_tip:'/ zum Fokussieren',no_clients:'Keine Clients',no_conns:'Keine Verbindungen',no_macs:'Noch keine MACs gelernt',no_bans:'Keine Sperren',srv_only:'Nur im Server-Modus',
 perm:'Dauerhaft',confirm_kick:'Diesen Client wirklich trennen?',confirm_ban:'Diesen Client sperren?',need_id:'Bitte ClientID eingeben',
 st:{up:'aktiv',connecting:'verbinde',skip:'Übergangen'},
 badge:{dup:'Dup',off:'Aus',ctr:'CTR',plain:'Klartext'},
 u:{day:'T',hour:'Std',min:'Min',sec:'Sek'},updated:'Aktualisiert um {n}',footer:'Aktualisierung alle {n}s',refresh_tip:'Aktualisierungsintervall',
 tls_http:'HTTP (HTTPS empfohlen)',mode_local:'lokal',theme_tip:'Design (System folgen)',theme:{sys:'Auto',light:'Hell',dark:'Dunkel'},
 ov:{alerts:'Anomalien',none:'Nichts Ungewöhnliches',alerts_off:'Anomalieanzeige aus',alerts_n:'{n} Punkt(e)',pad_kpi:'Padding-Overhead',pad_wire:'Padded Bytes (Draht)',pad_bytes:'Padding-Bytes',pad_pct:'Padding-Anteil',protect:'Schutzpfade',sessions:'Sitzungs-Auslastung',reconnect:'Reconnect-Versuche',prot:{off:'Nicht aktiviert',n:'{n} Punkte',conns:'Grenzwert abgelehnt',tls:'TLS-Handshake-Fehler',fallback:'Rückfall auf Tarnsite',tarpit:'Tarpit (langsame Proben)',fec:'FEC-Gruppe außerhalb des Bereichs',psk:'PSK-Fehler-Ranking',psk_empty:'Keine PSK-Fehler',window:'Fenster'},hooks:'up/down-Hooks',routes:'Policy-Routing (echter Kernel-Zustand)',tap:'TAP-Linkebene',routes_n:'{n} Einträge',rules_n:'{n} Regeln',routes_n2:'{n} Routen',age:'Snapshot {n}s',no_data:'Von dieser Plattform nicht unterstützt oder nicht konfiguriert',not_applied:'Nicht aktiviert',hook:{up:'up-Hook',down:'down-Hook',ran:'erfolgreich',fail:'fehlgeschlagen',never:'noch nicht ausgeführt',ms:'Dauer',out:'Ausgabe',err:'Fehler'},route:{rules:'ip rule',routes:'ip route',table:'Routentabelle',age:'Snapshot'},link:{up:'UP-Zustand',mtu:'MTU',rx:'RX-Bytes / Pakete',tx:'TX-Bytes / Pakete',errs:'RX / TX-Fehler',drops:'RX / TX verworfen'},err_tls:'TLS-Handshake-Fehler {n}',err_fb:'Nicht-Tunnel-Verkehr {n}',err_tarpit:'Tarpit {n}',err_prot:'Schutz-Abweisungen {n}',err_drop:'Frames verworfen {n}',err_tap:'TAP-Schreibfehler {n}',err_bp:'Queue-Überlauf',err_spoof:'gefälschte Quell-MAC',err_bcast:'Flood-Limit überschritten',err_reord:'Reorder-Puffer überlauf',err_fec:'FEC verloren {n}',err_rec:'FEC wiederhergestellt {n}',err_pool:'Adresspool {n}',err_sess:'Sitzungen {n}',err_cpu:'Prozess-CPU {n}',err_pad:'Padding-Overhead {n}',err_cert:'Zertifikat {n}',err_cert_ok:'Zertifikat läuft in {n} Tagen ab',err_cert_bad:'Zertifikat abgelaufen',err_reconn:'Reconnects {n}',err_neg:'Policy-Routing nicht angewendet',err_nosess:'Sitzungslimit erreicht',err_hookup:'up-Hook fehlgeschlagen',err_hookdown:'down-Hook fehlgeschlagen',err_psk:'PSK-Fehler {n}',export:'CSV exportieren',export_done:'CSV exportiert',no_table:'Noch nichts zum Exportieren',rtt:'RTT-Statistik',q:'Qualität',avg:'Ø',p95:'P95',mx:'Max',mn:'Min',drop_pct:'Verwurfrate',avgpkt:'Ø Paketgröße',fec_eff:'FEC-Effizienz',rtt_n:'{n} Verbindungen',avg_rtt:'Ø {n} ms',p95_rtt:'P95 {n} ms'},
 cfgk:{insecure:'Zertifikatsprüfung überspringen (unsicher)',cert_sha256:'Zertifikats-Fingerprint fixiert',sni:'Tarn-SNI',req_v4:'Angefordert IPv4',req_v6:'Angefordert IPv6',interface_manager:'Interface-Verwaltung',hooks_up:'up-Hook',hooks_down:'down-Hook',traffic_days:'Traffic-Aufbewahrung (Tage)',traffic_file:'Traffic-Statistikdatei',mode:'Modus',encrypt:'Innere Verschlüsselung',enc_algo:'Innerer Algorithmus',min_enc:'Minimale Verschlüsselung',pad_mode:'Padding-Modus',brutal:'TCP Brutal',brutal_up:'Uplink gesamt (Mbps)',brutal_down:'Downlink gesamt (Mbps)',socks5:'SOCKS5-Proxy',fec:'FEC',fec_group:'FEC-Gruppe',fec_group_min:'FEC-Gruppe Minimum',fec_group_max:'FEC-Gruppe Maximum',log_level:'Log-Level',conns:'Parallele Verbindungen',tap:'TAP-Gerät',mac:'MAC-Adresse',addr:'Serveradresse',web_addr:'Panel-Adresse',web_auth:'Panel-Auth',web_bind:'Panel-Bindung',web_https:'Panel-HTTPS',encrypt_psk:'PSK konfiguriert',session_encrypt:'Sitzungsverschlüsselung',max_sessions:'Max. Sitzungen',v4_cidr:'IPv4-CIDR',v6_cidr:'IPv6-CIDR',gw_v4:'IPv4-Gateway',gw_v6:'IPv6-Gateway',fwmark:'Policy-Routing fwmark',fwmark_priority:'Regel-Priorität',fwmark_table:'Routentabelle',extra_routes:'Zusatzrouten',source_rules:'Quellregeln'},
 stt:{title:'Laufzeitstatus',host:'Host & Prozess',negt:'Ausgehandelte Parameter',brutal:'TCP Brutal Details',cfg:'Aktive Konfiguration',
   restart:'Diese Felder wurden geändert und erfordern einen Neustart des Prozesses:',norestart:'Kein Feld erfordert einen Neustart',noneg:'Handshake mit der Gegenstelle noch nicht abgeschlossen',
   noerr:'Alle angewendet',kern_yes:'Kernel unterstützt',kern_no:'Kernel nicht unterstützt',
   sys:{os:'Betriebssystem',arch:'CPU-Architektur',go:'Go-Version',cpu:'CPU-Kerne',cpu_use:'Prozess-CPU',cert:'Serverzertifikat',host:'Hostname',cfgpath:'Konfigurationsdatei',ver:'Programmversion',load:'Load (1/5/15 Min)',mem:'Physischer Speicher',fd:'Offene Dateien',gc:'GC-Anzahl / Pause'},
   neg:{proto:'Protokollversion',fec:'FEC',grp:'FEC-Gruppe',enc:'Innere Verschlüsselung',pad:'Padding-Modus',minenc:'Minimale Verschlüsselung',stoken:'Session-Token',epoch:'Schlüssel-Epoche',tx:'Client → Server (Uplink)',rx:'Server → Client (Downlink)',prroute:'Policy-Routing aktiv',tlsfp:'ClientHello-Fingerprint der letzten Verbindung (nicht JA3/JA4)',tlsver:'Ausgehandelte TLS-Version',tlscipher:'Ausgehandelte TLS-Cipher',tlsalpn:'TLS ALPN',tlssni:'TLS SNI',tlsoffer:'ClientHello-Merkmale'},
   brut:{en:'Schalter',up:'Uplink gesamt',down:'Downlink gesamt',kern:'Kernel-Unterstützung',cur:'Aktive CC',avail:'Verfügbare CC',applied:'Angewendet / gesamt',perconn:'Rate pro Verbindung',errs:'Fehlerursachen',off:'Nicht aktiviert'},
   yes:'ja',no:'nein'},
 set:{hint:'JSON-Konfiguration bearbeiten. Speichern: in die Datei zurückschreiben. Speichern & anwenden: zurückschreiben und Laufzeitparameter heiß anwenden (genannte Felder erfordern einen Neustart).',
   load:'Neu laden',save:'Speichern',apply:'Speichern & anwenden',saved:'Gespeichert',applied:'Gespeichert & angewendet',restart_nr:'Neustart nötig:',loaded_err:'Ladefehler:'},
 tr:{today_up:'Uplink heute',today_down:'Downlink heute',today_total:'Gesamt heute',daily:'Täglicher Traffic',up:'Uplink',down:'Downlink',total:'Gesamt',date:'Datum',caption:'Letzte {n} Tage',empty:'Noch keine täglichen Traffic-Daten',client:'Client',all:'Alle'}},
'fr':{kpi:{active:'Clients actifs',tcp:'Connexions TCP',tx:'Total envoyé',rx:'Total reçu',uptime:'Disponibilité',version:'Version',gc:'GC maintenant',fec:'FEC récupérés / perdus',parity:'Trames de parité',dropped:'Abandons (file)',reorder:'Réordonnancement ignoré',mem:'Mémoire',goroutines:'Goroutines :',pool:'Pool IPv4',v6used:'IPv6 allouées :',pps:'Taux de paquets',overhead:'Surcharge FEC',cpu:'CPU du processus',cores:'Cœurs :'},
 chart:{title:'Débit',win:'(120 dernières s)',r2m:'2 min',r1h:'1 h',r24h:'24 h'},legend:{up:'Montant',down:'Descendant',rtt:'RTT (moy.)'},
 tab:{clients:'Clients',conns:'Connexions',macs:'Table MAC',bans:'Bannissements',traffic:'Trafic',status:'État runtime',logs:'Journaux',settings:'Paramètres'},
 th:{id:'ID',v4:'IPv4',v6:'IPv6',mac:'MAC',tcp:'TCP',tx:'TX (env.)',rx:'RX (rec.)',txs:'↑ Débit',rxs:'↓ Débit',fec:'FEC',enc:'Chiffrement',brutal:'Brutal',ops:'Actions',kick:'Éjecter',ban:'Bannir',unban:'Débannir',owner:'Client',target:'Cible',remote:'Distant',state:'État',rtt:'RTT',retries:'Réessais',age:'En ligne',epoch:'Époque de clé',sni:'SNI',err:'Dernière erreur'},
 m:{port:'Port',seen:'Dernière activité'},bans:{id_ph:'ClientID (préfixe accepté)',min_ph:'Minutes (vide = permanent)',add:'Bannir',refresh:'Rafraîchir',left:'Restant'},
 logs:{level:'Niveau',autoscroll:'Défilement auto',clear:'Effacer',download:'Télécharger'},
 ui:{cancel:'Annuler',confirm:'Confirmer'},goto:{traffic:'Ouvrir les détails de trafic',logs:'Ouvrir les journaux d’erreur'},menu_tip:'Plus d’options',no_logs:'Aucune entrée de journal',page:{showing:'{a}–{b} sur {n}',of:'Page {x} sur {y}',prev:'Précédent',next:'Suivant',size:'{n} par page',all:'Tout'},
 unauth:{title:'Identifiants requis',hint:'L’authentification du panneau est activée (-web-auth user:pass). Ouvrez le panneau avec les identifiants dans l’adresse, p. ex. http://user:pass@host:port/, ou répondez à la boîte de dialogue du navigateur.'},
 toast:{kick:'Client déconnecté',ban:'Client banni',unban:'Bannissement levé',gc:'GC déclenché',reconnect:'Reconnexion déclenchée',loglevel:'Niveau de log mis à jour',saved:'Config enregistrée',applied:'Enregistré & appliqué',fail:'Échec de l’action',need_id:'Veuillez saisir un ClientID',clear:'Journaux effacés',download:'Journal téléchargé'},
 filter_ph:'Taper pour filtrer…',filter_none:'Aucun résultat',filter_clear:'Effacer le filtre',filter_tip:'/ pour le focus',no_clients:'Aucun client',no_conns:'Aucune connexion',no_macs:'Aucune MAC apprise',no_bans:'Aucun bannissement',srv_only:'Mode serveur uniquement',
 perm:'Permanent',confirm_kick:'Déconnecter ce client de force ?',confirm_ban:'Bannir ce client ?',need_id:'Veuillez saisir un ClientID',
 st:{up:'actif',connecting:'connexion',skip:'Ignoré'},
 badge:{dup:'Dup',off:'Désactivé',ctr:'CTR',plain:'Clair'},
 u:{day:'j',hour:'h',min:'min',sec:'s'},updated:'Actualisé à {n}',footer:"Actualisation toutes les {n}s",refresh_tip:"Intervalle d'actualisation",
 tls_http:'HTTP (HTTPS recommandé)',mode_local:'local',theme_tip:"Thème (suivre le système)",theme:{sys:'Auto',light:'Clair',dark:'Sombre'},
 ov:{alerts:'Anomalies',none:'Rien d’anormal',alerts_off:'Alertes d’anomalie désactivées',alerts_n:'{n} point(s)',pad_kpi:'Surcharge de remplissage',pad_wire:'Octets sur le lien (remplis)',pad_bytes:'Octets de remplissage',pad_pct:'Part de remplissage',protect:'Voies de protection',sessions:'Niveau de sessions',reconnect:'Tentatives de reconnexion',prot:{off:'Non activé',n:'{n} points',conns:'Refusés (limite simultanée)',tls:'Échecs de handshake TLS',fallback:'Redirigés vers le site déguisé',tarpit:'Bourbier (probes lentes)',fec:'Groupe FEC hors plage',psk:'Classement des échecs PSK',psk_empty:'Aucun échec PSK',window:'fenêtre'},hooks:'Accroches up/down',routes:'Routage par stratégie (état réel du noyau)',tap:'Couche liaison TAP',routes_n:'{n} entrées',rules_n:'{n} règles',routes_n2:'{n} routes',age:'instantané {n}s',no_data:'Non pris en charge sur cette plateforme ou non configuré',not_applied:'Non activé',hook:{up:'accroche up',down:'accroche down',ran:'réussi',fail:'en échec',never:'pas encore exécutée',ms:'durée',out:'sortie',err:'erreur'},route:{rules:'ip rule',routes:'ip route',table:'Table de routage',age:'instantané'},link:{up:'État UP',mtu:'MTU',rx:'Octets / paquets RX',tx:'Octets / paquets TX',errs:'Erreurs RX / TX',drops:'Abandons RX / TX'},err_tls:'Échecs TLS {n}',err_fb:'Trafic non tunnel {n}',err_tarpit:'Bourbier {n}',err_prot:'Refus de protection {n}',err_drop:'Trames abandonnées {n}',err_tap:'Échecs d’écriture TAP {n}',err_bp:'débordement de file',err_spoof:'MAC source falsifiée',err_bcast:'budget de diffusion dépassé',err_reord:'débordement du tampon réordonnancement',err_fec:'FEC perdus {n}',err_rec:'FEC récupérés {n}',err_pool:'Pool d’adresses {n}',err_sess:'Sessions {n}',err_cpu:'CPU du processus {n}',err_pad:'Surcharge de remplissage {n}',err_cert:'Certificat {n}',err_cert_ok:'Certificat expire dans {n} jours',err_cert_bad:'Certificat expiré',err_reconn:'Reconnexions {n}',err_neg:'Routage par stratégie inopérant',err_nosess:'Limite de sessions atteinte',err_hookup:'accroche up en échec',err_hookdown:'accroche down en échec',err_psk:'Échecs PSK {n}',export:'Exporter CSV',export_done:'CSV exporté',no_table:'Rien à exporter',rtt:'Statistiques RTT',q:'Qualité',avg:'Moy.',p95:'P95',mx:'Max',mn:'Min',drop_pct:'Taux d’abandon',avgpkt:'Taille moyenne de paquet',fec_eff:'Efficacité FEC',rtt_n:'{n} connexions',avg_rtt:'moy. {n} ms',p95_rtt:'P95 {n} ms'},
 cfgk:{insecure:'Ignorer la vérification du certificat (non sûr)',cert_sha256:'Empreinte de certificat épinglée',sni:'SNI de camouflage',req_v4:'IPv4 demandée',req_v6:'IPv6 demandée',interface_manager:'Gestionnaire d’interface',hooks_up:'accroche up',hooks_down:'accroche down',traffic_days:'Rétention du trafic (jours)',traffic_file:'Fichier de statistiques de trafic',mode:'Mode',encrypt:'Chiffrement interne',enc_algo:'Algorithme interne',min_enc:'Chiffrement minimum',pad_mode:'Mode de remplissage',brutal:'TCP Brutal',brutal_up:'Montant total (Mbps)',brutal_down:'Descendant total (Mbps)',socks5:'Proxy SOCKS5',fec:'FEC',fec_group:'Groupe FEC',fec_group_min:'Groupe FEC min',fec_group_max:'Groupe FEC max',log_level:'Niveau de log',conns:'Connexions simultanées',tap:'Périphérique TAP',mac:'Adresse MAC',addr:'Adresse du serveur',web_addr:'Écoute du panneau',web_auth:'Auth du panneau',web_bind:'Liaison du panneau',web_https:'HTTPS du panneau',encrypt_psk:'PSK configurée',session_encrypt:'Chiffrement de session',max_sessions:'Sessions max',v4_cidr:'CIDR IPv4',v6_cidr:'CIDR IPv6',gw_v4:'Passerelle IPv4',gw_v6:'Passerelle IPv6',fwmark:'fwmark routage par stratégie',fwmark_priority:'Priorité de règle',fwmark_table:'Table de routage',extra_routes:'Routes supplémentaires',source_rules:'Règles par source'},
 stt:{title:'État runtime',host:'Hôte & processus',negt:'Paramètres négociés',brutal:'Détails TCP Brutal',cfg:'Instantané de la config effective',
   restart:'Ces champs ont été modifiés et exigent un redémarrage du processus :',norestart:'Aucun champ ne requiert de redémarrage',noneg:'Handshake avec le pair pas encore terminé',
   noerr:'Tout appliqué',kern_yes:'Noyau compatible',kern_no:'Noyau non compatible',
   sys:{os:'Système',arch:'Arch. CPU',go:'Version Go',cpu:'Cœurs CPU',cpu_use:'CPU du processus',cert:'Certificat serveur',host:"Nom d'hôte",cfgpath:'Fichier de configuration',ver:'Version du programme',load:'Charge (1/5/15 min)',mem:"Mémoire physique",fd:'Fichiers ouverts',gc:'GC : nombre / pause'},
   neg:{proto:'Version du protocole',fec:'FEC',grp:'Groupe FEC',enc:'Chiffrement interne',pad:'Mode de remplissage',minenc:'Chiffrement minimum',stoken:'Jeton de session',epoch:'Époque de clé',tx:'Client → serveur (montant)',rx:'Serveur → client (descendant)',prroute:'Routage par stratégie actif',tlsfp:"Empreinte ClientHello de la dernière connexion (pas JA3/JA4)",tlsver:'Version TLS négociée',tlscipher:'Suite TLS négociée',tlsalpn:'TLS ALPN',tlssni:'TLS SNI',tlsoffer:'Caractéristiques ClientHello'},
   brut:{en:'Activé',up:'Montant total',down:'Descendant total',kern:'Support noyau',cur:'CC actuel',avail:'CC disponibles',applied:'Appliqué / total',perconn:'Débit par connexion',errs:"Causes d'échec",off:'Non activé'},
   yes:'oui',no:'non'},
 set:{hint:'Éditer la config JSON. Enregistrer : réécrire le fichier. Enregistrer & appliquer : réécrire et appliquer à chaud les paramètres runtime (certains champs exigent un redémarrage).',
   load:'Recharger',save:'Enregistrer',apply:'Enregistrer & appliquer',saved:'Enregistré',applied:'Enregistré & appliqué',restart_nr:'Redémarrage requis :',loaded_err:'Échec du chargement :'},
 tr:{today_up:'Montant du jour',today_down:'Descendant du jour',today_total:'Total du jour',daily:'Trafic quotidien',up:'Montant',down:'Descendant',total:'Total',date:'Date',caption:'{n} derniers jours',empty:'Pas encore de données de trafic quotidien',client:'Client',all:'Tous'}},
'ja':{kpi:{active:'アクティブクライアント',tcp:'TCP 接続',tx:'送信合計',rx:'受信合計',uptime:'稼働時間',version:'バージョン',gc:'即時 GC',fec:'FEC 復元 / 確定ロスト',parity:'パリティフレーム',dropped:'廃棄（キュー）',reorder:'並べ替えスキップ',mem:'メモリ',goroutines:'Goroutines:',pool:'IPv4 プール',v6used:'IPv6 割り当て:',pps:'パケット速度',overhead:'FEC オーバーヘッド',cpu:'プロセス CPU',cores:'コア:'},
 chart:{title:'スループット',win:'（過去 120 秒）',r2m:'2 分',r1h:'1 時間',r24h:'24 時間'},legend:{up:'上り',down:'下り',rtt:'RTT（平均）'},
 tab:{clients:'クライアント',conns:'接続明細',macs:'MAC テーブル',bans:'禁止',traffic:'トラフィック',status:'稼働状態',logs:'ログ',settings:'設定'},
 th:{id:'ID',v4:'IPv4',v6:'IPv6',mac:'MAC',tcp:'TCP',tx:'TX（送）',rx:'RX（受）',txs:'↑ 速度',rxs:'↓ 速度',fec:'FEC',enc:'暗号化',brutal:'Brutal',ops:'操作',kick:'切断',ban:'禁止',unban:'解除',owner:'クライアント',target:'接続先',remote:'対向',state:'状態',rtt:'RTT',retries:'再試行',age:'経過時間',epoch:'鍵世代',sni:'SNI',err:'最新エラー'},
 m:{port:'ポート',seen:'最終アクティブ'},bans:{id_ph:'ClientID（前方一致可）',min_ph:'分数（空欄=永久）',add:'禁止',refresh:'更新',left:'残り'},
 logs:{level:'レベル',autoscroll:'自動スクロール',clear:'クリア',download:'ダウンロード'},
 ui:{cancel:'キャンセル',confirm:'確認'},goto:{traffic:'トラフィック詳細を表示',logs:'エラーログを表示'},menu_tip:'その他のオプション',no_logs:'ログはまだありません',page:{showing:'{n} 件中 {a}–{b}',of:'ページ {x} / {y}',prev:'前へ',next:'次へ',size:'{n} 件 / ページ',all:'すべて'},
 unauth:{title:'認証が必要です',hint:'パネルにアクセス制御が有効です（-web-auth user:pass）。http://user:pass@host:port/ のように認証情報を URL に含めたアドレスで開くか、ブラウザのプロンプトに入力してください。'},
 toast:{kick:'クライアントを強制切断しました',ban:'クライアントを禁止しました',unban:'禁止を解除しました',gc:'GC を実行しました',reconnect:'再接続を依頼しました',loglevel:'ログレベルを更新しました',saved:'設定を保存しました',applied:'設定を保存・適用しました',fail:'操作に失敗しました',need_id:'ClientID を入力してください',clear:'ログをクリアしました',download:'ログをエクスポートしました'},
 filter_ph:'入力して絞り込み…',filter_none:'該当なし',filter_clear:'フィルタ解除',filter_tip:'/ でフォーカス',no_clients:'クライアントなし',no_conns:'接続なし',no_macs:'学習済み MAC なし',no_bans:'禁止レコードなし',srv_only:'サーバーモードのみ',
 perm:'永久',confirm_kick:'このクライアントを強制切断しますか？',confirm_ban:'このクライアントを禁止しますか？',need_id:'ClientID を入力してください',
 st:{up:'up',connecting:'connecting',skip:'未適用'},
 badge:{dup:'複製',off:'オフ',ctr:'CTR',plain:'平文'},
 u:{day:'日',hour:'時間',min:'分',sec:'秒'},updated:'更新時刻 {n}',footer:'{n} 秒ごとに更新',refresh_tip:'更新間隔',
 tls_http:'HTTP（HTTPS 推奨）',mode_local:'ローカル',theme_tip:'テーマ（システムに従う）',theme:{sys:'Auto',light:'Light',dark:'Dark'},
 ov:{alerts:'異常アラート',none:'異常はありません',alerts_off:'異常アラートを無効化しました',alerts_n:'{n} 件',pad_kpi:'パディングオーバーヘッド',pad_wire:'パディング後の通信バイト',pad_bytes:'パディングバイト',pad_pct:'パディング割合',protect:'保護経路',sessions:'セッション水位',reconnect:'再接続試行',prot:{off:'未有効',n:'{n} 項目',conns:'同時接続上限による拒否',tls:'TLS ハンドシェイク失敗',fallback:'偽装サイトへ誘導',tarpit:'タールピット（遅延プローブ）',fec:'FEC グループ超過拒否',psk:'PSK 失敗ランキング',psk_empty:'PSK 失敗なし',window:'ウィンドウ'},hooks:'up/down フック',routes:'ポリシールーティング（カーネルの実状態）',tap:'TAP リンク層',routes_n:'{n} 件',rules_n:'{n} ルール',routes_n2:'{n} ルート',age:'スナップショット {n}s',no_data:'このプラットフォームは非対応、または未設定',not_applied:'未有効',hook:{up:'up フック',down:'down フック',ran:'成功',fail:'失敗',never:'未実行',ms:'所要時間',out:'出力',err:'エラー'},route:{rules:'ip rule',routes:'ip route',table:'ルートテーブル',age:'スナップショット'},link:{up:'UP 状態',mtu:'MTU',rx:'RX バイト / パケット',tx:'TX バイト / パケット',errs:'RX / TX エラー',drops:'RX / TX 破棄'},err_tls:'TLS ハンドシェイク失敗 {n}',err_fb:'トンネル外トラフィック {n}',err_tarpit:'タールピット {n}',err_prot:'保護による拒否 {n}',err_drop:'破棄フレーム {n}',err_tap:'TAP 書き込み失敗 {n}',err_bp:'キュー溢れ',err_spoof:'偽装元 MAC',err_bcast:'ブロードキャスト超過',err_reord:'リオーダバッファ溢れ',err_fec:'FEC ロスト {n}',err_rec:'FEC 復元 {n}',err_pool:'アドレスプール {n}',err_sess:'セッション {n}',err_cpu:'プロセス CPU {n}',err_pad:'パディングオーバーヘッド {n}',err_cert:'証明書 {n}',err_cert_ok:'証明書が {n} 日後に期限切れ',err_cert_bad:'証明書が期限切れ',err_reconn:'再接続 {n}',err_neg:'ポリシールーティング未有効',err_nosess:'セッション上限に達しました',err_hookup:'up フック失敗',err_hookdown:'down フック失敗',err_psk:'PSK 失敗 {n}',export:'CSV 出力',export_done:'CSV を出力しました',no_table:'出力できるデータがありません',rtt:'RTT 統計',q:'品質指標',avg:'平均',p95:'P95',mx:'最大',mn:'最小',drop_pct:'破棄率',avgpkt:'平均パケットサイズ',fec_eff:'FEC 効率',rtt_n:'{n} 接続',avg_rtt:'平均 {n} ms',p95_rtt:'P95 {n} ms'},
 cfgk:{insecure:'証明書検証をスキップ（危険）',cert_sha256:'証明書フィンガープリント固定',sni:'偽装 SNI',req_v4:'要求 IPv4',req_v6:'要求 IPv6',interface_manager:'インターフェース管理方式',hooks_up:'up フック',hooks_down:'down フック',traffic_days:'トラフィック保持日数',traffic_file:'トラフィック統計ファイル',mode:'動作モード',encrypt:'内層暗号化',enc_algo:'内層アルゴリズム',min_enc:'最低暗号化要件',pad_mode:'パディングモード',brutal:'TCP Brutal',brutal_up:'上り合計 (Mbps)',brutal_down:'下り合計 (Mbps)',socks5:'SOCKS5 プロキシ',fec:'FEC',fec_group:'FEC グループ',fec_group_min:'FEC グループ下限',fec_group_max:'FEC グループ上限',log_level:'ログレベル',conns:'同時接続数',tap:'TAP デバイス',mac:'MAC アドレス',addr:'サーバーアドレス',web_addr:'パネル待受',web_auth:'パネル認証',web_bind:'パネルバインド',web_https:'パネル HTTPS',encrypt_psk:'PSK 設定済み',session_encrypt:'セッション暗号化',max_sessions:'最大セッション数',v4_cidr:'IPv4 CIDR',v6_cidr:'IPv6 CIDR',gw_v4:'IPv4 ゲートウェイ',gw_v6:'IPv6 ゲートウェイ',fwmark:'ポリシールーティング fwmark',fwmark_priority:'ルール優先度',fwmark_table:'ルートテーブル',extra_routes:'追加ルート',source_rules:'送信元ルール'},
 stt:{title:'稼働状態',host:'ホストとプロセス',negt:'ネゴシエーション結果',brutal:'TCP Brutal 明細',cfg:'有効な設定スナップショット',
   restart:'以下のフィールドは変更済み、プロセスの再起動が必要です：',norestart:'再起動が必要なフィールドはありません',noneg:'対向とのハンドシェイク未完了',
   noerr:'すべて有効',kern_yes:'カーネル対応',kern_no:'カーネル未対応',
   sys:{os:'OS',arch:'CPU アーキ',go:'Go バージョン',cpu:'CPU コア数',cpu_use:'プロセス CPU 使用率',cert:'サーバー証明書',host:'ホスト名',cfgpath:'設定ファイル',ver:'プログラムバージョン',load:'負荷 (1/5/15 分)',mem:'物理メモリ',fd:'オープンファイル数',gc:'GC 回数 / 停止時間'},
   neg:{proto:'プロトコルバージョン',fec:'FEC',grp:'FEC グループ',enc:'内層暗号化',pad:'パディングモード',minenc:'最低暗号化要件',stoken:'セッショントークン',epoch:'鍵世代',tx:'クライアント → サーバー（上り）',rx:'サーバー → クライアント（下り）',prroute:'ポリシールーティング有効',tlsfp:'最新接続の ClientHello フィンガープリント（JA3/JA4 ではなく）',tlsver:'TLS バージョン',tlscipher:'TLS 暗号スイート',tlsalpn:'TLS ALPN',tlssni:'TLS SNI',tlsoffer:'ClientHello 特徴数'},
   brut:{en:'スイッチ',up:'上り合計',down:'下り合計',kern:'カーネル対応',cur:'現在の輻輳制御',avail:'利用可能な輻輳制御',applied:'適用 / 合計',perconn:'接続ごとの速度',errs:'失敗理由',off:'未有効'},
   yes:'はい',no:'いいえ'},
 set:{hint:'JSON 設定を編集。保存：設定ファイルへ書き戻し。保存して適用：書き戻した上で実行パラメータをホット適用（一部フィールドは再起動が必要）。',load:'再読み込み',save:'保存',apply:'保存して適用',saved:'保存済み',applied:'保存して適用済み',restart_nr:'再起動が必要：',loaded_err:'読み込み失敗：'},
 tr:{today_up:'本日の上り',today_down:'本日の下り',today_total:'本日合計',daily:'日別トラフィック',up:'上り',down:'下り',total:'合計',date:'日付',caption:'過去 {n} 日',empty:'日別トラフィックデータはまだありません',client:'クライアント',all:'全体'}}};
// 浏览器语言 → 面板语言：前缀匹配，zh 系一律落到 zh-CN（简体）
function detectLang(){
  const l=(navigator.language||'en').toLowerCase();
  if(l.startsWith('zh'))return 'zh-CN';
  if(l.startsWith('de'))return 'de';
  if(l.startsWith('fr'))return 'fr';
  if(l.startsWith('ja'))return 'ja';
  return 'en';
}
	let LANG=localStorage.getItem('tlsvpn_lang')||detectLang();
function t(path){const dig=d=>{let o=d;for(const k of path.split('.'))o=o?o[k]:undefined;return o;};
  const cur=dig(I18N[LANG]);if(cur!==undefined)return cur;
  const en=dig(I18N['en']);if(en!==undefined)return en;return path;}
function setSeg(id,val){
  const seg=document.getElementById(id);if(!seg)return;
  seg.querySelectorAll('button').forEach(b=>b.classList.toggle('on',b.dataset.v===val));
}
function applyI18n(){
  document.documentElement.lang=LANG;
  document.querySelectorAll('[data-i18n]').forEach(el=>el.textContent=t(el.dataset.i18n));
  document.querySelectorAll('[data-i18n-ph]').forEach(el=>el.placeholder=t(el.dataset.i18nPh));
  document.querySelectorAll('[data-i18n-title]').forEach(el=>el.title=t(el.dataset.i18nTitle));
  setSeg('lang-seg',LANG);
  setSeg('refresh-seg',String(REFRESH_S));
  setSeg('range-seg',chartRange);
  applyTheme();
  // 下拉框文案取自 option 文本，换语言后要跟着重画
  syncSelects();
}
function setLang(v){localStorage.setItem('tlsvpn_lang',v);location.reload();}
function fmtDur(s){s=Math.floor(s);const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
  if(d>0)return d+t('u.day')+h+t('u.hour');if(h>0)return h+t('u.hour')+m+t('u.min');
  if(m>0)return m+t('u.min')+(s%60)+t('u.sec');return s+t('u.sec');}
function fmtBytes(b,s=false){
  if(!isFinite(b)||b<=0)return '0 '+(s?'B/s':'B');
  const u=["B","KB","MB","GB","TB"],i=Math.min(4,Math.max(0,Math.floor(Math.log(b)/Math.log(1024))));
  return parseFloat((b/Math.pow(1024,i)).toFixed(2))+' '+u[i]+(s?'/s':'');
}
function badge(f){if(!f||f==='off')return '<span class="badge b-off">'+t('badge.off')+'</span>';
  if(f==='dup')return '<span class="badge b-dup">'+t('badge.dup')+'</span>';return '<span class="badge b-on">'+f+'</span>';}
function encBadge(a){if(a===2)return '<span class="badge b-on">AES-256-GCM</span>';
  if(a===4)return '<span class="badge b-on">AES-128-GCM</span>';
  return '<span class="badge b-off">'+t('badge.plain')+'</span>';}
function stBadge(s){if(s==='up')return '<span class="badge b-on">'+t('st.up')+'</span>';
  if(s==='connecting')return '<span class="badge b-dup">'+t('st.connecting')+'</span>';
  return '<span class="badge b-off">'+(s||'-')+'</span>';}
function shortId(id,n){return id.length>n?id.slice(0,n)+'…':id;}
function esc(x){return String(x==null?'':x).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\x22/g,'&quot;').replace(/\x27/g,'&#39;');}
// hi 在已转义的文本上高亮首个命中（查询词为小写）；无命中原样返回
function hi(s,q){
  if(!q)return s;
  const i=s.toLowerCase().indexOf(q);
  return i<0?s:s.slice(0,i)+'<mark>'+s.slice(i,i+q.length)+'</mark>'+s.slice(i+q.length);
}
function showPane(id){
  document.querySelectorAll('#tabs button').forEach(b=>b.classList.toggle('on',b.dataset.pane===id));
  document.querySelectorAll('.pane').forEach(p=>p.classList.remove('on'));
  document.getElementById('pane-'+id).classList.add('on');
  if(id==='logs')startLogPoll();else stopLogPoll();
  if(id==='settings')loadConfig();
  // 刚显示的面板之前在 display:none 里量不到宽度，按钮的 min-width 还是 0
  syncSelects();
}
document.getElementById('tabs').addEventListener('click',function(ev){
  const btn=ev.target.closest('button');if(!btn)return;
  showPane(btn.dataset.pane);
});

// ---------- 通用折线图渲染：纵轴刻度 + 末端标签防裁剪 + 悬停提示 ----------
const chartState={};
function roundRectPath(ctx,x,y,w,h,r){
  ctx.beginPath();
  ctx.moveTo(x+r,y);ctx.arcTo(x+w,y,x+w,y+h,r);ctx.arcTo(x+w,y+h,x,y+h,r);
  ctx.arcTo(x,y+h,x,y,r);ctx.arcTo(x,y,x+w,y,r);ctx.closePath();
}
function fmtHM(ms){
  const d=new Date(ms);
  return ('0'+d.getHours()).slice(-2)+':'+('0'+d.getMinutes()).slice(-2)+':'+('0'+d.getSeconds()).slice(-2);
}
// pts: [{x∈0..1, up, down, rtt?, label}]；opts: {max, maxRtt, perSec, hover}
// 上下行共用字节纵轴（左侧刻度），RTT 独立刻度（右侧琥珀色，仅趋势图有值时）。
function renderLineChart(canvasId,pts,opts){
  const c=document.getElementById(canvasId);if(!c)return;
  const ctx=c.getContext('2d');
  const dpr=window.devicePixelRatio||1;
  const W=c.clientWidth||1100,H=c.clientHeight||216;
  if(c.width!==Math.round(W*dpr)||c.height!==Math.round(H*dpr)){c.width=Math.round(W*dpr);c.height=Math.round(H*dpr);}
  ctx.setTransform(dpr,0,0,dpr,0,0);
  ctx.clearRect(0,0,W,H);
  const L=56,R=16,T=16,B=24,pw=W-L-R,ph=H-T-B;
  const max=Math.max(1,opts.max||1);
  // 网格 + 纵坐标刻度
  ctx.strokeStyle=cssv('--grid');ctx.lineWidth=1;
  ctx.fillStyle=cssv('--sub');ctx.font='10px sans-serif';ctx.textAlign='right';
  for(let g=0;g<=4;g++){
    const y=T+ph*g/4;
    ctx.beginPath();ctx.moveTo(L,y+.5);ctx.lineTo(W-R,y+.5);ctx.stroke();
    ctx.fillText(fmtBytes(max*(4-g)/4,opts.perSec),L-6,y+3);
  }
  ctx.textAlign='left';
  if(!pts||pts.length<2){
    chartState[canvasId]={pts:[],plot:{l:L,r:W-R,t:T,b:H-B},hover:-1};
    return;
  }
  // 上下行：面积填充 + 折线
  const plot=(get,col)=>{
    ctx.beginPath();
    pts.forEach((p,i)=>{
      const x=L+p.x*pw,y=T+(1-get(p)/max)*ph;
      if(i)ctx.lineTo(x,y);else ctx.moveTo(x,y);
    });
    ctx.strokeStyle=col;ctx.lineWidth=2;ctx.lineJoin='round';ctx.lineCap='round';ctx.stroke();
    const grad=ctx.createLinearGradient(0,T,0,H-B);
    grad.addColorStop(0,col+'3d');grad.addColorStop(1,col+'00');
    ctx.lineTo(L+pts[pts.length-1].x*pw,H-B);ctx.lineTo(L,H-B);ctx.closePath();
    ctx.fillStyle=grad;ctx.fill();
  };
  plot(p=>p.down,cssv('--down'));
  plot(p=>p.up,cssv('--up'));
  // RTT 独立刻度虚线 + 右侧刻度
  const maxRtt=opts.maxRtt||0;
  if(maxRtt>0){
    ctx.beginPath();
    pts.forEach((p,i)=>{
      const x=L+p.x*pw,y=T+(1-p.rtt/maxRtt)*ph;
      if(i)ctx.lineTo(x,y);else ctx.moveTo(x,y);
    });
    ctx.strokeStyle=cssv('--warn');ctx.lineWidth=1.5;ctx.setLineDash([4,4]);ctx.stroke();ctx.setLineDash([]);
    ctx.fillStyle=cssv('--warn');ctx.font='10px sans-serif';ctx.textAlign='right';
    ctx.fillText('RTT ≤ '+Math.ceil(maxRtt)+' ms',W-R,T+2);
    ctx.fillText(Math.ceil(maxRtt/2)+' ms',W-R,T+ph/2+2);
    ctx.textAlign='left';
  }
  // x 轴刻度：稀疏标注，末端标签钳制在画布内防裁剪
  ctx.fillStyle=cssv('--sub');ctx.font='10px sans-serif';ctx.textAlign='center';
  const step=Math.ceil(pts.length/8);
  pts.forEach((p,i)=>{
    if(i%step!==0&&i!==pts.length-1)return;
    const tw=ctx.measureText(p.label).width;
    const tx=Math.max(L,Math.min(L+p.x*pw-tw/2,W-R-tw));
    ctx.fillText(p.label,tx,H-8);
  });
  ctx.textAlign='left';
  // 悬停：十字线 + 数据点圆标 + 提示框
  const hover=opts.hover;
  if(hover>=0&&hover<pts.length){
    const p=pts[hover],px=L+p.x*pw;
    ctx.strokeStyle=cssv('--border2');ctx.setLineDash([3,3]);
    ctx.beginPath();ctx.moveTo(px+.5,T);ctx.lineTo(px+.5,H-B);ctx.stroke();ctx.setLineDash([]);
    const dot=(y,col)=>{
      ctx.beginPath();ctx.arc(px,y,3.5,0,Math.PI*2);
      ctx.fillStyle=col;ctx.fill();
      ctx.strokeStyle=cssv('--card');ctx.lineWidth=1.5;ctx.stroke();
    };
    dot(T+(1-p.up/max)*ph,cssv('--up'));
    dot(T+(1-p.down/max)*ph,cssv('--down'));
    if(maxRtt>0&&p.rtt)dot(T+(1-p.rtt/maxRtt)*ph,cssv('--warn'));
    const lines=[p.label,'↑ '+fmtBytes(p.up,opts.perSec),'↓ '+fmtBytes(p.down,opts.perSec)];
    if(maxRtt>0&&p.rtt)lines.push('RTT '+p.rtt.toFixed(0)+' ms');
    ctx.font='11px sans-serif';
    let bw=0;
    lines.forEach(s=>{bw=Math.max(bw,ctx.measureText(s).width);});
    bw+=16;const bh=lines.length*15+10;
    let bx=px+10;if(bx+bw>W-R)bx=px-10-bw;
    const by=T;
    ctx.globalAlpha=.95;ctx.fillStyle=cssv('--card');
    roundRectPath(ctx,bx,by,bw,bh,7);ctx.fill();
    ctx.globalAlpha=1;ctx.strokeStyle=cssv('--border2');ctx.lineWidth=1;
    roundRectPath(ctx,bx,by,bw,bh,7);ctx.stroke();
    lines.forEach((s,i)=>{
      ctx.fillStyle=i===0?cssv('--sub'):(i===1?cssv('--up'):(i===2?cssv('--down'):cssv('--warn')));
      ctx.fillText(s,bx+8,by+18+i*15);
    });
  }
  chartState[canvasId]={pts:pts,plot:{l:L,r:W-R,t:T,b:H-B},hover:opts.hover};
}
// 把横坐标换算成最近数据点的下标（几何信息存于 chartState）
function chartIdxAt(canvasId,cx){
  const st=chartState[canvasId];
  if(!st||st.pts.length<2)return -1;
  const rect=document.getElementById(canvasId).getBoundingClientRect();
  const idx=Math.round((cx-rect.left-st.plot.l)/(st.plot.r-st.plot.l)*(st.pts.length-1));
  return Math.max(0,Math.min(st.pts.length-1,idx));
}
// 悬停/点按提示：用 Pointer 事件同时覆盖鼠标悬停、触屏点按与横滑选点，
// 触屏上没有 hover，点按后提示保持停留直到移到画布外。
function bindChartHover(canvasId,redraw){
  const c=document.getElementById(canvasId);if(!c)return;
  const pick=function(ev){
    const st=chartState[canvasId];
    const idx=chartIdxAt(canvasId,ev.clientX);
    if(idx>=0&&st&&st.hover!==idx){st.hover=idx;redraw();}
  };
  c.addEventListener('pointermove',pick);
  c.addEventListener('pointerdown',pick);
  c.addEventListener('pointerleave',function(){
    const st=chartState[canvasId];
    if(st&&st.hover!==-1){st.hover=-1;redraw();}
  });
}

function drawChart(){
  const n=txHist.length;
  const pts=[];
  for(let i=0;i<n;i++){
    pts.push({x:n>1?i/(n-1):0,up:txHist[i],down:rxHist[i],label:fmtHM(txTimes[i]||Date.now())});
  }
  const old=chartState['chart'];
  const hover=(old&&old.hover>=0&&old.hover<n)?old.hover:-1;
  renderLineChart('chart',pts,{max:Math.max(1,...txHist,...rxHist,1),perSec:true,hover:hover});
}

// 刷新间隔以秒存储（兼容旧版存毫秒的值）；面板顶栏为分段按钮
let REFRESH_S=parseInt(localStorage.getItem('tlsvpn_refresh')||'2',10);
if(REFRESH_S!==2&&REFRESH_S!==5&&REFRESH_S!==10){
  const ms=REFRESH_S;
  REFRESH_S=(ms===2000||ms===5000||ms===10000)?ms/1000:2;
}
let REFRESH=REFRESH_S*1000;
let statsTimer=null;
function setRefresh(sec){REFRESH_S=sec;REFRESH=sec*1000;localStorage.setItem('tlsvpn_refresh',String(sec));
  setSeg('refresh-seg',String(sec));
  document.getElementById('footer-text').textContent=t('footer').replace('{n}',sec);
  restartLoop();}
function restartLoop(){if(statsTimer)clearInterval(statsTimer);statsTimer=setInterval(fetchStats,REFRESH);}

// 用带凭据的地址（http://admin:xx@host/ 打开面板）时，Chrome 拒绝构造任何 fetch——
// "Request cannot be constructed from a URL that includes credentials"——于是每一轮轮询都抛
// 同一条 TypeError，面板永远停在初始骨架上，日志里只剩一行重复报错，完全看不出是地址栏
// 里的凭据引起的。换成 Authorization 头 + 去掉 userinfo 的 URL 即可；同域请求带这个头
// 不触发预检，所以不影响未启用认证的情况。
const AUTH_HDR=(location.username||location.password)
  ?{Authorization:'Basic '+btoa(unescape(encodeURIComponent(location.username+':'+location.password)))}
  :{};
// location.origin 按规范不含 userinfo，是构造不带凭据 URL 的可靠基址
function url(path){return location.origin+path;}

async function api(path,opts){opts=opts||{};opts.headers=Object.assign({'X-Requested-With':'tlsvpn'},AUTH_HDR,opts.headers||{});return fetch(url(path),opts);}
// 控制类请求统一入口：成功与失败都给出 Toast，不再静默。成功返回解析后的响应体，
// 失败返回 null（调用方一般不依赖返回值，动作后统一 fetchStats 刷新可见状态）。
async function control(body,okMsg){
  try{
    const res=await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(!res.ok){
      const err=await res.text().catch(function(){return String(res.status);});
      toast(t('toast.fail')+' '+err.slice(0,120),'err');
      return null;
    }
    toast(okMsg,'ok');
    return await res.json().catch(function(){return {};});
  }catch(e){
    toast(String(e),'err');
    return null;
  }
}
// 401：面板启用了 -web-auth 时用统一风格的认证提示页，而不是换进一张裸卡片
function showUnauthorized(){
  document.body.className='unauth';
  document.body.innerHTML=
    '<div class="auth-401">'+
      '<div class="auth-401-logo"><svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div>'+
      '<h2>401</h2>'+
      '<div class="auth-401-title">'+esc(t('unauth.title'))+'</div>'+
      '<p class="auth-401-hint">'+esc(t('unauth.hint'))+'</p>'+
      '<code class="mono auth-401-cmd">-web-auth user:pass</code>'+
    '</div>';
}

// ---------- 交互反馈：Toast 通知 / 美化确认框 / 按钮忙碌态 ----------
const TOAST_MAX=4;
function toast(msg,kind){
  const box=document.getElementById('toasts');if(!box)return;
  while(box.childElementCount>=TOAST_MAX)box.firstChild.remove();
  const el=document.createElement('div');
  el.className='toast '+(kind||'ok');
  el.innerHTML='<span class="toast-ico">'+(kind==='err'?'✕':'✓')+'</span>'+
    '<span class="toast-msg">'+esc(msg)+'</span>';
  box.appendChild(el);
  setTimeout(function(){el.classList.add('out');setTimeout(function(){el.remove();},350);},2600);
}
// uiConfirm 替代原生 confirm()：统一风格的美化模态框，Promise 语义；Esc 与点遮罩都等于取消
function uiConfirm(msg){
  return new Promise(function(resolve){
    const wrap=document.createElement('div');
    wrap.className='modal-mask';
    wrap.innerHTML='<div class="modal"><div class="modal-msg">'+esc(msg)+'</div>'+
      '<div class="modal-btns"><button class="btn ghost" data-r="0">'+t('ui.cancel')+'</button>'+
      '<button class="btn danger" data-r="1">'+t('ui.confirm')+'</button></div></div>';
    document.body.appendChild(wrap);
    function settle(ok){
      document.removeEventListener('keydown',onKey,true);
      wrap.remove();
      resolve(ok);
    }
    function onKey(ev){
      if(ev.key==='Escape'){ev.stopPropagation();settle(false);}
    }
    wrap.addEventListener('click',function(ev){
      const b=ev.target.closest('button');
      if(b){settle(b.getAttribute('data-r')==='1');return;}
      if(ev.target===wrap)settle(false);
    });
    document.addEventListener('keydown',onKey,true);
  });
}
// 动作按钮点击后短暂禁用，防止连点重复触发（控制类请求都伴随一次 fetchStats）
document.addEventListener('click',function(ev){
  const b=ev.target.closest('button.btn');
  if(!b||b.classList.contains('busy'))return;
  b.classList.add('busy');
  setTimeout(function(){b.classList.remove('busy');},900);
},true);
// 可点击 KPI 卡：流量卡直达流量页，丢帧卡直达日志页并预置错误过滤
document.addEventListener('click',function(ev){
  const card=ev.target.closest('.kpi-card[data-goto]');
  if(!card)return;
  const pane=card.getAttribute('data-goto');
  if(!document.getElementById('pane-'+pane))return;
  showPane(pane);
  const f=card.getAttribute('data-log-filter');
  const inp=document.getElementById('log-filter');
  if(f&&inp){
    logFilter=f.toLowerCase();
    inp.value=f;
    const clr=document.getElementById('log-filter-clear');
    if(clr)clr.classList.add('show');
  }
  applyLogFilter();
});
// 窄屏收纳：顶栏三段控件折进右上角可展开菜单，点菜单外或 Esc 收起
(function(){
  const btn=document.getElementById('menu-btn'),ctl=document.getElementById('topctl');
  if(!btn||!ctl)return;
  btn.addEventListener('click',function(ev){ev.stopPropagation();ctl.classList.toggle('open');});
  document.addEventListener('click',function(ev){if(!ctl.contains(ev.target))ctl.classList.remove('open');});
  document.addEventListener('keydown',function(ev){if(ev.key==='Escape')ctl.classList.remove('open');});
})();

function passFilter(obj,f){return !f||JSON.stringify(obj).toLowerCase().includes(f);}

const NO_TXT={clients:'no_clients',conns:'no_conns',macs:'no_macs',bans:'no_bans',srv:'srv_only',traffic:'tr.empty',logs:'no_logs'};
// 空状态配一个淡色图标：一整块纯空白读起来像渲染失败
const EMPTY_ICON={
  clients:'<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/>',
  conns:'<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>',
  macs:'<rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/>',
  bans:'<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/>',
  srv:'<circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>',
  traffic:'<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>',
  logs:'<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="16" y2="13"/>'
};
function emptyIcon(kind){return '<svg class="empty-ico" viewBox="0 0 24 24">'+(EMPTY_ICON[kind]||EMPTY_ICON.srv)+'</svg>';}
// msg 为可信 i18n 文案（允许内嵌 <br>），extra 放"清除过滤"按钮
function emptyRow(key,cols,msg,extra){
  return '<tr><td class="empty" colspan="'+cols+'">'+emptyIcon(key)+'<div class="empty-txt">'+msg+'</div>'+
    (extra||'')+'</td></tr>';
}
// 表格空状态：完全没有数据 vs 有数据但被过滤掉，两种提示要能区分
function emptyTableRow(key,cols,total){
  if(!total)return emptyRow(key,cols,t(NO_TXT[key]));
  return emptyRow(key,cols,t('filter_none')+'<br>','<button class="btn ghost sm" onclick="clearFilter(\''+key+'\')">'+t('filter_clear')+'</button>');
}
// ---------- 表格分页：默认 25 行/页，可切 50/100/全部；每页只重画工具条内容有变化时，
// 否则 2 秒一次的轮询会重建 DOM、打断已展开的页大小下拉框 ----------
const PAGE_SIZES=[25,50,100,0];
let pageState={};
function pageConf(key){
  if(!pageState[key])pageState[key]={page:1,size:PAGE_SIZES[0]};
  return pageState[key];
}
// size=0 表示不分页；行数变少时页码越界，收敛到最后一页而不是停在空白页
function settlePage(key,total){
  const c=pageConf(key);
  let pages=1;
  if(c.size>0)pages=Math.max(1,Math.ceil(total/c.size));
  if(c.page<1||c.page>pages)c.page=pages;
  c.pages=pages;
  return c;
}
function pageView(key,arr){
  const c=settlePage(key,arr.length);
  let rows=arr;
  if(c.size>0)rows=arr.slice((c.page-1)*c.size,(c.page-1)*c.size+c.size);
  const out={rows:rows,c:c};
  return out;
}
function renderPager(key,total){
  const el=document.getElementById('pager-'+key);
  if(!el)return;
  const c=settlePage(key,total);
  // 单页（或选"全部"后只剩一页）不占位置；空表同样不占位置
  if(c.size>0&&total<=c.size){if(el.innerHTML)el.innerHTML='';return;}
  let from=0,to=total;
  if(c.size>0){from=(c.page-1)*c.size;to=Math.min(total,from+c.size);}
  let opts='';
  PAGE_SIZES.forEach(function(n){
    let sel='';
    if(n===c.size)sel=' selected';
    // n=0 是"不分页"，显示全部而不是"0 条 / 页"
    let label=t('page.size');
    if(n>0)label=tpl(label,{n:n});
    else label=t('page.all');
    opts+='<option value="'+n+'"'+sel+'>'+label+'</option>';
  });
  // 上一页 / 下一页：chevron 图标 + i18n 悬停文案，到边界时禁用
  let prevBtn='<button class="btn ghost sm pg-btn"';
  let nextBtn='<button class="btn ghost sm pg-btn"';
  if(c.page<=1)prevBtn+=' disabled';
  if(c.page>=c.pages)nextBtn+=' disabled';
  prevBtn+=' title="'+esc(t('page.prev'))+'" onclick="goPage(\''+key+'\','+(c.page-1)+')">‹</button>';
  nextBtn+=' title="'+esc(t('page.next'))+'" onclick="goPage(\''+key+'\','+(c.page+1)+')">›</button>';
  const html='<span class="dim">'+tpl(t('page.showing'),{a:from+1,b:to,n:total})+'</span>'+
    '<span class="pager-right">'+
      '<select class="sel pg-sel" onchange="setPageSize(\''+key+'\',this.value)">'+opts+'</select>'+
      prevBtn+
      '<span class="pg-of">'+tpl(t('page.of'),{x:c.page,y:c.pages})+'</span>'+
      nextBtn+
    '</span>';
  // 工具条内容变了就整块重画；重画出来的原生 select 要重新包成自绘下拉框
  if(el.innerHTML!==html){el.innerHTML=html;syncSelects();}
}
function goPage(key,p){
  pageConf(key).page=p;
  if(key==='traffic')renderTrafficView();else rerenderTables();
}
function setPageSize(key,n){
  const c=pageConf(key);
  // 0 是"不分页"的哨兵值，不能用 || 兜底，否则"全部"会被悄悄改成默认 25
  const v=parseInt(n,10);
  if(!isNaN(v))c.size=v;
  else c.size=PAGE_SIZES[0];
  c.page=1;
  if(key==='traffic')renderTrafficView();else rerenderTables();
}
// 多占位符替换：词条里可能同时出现 {a}{b}{n}
function tpl(s,o){
  let out=String(s);
  for(const k in o)out=out.split('{'+k+'}').join(o[k]);
  return out;
}
// ---------- 自定义下拉框 ----------
// 原生 <select> 的弹层是操作系统画的，CSS 染不上去（暗色面板配一个白底黑字菜单）。
// 做法：select 留在 DOM 里继续当唯一取值来源（.dl-native 只把它缩成 1px 藏起来），
// 外面套自绘的触发按钮和菜单；选中项只写 select.value 再派发一次原生 change 事件，
// 所以各处 onchange（setLogLevel / renderTrafficView / setPageSize）和程序化写值
// （服务端每轮轮询回写 log_level）一行都不用改。
const DL=new WeakMap();
let dlCur=null;
const DL_ARROW='<svg width="10" height="6" viewBox="0 0 10 6" aria-hidden="true"><path d="M1 1l4 4 4-4" stroke="currentColor" stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>';

// 包起来：外壳 + 触发按钮（当前值 + chevron）+ 菜单；原生 select 缩成 1px 藏在里面
function buildSelect(sel){
  if(DL.has(sel))return;
  const host=sel.parentNode;
  const wrap=document.createElement('div');
  wrap.className='dl';
  // select 上的内联宽度约束（如 max-width:260px）搬给外壳，否则外壳会塌成按钮内容宽
  const stStyle=sel.getAttribute('style');
  if(stStyle)wrap.setAttribute('style',stStyle);
  host.insertBefore(wrap,sel);
  wrap.appendChild(sel);
  sel.classList.add('dl-native');
  sel.tabIndex=-1;
  sel.setAttribute('aria-hidden','true');
  const btn=document.createElement('div');
  // 复用 select 上的附加类（pg-sel 等）拿到它们的尺寸规则，剥掉 .sel 与 .dl-native 本身
  let bcls='dl-btn';
  sel.classList.forEach(function(c){if(c!=='sel'&&c!=='dl-native')bcls+=' '+c;});
  btn.className=bcls;
  btn.setAttribute('role','combobox');
  btn.setAttribute('aria-haspopup','listbox');
  btn.setAttribute('aria-expanded','false');
  btn.tabIndex=0;
  const lab=document.createElement('span');
  lab.className='dl-lab';
  // sz 是占位撑子：装最宽的那条选项文本，让按钮宽度跟最宽项走、切选项时不左右抖；
  // cur 才是真正显示当前值的文本，绝对定位叠在 sz 上面
  const sz=document.createElement('span');
  sz.className='dl-sz';
  const cur=document.createElement('span');
  cur.className='dl-cur';
  lab.appendChild(sz);
  lab.appendChild(cur);
  btn.appendChild(lab);
  const ar=document.createElement('span');
  ar.className='dl-arrow';
  ar.innerHTML=DL_ARROW;
  btn.appendChild(ar);
  wrap.appendChild(btn);
  const menu=document.createElement('div');
  menu.className='dl-menu';
  menu.setAttribute('role','listbox');
  menu.setAttribute('aria-hidden','true');
  wrap.appendChild(menu);
  const st={wrap:wrap,host:host&&host.tagName==='LABEL'?host:null,btn:btn,cur:cur,sz:sz,menu:menu,items:[],active:0};
  DL.set(sel,st);
  btn.addEventListener('click',function(ev){ev.stopPropagation();dlToggle(sel);});
  btn.addEventListener('keydown',function(ev){dlKey(sel,ev);});
  menu.addEventListener('click',function(ev){
    const d=ev.target.closest('.dl-opt');
    if(d)dlPick(sel,parseInt(d.getAttribute('data-i'),10));
  });
  // 原生 change 时重建菜单与文案（含我们派发的那一次）
  sel.addEventListener('change',function(){syncSelect(sel);});
  // 外层若是 <label>，点标签文字也要能开合弹层
  if(st.host)st.host.addEventListener('click',function(ev){
    if(wrap.contains(ev.target))return;
    ev.preventDefault();
    dlToggle(sel);
    btn.focus();
  });
  syncSelect(sel);
}

// 以原生 select 为准重建菜单与触发器文案：选项列表和当前值都可能被外部改写过
function syncSelect(sel){
  const st=DL.get(sel);
  if(!st)return;
  const ops=sel.options;
  const n=ops.length;
  let cur=sel.selectedIndex;
  if(cur<0)cur=0;
  if(cur>n-1)cur=n-1;
  st.items=[];
  let html='';
  for(let i=0;i<n;i++){
    const op=ops[i];
    let c='dl-opt';
    if(i===cur)c+=' on';
    if(op.disabled)c+=' disabled';
    const asel=i===cur?'true':'false';
    html+='<div class="'+c+'" role="option" aria-selected="'+asel+'" data-i="'+i+'"><span class="dl-tx">'+esc(op.textContent||op.value||'')+'</span></div>';
    st.items.push({v:op.value,off:op.disabled});
  }
  st.menu.innerHTML=html;
  let txt='';
  if(n>0)txt=ops[cur].textContent||ops[cur].value;
  st.cur.textContent=txt||'-';
  // 撑子装最宽那一条的文本，按钮宽度因此固定，切选项时右侧控件不会跟着挪
  let wide='';
  for(let j=0;j<n;j++){
    const w=ops[j].textContent||ops[j].value||'';
    if(dlW(w)>dlW(wide))wide=w;
  }
  st.sz.textContent=wide;
  st.active=cur;
  if(dlCur===sel)dlPlace(sel);
}

// 扫一遍所有原生 select：没包的包起来，已经包的按当前选项与值重建
function syncSelects(){
  document.querySelectorAll('select.sel').forEach(function(sel){
    if(DL.has(sel))syncSelect(sel);
    else buildSelect(sel);
  });
}

// 弹层用 fixed 定位：表格容器的 overflow-x 会把 absolute 菜单裁掉；越界就翻转/右移
function dlPlace(sel){
  const st=DL.get(sel);
  if(!st)return;
  const b=st.btn.getBoundingClientRect();
  st.menu.style.minWidth=Math.round(b.width)+'px';
  const mw=st.menu.getBoundingClientRect().width;
  const mh=st.menu.getBoundingClientRect().height;
  let left=b.left;
  if(left+mw>window.innerWidth-8)left=Math.max(8,window.innerWidth-8-mw);
  let top=b.bottom+6;
  if(top+mh>window.innerHeight-8&&b.top-6-mh>8)top=Math.max(8,b.top-6-mh);
  st.menu.style.left=Math.round(left)+'px';
  st.menu.style.top=Math.round(top)+'px';
}

function dlToggle(sel){
  if(dlCur===sel)dlClose(sel);
  else dlOpen(sel);
}

function dlOpen(sel){
  if(dlCur&&dlCur!==sel)dlClose(dlCur);
  const st=DL.get(sel);
  if(!st)return;
  const it=st.active>=0?st.items[st.active]:null;
  if(!it||it.off)st.active=dlNext(st,st.active,1);
  dlPlace(sel);
  st.btn.classList.add('on');
  st.menu.classList.add('on');
  st.btn.setAttribute('aria-expanded','true');
  st.menu.setAttribute('aria-hidden','false');
  dlHot(sel,st.active);
  dlCur=sel;
}

function dlClose(sel){
  const st=DL.get(sel);
  if(st){
    st.btn.classList.remove('on');
    st.menu.classList.remove('on');
    st.btn.setAttribute('aria-expanded','false');
    st.menu.setAttribute('aria-hidden','true');
  }
  if(dlCur===sel)dlCur=null;
}

// 选中：写回原生 select.value，再派一次 change 让原有 onchange 生效
function dlPick(sel,i){
  const st=DL.get(sel);
  if(!st)return;
  dlClose(sel);
  const it=st.items[i];
  if(!it||it.off)return;
  sel.value=it.v;
  sel.dispatchEvent(new Event('change',{bubbles:true}));
  st.btn.focus();
}

// 从 i 出发按 dir 找下一个可用项（跳过 disabled），越过末端回绕
function dlNext(st,i,dir){
  const n=st.items.length;
  if(n===0)return -1;
  if(i<0)i=dir>0?n-1:0;
  for(let k=1;k<=n;k++){
    let j=(i+dir*k)%n;
    if(j<0)j+=n;
    if(!st.items[j].off)return j;
  }
  return -1;
}

// 粗估文本宽度：中日韩全角字符按两格计。只做同组比较，不出回流
function dlW(s){
  let n=0;
  for(let k=0;k<s.length;k++)n+=s.charCodeAt(k)>0xff?2:1;
  return n;
}

// 键盘高亮移动；滚出菜单可视区时把它滚进来看见
function dlHot(sel,i){
  const st=DL.get(sel);
  if(!st)return;
  const ops=st.menu.querySelectorAll('.dl-opt');
  ops.forEach(function(o,k){o.classList.toggle('hot',k===i);});
  if(i<0)return;
  const o=ops[i];
  if(!o)return;
  const r=o.getBoundingClientRect();
  const m=st.menu.getBoundingClientRect();
  if(r.top<m.top||r.bottom>m.bottom)o.scrollIntoView({block:'nearest'});
}

// 触发器上的键盘：上下/Home/End 移动，Enter/Space 展开或选中，Esc 收起，Tab 收起
function dlKey(sel,ev){
  const st=DL.get(sel);
  if(!st)return;
  const open=dlCur===sel;
  if(ev.key==='ArrowDown'||ev.key==='ArrowUp'){
    ev.preventDefault();
    if(!open){dlOpen(sel);return;}
    // 要记下这次移动，否则 Enter 还是选中原来那一项
    st.active=dlNext(st,st.active,ev.key==='ArrowUp'?-1:1);
    dlHot(sel,st.active);
    return;
  }
  if(ev.key==='Home'){
    if(open){st.active=dlNext(st,-1,1);dlHot(sel,st.active);}
    ev.preventDefault();
    return;
  }
  if(ev.key==='End'){
    if(open){st.active=dlNext(st,0,-1);dlHot(sel,st.active);}
    ev.preventDefault();
    return;
  }
  if(ev.key==='Enter'||ev.key===' '){
    ev.preventDefault();
    if(open)dlPick(sel,st.active);
    else dlOpen(sel);
    return;
  }
  if(ev.key==='Escape'&&open)ev.preventDefault();
  if(ev.key==='Tab'&&open)dlClose(sel);
}

// 点在控件外就收起；外层 <label> 的文字算控件的一部分
function dlOutside(ev){
  if(!dlCur)return;
  const sel=dlCur;
  const st=DL.get(sel);
  if(st){
    if(st.wrap.contains(ev.target))return;
    if(st.host&&st.host.contains(ev.target))return;
  }
  dlClose(sel);
}

// 页面滚动时 fixed 弹层不会跟着动，收起比留一个错位菜单强；菜单自己滚动不算
function dlScroll(ev){
  if(!dlCur)return;
  const st=DL.get(dlCur);
  if(st&&ev&&ev.target===st.menu)return;
  dlClose(dlCur);
}

// Esc 收起（触发器没聚焦时也要有效）；Tab 让焦点正常走
document.addEventListener('keydown',function(ev){
  if(ev.key==='Escape'&&dlCur){
    const sel=dlCur;
    const st=DL.get(sel);
    dlClose(sel);
    if(st)st.btn.focus();
  }
});
document.addEventListener('mousedown',dlOutside);
window.addEventListener('scroll',dlScroll,true);
window.addEventListener('resize',function(){if(dlCur)dlClose(dlCur);});

// ---------- 表头排序：点击 <th data-sort> 循环 降序 → 升序 → 取消 ----------
// 数值列按数值比较、其余按字符串；速率列用最近一次快照算出的差分
const SORTCOLS={
  clients:{
    id:function(r){return r.id;},v4:function(r){return r.c.ipv4||'';},tcp:function(r){return r.c.active_conns;},
    tx:function(r){return r.c.tx_bytes;},rx:function(r){return r.c.rx_bytes;},txs:function(r){return r.sx;},rxs:function(r){return r.sr;}
  },
  conns:{
    owner:function(r){return r.owner;},target:function(r){return r.target||'';},remote:function(r){return r.remote||'';},
    rtt:function(r){return r.rtt;},tx:function(r){return r.tx;},rx:function(r){return r.rx;},
    txs:function(r){return r.sx;},rxs:function(r){return r.sr;},age:function(r){return r.age;}
  },
  traffic:{
    date:function(r){return r.date;},up:function(r){return r.up;},down:function(r){return r.down;},
    total:function(r){return r.up+r.down;}
  }
};
let sortState={};
function sortRows(key,rows){
  const s=sortState[key];
  if(!s)return rows;
  const col=SORTCOLS[key][s.f];
  if(!col)return rows;
  const d=s.d;
  return rows.slice().sort(function(a,b){
    const x=col(a),y=col(b);
    if(typeof x==='number'&&typeof y==='number')return (x-y)*d;
    return String(x).localeCompare(String(y))*d;
  });
}
// 箭头由 data-arrow 属性承载，当前排序列表头高亮
function syncSortUI(key){
  const pane=document.getElementById('pane-'+key);
  if(!pane)return;
  const s=sortState[key];
  pane.querySelectorAll('th[data-sort]').forEach(function(th){
    if(s&&th.getAttribute('data-sort')===s.f){
      th.classList.add('sorted');
      th.setAttribute('data-arrow',s.d<0?'↓':'↑');
    }else{
      th.classList.remove('sorted');
      th.removeAttribute('data-arrow');
    }
  });
}
document.addEventListener('click',function(ev){
  const th=ev.target.closest('th[data-sort]');
  if(!th)return;
  const pane=th.closest('.pane');
  if(!pane)return;
  const key=pane.id.replace('pane-','');
  const f=th.getAttribute('data-sort');
  const cur=sortState[key];
  if(cur&&cur.f===f){
    if(cur.d<0)sortState[key]={f:f,d:1};
    else delete sortState[key];
  }else{
    sortState[key]={f:f,d:-1};
  }
  syncSortUI(key);
  if(key==='traffic')renderTrafficView();else rerenderTables();
});
function setCount(id,f,shown,total){
  const el=document.getElementById(id);if(!el)return;
  el.textContent=f?(shown+' / '+total):'';
}
// 过滤框：纯本地过滤——基于最近一次 /api/stats 的缓存重渲染表格，不打 API；
// 140ms 防抖，×/Esc 一键清空，命中片段 <mark> 高亮，计数徽章显示 命中/总数。
const Q={clients:'',conns:'',macs:''};
function attachSearch(key){
  const box=document.getElementById('search-'+key);if(!box)return;
  const input=box.querySelector('.search-input');
  const clear=box.querySelector('.search-clear');
  let timer=null;
  input.addEventListener('input',function(){
    clear.classList.toggle('show',!!input.value);
    clearTimeout(timer);
    timer=setTimeout(function(){Q[key]=input.value.trim().toLowerCase();pageConf(key).page=1;rerenderTables();},140);
  });
  clear.addEventListener('click',function(){input.value='';Q[key]='';clear.classList.remove('show');rerenderTables();input.focus();});
  input.addEventListener('keydown',function(e){if(e.key==='Escape')clear.click();});
}
function clearFilter(key){
  const box=document.getElementById('search-'+key);if(!box)return;
  box.querySelector('.search-input').value='';
  box.querySelector('.search-clear').classList.remove('show');
  Q[key]='';
  pageConf(key).page=1;
  rerenderTables();
}
// "/" 聚焦当前页签的过滤框（输入控件已聚焦时不拦截）
document.addEventListener('keydown',function(e){
  if(e.key!=='/')return;
  const tag=(document.activeElement&&document.activeElement.tagName)||'';
  if(tag==='INPUT'||tag==='TEXTAREA'||tag==='SELECT')return;
  const pane=document.querySelector('.pane.on');if(!pane)return;
  const key=pane.id.replace('pane-','');
  if(key!=='clients'&&key!=='conns'&&key!=='macs')return;
  const box=document.getElementById('search-'+key);
  if(box){box.querySelector('.search-input').focus();e.preventDefault();}
});

let lastStats=null,lastSpeeds={},lastTraffic=null,lastClientTraffic=null,trClientSig='';
let prevPps={tx:0,rx:0,ok:false},prevConns={},lastConnsT=0,lastConnSpeeds={};
// 异常提醒条手动关闭后，在下一个不同的告警组合出现前不再自动弹回
let alertOff=false,alertSig='';
async function fetchStats(){
  try{
    const res=await fetch(url('/api/stats'),AUTH_HDR);
    if(res.status===401){showUnauthorized();return;}
    const data=await res.json();
    lastStats=data;
    const upd=document.getElementById('updated-at');
    if(upd)upd.textContent=t('updated').replace('{n}',new Date().toLocaleTimeString());
    const now=performance.now();const dt=lastT?(now-lastT)/1000:2;lastT=now;

    document.getElementById('mode').innerText=data.mode.toUpperCase();
    const chip=document.getElementById('mode-chip');
    if(chip)chip.classList.toggle('client',data.mode!=='server');
    document.getElementById('ver').innerText=data.version||'-';
    document.getElementById('uptime').innerText=fmtDur(data.uptime_sec||0);
    // 级别来自服务端：直接写 value 不会触发 change，要顺手刷新自绘下拉框的文案
    const lvSel=document.getElementById('loglevel');
    lvSel.value=data.log_level||'info';
    syncSelect(lvSel);
    document.getElementById('tls-flag').innerText=location.protocol==='https:'?'HTTPS':t('tls_http');

    // 速率/总量统计覆盖全部客户端；过滤只作用于表格行
    const speeds={};let tTx=0,tRx=0,tTxS=0,tRxS=0,cur={},tConns=0;
    const proc=(id,c)=>{
      tTx+=c.tx_bytes;tRx+=c.rx_bytes;tConns+=c.active_conns||0;
      let sx=0,sr=0;
      if(prev[id]){sx=Math.max(0,(c.tx_bytes-prev[id].tx_bytes)/dt);sr=Math.max(0,(c.rx_bytes-prev[id].rx_bytes)/dt);}
      cur[id]={tx_bytes:c.tx_bytes,rx_bytes:c.rx_bytes};
      speeds[id]={sx:sx,sr:sr};
      tTxS+=sx;tRxS+=sr;
    };
    if(data.mode==='server'){for(const [id,c] of Object.entries(data.clients||{}))proc(id,c);}
    else if(data.clients&&data.clients.local)proc('local',data.clients.local);
    prev=cur;lastSpeeds=speeds;
    txHist.push(tTxS);rxHist.push(tRxS);txTimes.push(Date.now());
    if(txHist.length>MAXPTS){txHist.shift();rxHist.shift();txTimes.shift();}
    if(chartRange==='2m')drawChart(); // 趋势视图下画布由 drawTrendChart 接管

    document.getElementById('active-clients').innerText=data.active_clients;
    document.getElementById('conns-sub').innerText=t('kpi.tcp')+': '+tConns+(data.mode==='client'?' / '+((data.conns||[]).length):'');
    document.getElementById('total-tx').innerText=fmtBytes(tTx);
    document.getElementById('total-rx').innerText=fmtBytes(tRx);
    document.getElementById('total-tx-speed').innerText=fmtBytes(tTxS,true);
    document.getElementById('total-rx-speed').innerText=fmtBytes(tRxS,true);
    document.getElementById('live-up').innerText=fmtBytes(tTxS,true);
    document.getElementById('live-down').innerText=fmtBytes(tRxS,true);
    renderClientsTable(data);

    const f=data.fec||{};
    document.getElementById('fec-kpi').innerHTML=(f.recovered||0)+' <small>/</small> '+(f.lost||0);
    document.getElementById('parity').innerText=f.parity_tx||0;
    // 包总量（服务端=各会话之和；客户端=local），PPS 与 FEC 开销都基于它
    let txPk=0,rxPk=0;
    if(data.mode==='server'){
      const vals=data.clients?Object.values(data.clients):[];
      vals.forEach(function(c){txPk+=c.tx_packets||0;rxPk+=c.rx_packets||0;});
    }else if(data.clients&&data.clients.local){
      txPk=data.clients.local.tx_packets||0;rxPk=data.clients.local.rx_packets||0;
    }
    // FEC 开销 ≈ 校验帧 / 已发帧总数（含校验帧），无流量时不显示
    document.getElementById('fec-overhead').innerText=txPk>0?((f.parity_tx||0)/txPk*100).toFixed(1)+'%':'-';
    document.getElementById('k-dropped').innerText=data.dropped_frames||0;
	const ro=data.reorder||{};
	document.getElementById('reorder-skipped').innerText=ro.skipped_frames||0;
    document.getElementById('tap-errors').innerText=data.tap_write_errors||0;
    // 包速率 PPS：与字节速率同口径的差分
    const ppsTx=prevPps.ok?Math.max(0,(txPk-prevPps.tx)/dt):0;
    const ppsRx=prevPps.ok?Math.max(0,(rxPk-prevPps.rx)/dt):0;
    prevPps={tx:txPk,rx:rxPk,ok:true};
    document.getElementById('k-pps').innerText=Math.round(ppsTx+ppsRx).toLocaleString();
    document.getElementById('pps-up').innerText=Math.round(ppsTx).toLocaleString();
    document.getElementById('pps-down').innerText=Math.round(ppsRx).toLocaleString();
    const m=data.mem||{};
    document.getElementById('mem').innerHTML=(m.heap_alloc_mb||0).toFixed(1)+'<small> MB</small>';
    document.getElementById('goroutines').innerText=m.num_goroutine||0;

    if(data.ip_pool){document.getElementById('ippool-card').style.display='';
      document.getElementById('ippool-kpi').innerHTML=data.ip_pool.v4_used+'<small> / '+data.ip_pool.v4_total+'</small>';
      document.getElementById('v6used').innerText=data.ip_pool.v6_used;}

    const meta=[];if(data.enc_algo===2)meta.push('AES-256-GCM');else if(data.enc_algo===4)meta.push('AES-128-GCM');
    if(data.fec_mode&&data.fec_mode!=='off')meta.push('FEC '+data.fec_mode);
    document.getElementById('meta').innerText=meta.join(' · ');

	renderConnsTable(data,true);renderMacsTable(data);renderBansTable(data);renderTraffic(data);renderStatus(data);
  }catch(e){console.error('stats fetch failed',e);}
}

// 过滤输入时不重新拉取：对最近一次快照重渲染各表格
function rerenderTables(){
  if(!lastStats)return;
  renderClientsTable(lastStats);
  renderConnsTable(lastStats,false);
  renderMacsTable(lastStats);
  renderBansTable(lastStats);
}

function renderClientsTable(data){
  const f=Q.clients;
  const entries=data.mode==='server'?Object.entries(data.clients||{}):(data.clients&&data.clients.local?[['local',data.clients.local]]:[]);
  let rows=[];
  entries.forEach(function(pair){
    const sp=lastSpeeds[pair[0]]||{sx:0,sr:0};
    rows.push({id:pair[0],c:pair[1],sx:sp.sx,sr:sp.sr});
  });
  rows=sortRows('clients',rows);
  syncSortUI('clients');
  const all=entries.length;
  rows=rows.filter(function(r){return passFilter(Object.assign({id:r.id},r.c),f);});
  const total=rows.length;
  const pv=pageView('clients',rows);
  document.getElementById('clients-body').innerHTML=pv.rows.map(function(r){
    return '<tr><td class="num dim" title="'+esc(r.id)+'">'+hi(esc(shortId(r.id,10)),f)+'</td>'+
      '<td class="num">'+hi(esc(r.c.ipv4||'-'),f)+'</td>'+
      '<td class="hide-sm num dim">'+hi(esc(r.c.ipv6||'-'),f)+'</td>'+
      '<td class="hide-sm num dim">'+hi(esc(r.c.mac||'-'),f)+'</td>'+
      '<td class="num">'+r.c.active_conns+'</td>'+
      '<td class="num">'+fmtBytes(r.c.tx_bytes)+'</td><td class="num">'+fmtBytes(r.c.rx_bytes)+'</td>'+
      '<td class="num speed">'+fmtBytes(r.sx,true)+'</td><td class="num speed dn">'+fmtBytes(r.sr,true)+'</td>'+
      '<td class="hide-sm">'+badge(r.c.fec)+'</td><td class="hide-sm">'+encBadge(r.c.enc_algo)+'</td>'+
      '<td>'+(data.mode==='server'?'<button class="btn danger sm" onclick="kickClient(\''+r.id+'\')">'+t('th.kick')+'</button>'+
        '<button class="btn ghost sm" onclick="banClient(\''+r.id+'\',0)">'+t('th.ban')+'</button>':'-')+'</td></tr>';
  }).join('')||emptyTableRow('clients',12,all);
  setCount('client-count',f,total,all);
  renderPager('clients',total);
}

// ---------- "运行状态" 页：宿主/协商/brutal/配置 四块明细 ----------
// 空值不占行：面板上留一堆空行只会让人误以为字段缺失是故障
function kv(el,rows){
  el.innerHTML=rows.length?rows.map(r=>'<tr><th>'+esc(r[0])+'</th><td>'+r[1]+'</td></tr>').join(''):'';
}
function yn(v){return v?'<span class="badge b-on">'+t('stt.yes')+'</span>':'<span class="badge b-off">'+t('stt.no')+'</span>';}
function mtxt(v){return '<span class="mono">'+esc(v)+'</span>';}
function ntxt(){return '<span style="color:var(--sub)">-</span>';}
// 证书有效期：剩余天数按远近配色，过期与自签都显式标出来
function certCell(c){
  const d=c.days_left;
  let col='var(--sub)',txt;
  if(d<=0){col='var(--err)';txt=t('ov.err_cert_bad');}
  else if(d<=7){col='var(--err)';txt=t('ov.err_cert_ok').replace('{n}',d);}
  else if(d<=30){col='var(--warn)';txt=t('ov.err_cert_ok').replace('{n}',d);}
  else txt=t('ov.err_cert_ok').replace('{n}',d);
  return '<span class="mono" style="color:'+col+'">'+esc(txt)+'</span>'
    +(c.not_after?' <span class="mono" style="color:var(--sub)">'+esc(c.not_after)+'</span>':'')
    +(c.self_signed?' <span class="badge b-dup">self-signed</span>':'');
}
function encName(a){return a===2?'AES-256-GCM':(a===4?'AES-128-GCM':(a===0?'none (TLS only)':String(a)));}
function rateRange(lo,hi2){if(!lo&&!hi2)return '-';return (lo===hi2?String(lo):lo+'~'+hi2)+' Mbps';}
function renderStatus(data){
  const sys=data.system||{},neg=data.negotiate||{},b=neg.brutal||{},tls=neg.tls||{},cfg=data.cfg||{};
  const rw=document.getElementById('status-restart');
  const rn=sys.needs_restart||[];
  if(rn.length){rw.style.display='';rw.innerHTML='<strong>'+t('stt.restart')+'</strong><br><span class="mono">'+esc(rn.join(', '))+'</span>';}
  else{rw.style.display='none';}
  const sysRows=[
    [t('stt.sys.os'),esc(sys.os||'-')+' '+mtxt(sys.arch||'')],
    [t('stt.sys.go'),mtxt(sys.go_version||'-')],
    [t('stt.sys.cpu'),sys.num_cpu||'-'],
    [t('stt.sys.host'),mtxt(sys.host||'-')],
    [t('stt.sys.cfgpath'),mtxt(sys.cfg_path||'-')],
    [t('stt.sys.ver'),mtxt(data.version||'-')+' · '+fmtDur(data.uptime_sec||0)],
  ];
  // 系统指标尽力而为：Linux 才有负载/内存/文件描述符，缺位不占行
  if(sys.load)sysRows.push([t('stt.sys.load'),'<span class="mono">'+sys.load.one.toFixed(2)+' / '+sys.load.five.toFixed(2)+' / '+sys.load.fifteen.toFixed(2)+'</span>']);
  if(sys.mem)sysRows.push([t('stt.sys.mem'),'<span class="mono">'+fmtBytes(sys.mem.used_mb*1048576)+' / '+fmtBytes(sys.mem.total_mb*1048576)+'</span> ('+Math.round(sys.mem.used_mb/sys.mem.total_mb*100)+'%)']);
  if(sys.fd_open)sysRows.push([t('stt.sys.fd'),'<span class="mono">'+sys.fd_open+'</span>']);
  if(sys.num_gc)sysRows.push([t('stt.sys.gc'),'<span class="mono">'+sys.num_gc+'</span> / <span class="mono">'+sys.gc_pause_ms.toFixed(1)+' ms</span>']);
  // 证书有效期与进程 CPU 是"到期前就该看到"的指标，放在宿主块而不是靠翻告警
  if(data.cpu)sysRows.push([t('stt.sys.cpu_use'),'<span class="mono">'+data.cpu.percent.toFixed(1)+'%</span>']);
  if(data.cert)sysRows.push([t('stt.sys.cert'),certCell(data.cert)]);
  kv(document.getElementById('st-sys'),sysRows);
  // 密钥代际与端到端 shaping 速率是"一条会话"的概念，服务端不消费单一会话，
  // 逐连接结果看"连接明细"页，这里只在客户端模式显示。
  const nrw=[
    [t('stt.neg.proto'),neg.protocol_version?('v'+neg.protocol_version):ntxt()],
    [t('stt.neg.enc'),neg.enc_algo?encName(neg.enc_algo):ntxt()],
    [t('stt.neg.fec'),yn(!!neg.fec)],
    [t('stt.neg.grp'),neg.fec_group?String(neg.fec_group):ntxt()],
    [t('stt.neg.pad'),neg.pad_mode?mtxt(neg.pad_mode):ntxt()],
    [t('stt.neg.minenc'),neg.min_enc?mtxt(neg.min_enc):ntxt()],
    [t('stt.neg.stoken'),yn(!!neg.session_token)],
  ];
  if(data.mode==='client'){
    nrw.push([t('stt.neg.epoch'),neg.session_epoch?String(neg.session_epoch):ntxt()]);
    nrw.push([t('stt.neg.tx'),(neg.tx_rate_mbps||0)+' Mbps']);
    nrw.push([t('stt.neg.rx'),(neg.rx_rate_mbps||0)+' Mbps']);
	  nrw.push([t('stt.neg.tlsfp'),tls.fingerprint_sha256?mtxt(tls.fingerprint_kind+':'+tls.fingerprint_sha256):ntxt()]);
	  nrw.push([t('stt.neg.tlsver'),tls.version?mtxt(tls.version+' (0x'+Number(tls.version_id||0).toString(16).padStart(4,'0')+')'):ntxt()]);
	  nrw.push([t('stt.neg.tlscipher'),tls.cipher_suite?mtxt(tls.cipher_suite+' (0x'+Number(tls.cipher_suite_id||0).toString(16).padStart(4,'0')+')'):ntxt()]);
	  nrw.push([t('stt.neg.tlsalpn'),tls.alpn?mtxt(tls.alpn):ntxt()]);
	  nrw.push([t('stt.neg.tlssni'),tls.sni?mtxt(tls.sni):ntxt()]);
	  nrw.push([t('stt.neg.tlsoffer'),tls.fingerprint_sha256?mtxt((tls.offered_cipher_suites||[]).length+' cipher / '+(tls.offered_signature_schemes||[]).length+' sig / '+(tls.offered_groups||[]).length+' group / '+(tls.offered_alpn||[]).length+' ALPN'):ntxt()]);
    // 配了 fwmark 才显示：策略路由是否真的装进内核，以及失败原因。
    if(neg.policy_routing!==undefined){
      nrw.push([t('stt.neg.prroute'),neg.policy_routing_error
        ?'<span class="badge b-off">'+esc(neg.policy_routing_error)+'</span>'
        :yn(!!neg.policy_routing)]);
    }
  }
  kv(document.getElementById('st-neg'),nrw);
  kv(document.getElementById('st-brutal'),[
    [t('stt.brut.en'),yn(!!b.enabled)],
    [t('stt.brut.up'),(b.up_mbps||0)+' Mbps'],
    [t('stt.brut.down'),(b.down_mbps||0)+' Mbps'],
    [t('stt.brut.kern'),b.kernel_supported?'<span class="badge b-on">'+t('stt.kern_yes')+'</span>':'<span class="badge b-off">'+t('stt.kern_no')+'</span>'],
    [t('stt.brut.cur'),b.kernel_current?mtxt(b.kernel_current):ntxt()],
    [t('stt.brut.avail'),(b.kernel_available&&b.kernel_available.length)?mtxt(b.kernel_available.join(', ')):ntxt()],
    [t('stt.brut.applied'),(b.applied_conns||0)+' / '+(b.total_conns||0)],
    [t('stt.brut.perconn'),'<span class="mono">'+rateRange(b.min_up_mbps,b.max_up_mbps)+' / '+rateRange(b.min_down_mbps,b.max_down_mbps)+'</span>'],
    [t('stt.brut.errs'),(b.errors&&b.errors.length)?'<span style="color:var(--err)">'+esc(b.errors.join('; '))+'</span>':'<span class="badge b-on">'+t('stt.noerr')+'</span>'],
  ]);
  kv(document.getElementById('st-cfg'),Object.keys(cfg).map(function(k){
    const v=cfg[k];let cell;
    if(typeof v==='boolean')cell=yn(v);
    else if(Array.isArray(v))cell=v.length?mtxt(v.map(function(x){
      // 对象元素（source_rules）直接 join 会变成 [object Object]，转成 JSON 展示
      return typeof x==='object'&&x!==null?JSON.stringify(x):x;
    }).join(' ; ')):ntxt();
    else if(v===undefined||v===null||v==='')cell=ntxt();
    else cell=mtxt(v);
    const lab=t('cfgk.'+k);
    return [lab==='cfgk.'+k?k:lab,cell];
  }));
  // 新增观测块：填充开销 / 防护路径 / 钩子 / 策略路由 / TAP 链路，
  // 以及顶部异常提醒条。都按"缺位不占位"处理。
  renderPadStatus(data.pad);
  renderProtectStatus(data.protect);
  renderHookStatus(data.hooks);
  renderRouteStatus(data.routes);
  renderTapStatus(data.tap_link);
  renderOverview(data);
}

// ---------- 新增观测面板：填充开销 / 防护路径 / 钩子 / 策略路由 / TAP 链路 ----------
function fmtNum(n){return Number(n||0).toLocaleString();}

// 填充开销：线路字节与其中填充字节的比值，回答"混淆吃了多少带宽"
function renderPadStatus(p){
  const rows=[];
  if(!p){kv(document.getElementById('st-pad'),[[t('ov.no_data'),ntxt()]]);return;}
  rows.push([t('ov.pad_wire'),mtxt(fmtBytes(p.wire_bytes))]);
  rows.push([t('ov.pad_bytes'),mtxt(fmtBytes(p.pad_bytes))]);
  rows.push([t('ov.pad_pct'),'<span class="mono">'+(p.overhead_pct||0).toFixed(1)+'%</span>']);
  kv(document.getElementById('st-pad'),rows);
}

// 防护路径计数 + PSK 失败排行。这些都是"过去只进日志"的拒绝，
// 面板能看见才能回答"伪装站点挡住了多少扫描"。
function renderProtectStatus(pr){
  const rows=[];
  if(!pr){kv(document.getElementById('st-protect'),[[t('ov.prot.off'),ntxt()]]);return;}
  else{
    [['conns_rejected',t('ov.prot.conns')],['tls_handshake_fail',t('ov.prot.tls')],
     ['fallback_http',t('ov.prot.fallback')],['tarpit',t('ov.prot.tarpit')],
     ['fec_group_rejected',t('ov.prot.fec')]].forEach(function(e){
      const v=pr[e[0]]||0;
      rows.push([e[1],'<span class="mono" style="color:'+(v>0?'var(--warn)':'var(--sub)')+'">'+fmtNum(v)+'</span>']);
    });
  }
  kv(document.getElementById('st-protect'),rows);
  const psk=pr&&pr.psk_fail||[];
  const out=[];
  if(!psk.length){
    out.push([t('ov.prot.psk'),'<span style="color:var(--sub)">'+t('ov.prot.psk_empty')+'</span>']);
  }else{
    out.push([t('ov.prot.psk'),'<span class="mono">'+psk.length+' / '+t('ov.prot.window')+'</span>']);
    psk.slice(0,8).forEach(function(p){
      out.push(['<span class="mono">'+esc(p.remote)+'</span>','<span class="mono">'+(p.count||0)+'</span>']);
    });
  }
  kv(document.getElementById('st-psk'),out);
}

// up/down 钩子：面板此前只知道配了什么，不知道跑成功没有
function renderHookStatus(h){
  if(!h){kv(document.getElementById('st-hooks'),[[t('ov.not_applied'),ntxt()]]);return;}
  const run=function(ok,ran,ms,err){
    if(!ran)return '<span style="color:var(--sub)">'+t('ov.hook.never')+'</span>';
    if(ok)return '<span class="badge b-on">'+t('ov.hook.ran')+'</span> <span class="mono">'+ms+' ms</span>';
    return '<span class="badge b-off">'+t('ov.hook.fail')+'</span> <span class="mono">'+ms+' ms</span>';
  };
  const tail=function(info){
    const o=[];
    if(info.err)o.push([t('ov.hook.err'),'<span class="mono" style="color:var(--err)">'+esc(info.err)+'</span>']);
    else if(info.out)o.push([t('ov.hook.out'),'<span class="mono">'+esc(String(info.out).slice(0,240))+'</span>']);
    return o;
  };
  const rows=[];
  if(h.up_path)rows.push([t('ov.hook.up'),'<span class="mono">'+esc(h.up_path)+'</span>']);
  if(h.down_path)rows.push([t('ov.hook.down'),'<span class="mono">'+esc(h.down_path)+'</span>']);
  rows.push([t('ov.hook.ran')+' (up)',run(h.up_ok,h.up_ran,h.up_ms,h.up_error)]);
  rows=rows.concat(tail({err:h.up_error,out:h.up_out}));
  rows.push([t('ov.hook.ran')+' (down)',run(h.down_ok,h.down_ran,h.down_ms,h.down_error)]);
  rows=rows.concat(tail({err:h.down_error,out:h.down_out}));
  kv(document.getElementById('st-hooks'),rows);
}

// 策略路由的内核实际内容：配置值不等于内核里装上的东西
function renderRouteStatus(rt){
  const kvEl=document.getElementById('st-routes');
  if(!rt){kv(kvEl,[[t('ov.no_data'),ntxt()]]);return;}
  const age=rt.age_sec?(' · '+t('ov.age').replace('{n}',rt.age_sec)):'';
  const rules=rt.rules||[],routes=rt.routes||[];
  const rows=[];
  if(rt.error)rows.push([t('ov.hook.err'),'<span class="mono" style="color:var(--err)">'+esc(rt.error)+'</span>']);
  rows.push([t('ov.route.rules')+age,'<span class="mono">'+(rules.length?String(rules.length):'-')+'</span>']);
  rules.slice(0,12).forEach(function(l){rows.push(['',esc(l)]);});
  if(rules.length>12)rows.push(['<span style="color:var(--sub)">'+t('ov.rules_n').replace('{n}',rules.length-12)+'</span>','']);
  rows.push([t('ov.route.routes'),'<span class="mono">'+(routes.length?String(routes.length):'-')+'</span>']);
  routes.slice(0,12).forEach(function(l){rows.push(['',esc(l)]);});
  if(routes.length>12)rows.push(['<span style="color:var(--sub)">'+t('ov.routes_n2').replace('{n}',routes.length-12)+'</span>','']);
  kv(kvEl,rows);
}

// TAP 链路层统计：内核接口计数，与隧道层计数是两个口径
function renderTapStatus(lp){
  if(!lp){kv(document.getElementById('st-tap'),[[t('ov.no_data'),ntxt()]]);return;}
  kv(document.getElementById('st-tap'),[
    [t('ov.link.up'),yn(lp.up)],
    [t('ov.link.mtu'),'<span class="mono">'+(lp.mtu||'-')+'</span>'],
    [t('ov.link.rx'),'<span class="mono">'+fmtBytes(lp.rx_bytes||0)+' / '+fmtNum(lp.rx_pkts||0)+'</span>'],
    [t('ov.link.tx'),'<span class="mono">'+fmtBytes(lp.tx_bytes||0)+' / '+fmtNum(lp.tx_pkts||0)+'</span>'],
    [t('ov.link.errs'),'<span class="mono">'+fmtNum(lp.rx_errs||0)+' / '+fmtNum(lp.tx_errs||0)+'</span>'],
    [t('ov.link.drops'),'<span class="mono">'+fmtNum(lp.rx_drops||0)+' / '+fmtNum(lp.tx_drops||0)+'</span>'],
  ]);
}

// ---------- 概览派生指标与异常提醒条 ----------
// RTT 分布：连接表里只有逐连接的当前值，这里给出全量的均值与 P95
function rttStats(rows){
  const v=rows.map(function(r){return r.rtt;}).filter(function(x){return x>0&&x<100000;});
  if(!v.length)return null;
  v.sort(function(a,b){return a-b;});
  const avg=v.reduce(function(a,b){return a+b;},0)/v.length;
  const i=Math.min(v.length-1,Math.floor(v.length*0.95));
  const out={n:v.length,avg:avg,p95:v[i],max:v[v.length-1],min:v[0]};
  return out;
}

function chip(l,v,cls){
  return '<span class="statchip'+(cls?' '+cls:'')+'"><span class="lbl">'+esc(l)+'</span><b>'+v+'</b></span>';
}

// 连接页的派生指标条：RTT 分布 + 丢帧率 / 平均包大小 / FEC 效率
function renderConnQuality(data,rtt){
  const q=data.quality||{};
  const out=[];
  if(rtt)out.push(chip(t('ov.rtt'),t('ov.rtt_n').replace('{n}',rtt.n)),chip(t('ov.avg'),Math.round(rtt.avg)+' ms'),chip(t('ov.p95'),Math.round(rtt.p95)+' ms'));
  else out.push(chip(t('ov.rtt'),'-'));
  if(q.pkts)out.push(chip(t('ov.avgpkt'),fmtBytes(Math.round(q.avgpkt_size))));
  if(q.pkts&&q.total_drop>=0){
    const d=(q.total_drop/q.pkts*100);
    out.push(chip(t('ov.drop_pct'),d.toFixed(3)+'%',d>1?'bad':(d>0?'warn':'good')));
  }
  if(data.fec&&data.fec.enabled){
    const tot=q.pkts+q.parity;
    if(tot>0&&q.recovered>0)out.push(chip(t('ov.fec_eff'),(q.recovered/tot*100).toFixed(1)+'%',q.lost?'warn':'good'));
  }
  const el=document.getElementById('conn-quality');
  if(el)el.innerHTML=out.join('');
}

// 异常提醒条：把各卡片的坏消息集中到顶。人工关闭后按"组合"记忆，
// 同一组告警不会反复弹回，出现新告警才重新提示。
function renderAlerts(data,items){
  const el=document.getElementById('alertbar');
  if(!el)return;
  if(!items.length){el.style.display='none';return;}
  if(alertOff&&alertSig===items.join('|')){el.style.display='none';return;}
  alertSig=items.join('|');
  el.style.display='';
  el.className='alertbar';
  document.getElementById('alertbar-txt').innerText=items.join('  ·  ');
  document.getElementById('alertbar-cnt').innerText=t('ov.alerts_n').replace('{n}',items.length);
}

function renderOverview(data){
  // 进程 CPU 与核数
  const cpu=document.getElementById('cpu-kpi'),cores=document.getElementById('cores');
  if(data.cpu&&cpu){cpu.innerHTML=data.cpu.percent.toFixed(1)+'<small>%</small>';}
  else if(cpu)cpu.textContent='-';
  if(cores)cores.innerText=(data.system&&data.system.num_cpu)||'-';
  // 填充开销卡：只有真正产生了填充记录才显示，off 模式不占位
  const pad=document.getElementById('pad-card');
  if(pad){
    if(data.pad&&data.pad.pad_bytes>0){
      pad.style.display='';
      document.getElementById('pad-kpi').innerText=(data.pad.overhead_pct||0).toFixed(1)+'%';
      document.getElementById('pad-bytes').innerText=fmtBytes(data.pad.pad_bytes);
      document.getElementById('pad-mode').innerText=data.pad.mode||'-';
    }else pad.style.display='none';
  }
  // 会话水位卡：服务端对 max_sessions，客户端对本机并发连接上限
  const sc=document.getElementById('sess-card');
  if(sc){
    const s=data.sessions;
    if(s){
      sc.style.display='';
      document.getElementById('sess-kpi').innerHTML=s.active+'<small> / '+(s.max||0)+'</small>';
      document.getElementById('reconn-kpi').innerText=fmtNum(data.reconnect_attempts||0);
    }else sc.style.display='none';
  }
  // 告警条件：任一触发即在顶部集中提示
  const items=[],s=data.sessions,p=data.pad,pr=data.protect,c=data.cert,ro=data.drop_breakdown||{},h=data.hooks;
  if(c&&c.days_left<=0)items.push(t('ov.err_cert_bad'));
  else if(c&&c.days_left<=7)items.push(t('ov.err_cert_ok').replace('{n}',c.days_left));
  else if(c&&c.days_left<=30)items.push(t('ov.err_cert_ok').replace('{n}',c.days_left));
  if((data.tap_write_errors||0)>0)items.push(t('ov.err_tap').replace('{n}',fmtNum(data.tap_write_errors)));
  if((data.dropped_frames||0)>0){
    const brk=[];
    if(ro.backpressure)brk.push(t('ov.err_bp'));
    if(ro.spoofed_src)brk.push(t('ov.err_spoof'));
    if(ro.broadcast)brk.push(t('ov.err_bcast'));
    if(ro.reorder)brk.push(t('ov.err_reord'));
    items.push(t('ov.err_drop').replace('{n}',fmtNum(data.dropped_frames))+(brk.length?'（'+brk.join('、')+'）':''));
  }
  if(data.fec&&data.fec.lost>0)items.push(t('ov.err_fec').replace('{n}',fmtNum(data.fec.lost)));
  if(pr&&(pr.tls_handshake_fail||0)>0)items.push(t('ov.err_tls').replace('{n}',fmtNum(pr.tls_handshake_fail)));
  if(pr&&(pr.conns_rejected||pr.fec_group_rejected)>0)items.push(t('ov.err_prot').replace('{n}',fmtNum((pr.conns_rejected||0)+(pr.fec_group_rejected||0))));
  if(pr&&(pr.fallback_http||pr.tarpit)>0)items.push(t('ov.err_fb').replace('{n}',fmtNum((pr.fallback_http||0)+(pr.tarpit||0))));
  if(pr&&(pr.psk_fail||[]).length>0)items.push(t('ov.err_psk').replace('{n}',fmtNum(pr.psk_fail.length)));
  if(data.ip_pool&&data.ip_pool.v4_total&&data.ip_pool.v4_used>=data.ip_pool.v4_total)items.push(t('ov.err_pool').replace('{n}',data.ip_pool.v4_used+'/'+data.ip_pool.v4_total));
  if(s&&s.max&&s.active>=s.max)items.push(t('ov.err_nosess'));
  if((data.reconnect_attempts||0)>0)items.push(t('ov.err_reconn').replace('{n}',fmtNum(data.reconnect_attempts)));
  if(data.negotiate&&data.negotiate.policy_routing===false)items.push(t('ov.err_neg'));
  if(p&&p.overhead_pct>40)items.push(t('ov.err_pad').replace('{n}',p.overhead_pct.toFixed(1)+'%'));
  if(data.cpu&&data.cpu.percent>80)items.push(t('ov.err_cpu').replace('{n}',data.cpu.percent.toFixed(0)+'%'));
  if(h&&h.up_ran&&!h.up_ok)items.push(t('ov.err_hookup'));
  if(h&&h.down_ran&&!h.down_ok)items.push(t('ov.err_hookdown'));
  renderAlerts(data,items);
}

// ---------- CSV 导出：只读导出，不发任何 /api/control 请求 ----------
const QUOTE='"';
function csvCell(v){
  const s=v==null?'':String(v);
  // 只读表格文本可能含逗号/换行/双引号，按 RFC4180 加引号并双写
  if(s.indexOf(',')<0&&s.indexOf(QUOTE)<0&&s.indexOf('\n')<0)return s;
  return QUOTE+s.split(QUOTE).join(QUOTE+QUOTE)+QUOTE;
}

function csvDownload(name,rows){
  // BOM 让 Excel 直接识别 UTF-8（中文/日文列名不乱码）
  const blob=new Blob([''+rows.map(r=>r.join(',')).join('\r\n')+'\r\n'],{type:'text/csv;charset=utf-8'});
  const a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download=name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(function(){URL.revokeObjectURL(a.href);},1000);
  toast(t('ov.export_done'),'ok');
}

// 读当前渲染出来的表格 DOM（已过滤、已排序、当前页），所以导出结果与屏幕所见一致
function tableRows(tableId){
  return Array.prototype.slice.call(document.querySelectorAll('#'+tableId+' tr')).map(function(tr){
    return Array.prototype.slice.call(tr.children).map(function(td){return csvCell(td.innerText.trim());});
  }).filter(function(c){return c.length>1;});
}

function exportCSV(which){
  const st=lastStats;
  if(!st){toast(t('ov.no_table'),'err');return;}
  const ts=new Date().toISOString().replace(/[:]/g,'-');
  const id=which==='conns'?'conns-body':(which==='traffic'?'traffic-body':'clients-body');
  const rows=tableRows(id);
  if(!rows.length){toast(t('ov.no_table'),'err');return;}
  csvDownload('tlsvpn-'+which+'-'+ts+'.csv',rows);
}

function renderConnsTable(data,fresh){
  const tb=document.getElementById('conns-body');
  let rows=[];
  if(data.mode==='server'){
    (data.server_conns||[]).forEach(c=>rows.push({key:c.client_id+'|'+c.remote,owner:shortId(c.client_id,10),fullId:c.client_id,target:'',remote:c.remote,state:'up',rtt:c.rtt_ms,tx:c.tx_bytes,rx:c.rx_bytes,age:c.age_sec,epoch:c.session_epoch||0,err:'',enc:c.enc_algo,fec:c.fec||'',sni:c.sni||'',tlsVer:c.tls_version||'',tlsCipher:c.tls_cipher||'',tlsAlpn:c.tls_alpn||'',brut:c.brutal_applied,brutErr:c.brutal_error||'',up:c.brutal_cli_tx_mbps||0,down:c.brutal_srv_tx_mbps||0}));
  }else{
    (data.conns||[]).forEach((c,i)=>rows.push({key:i+'|'+(c.target||'')+'|'+(c.remote||''),owner:'local',fullId:null,target:c.target,remote:c.remote,state:c.state,rtt:c.rtt_ms,tx:c.tx_bytes,rx:c.rx_bytes,retries:c.retries,age:c.age_sec,epoch:data.session_epoch||0,err:c.last_error||'',enc:data.enc_algo,fec:data.fec_mode||'',sni:c.sni||'',tlsVer:c.tls_version||'',tlsCipher:c.tls_cipher||'',tlsAlpn:c.tls_alpn||'',brut:c.brutal_applied,brutErr:c.brutal_error||'',up:c.brutal_tx_mbps||0,down:c.brutal_rx_mbps||0}));
  }
  // 速率差分：fresh=true 仅在拿到新快照时（fetchStats），过滤重渲染沿用缓存
  const now=Date.now();
  const dt=(fresh&&lastConnsT)?(now-lastConnsT)/1000:2;
  rows.forEach(function(r){
    if(fresh){
      const p=prevConns[r.key];
      r.sx=p?Math.max(0,(r.tx-p.tx)/dt):0;
      r.sr=p?Math.max(0,(r.rx-p.rx)/dt):0;
      prevConns[r.key]={tx:r.tx,rx:r.rx};
    }else{
      const s=lastConnSpeeds[r.key]||{sx:0,sr:0};
      r.sx=s.sx;r.sr=s.sr;
    }
  });
  if(fresh){
    lastConnsT=now;
    lastConnSpeeds={};
    rows.forEach(function(r){lastConnSpeeds[r.key]={sx:r.sx,sr:r.sr};});
  }
  const f=Q.conns;
  const all=rows.length;
  // 质量指标与导出基于过滤前的全量行：过滤条件不该改变统计口径
  exportCSV('conns');
  renderConnQuality(data,rttStats(rows));
  rows=sortRows('conns',rows);
  syncSortUI('conns');
  // 服务端模式的"目标"列恒为占位符，整列隐藏；客户端模式有真实目标地址，保持可见
  const wrap=tb.closest('.twrap');
  if(wrap)wrap.classList.toggle('srv-mode',data.mode==='server');
  if(f)rows=rows.filter(r=>JSON.stringify(r).toLowerCase().includes(f));
  const total=rows.length;
  const pv=pageView('conns',rows);
  tb.innerHTML=pv.rows.map(r=>{
    const st=r.state==='up'?'<span class="badge b-on">'+t('st.up')+'</span>':
      r.state==='connecting'?'<span class="badge b-dup">'+t('st.connecting')+'</span>':
      '<span class="badge b-off">'+esc(r.state||'-')+'</span>';
    const rtt=r.rtt>=100000?'-':r.rtt+' ms';
    // Brutal 列同时是"为什么没生效"的入口：速率生效显示双向速率，
    // 配置了但内核/平台不支持显示"未生效"，悬停看具体原因。
    let brutTxt='-',brutCls='b-off',brutTip='brutal off';
    if(r.brutErr){brutTxt=t('st.skip');brutCls='b-dup';brutTip='brutal skipped: '+r.brutErr;}
    else if(r.brut===true){brutTxt=r.up+'↑/'+r.down+'↓';brutCls='b-on';brutTip='brutal shaping '+r.up+' Mbps upstream / '+r.down+' Mbps downstream';}
    const brut='<span class="badge '+brutCls+'">'+brutTxt+'</span>';
    const ops=(data.mode==='server'&&r.fullId)?'<button class="btn danger sm" onclick="kickClient(\''+r.fullId+'\')">'+t('th.kick')+'</button>':'';
    const sniMeta=[r.tlsVer,r.tlsCipher,r.tlsAlpn].filter(Boolean).join(' · ');
    return '<tr><td class="num dim">'+hi(esc(r.owner),f)+'</td><td class="num hide-srv">'+hi(esc(r.target||'-'),f)+'</td><td class="num">'+hi(esc(r.remote||'-'),f)+'</td><td title="'+esc(brutTip)+'">'+st+'</td>'+
      '<td class="num">'+rtt+'</td><td class="num">'+fmtBytes(r.tx)+'</td><td class="num">'+fmtBytes(r.rx)+'</td>'+
      '<td class="hide-sm num speed">'+fmtBytes(r.sx,true)+'</td><td class="hide-sm num speed dn">'+fmtBytes(r.sr,true)+'</td>'+
      '<td class="hide-sm dim" title="'+esc(sniMeta)+'">'+(r.sni?hi(esc(r.sni),f):'<span style="color:var(--sub)">-</span>')+'</td>'+
      '<td class="hide-sm num dim">'+(r.age?fmtDur(r.age):'-')+'</td>'+
      '<td class="hide-sm num dim" title="'+esc(r.epoch?'session key epoch '+r.epoch:'no epoch yet')+'">'+(r.epoch?r.epoch:'-')+'</td>'+
      '<td class="hide-sm">'+encBadge(r.enc)+'</td><td class="hide-sm">'+badge(r.fec)+'</td>'+
      '<td class="hide-sm" title="'+esc(brutTip)+'">'+brut+'</td>'+
      '<td class="hide-sm" style="color:var(--err)" title="'+esc(r.err||r.brutErr)+'">'+esc(String(r.err||r.brutErr).slice(0,40))+'</td><td>'+ops+'</td></tr>';
  }).join('')||emptyTableRow('conns',17,all);
  setCount('conn-count',f,total,all);
  renderPager('conns',total);
}
function renderMacsTable(data){
  const tb=document.getElementById('macs-body');
  if(data.mode!=='server'){
    tb.innerHTML=emptyRow('srv',3,t('srv_only'));
    setCount('mac-count','',0,0);renderPager('macs',0);return;
  }
  const all=data.mac_table||[];
  const f=Q.macs;
  const list=all.filter(function(e){return passFilter(e,f);});
  const pv=pageView('macs',list);
  tb.innerHTML=pv.rows.map(function(e){
    return '<tr><td class="num">'+hi(esc(e.mac),f)+'</td><td class="num dim">'+hi(esc(e.port),f)+'</td><td class="num dim">'+e.age_sec+'s</td></tr>';
  }).join('')||emptyTableRow('macs',3,all.length);
  setCount('mac-count',f,list.length,all.length);
  renderPager('macs',list.length);
}
function renderBansTable(data){
  const tb=document.getElementById('bans-body');
  if(data.mode!=='server'){tb.innerHTML=emptyRow('srv',3,t('srv_only'));renderPager('bans',0);return;}
  const bans=Object.entries(data.banned||{});
  const pv=pageView('bans',bans);
  tb.innerHTML=pv.rows.map(function(p){
    const id=p[0],left=p[1];
    return '<tr><td class="num dim" title="'+esc(id)+'">'+esc(shortId(id,18))+'</td>'+
      '<td>'+(left===0?'<span class="badge b-dup">'+t('perm')+'</span>':'<span class="badge b-on">'+fmtDur(left)+'</span>')+'</td>'+
      '<td><button class="btn ghost sm" onclick="unban(\''+id+'\')">'+t('th.unban')+'</button></td></tr>';
  }).join('')||emptyRow('bans',3,t('no_bans'));
  renderPager('bans',bans.length);
}

// ---------- 流量页：今日汇总 + 每日柱状图 + 日表 ----------
function renderTraffic(data){
  const tr=data.traffic;if(!tr)return;
  lastTraffic=tr;
  lastClientTraffic=data.client_traffic||[];
  document.getElementById('tr-up').innerText=fmtBytes(tr.up||0);
  document.getElementById('tr-down').innerText=fmtBytes(tr.down||0);
  document.getElementById('tr-total').innerText=fmtBytes((tr.up||0)+(tr.down||0));
  syncTrafficClients();
  renderTrafficView();
}
function syncTrafficClients(){
  const sel=document.getElementById('tr-client');if(!sel)return;
  const want=sel.value;
  const ids=(lastClientTraffic||[]).map(function(c){return c.id;}).join(',');
  if(ids!==trClientSig){
    trClientSig=ids;
    let opts='<option value="">'+t('tr.all')+'</option>';
    (lastClientTraffic||[]).forEach(function(ct){opts+='<option value="'+esc(ct.id)+'">'+esc(shortId(ct.id,14))+'</option>';});
    sel.innerHTML=opts;
  }
  sel.value=want;
  syncSelect(sel);
}
function renderTrafficView(){
  if(!lastTraffic)return;
  const sel=document.getElementById('tr-client');
  const id=sel?sel.value:'';
  let daily=lastTraffic.daily||[];
  let prefix='';
  if(id&&lastClientTraffic){
    const ct=lastClientTraffic.find(function(c){return c.id===id;});
    if(ct){daily=ct.daily;prefix=shortId(id,14)+' · ';}
  }
  document.getElementById('tr-caption').innerText=prefix+t('tr.caption').replace('{n}',lastTraffic.days);
  drawTrafficChart(daily);
  const tb=document.getElementById('traffic-body');
  let days=(daily||[]).slice();
  days=sortRows('traffic',days);
  syncSortUI('traffic');
  if(!sortState.traffic)days.reverse();
  const pv=pageView('traffic',days);
  tb.innerHTML=pv.rows.map(function(d){
    return '<tr><td class="num dim">'+esc(d.date)+'</td><td class="num speed">'+fmtBytes(d.up)+'</td>'+
      '<td class="num speed dn">'+fmtBytes(d.down)+'</td><td class="num">'+fmtBytes(d.up+d.down)+'</td></tr>';
  }).join('')||emptyRow('traffic',4,t('tr.empty'));
  renderPager('traffic',days.length);
}
function drawTrafficChart(daily){
  const days=(daily||[]).slice(-60); // 点数上限：日期标签保持可读
  const pts=days.map((d,i)=>({x:days.length>1?i/(days.length-1):0,up:d.up,down:d.down,label:d.date.slice(5)}));
  let max=1;
  pts.forEach(p=>{if(p.up>max)max=p.up;if(p.down>max)max=p.down;});
  const old=chartState['traffic-chart'];
  const hover=(old&&old.hover>=0&&old.hover<pts.length)?old.hover:-1;
  renderLineChart('traffic-chart',pts,{max:max,perSec:false,hover:hover});
}

async function kickClient(id){
  if(!(await uiConfirm(t('confirm_kick'))))return;
  await control({action:'kick',client_id:id},t('toast.kick'));fetchStats();
}
async function banClient(id,minutes){
  if(!(await uiConfirm(t('confirm_ban'))))return;
  await control({action:'ban',client_id:id,ttl_minutes:minutes},t('toast.ban'));fetchStats();
}
async function addBan(){
  const id=document.getElementById('ban-id').value.trim();
  if(!id){toast(t('toast.need_id'),'err');return;}
  const m=parseInt(document.getElementById('ban-min').value,10);
  await control({action:'ban',client_id:id,ttl_minutes:isNaN(m)?0:m},t('toast.ban'));
  document.getElementById('ban-id').value='';document.getElementById('ban-min').value='';fetchStats();
}
async function unban(id){
  await control({action:'unban',client_id:id},t('toast.unban'));fetchStats();
}
// gc / reconnect 不改变连接表，只在成功时刷一次内存读数
async function doAction(action){
  const msg=action==='gc'?t('toast.gc'):t('toast.reconnect');
  if(await control({action:action},msg))fetchStats();
}
async function setLogLevel(v){
  await control({action:'loglevel',level:v},t('toast.loglevel'));
}

// ---------- 设置页：配置查看/保存/热应用 ----------
async function loadConfig(){
  const st=document.getElementById('cfg-status');
  try{
    const res=await fetch(url('/api/config'),AUTH_HDR);
    if(!res.ok){st.textContent=t('set.loaded_err')+' HTTP '+res.status;return;}
    document.getElementById('cfg-editor').value=await res.text();
    st.textContent='';
  }catch(e){st.textContent=t('set.loaded_err')+' '+e;}
}
async function saveConfig(apply){
  const st=document.getElementById('cfg-status');
  let cfg;
  try{cfg=JSON.parse(document.getElementById('cfg-editor').value);}
  catch(e){st.textContent='JSON: '+e.message;toast(t('toast.fail')+' JSON','err');return;}
  try{
    const res=await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:apply?'save_apply':'save',config:cfg})});
    const data=await res.json().catch(()=>({}));
    if(!res.ok){st.textContent=(data.error||('HTTP '+res.status));toast(t('toast.fail')+' '+st.textContent.slice(0,120),'err');return;}
    if(apply){
      st.textContent=t('set.applied')+(data.needs_restart&&data.needs_restart.length?(' · '+t('set.restart_nr')+' '+data.needs_restart.join(', ')):'');
      toast(t('toast.applied'),'ok');
      setTimeout(fetchStats,500);
    }else{
      st.textContent=t('set.saved');
      toast(t('toast.saved'),'ok');
    }
  }catch(e){st.textContent=String(e);toast(String(e),'err');}
}

let logSeq=0,logTimer=null,logFilter='';
function startLogPoll(){stopLogPoll();pollLogs();logTimer=setInterval(pollLogs,2000);}
function stopLogPoll(){if(logTimer){clearInterval(logTimer);logTimer=null;}}
async function pollLogs(){
  try{
    const res=await fetch(url('/api/logs?after='+logSeq),AUTH_HDR);
    if(!res.ok)return;
    const lines=await res.json();
    if(!lines.length)return;
    const box=document.getElementById('logbox');
    if(box.querySelector('.empty-box'))box.innerHTML='';
    box.innerHTML+=lines.map(l=>'<div class="ln lv-'+l.level+'"><span class="ts">['+l.time+']</span><span class="lv">'+l.level+'</span><span class="msg">'+esc(l.msg)+'</span></div>').join('');
    logSeq=lines[lines.length-1].seq;
    applyLogFilter();
    if(document.getElementById('autoscroll').checked)box.scrollTop=box.scrollHeight;
  }catch(e){}
}
// 日志过滤：本地隐藏不匹配的行，缓冲不丢，计数显示 命中/总数
function applyLogFilter(){
  const box=document.getElementById('logbox');
  if(!box)return;
  const f=logFilter.toLowerCase();
  const all=box.querySelectorAll('.ln');
  let shown=0;
  all.forEach(function(l){
    const hit=!f||l.textContent.toLowerCase().indexOf(f)>=0;
    l.style.display=hit?'':'none';
    if(hit)shown++;
  });
  const cnt=document.getElementById('log-count');
  if(cnt)cnt.textContent=f?(shown+' / '+all.length):'';
}
function logEmptyBox(){
  return '<div class="empty-box"><svg viewBox="0 0 24 24">'+EMPTY_ICON.logs+'</svg>'+
    '<div>'+esc(t('no_logs'))+'</div></div>';
}
function clearLog(){
  logSeq=0;logFilter='';
  const inp=document.getElementById('log-filter');
  const clr=document.getElementById('log-filter-clear');
  if(inp)inp.value='';
  if(clr)clr.classList.remove('show');
  document.getElementById('logbox').innerHTML=logEmptyBox();
  applyLogFilter();
  toast(t('toast.clear'),'ok');
}
function downloadLog(){
  // innerText 跳过 display:none 的行，所以导出内容自然跟随当前过滤条件
  const blob=new Blob([document.getElementById('logbox').innerText],{type:'text/plain;charset=utf-8'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download='tlsvpn-dashboard-'+new Date().toISOString().replace(/[:.]/g,'-')+'.log';a.click();
  toast(t('toast.download'),'ok');
}
// 日志过滤框：与其他表格搜索框同样的防抖/清空/Esc 交互
(function(){
  const inp=document.getElementById('log-filter');
  const clr=document.getElementById('log-filter-clear');
  if(!inp)return;
  let timer=null;
  inp.addEventListener('input',function(){
    if(clr)clr.classList.toggle('show',!!inp.value);
    clearTimeout(timer);
    timer=setTimeout(function(){logFilter=inp.value.trim();applyLogFilter();},140);
  });
  if(clr)clr.addEventListener('click',function(){inp.value='';logFilter='';clr.classList.remove('show');applyLogFilter();inp.focus();});
  inp.addEventListener('keydown',function(ev){if(ev.key==='Escape'&&clr)clr.click();});
})();

	let THEME=localStorage.getItem('tlsvpn_theme')||'system';
function cssv(n){return getComputedStyle(document.documentElement).getPropertyValue(n).trim()||'#888';}
function isDark(){return THEME==='dark'||(THEME==='system'&&matchMedia('prefers-color-scheme: dark').matches);}
function applyTheme(){
  document.documentElement.dataset.theme=isDark()?'dark':'light';
  setSeg('theme-seg',THEME);
}
function setTheme(v){THEME=v;localStorage.setItem('tlsvpn_theme',v);applyTheme();
  if(chartRange!=="2m"&&trendData){drawTrendChart(trendData.points||[]);}else if(txHist.length||rxHist.length){drawChart();}
  if(lastTraffic)drawTrafficChart(lastTraffic.daily||[]);}
matchMedia('prefers-color-scheme: dark').addEventListener('change',function(){if(THEME==='system'){applyTheme();if(txHist.length||rxHist.length)drawChart();}});

['clients','conns','macs'].forEach(attachSearch);
bindChartHover('chart',function(){if(chartRange==='2m'){drawChart();}else if(trendData){drawTrendChart(trendData.points||[]);}});
bindChartHover('traffic-chart',function(){renderTrafficView();});
let chartRange='2m',trendTimer=null,trendData=null;
function setRange(v){
  chartRange=v;setSeg('range-seg',v);
  if(trendTimer){clearInterval(trendTimer);trendTimer=null;}
  const rttLegend=document.getElementById('legend-rtt');
  if(v==='2m'){
    if(rttLegend)rttLegend.style.display='none';
    drawChart();
    return;
  }
  fetchTrend();
  trendTimer=setInterval(fetchTrend,30000); // 趋势变化慢，独立低频拉取
}
async function fetchTrend(){
  try{
    const res=await fetch(url('/api/trend?range='+(chartRange==='24h'?'24h':'1h')),AUTH_HDR);
    if(!res.ok)return;
    trendData=await res.json();
    if(chartRange!=='2m')drawTrendChart(trendData.points||[]);
  }catch(e){}
}
function drawTrendChart(points){
  const arr=points||[];
  const pts=arr.map((p,i)=>({
    x:arr.length>1?i/(arr.length-1):0,up:p.up,down:p.down,rtt:p.rtt||0,label:fmtHM(p.t*1000).slice(0,5)
  }));
  let max=1,maxRtt=0;
  pts.forEach(p=>{if(p.up>max)max=p.up;if(p.down>max)max=p.down;if(p.rtt>maxRtt)maxRtt=p.rtt;});
  const old=chartState['chart'];
  const hover=(old&&old.hover>=0&&old.hover<pts.length)?old.hover:-1;
  renderLineChart('chart',pts,{max:max,maxRtt:maxRtt,perSec:true,hover:hover});
}

let prev={},lastT=0;const txHist=[],rxHist=[],txTimes=[];const MAXPTS=60;
applyI18n();
// 异常提醒条的关闭按钮：静默当前组合，出现新的告警内容时再自动弹出
(function(){const x=document.getElementById('alertbar-x');
  if(x)x.onclick=function(){alertOff=true;document.getElementById('alertbar').style.display='none';toast(t('ov.alerts_off'),'ok');};})();
document.getElementById('logbox').innerHTML=logEmptyBox();
setRefresh(REFRESH_S);fetchStats();
window.addEventListener('resize',function(){if(chartRange==='2m'){drawChart();}else if(trendData){drawTrendChart(trendData.points||[]);}});
