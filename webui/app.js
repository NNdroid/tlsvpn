const I18N={
'zh-CN':{kpi:{active:'活跃客户端/设备',tcp:'TCP 连接',tx:'总发送',rx:'总接收',uptime:'运行时长',version:'版本',gc:'立即回收',fec:'FEC 恢复 / 确认丢失',parity:'校验帧',overhead:'FEC 开销',pps:'包速率',dropped:'丢帧(队列)',reorder:'重排跳过',mem:'内存',goroutines:'Goroutines:',pool:'IPv4 地址池',v6used:'IPv6 已分配:'},
 chart:{title:'吞吐趋势',win:'(近 120 秒)',r2m:'2 分钟',r1h:'1 小时',r24h:'24 小时'},legend:{up:'上行',down:'下行',rtt:'RTT（均）'},
	tab:{clients:'客户端',conns:'连接明细',macs:'MAC 表',bans:'封禁',traffic:'流量',status:'运行状态',logs:'日志',settings:'设置'},
 tr:{today_up:'今日上行',today_down:'今日下行',today_total:'今日合计',daily:'每日流量',up:'上行',down:'下行',total:'合计',date:'日期',caption:'近 {n} 天',empty:'暂无按日统计数据',client:'客户端',all:'全部'},
 th:{id:'ID',v4:'IPv4',v6:'IPv6',mac:'MAC',tcp:'TCP',tx:'TX (发)',rx:'RX (收)',txs:'↑ 速率',rxs:'↓ 速率',fec:'FEC',enc:'加密',brutal:'Brutal',ops:'操作',kick:'踢出',ban:'封禁',unban:'解封',owner:'客户端',target:'目标',remote:'对端',state:'状态',rtt:'RTT',retries:'重试',age:'在线',epoch:'密钥代际',sni:'SNI',err:'最近错误'},
 m:{port:'端口',seen:'最近活跃'},bans:{id_ph:'ClientID（可短前缀）',min_ph:'分钟（留空=永久）',add:'封禁',refresh:'刷新',left:'剩余'},
 logs:{level:'级别',autoscroll:'自动滚动',clear:'清屏',download:'下载日志'},
 filter_ph:'输入关键字过滤…',filter_none:'无匹配结果',filter_clear:'清除过滤',filter_tip:'按 / 快速聚焦',no_clients:'暂无客户端',no_conns:'无连接',no_macs:'尚未学习到 MAC',no_bans:'无封禁记录',srv_only:'仅服务端模式提供',
 perm:'永久',confirm_kick:'确定要强制断开该客户端吗？',confirm_ban:'确定封禁该客户端吗？',need_id:'请输入 ClientID',
 st:{up:'up',connecting:'connecting',skip:'未生效'},
 badge:{dup:'复制',off:'关闭',ctr:'CTR',plain:'明文'},
 u:{day:'天',hour:'时',min:'分',sec:'秒'},footer:'数据每 {n} 秒刷新',refresh_tip:'刷新间隔',
	tls_http:'HTTP（建议启用 HTTPS）',mode_local:'本机',theme_tip:'主题（跟随系统）',theme:{sys:'Auto',light:'Light',dark:'Dark'},
 cfgk:{traffic_days:'流量统计保留天数',traffic_file:'流量统计文件',mode:'运行模式',encrypt:'内层加密',enc_algo:'内层算法',min_enc:'最低加密要求',pad_mode:'填充模式',brutal:'TCP Brutal',brutal_up:'上行总量 (Mbps)',brutal_down:'下行总量 (Mbps)',socks5:'SOCKS5 代理',fec:'FEC',fec_group:'FEC 分组',fec_group_min:'FEC 分组下限',fec_group_max:'FEC 分组上限',log_level:'日志级别',conns:'并发连接数',tap:'TAP 设备',mac:'MAC 地址',addr:'服务端地址',web_addr:'面板监听',web_auth:'面板认证',web_bind:'面板绑定地址',web_https:'面板 HTTPS',encrypt_psk:'PSK 已配置',session_encrypt:'会话加密',max_sessions:'最大会话数',v4_cidr:'IPv4 网段',v6_cidr:'IPv6 网段',gw_v4:'IPv4 网关',gw_v6:'IPv6 网关',fwmark:'策略路由 fwmark',fwmark_priority:'规则优先级',fwmark_table:'路由表号',extra_routes:'额外路由',source_rules:'按源前缀路由'},
 stt:{title:'运行状态',host:'宿主与进程',negt:'协议协商结果',brutal:'TCP Brutal 明细',cfg:'生效配置快照',
   restart:'以下字段已修改，需要重启进程才能生效：',norestart:'无字段需要重启生效',noneg:'尚未与对端完成握手',
   noerr:'全部生效',kern_yes:'内核已支持',kern_no:'内核不支持',
   sys:{os:'操作系统',arch:'CPU 架构',go:'Go 版本',cpu:'CPU 核数',host:'主机名',cfgpath:'配置文件',ver:'程序版本',load:'负载 (1/5/15 分)',mem:'物理内存',fd:'打开文件数',gc:'GC 次数 / 暂停'},
	  neg:{proto:'协议版本',fec:'FEC',grp:'FEC 分组',enc:'内层加密',pad:'填充模式',minenc:'最低加密要求',stoken:'Session Token',epoch:'密钥代际',tx:'客户端 → 服务端（上行）',rx:'服务端 → 客户端（下行）',prroute:'策略路由生效',tlsfp:'最近连接 ClientHello 指纹（非 JA3/JA4）',tlsver:'TLS 协商版本',tlscipher:'TLS 协商套件',tlsalpn:'TLS ALPN',tlssni:'TLS SNI',tlsoffer:'ClientHello 特征数'},
   brut:{en:'开关',up:'上行总量',down:'下行总量',kern:'内核支持',cur:'当前拥塞控制',avail:'可用拥塞控制',applied:'已生效 / 总数',perconn:'每连接速率',errs:'失败原因',off:'未启用'},
   yes:'是',no:'否'},
 set:{hint:'编辑 JSON 配置。保存：写回配置文件；保存并应用：写回并立即热更运行参数（列出的字段需重启生效）。',
   load:'重新加载',save:'保存',apply:'保存并应用',saved:'已保存',applied:'已保存并应用',restart_nr:'需重启生效:',loaded_err:'加载失败:'}},
'en':{kpi:{active:'Active clients',tcp:'TCP connections',tx:'Total sent',rx:'Total received',uptime:'Uptime',version:'Version',gc:'GC now',fec:'FEC recovered / confirmed lost',parity:'Parity frames',dropped:'Dropped (queue)',reorder:'Reorder skipped',mem:'Memory',goroutines:'Goroutines:',pool:'IPv4 pool',v6used:'IPv6 allocated:',pps:'Packet rate',overhead:'FEC overhead'},
 chart:{title:'Throughput',win:'(last 120s)',r2m:'2 min',r1h:'1 h',r24h:'24 h'},legend:{up:'Up',down:'Down',rtt:'RTT (avg)'},
	tab:{clients:'Clients',conns:'Connections',macs:'MAC table',bans:'Bans',traffic:'Traffic',status:'Runtime status',logs:'Logs',settings:'Settings'},
 tr:{today_up:'Up today',today_down:'Down today',today_total:'Total today',daily:'Daily traffic',up:'Up',down:'Down',total:'Total',date:'Date',caption:'Last {n} days',empty:'No daily traffic data yet',client:'Client',all:'All'},
 th:{id:'ID',v4:'IPv4',v6:'IPv6',mac:'MAC',tcp:'TCP',tx:'TX',rx:'RX',txs:'↑ Rate',rxs:'↓ Rate',fec:'FEC',enc:'Encrypt',brutal:'Brutal',ops:'Actions',kick:'Kick',ban:'Ban',unban:'Unban',owner:'Client',target:'Target',remote:'Remote',state:'State',rtt:'RTT',retries:'Retries',age:'Uptime',epoch:'Epoch',sni:'SNI',err:'Last error'},
 m:{port:'Port',seen:'Last seen'},bans:{id_ph:'ClientID (short prefix ok)',min_ph:'Minutes (empty = permanent)',add:'Ban',refresh:'Refresh',left:'Remaining'},
 logs:{level:'Level',autoscroll:'Auto scroll',clear:'Clear',download:'Download'},
 filter_ph:'Type to filter…',filter_none:'No matches',filter_clear:'Clear filter',filter_tip:'Press / to focus',no_clients:'No clients yet',no_conns:'No connections',no_macs:'No MACs learned yet',no_bans:'No banned clients',srv_only:'Server mode only',
 perm:'Permanent',confirm_kick:'Force-disconnect this client?',confirm_ban:'Ban this client?',need_id:'Please enter a ClientID',
 st:{up:'up',connecting:'connecting',skip:'Skipped'},
 badge:{dup:'Dup',off:'Off',ctr:'CTR',plain:'Plain'},
 u:{day:'d',hour:'h',min:'m',sec:'s'},footer:'Refreshing every {n}s',refresh_tip:'Refresh interval',
	tls_http:'HTTP (HTTPS recommended)',mode_local:'local',theme_tip:'Theme (follow system)',theme:{sys:'Auto',light:'Light',dark:'Dark'},
 cfgk:{traffic_days:'Traffic retention days',traffic_file:'Traffic stats file',mode:'Mode',encrypt:'Inner cipher',enc_algo:'Inner algorithm',min_enc:'Minimum cipher',pad_mode:'Padding mode',brutal:'TCP Brutal',brutal_up:'Upstream total (Mbps)',brutal_down:'Downstream total (Mbps)',socks5:'SOCKS5 proxy',fec:'FEC',fec_group:'FEC group',fec_group_min:'FEC group floor',fec_group_max:'FEC group ceiling',log_level:'Log level',conns:'Concurrent conns',tap:'TAP device',mac:'MAC address',addr:'Server address',web_addr:'Dashboard listen',web_auth:'Dashboard auth',web_bind:'Dashboard bind',web_https:'Dashboard HTTPS',encrypt_psk:'PSK configured',session_encrypt:'Session encryption',max_sessions:'Max sessions',v4_cidr:'IPv4 CIDR',v6_cidr:'IPv6 CIDR',gw_v4:'IPv4 gateway',gw_v6:'IPv6 gateway',fwmark:'Policy routing fwmark',fwmark_priority:'Rule priority',fwmark_table:'Route table',extra_routes:'Extra routes',source_rules:'Source rules'},
 stt:{title:'Runtime status',host:'Host & process',negt:'Negotiated protocol',brutal:'TCP Brutal detail',cfg:'Effective config snapshot',
   restart:'These fields changed and require a process restart:',norestart:'Nothing pending restart',noneg:'Handshake with peer not completed yet',
   noerr:'All applied',kern_yes:'Kernel supported',kern_no:'Not supported by kernel',
   sys:{os:'OS',arch:'CPU arch',go:'Go version',cpu:'CPU cores',host:'Hostname',cfgpath:'Config file',ver:'App version',load:'Load (1/5/15 min)',mem:'Physical memory',fd:'Open files',gc:'GC count / pause'},
	  neg:{proto:'Protocol version',fec:'FEC',grp:'FEC group',enc:'Inner cipher',pad:'Padding mode',minenc:'Minimum cipher',stoken:'Session token',epoch:'Key epoch',tx:'Client → server (uplink)',rx:'Server → client (downlink)',prroute:'Policy routing applied',tlsfp:'Latest connection ClientHello fingerprint (not JA3/JA4)',tlsver:'Negotiated TLS version',tlscipher:'Negotiated TLS cipher',tlsalpn:'TLS ALPN',tlssni:'TLS SNI',tlsoffer:'ClientHello feature counts'},
   brut:{en:'Enabled',up:'Upstream total',down:'Downstream total',kern:'Kernel support',cur:'Current CC',avail:'Available CC',applied:'Applied / total',perconn:'Per-conn rate',errs:'Failure reasons',off:'Not enabled'},
   yes:'yes',no:'no'},
 set:{hint:'Edit the JSON config. Save: write back to the config file. Save & apply: write back and hot-apply runtime parameters (listed fields require a restart).',
   load:'Reload',save:'Save',apply:'Save & apply',saved:'Saved',applied:'Saved & applied',restart_nr:'Needs restart:',loaded_err:'Load failed:'}},
'de':{kpi:{active:'Aktive Clients',tcp:'TCP-Verbindungen',tx:'Gesendet',rx:'Empfangen',uptime:'Laufzeit',version:'Version',gc:'GC ausführen',fec:'FEC wiederhergestellt / verloren',parity:'Paritätsframes',dropped:'Verworfen (Queue)',reorder:'Reorder übersprungen',mem:'Speicher',goroutines:'Goroutines:',pool:'IPv4-Pool',v6used:'IPv6 zugewiesen:',pps:'Paktrate',overhead:'FEC-Overhead'},
 chart:{title:'Durchsatz',win:'(letzte 120 s)',r2m:'2 Min',r1h:'1 Std',r24h:'24 Std'},legend:{up:'Uplink',down:'Downlink',rtt:'RTT (Ø)'},
 tab:{clients:'Clients',conns:'Verbindungen',macs:'MAC-Tabelle',bans:'Sperren',traffic:'Traffic',status:'Laufzeitstatus',logs:'Protokolle',settings:'Einstellungen'},
 th:{id:'ID',v4:'IPv4',v6:'IPv6',mac:'MAC',tcp:'TCP',tx:'TX (S)',rx:'RX (E)',txs:'↑ Rate',rxs:'↓ Rate',fec:'FEC',enc:'Verschlüsselung',brutal:'Brutal',ops:'Aktionen',kick:'Trennen',ban:'Sperren',unban:'Entsperren',owner:'Client',target:'Ziel',remote:'Gegenstelle',state:'Status',rtt:'RTT',retries:'Wiederholungen',age:'Online',epoch:'Schlüssel-Epoche',sni:'SNI',err:'Letzter Fehler'},
 m:{port:'Port',seen:'Zuletzt aktiv'},bans:{id_ph:'ClientID (Präfix ok)',min_ph:'Minuten (leer = dauerhaft)',add:'Sperren',refresh:'Aktualisieren',left:'Restlaufzeit'},
 logs:{level:'Level',autoscroll:'Auto-Scroll',clear:'Leeren',download:'Download'},
 filter_ph:'Zum Filtern eingeben…',filter_none:'Keine Treffer',filter_clear:'Filter löschen',filter_tip:'/ zum Fokussieren',no_clients:'Keine Clients',no_conns:'Keine Verbindungen',no_macs:'Noch keine MACs gelernt',no_bans:'Keine Sperren',srv_only:'Nur im Server-Modus',
 perm:'Dauerhaft',confirm_kick:'Diesen Client wirklich trennen?',confirm_ban:'Diesen Client sperren?',need_id:'Bitte ClientID eingeben',
 st:{up:'aktiv',connecting:'verbinde',skip:'Übergangen'},
 badge:{dup:'Dup',off:'Aus',ctr:'CTR',plain:'Klartext'},
 u:{day:'T',hour:'Std',min:'Min',sec:'Sek'},footer:'Aktualisierung alle {n}s',refresh_tip:'Aktualisierungsintervall',
 tls_http:'HTTP (HTTPS empfohlen)',mode_local:'lokal',theme_tip:'Design (System folgen)',theme:{sys:'Auto',light:'Hell',dark:'Dunkel'},
 cfgk:{traffic_days:'Traffic-Aufbewahrung (Tage)',traffic_file:'Traffic-Statistikdatei',mode:'Modus',encrypt:'Innere Verschlüsselung',enc_algo:'Innerer Algorithmus',min_enc:'Minimale Verschlüsselung',pad_mode:'Padding-Modus',brutal:'TCP Brutal',brutal_up:'Uplink gesamt (Mbps)',brutal_down:'Downlink gesamt (Mbps)',socks5:'SOCKS5-Proxy',fec:'FEC',fec_group:'FEC-Gruppe',fec_group_min:'FEC-Gruppe Minimum',fec_group_max:'FEC-Gruppe Maximum',log_level:'Log-Level',conns:'Parallele Verbindungen',tap:'TAP-Gerät',mac:'MAC-Adresse',addr:'Serveradresse',web_addr:'Panel-Adresse',web_auth:'Panel-Auth',web_bind:'Panel-Bindung',web_https:'Panel-HTTPS',encrypt_psk:'PSK konfiguriert',session_encrypt:'Sitzungsverschlüsselung',max_sessions:'Max. Sitzungen',v4_cidr:'IPv4-CIDR',v6_cidr:'IPv6-CIDR',gw_v4:'IPv4-Gateway',gw_v6:'IPv6-Gateway',fwmark:'Policy-Routing fwmark',fwmark_priority:'Regel-Priorität',fwmark_table:'Routentabelle',extra_routes:'Zusatzrouten',source_rules:'Quellregeln'},
 stt:{title:'Laufzeitstatus',host:'Host & Prozess',negt:'Ausgehandelte Parameter',brutal:'TCP Brutal Details',cfg:'Aktive Konfiguration',
   restart:'Diese Felder wurden geändert und erfordern einen Neustart des Prozesses:',norestart:'Kein Feld erfordert einen Neustart',noneg:'Handshake mit der Gegenstelle noch nicht abgeschlossen',
   noerr:'Alle angewendet',kern_yes:'Kernel unterstützt',kern_no:'Kernel nicht unterstützt',
   sys:{os:'Betriebssystem',arch:'CPU-Architektur',go:'Go-Version',cpu:'CPU-Kerne',host:'Hostname',cfgpath:'Konfigurationsdatei',ver:'Programmversion',load:'Load (1/5/15 Min)',mem:'Physischer Speicher',fd:'Offene Dateien',gc:'GC-Anzahl / Pause'},
   neg:{proto:'Protokollversion',fec:'FEC',grp:'FEC-Gruppe',enc:'Innere Verschlüsselung',pad:'Padding-Modus',minenc:'Minimale Verschlüsselung',stoken:'Session-Token',epoch:'Schlüssel-Epoche',tx:'Client → Server (Uplink)',rx:'Server → Client (Downlink)',prroute:'Policy-Routing aktiv',tlsfp:'ClientHello-Fingerprint der letzten Verbindung (nicht JA3/JA4)',tlsver:'Ausgehandelte TLS-Version',tlscipher:'Ausgehandelte TLS-Cipher',tlsalpn:'TLS ALPN',tlssni:'TLS SNI',tlsoffer:'ClientHello-Merkmale'},
   brut:{en:'Schalter',up:'Uplink gesamt',down:'Downlink gesamt',kern:'Kernel-Unterstützung',cur:'Aktive CC',avail:'Verfügbare CC',applied:'Angewendet / gesamt',perconn:'Rate pro Verbindung',errs:'Fehlerursachen',off:'Nicht aktiviert'},
   yes:'ja',no:'nein'},
 set:{hint:'JSON-Konfiguration bearbeiten. Speichern: in die Datei zurückschreiben. Speichern & anwenden: zurückschreiben und Laufzeitparameter heiß anwenden (genannte Felder erfordern einen Neustart).',
   load:'Neu laden',save:'Speichern',apply:'Speichern & anwenden',saved:'Gespeichert',applied:'Gespeichert & angewendet',restart_nr:'Neustart nötig:',loaded_err:'Ladefehler:'},
 tr:{today_up:'Uplink heute',today_down:'Downlink heute',today_total:'Gesamt heute',daily:'Täglicher Traffic',up:'Uplink',down:'Downlink',total:'Gesamt',date:'Datum',caption:'Letzte {n} Tage',empty:'Noch keine täglichen Traffic-Daten',client:'Client',all:'Alle'}},
'fr':{kpi:{active:'Clients actifs',tcp:'Connexions TCP',tx:'Total envoyé',rx:'Total reçu',uptime:'Disponibilité',version:'Version',gc:'GC maintenant',fec:'FEC récupérés / perdus',parity:'Trames de parité',dropped:'Abandons (file)',reorder:'Réordonnancement ignoré',mem:'Mémoire',goroutines:'Goroutines :',pool:'Pool IPv4',v6used:'IPv6 allouées :'},
 chart:{title:'Débit',win:'(120 dernières s)',r2m:'2 min',r1h:'1 h',r24h:'24 h'},legend:{up:'Montant',down:'Descendant',rtt:'RTT (moy.)'},
 tab:{clients:'Clients',conns:'Connexions',macs:'Table MAC',bans:'Bannissements',traffic:'Trafic',status:'État runtime',logs:'Journaux',settings:'Paramètres'},
 th:{id:'ID',v4:'IPv4',v6:'IPv6',mac:'MAC',tcp:'TCP',tx:'TX (env.)',rx:'RX (rec.)',txs:'↑ Débit',rxs:'↓ Débit',fec:'FEC',enc:'Chiffrement',brutal:'Brutal',ops:'Actions',kick:'Éjecter',ban:'Bannir',unban:'Débannir',owner:'Client',target:'Cible',remote:'Distant',state:'État',rtt:'RTT',retries:'Réessais',age:'En ligne',epoch:'Époque de clé',sni:'SNI',err:'Dernière erreur'},
 m:{port:'Port',seen:'Dernière activité'},bans:{id_ph:'ClientID (préfixe accepté)',min_ph:'Minutes (vide = permanent)',add:'Bannir',refresh:'Rafraîchir',left:'Restant'},
 logs:{level:'Niveau',autoscroll:'Défilement auto',clear:'Effacer',download:'Télécharger'},
 filter_ph:'Taper pour filtrer…',filter_none:'Aucun résultat',filter_clear:'Effacer le filtre',filter_tip:'/ pour le focus',no_clients:'Aucun client',no_conns:'Aucune connexion',no_macs:'Aucune MAC apprise',no_bans:'Aucun bannissement',srv_only:'Mode serveur uniquement',
 perm:'Permanent',confirm_kick:'Déconnecter ce client de force ?',confirm_ban:'Bannir ce client ?',need_id:'Veuillez saisir un ClientID',
 st:{up:'actif',connecting:'connexion',skip:'Ignoré'},
 badge:{dup:'Dup',off:'Désactivé',ctr:'CTR',plain:'Clair'},
 u:{day:'j',hour:'h',min:'min',sec:'s'},footer:"Actualisation toutes les {n}s",refresh_tip:"Intervalle d'actualisation",
 tls_http:'HTTP (HTTPS recommandé)',mode_local:'local',theme_tip:"Thème (suivre le système)",theme:{sys:'Auto',light:'Clair',dark:'Sombre'},
 cfgk:{traffic_days:'Rétention du trafic (jours)',traffic_file:'Fichier de statistiques de trafic',mode:'Mode',encrypt:'Chiffrement interne',enc_algo:'Algorithme interne',min_enc:'Chiffrement minimum',pad_mode:'Mode de remplissage',brutal:'TCP Brutal',brutal_up:'Montant total (Mbps)',brutal_down:'Descendant total (Mbps)',socks5:'Proxy SOCKS5',fec:'FEC',fec_group:'Groupe FEC',fec_group_min:'Groupe FEC min',fec_group_max:'Groupe FEC max',log_level:'Niveau de log',conns:'Connexions simultanées',tap:'Périphérique TAP',mac:'Adresse MAC',addr:'Adresse du serveur',web_addr:'Écoute du panneau',web_auth:'Auth du panneau',web_bind:'Liaison du panneau',web_https:'HTTPS du panneau',encrypt_psk:'PSK configurée',session_encrypt:'Chiffrement de session',max_sessions:'Sessions max',v4_cidr:'CIDR IPv4',v6_cidr:'CIDR IPv6',gw_v4:'Passerelle IPv4',gw_v6:'Passerelle IPv6',fwmark:'fwmark routage par stratégie',fwmark_priority:'Priorité de règle',fwmark_table:'Table de routage',extra_routes:'Routes supplémentaires',source_rules:'Règles par source'},
 stt:{title:'État runtime',host:'Hôte & processus',negt:'Paramètres négociés',brutal:'Détails TCP Brutal',cfg:'Instantané de la config effective',
   restart:'Ces champs ont été modifiés et exigent un redémarrage du processus :',norestart:'Aucun champ ne requiert de redémarrage',noneg:'Handshake avec le pair pas encore terminé',
   noerr:'Tout appliqué',kern_yes:'Noyau compatible',kern_no:'Noyau non compatible',
   sys:{os:'Système',arch:'Arch. CPU',go:'Version Go',cpu:'Cœurs CPU',host:"Nom d'hôte",cfgpath:'Fichier de configuration',ver:'Version du programme',load:'Charge (1/5/15 min)',mem:"Mémoire physique",fd:'Fichiers ouverts',gc:'GC : nombre / pause'},
   neg:{proto:'Version du protocole',fec:'FEC',grp:'Groupe FEC',enc:'Chiffrement interne',pad:'Mode de remplissage',minenc:'Chiffrement minimum',stoken:'Jeton de session',epoch:'Époque de clé',tx:'Client → serveur (montant)',rx:'Serveur → client (descendant)',prroute:'Routage par stratégie actif',tlsfp:"Empreinte ClientHello de la dernière connexion (pas JA3/JA4)",tlsver:'Version TLS négociée',tlscipher:'Suite TLS négociée',tlsalpn:'TLS ALPN',tlssni:'TLS SNI',tlsoffer:'Caractéristiques ClientHello'},
   brut:{en:'Activé',up:'Montant total',down:'Descendant total',kern:'Support noyau',cur:'CC actuel',avail:'CC disponibles',applied:'Appliqué / total',perconn:'Débit par connexion',errs:"Causes d'échec",off:'Non activé'},
   yes:'oui',no:'non'},
 set:{hint:'Éditer la config JSON. Enregistrer : réécrire le fichier. Enregistrer & appliquer : réécrire et appliquer à chaud les paramètres runtime (certains champs exigent un redémarrage).',
   load:'Recharger',save:'Enregistrer',apply:'Enregistrer & appliquer',saved:'Enregistré',applied:'Enregistré & appliqué',restart_nr:'Redémarrage requis :',loaded_err:'Échec du chargement :'},
 tr:{today_up:'Montant du jour',today_down:'Descendant du jour',today_total:'Total du jour',daily:'Trafic quotidien',up:'Montant',down:'Descendant',total:'Total',date:'Date',caption:'{n} derniers jours',empty:'Pas encore de données de trafic quotidien',client:'Client',all:'Tous'}},
'ja':{kpi:{active:'アクティブクライアント',tcp:'TCP 接続',tx:'送信合計',rx:'受信合計',uptime:'稼働時間',version:'バージョン',gc:'即時 GC',fec:'FEC 復元 / 確定ロスト',parity:'パリティフレーム',dropped:'廃棄（キュー）',reorder:'並べ替えスキップ',mem:'メモリ',goroutines:'Goroutines:',pool:'IPv4 プール',v6used:'IPv6 割り当て:',pps:'パケット速度',overhead:'FEC オーバーヘッド'},
 chart:{title:'スループット',win:'（過去 120 秒）',r2m:'2 分',r1h:'1 時間',r24h:'24 時間'},legend:{up:'上り',down:'下り',rtt:'RTT（平均）'},
 tab:{clients:'クライアント',conns:'接続明細',macs:'MAC テーブル',bans:'禁止',traffic:'トラフィック',status:'稼働状態',logs:'ログ',settings:'設定'},
 th:{id:'ID',v4:'IPv4',v6:'IPv6',mac:'MAC',tcp:'TCP',tx:'TX（送）',rx:'RX（受）',txs:'↑ 速度',rxs:'↓ 速度',fec:'FEC',enc:'暗号化',brutal:'Brutal',ops:'操作',kick:'切断',ban:'禁止',unban:'解除',owner:'クライアント',target:'接続先',remote:'対向',state:'状態',rtt:'RTT',retries:'再試行',age:'経過時間',epoch:'鍵世代',sni:'SNI',err:'最新エラー'},
 m:{port:'ポート',seen:'最終アクティブ'},bans:{id_ph:'ClientID（前方一致可）',min_ph:'分数（空欄=永久）',add:'禁止',refresh:'更新',left:'残り'},
 logs:{level:'レベル',autoscroll:'自動スクロール',clear:'クリア',download:'ダウンロード'},
 filter_ph:'入力して絞り込み…',filter_none:'該当なし',filter_clear:'フィルタ解除',filter_tip:'/ でフォーカス',no_clients:'クライアントなし',no_conns:'接続なし',no_macs:'学習済み MAC なし',no_bans:'禁止レコードなし',srv_only:'サーバーモードのみ',
 perm:'永久',confirm_kick:'このクライアントを強制切断しますか？',confirm_ban:'このクライアントを禁止しますか？',need_id:'ClientID を入力してください',
 st:{up:'up',connecting:'connecting',skip:'未適用'},
 badge:{dup:'複製',off:'オフ',ctr:'CTR',plain:'平文'},
 u:{day:'日',hour:'時間',min:'分',sec:'秒'},footer:'{n} 秒ごとに更新',refresh_tip:'更新間隔',
 tls_http:'HTTP（HTTPS 推奨）',mode_local:'ローカル',theme_tip:'テーマ（システムに従う）',theme:{sys:'Auto',light:'Light',dark:'Dark'},
 cfgk:{traffic_days:'トラフィック保持日数',traffic_file:'トラフィック統計ファイル',mode:'動作モード',encrypt:'内層暗号化',enc_algo:'内層アルゴリズム',min_enc:'最低暗号化要件',pad_mode:'パディングモード',brutal:'TCP Brutal',brutal_up:'上り合計 (Mbps)',brutal_down:'下り合計 (Mbps)',socks5:'SOCKS5 プロキシ',fec:'FEC',fec_group:'FEC グループ',fec_group_min:'FEC グループ下限',fec_group_max:'FEC グループ上限',log_level:'ログレベル',conns:'同時接続数',tap:'TAP デバイス',mac:'MAC アドレス',addr:'サーバーアドレス',web_addr:'パネル待受',web_auth:'パネル認証',web_bind:'パネルバインド',web_https:'パネル HTTPS',encrypt_psk:'PSK 設定済み',session_encrypt:'セッション暗号化',max_sessions:'最大セッション数',v4_cidr:'IPv4 CIDR',v6_cidr:'IPv6 CIDR',gw_v4:'IPv4 ゲートウェイ',gw_v6:'IPv6 ゲートウェイ',fwmark:'ポリシールーティング fwmark',fwmark_priority:'ルール優先度',fwmark_table:'ルートテーブル',extra_routes:'追加ルート',source_rules:'送信元ルール'},
 stt:{title:'稼働状態',host:'ホストとプロセス',negt:'ネゴシエーション結果',brutal:'TCP Brutal 明細',cfg:'有効な設定スナップショット',
   restart:'以下のフィールドは変更済み、プロセスの再起動が必要です：',norestart:'再起動が必要なフィールドはありません',noneg:'対向とのハンドシェイク未完了',
   noerr:'すべて有効',kern_yes:'カーネル対応',kern_no:'カーネル未対応',
   sys:{os:'OS',arch:'CPU アーキ',go:'Go バージョン',cpu:'CPU コア数',host:'ホスト名',cfgpath:'設定ファイル',ver:'プログラムバージョン',load:'負荷 (1/5/15 分)',mem:'物理メモリ',fd:'オープンファイル数',gc:'GC 回数 / 停止時間'},
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
// 鼠标悬停：定位最近数据点后重绘（几何信息存于 chartState）
function bindChartHover(canvasId,redraw){
  const c=document.getElementById(canvasId);if(!c)return;
  c.addEventListener('mousemove',function(ev){
    const st=chartState[canvasId];if(!st||st.pts.length<2)return;
    const rect=c.getBoundingClientRect();
    let idx=Math.round((ev.clientX-rect.left-st.plot.l)/(st.plot.r-st.plot.l)*(st.pts.length-1));
    idx=Math.max(0,Math.min(st.pts.length-1,idx));
    if(st.hover!==idx){st.hover=idx;redraw();}
  });
  c.addEventListener('mouseleave',function(){
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

function passFilter(obj,f){return !f||JSON.stringify(obj).toLowerCase().includes(f);}

const NO_TXT={clients:'no_clients',conns:'no_conns',macs:'no_macs',bans:'no_bans'};
function emptyRow(key,cols,total){
  if(!total)return '<tr><td class="empty" colspan="'+cols+'">'+t(NO_TXT[key])+'</td></tr>';
  return '<tr><td class="empty" colspan="'+cols+'">'+t('filter_none')+
    ' <button class="btn ghost sm" onclick="clearFilter(\''+key+'\')">'+t('filter_clear')+'</button></td></tr>';
}
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
    timer=setTimeout(function(){Q[key]=input.value.trim().toLowerCase();rerenderTables();},140);
  });
  clear.addEventListener('click',function(){input.value='';Q[key]='';clear.classList.remove('show');rerenderTables();input.focus();});
  input.addEventListener('keydown',function(e){if(e.key==='Escape')clear.click();});
}
function clearFilter(key){
  const box=document.getElementById('search-'+key);if(!box)return;
  box.querySelector('.search-input').value='';
  box.querySelector('.search-clear').classList.remove('show');
  Q[key]='';
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
async function fetchStats(){
  try{
    const res=await fetch(url('/api/stats'),AUTH_HDR);
    if(res.status===401){document.body.innerHTML='<div class="card"><h2>401</h2><p>'+t('logs.level')+': -web-auth user:pass</p></div>';return;}
    const data=await res.json();
    lastStats=data;
    const now=performance.now();const dt=lastT?(now-lastT)/1000:2;lastT=now;

    document.getElementById('mode').innerText=data.mode.toUpperCase();
    const chip=document.getElementById('mode-chip');
    if(chip)chip.classList.toggle('client',data.mode!=='server');
    document.getElementById('ver').innerText=data.version||'-';
    document.getElementById('uptime').innerText=fmtDur(data.uptime_sec||0);
    document.getElementById('loglevel').value=data.log_level||'info';
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
  let rows='',shown=0;
  for(const [id,c] of entries){
    if(!passFilter(Object.assign({id:id},c),f))continue;
    shown++;
    const sp=lastSpeeds[id]||{sx:0,sr:0};
    rows+='<tr><td class="num dim" title="'+esc(id)+'">'+hi(esc(shortId(id,10)),f)+'</td>'+
      '<td class="num">'+hi(esc(c.ipv4||'-'),f)+'</td>'+
      '<td class="hide-sm num dim">'+hi(esc(c.ipv6||'-'),f)+'</td>'+
      '<td class="hide-sm num dim">'+hi(esc(c.mac||'-'),f)+'</td>'+
      '<td class="num">'+c.active_conns+'</td>'+
      '<td class="num">'+fmtBytes(c.tx_bytes)+'</td><td class="num">'+fmtBytes(c.rx_bytes)+'</td>'+
      '<td class="num speed">'+fmtBytes(sp.sx,true)+'</td><td class="num speed dn">'+fmtBytes(sp.sr,true)+'</td>'+
      '<td class="hide-sm">'+badge(c.fec)+'</td><td class="hide-sm">'+encBadge(c.enc_algo)+'</td>'+
      '<td>'+(data.mode==='server'?'<button class="btn danger sm" onclick="kickClient(\''+id+'\')">'+t('th.kick')+'</button>'+
        '<button class="btn ghost sm" onclick="banClient(\''+id+'\',0)">'+t('th.ban')+'</button>':'-')+'</td></tr>';
  }
  document.getElementById('clients-body').innerHTML=rows||emptyRow('clients',12,entries.length);
  setCount('client-count',f,shown,entries.length);
}

// ---------- "运行状态" 页：宿主/协商/brutal/配置 四块明细 ----------
// 空值不占行：面板上留一堆空行只会让人误以为字段缺失是故障
function kv(el,rows){
  el.innerHTML=rows.length?rows.map(r=>'<tr><th>'+esc(r[0])+'</th><td>'+r[1]+'</td></tr>').join(''):'';
}
function yn(v){return v?'<span class="badge b-on">'+t('stt.yes')+'</span>':'<span class="badge b-off">'+t('stt.no')+'</span>';}
function mtxt(v){return '<span class="mono">'+esc(v)+'</span>';}
function ntxt(){return '<span style="color:var(--sub)">-</span>';}
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
  if(f)rows=rows.filter(r=>JSON.stringify(r).toLowerCase().includes(f));
  const total=rows.length;
  tb.innerHTML=rows.map(r=>{
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
    return '<tr><td class="num dim">'+hi(esc(r.owner),f)+'</td><td class="num">'+hi(esc(r.target||'-'),f)+'</td><td class="num">'+hi(esc(r.remote||'-'),f)+'</td><td title="'+esc(brutTip)+'">'+st+'</td>'+
      '<td class="num">'+rtt+'</td><td class="num">'+fmtBytes(r.tx)+'</td><td class="num">'+fmtBytes(r.rx)+'</td>'+
      '<td class="hide-sm num speed">'+fmtBytes(r.sx,true)+'</td><td class="hide-sm num speed dn">'+fmtBytes(r.sr,true)+'</td>'+
      '<td class="hide-sm dim" title="'+esc(sniMeta)+'">'+(r.sni?hi(esc(r.sni),f):'<span style="color:var(--sub)">-</span>')+'</td>'+
      '<td class="hide-sm num dim">'+(r.age?fmtDur(r.age):'-')+'</td>'+
      '<td class="hide-sm num dim" title="'+esc(r.epoch?'session key epoch '+r.epoch:'no epoch yet')+'">'+(r.epoch?r.epoch:'-')+'</td>'+
      '<td class="hide-sm">'+encBadge(r.enc)+'</td><td class="hide-sm">'+badge(r.fec)+'</td>'+
      '<td class="hide-sm" title="'+esc(brutTip)+'">'+brut+'</td>'+
      '<td class="hide-sm" style="color:var(--err)" title="'+esc(r.err||r.brutErr)+'">'+esc(String(r.err||r.brutErr).slice(0,40))+'</td><td>'+ops+'</td></tr>';
  }).join('')||emptyRow('conns',17,all);
  setCount('conn-count',f,rows.length,all);
}
function renderMacsTable(data){
  const tb=document.getElementById('macs-body');
  if(data.mode!=='server'){
    tb.innerHTML='<tr><td colspan="3" class="empty">'+t('srv_only')+'</td></tr>';
    setCount('mac-count','',0,0);return;
  }
  const f=Q.macs;
  const list=data.mac_table||[];
  let rows='',shown=0;
  list.forEach(e=>{
    if(!passFilter(e,f))return;
    shown++;
    rows+='<tr><td class="num">'+hi(esc(e.mac),f)+'</td><td class="num dim">'+hi(esc(e.port),f)+'</td><td class="num dim">'+e.age_sec+'s</td></tr>';
  });
  tb.innerHTML=rows||emptyRow('macs',3,list.length);
  setCount('mac-count',f,shown,list.length);
}
function renderBansTable(data){
  const tb=document.getElementById('bans-body');
  if(data.mode!=='server'){tb.innerHTML='<tr><td colspan="3" class="empty">'+t('srv_only')+'</td></tr>';return;}
  const bans=data.banned||{};
  tb.innerHTML=Object.entries(bans).map(([id,left])=>'<tr><td class="num dim" title="'+esc(id)+'">'+esc(shortId(id,18))+'</td>'+
    '<td>'+(left===0?'<span class="badge b-dup">'+t('perm')+'</span>':'<span class="badge b-on">'+fmtDur(left)+'</span>')+'</td>'+
    '<td><button class="btn ghost sm" onclick="unban(\''+id+'\')">'+t('th.unban')+'</button></td></tr>').join('')||
    '<tr><td colspan="3" class="empty">'+t('no_bans')+'</td></tr>';
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
  const days=(daily||[]).slice().reverse();
  const rows=days.map(d=>'<tr><td class="num dim">'+esc(d.date)+'</td><td class="num speed">'+fmtBytes(d.up)+'</td>'+
    '<td class="num speed dn">'+fmtBytes(d.down)+'</td><td class="num">'+fmtBytes(d.up+d.down)+'</td></tr>').join('');
  tb.innerHTML=rows||'<tr><td colspan="4" class="empty">'+t('tr.empty')+'</td></tr>';
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

async function kickClient(id){if(!confirm(t('confirm_kick')))return;
  await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'kick',client_id:id})});fetchStats();}
async function banClient(id,minutes){if(!confirm(t('confirm_ban')))return;
  await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'ban',client_id:id,ttl_minutes:minutes})});fetchStats();}
async function addBan(){const id=document.getElementById('ban-id').value.trim();if(!id)return alert(t('need_id'));
  const m=parseInt(document.getElementById('ban-min').value,10);
  await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'ban',client_id:id,ttl_minutes:isNaN(m)?0:m})});
  document.getElementById('ban-id').value='';document.getElementById('ban-min').value='';fetchStats();}
async function unban(id){await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'unban',client_id:id})});fetchStats();}
async function doAction(action){await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:action})});fetchStats();}
async function setLogLevel(v){await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'loglevel',level:v})});}

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
  catch(e){st.textContent='JSON: '+e.message;return;}
  try{
    const res=await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({action:apply?'save_apply':'save',config:cfg})});
    const data=await res.json().catch(()=>({}));
    if(!res.ok){st.textContent=(data.error||('HTTP '+res.status));return;}
    if(apply){
      st.textContent=t('set.applied')+(data.needs_restart&&data.needs_restart.length?(' · '+t('set.restart_nr')+' '+data.needs_restart.join(', ')):'');
      setTimeout(fetchStats,500);
    }else{
      st.textContent=t('set.saved');
    }
  }catch(e){st.textContent=String(e);}
}

let logSeq=0,logTimer=null;
function startLogPoll(){stopLogPoll();pollLogs();logTimer=setInterval(pollLogs,2000);}
function stopLogPoll(){if(logTimer){clearInterval(logTimer);logTimer=null;}}
async function pollLogs(){
  try{
    const res=await fetch(url('/api/logs?after='+logSeq),AUTH_HDR);
    if(!res.ok)return;
    const lines=await res.json();
    if(!lines.length)return;
    const box=document.getElementById('logbox');
    box.innerHTML+=lines.map(l=>'<div class="ln lv-'+l.level+'"><span class="ts">['+l.time+']</span><span class="lv">'+l.level+'</span><span class="msg">'+esc(l.msg)+'</span></div>').join('');
    logSeq=lines[lines.length-1].seq;
    if(document.getElementById('autoscroll').checked)box.scrollTop=box.scrollHeight;
  }catch(e){}
}
function clearLog(){logSeq=0;document.getElementById('logbox').innerHTML='';}
function downloadLog(){
  const blob=new Blob([document.getElementById('logbox').innerText],{type:'text/plain;charset=utf-8'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);
  a.download='tlsvpn-dashboard-'+new Date().toISOString().replace(/[:.]/g,'-')+'.log';a.click();
}

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
applyI18n();setRefresh(REFRESH_S);fetchStats();
window.addEventListener('resize',function(){if(chartRange==='2m'){drawChart();}else if(trendData){drawTrendChart(trendData.points||[]);}});
