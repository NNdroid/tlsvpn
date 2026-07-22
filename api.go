package main

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
)

// ======================= Web UI 与 监控 API =======================

type WebStats struct {
	Mode          string                 `json:"mode"`
	ActiveClients int                    `json:"active_clients"`
	Clients       map[string]interface{} `json:"clients,omitempty"`
	GlobalTxBytes uint64                 `json:"global_tx_bytes"`
	GlobalRxBytes uint64                 `json:"global_rx_bytes"`
}

var dashboardHTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>VPN Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #121212; color: #e0e0e0; margin: 0; padding: 20px; }
        .card { background: #1e1e1e; border-radius: 8px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); margin-bottom: 20px; }
        h1, h2 { margin-top: 0; color: #bb86fc; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        th { background-color: #2c2c2c; }
        .btn { padding: 6px 12px; background-color: #cf6679; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .btn:hover { background-color: #ff7597; }
        /* 新增：高亮速率显示的颜色 */
        .speed { color: #03dac6; font-weight: bold; } 
    </style>
</head>
<body>
    <h1>🚀 VPN Dashboard (<span id="mode">加载中...</span>)</h1>
    <div class="card">
        <h2>系统状态</h2>
        <p>活跃连接数/设备: <strong id="active-clients">0</strong></p>
        <p>总发送: <strong id="total-tx">0 B</strong> | 总接收: <strong id="total-rx">0 B</strong></p>
        <p>总上传速率: <strong id="total-tx-speed" class="speed">0 B/s</strong> | 总下载速率: <strong id="total-rx-speed" class="speed">0 B/s</strong></p>
    </div>
    <div class="card" id="clients-container">
        <h2>客户端列表 / 本机详情</h2>
        <table>
            <thead>
                <tr>
                    <th>ID / Name</th>
                    <th>IPv4</th>
                    <th>MAC</th>
                    <th>TCP连接数</th>
                    <th>TX (发)</th>
                    <th>RX (收)</th>
                    <th>↑ 上传速率</th>
                    <th>↓ 下载速率</th>
                    <th>操作</th>
                </tr>
            </thead>
            <tbody id="clients-body">
            </tbody>
        </table>
    </div>

    <script>
        // 格式化字节或速率
        function formatBytes(bytes, isSpeed = false) {
            if (bytes === 0 || isNaN(bytes)) return '0 ' + (isSpeed ? 'B/s' : 'B');
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            const unit = sizes[i] + (isSpeed ? '/s' : '');
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + unit;
        }

        // 用于缓存上一次请求的数据和时间
        let previousClients = {};
        let lastFetchTime = 0;

        async function fetchStats() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                
                // 计算两次请求精确的时间差（秒）
                const now = performance.now();
                let timeDelta = lastFetchTime ? (now - lastFetchTime) / 1000 : 2; 
                lastFetchTime = now;

                document.getElementById('mode').innerText = data.mode.toUpperCase();
                document.getElementById('active-clients').innerText = data.active_clients;
                
                let tbody = '';
                let totalTx = 0, totalRx = 0;
                let totalTxSpeed = 0, totalRxSpeed = 0;
                
                const currentClientsState = {};

                const processClient = (id, c) => {
                    totalTx += c.tx_bytes;
                    totalRx += c.rx_bytes;
                    
                    let txSpeed = 0;
                    let rxSpeed = 0;
                    
                    // 如果存在上一次的数据，计算速率： (当前字节 - 上次字节) / 时间差
                    if (previousClients[id]) {
                        txSpeed = Math.max(0, (c.tx_bytes - previousClients[id].tx_bytes) / timeDelta);
                        rxSpeed = Math.max(0, (c.rx_bytes - previousClients[id].rx_bytes) / timeDelta);
                    }
                    
                    // 保存当前状态供下一次计算使用
                    currentClientsState[id] = { tx_bytes: c.tx_bytes, rx_bytes: c.rx_bytes };
                    
                    totalTxSpeed += txSpeed;
                    totalRxSpeed += rxSpeed;

                    return '<tr>' +
                        '<td>' + (id.length > 8 ? id.substring(0,8) + '...' : id) + '</td>' +
                        '<td>' + c.ipv4 + '</td>' +
                        '<td>' + c.mac + '</td>' +
                        '<td>' + c.active_conns + '</td>' +
                        '<td>' + formatBytes(c.tx_bytes) + '</td>' +
                        '<td>' + formatBytes(c.rx_bytes) + '</td>' +
                        '<td class="speed">' + formatBytes(txSpeed, true) + '</td>' +
                        '<td class="speed">' + formatBytes(rxSpeed, true) + '</td>' +
                        '<td>' + (data.mode === 'server' ? '<button class="btn" onclick="kickClient(\''+id+'\')">踢出</button>' : '-') + '</td>' +
                    '</tr>';
                };

                if (data.mode === 'server') {
                    for (const [id, c] of Object.entries(data.clients)) {
                        tbody += processClient(id, c);
                    }
                } else if (data.mode === 'client' && data.clients.local) {
                    tbody += processClient('local', data.clients.local);
                }

                // 更新全局缓存
                previousClients = currentClientsState;

                document.getElementById('clients-body').innerHTML = tbody;
                document.getElementById('total-tx').innerText = formatBytes(totalTx);
                document.getElementById('total-rx').innerText = formatBytes(totalRx);
                document.getElementById('total-tx-speed').innerText = formatBytes(totalTxSpeed, true);
                document.getElementById('total-rx-speed').innerText = formatBytes(totalRxSpeed, true);

            } catch (err) {
                console.error("获取统计数据失败", err);
            }
        }

        async function kickClient(id) {
            if(!confirm("确定要强制断开该客户端吗？")) return;
            await fetch('/api/control', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ action: 'kick', client_id: id })
            });
            fetchStats(); // 踢出后立即刷新
        }

        setInterval(fetchStats, 2000); // 每2秒刷新一次
        fetchStats();
    </script>
</body>
</html>`

func startWebServer(addr string, srv *Server, cli *Client) {
	mux := http.NewServeMux()

	// 仪表盘页面
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(dashboardHTML))
	})

	// 状态统计 API
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		stats := WebStats{Clients: make(map[string]interface{})}

		if srv != nil {
			stats.Mode = "server"
			srv.mu.RLock()
			stats.ActiveClients = len(srv.activeClients)
			// 建立一个临时快照，迅速释放全局锁
			type tmpSession struct {
				v4, v6, mac        string
				conns              int
				txB, rxB, txP, rxP uint64
			}
			snapClients := make(map[string]tmpSession, len(srv.activeClients))
			for id, session := range srv.activeClients {
				session.sessionMu.Lock()
				conns := session.ActiveConns
				session.sessionMu.Unlock()

				snapClients[id] = tmpSession{
					v4: session.IPv4, v6: session.IPv6, mac: session.MAC, conns: conns,
					txB: atomic.LoadUint64(&session.TxBytes),
					rxB: atomic.LoadUint64(&session.RxBytes),
					txP: atomic.LoadUint64(&session.TxPackets),
					rxP: atomic.LoadUint64(&session.RxPackets),
				}
			}
			srv.mu.RUnlock()

			for id, snap := range snapClients {
				stats.Clients[id] = map[string]interface{}{
					"ipv4":         snap.v4,
					"ipv6":         snap.v6,
					"mac":          snap.mac,
					"active_conns": snap.conns,
					"tx_bytes":     snap.txB,
					"rx_bytes":     snap.rxB,
					"tx_packets":   snap.txP,
					"rx_packets":   snap.rxP,
				}
			}
		} else if cli != nil {
			stats.Mode = "client"
			stats.ActiveClients = 1
			stats.Clients["local"] = map[string]interface{}{
				"client_id":    cli.clientID,
				"ipv4":         cli.reqV4,
				"mac":          cli.macAddr,
				"active_conns": cli.connsCount,
				"tx_bytes":     atomic.LoadUint64(&cli.TxBytes),
				"rx_bytes":     atomic.LoadUint64(&cli.RxBytes),
				"tx_packets":   atomic.LoadUint64(&cli.TxPackets),
				"rx_packets":   atomic.LoadUint64(&cli.RxPackets),
			}
		}

		json.NewEncoder(w).Encode(stats)
	})

	// 控制 API
	mux.HandleFunc("/api/control", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", 405)
			return
		}
		var req struct {
			Action   string `json:"action"`
			ClientID string `json:"client_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}

		if srv != nil && req.Action == "kick" {
			srv.mu.Lock()
			if session, exists := srv.activeClients[req.ClientID]; exists {
				// 强制关闭客户端所有底层的绑定 (这里直接调用 Port 关闭来触发断线)
				session.Port.Close()
				log.Infof("[WebUI] Force kicked client: %s", req.ClientID)
			}
			srv.mu.Unlock()
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status": "ok"}`))
	})

	log.Infof("🚀 Web Dashboard started at http://%s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Web Server failed: %v", err)
	}
}
