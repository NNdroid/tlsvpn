#!/usr/bin/env python3
from pathlib import Path

p = Path('client.go')
s = p.read_text()

needle = '''\t// 回带上一次握手收到的会话令牌（首次接入时为空）。与 PSK 快照一起读，
\t// 避免与握手响应处理协程的写入构成数据竞争。
\tc.sessionMu.Lock()
\tsessionToken := c.sessionToken
\tc.sessionMu.Unlock()
'''
repl = '''\t// 回带上一次握手收到的会话令牌（首次接入时为空）。客户端服务重启时
\t// 新旧进程可能短暂重叠：旧进程可能在新进程启动后完成 token rollover 并
\t// 把更新的 token 写回同一 state 文件。每次握手前重新吸收同一 SessionID
\t// 的较新落盘状态，避免新进程永远拿着启动瞬间读到的旧 token 重试。
\tc.refreshSessionStateFromDisk()
\tc.sessionMu.Lock()
\tsessionToken := c.sessionToken
\tc.sessionMu.Unlock()
'''
if needle not in s:
    raise SystemExit('handshake token snapshot marker not found')
s = s.replace(needle, repl, 1)

old = '''// persistSessionState 把服务端下发的会话身份落盘，供进程重启后第一次握手
// 复用既有会话。按 clientID（MAC+PSK 派生）绑定：配置变更后旧令牌自动失效。
func (c *Client) persistSessionState(sessionID, token string, epoch uint64) {
\tif c.stateFile == "" {
\t\treturn
\t}
\tc.stateMu.Lock()
\tdefer c.stateMu.Unlock()
\tst := c.state
\tif st == nil {
\t\tst = &clientState{}
\t}
\t// 多条物理连接会并发完成握手。迟到的旧响应不能覆盖已经持久化的
\t// 新 epoch，否则下次进程重启会携带不匹配的令牌和代际。
\tif epoch < st.SessionEpoch {
\t\treturn
\t}
\tst.ClientID = c.clientID
\tst.SessionID = sessionID
\tst.SessionToken = token
\tst.SessionEpoch = epoch
\tif err := saveClientState(c.stateFile, st); err != nil {
\t\tlog.Warnf("Client failed to persist session state: %v", err)
\t}
}
'''
new = '''// refreshSessionStateFromDisk 吸收另一个、仍在退出中的同客户端进程刚刚
// 写下的 token rollover。SessionEpoch 只在同一个 SessionID 内可比较；不同
// SessionID 可能来自服务端重启，不能用 epoch 大小判断新旧。
func (c *Client) refreshSessionStateFromDisk() {
\tif c.stateFile == "" {
\t\treturn
\t}
\tc.stateMu.Lock()
\tdefer c.stateMu.Unlock()
\tdisk, err := loadClientState(c.stateFile)
\tif err != nil {
\t\tlog.Warnf("Client failed to refresh persisted session state: %v", err)
\t\treturn
\t}
\tif disk == nil || disk.ClientID != c.clientID || disk.SessionID == "" || disk.SessionToken == "" {
\t\treturn
\t}

\tc.sessionMu.Lock()
\tdefer c.sessionMu.Unlock()
\t// 只自动吸收同一服务端 session 的进展。不同 SessionID 的磁盘状态可能是
\t// 当前进程建立新会话之前留下的旧状态，不能在这里反向覆盖内存。
\tif disk.SessionID != c.serverSessionID {
\t\treturn
\t}
\tif disk.SessionEpoch < c.sessionEpoch {
\t\treturn
\t}
\tif disk.SessionEpoch == c.sessionEpoch && disk.SessionToken == c.sessionToken {
\t\treturn
\t}
\tc.serverSessionID = disk.SessionID
\tc.sessionEpoch = disk.SessionEpoch
\tc.sessionToken = disk.SessionToken
\tc.state = disk
\tlog.Infof("Refreshed session token from state file for %s at epoch %d", disk.SessionID, disk.SessionEpoch)
}

// persistSessionState 把服务端下发的会话身份落盘，供进程重启后第一次握手
// 复用既有会话。SessionEpoch 是 session-local generation：服务端重启后会生成
// 新 SessionID，并可能从更小的 epoch 重新开始，因此绝不能拿旧 SessionID 的
// epoch 阻止新 SessionID 落盘。
func (c *Client) persistSessionState(sessionID, token string, epoch uint64) {
\tif c.stateFile == "" {
\t\treturn
\t}

\t// 多条物理连接可能并发返回；只允许仍与当前内存会话完全一致的响应落盘。
\t// 若期间另一条握手已经切到新 SessionID/epoch/token，这个迟到响应直接丢弃。
\tc.sessionMu.Lock()
\tcurrentID, currentToken, currentEpoch := c.serverSessionID, c.sessionToken, c.sessionEpoch
\tc.sessionMu.Unlock()
\tif sessionID != currentID || epoch != currentEpoch || token != currentToken {
\t\treturn
\t}

\tc.stateMu.Lock()
\tdefer c.stateMu.Unlock()

\t// stateMu 只能序列化当前进程。服务管理器重启时新旧进程可能短暂重叠，
\t// 所以再读一次磁盘：同一 SessionID 下不允许较低 epoch 覆盖较高 epoch；
\t// 同 epoch 出现不同 token 时保留已经落盘的一方，避免交叉进程回滚。
\tif disk, err := loadClientState(c.stateFile); err == nil && disk != nil && disk.ClientID == c.clientID && disk.SessionID == sessionID {
\t\tif disk.SessionEpoch > epoch || (disk.SessionEpoch == epoch && disk.SessionToken != "" && disk.SessionToken != token) {
\t\t\tc.state = disk
\t\t\treturn
\t\t}
\t}

\tst := c.state
\tif st == nil {
\t\tst = &clientState{}
\t}
\t// 只有同一 SessionID 的 epoch 才能比较。不同 SessionID 表示服务端会话已
\t// 重建（最常见是服务端重启），即使新 epoch 更小也必须覆盖旧状态。
\tif st.ClientID == c.clientID && st.SessionID == sessionID && epoch < st.SessionEpoch {
\t\treturn
\t}
\tst.ClientID = c.clientID
\tst.SessionID = sessionID
\tst.SessionToken = token
\tst.SessionEpoch = epoch
\tif err := saveClientState(c.stateFile, st); err != nil {
\t\tlog.Warnf("Client failed to persist session state: %v", err)
\t\treturn
\t}
\tc.state = st
}
'''
if old not in s:
    raise SystemExit('persistSessionState block not found')
s = s.replace(old, new, 1)
p.write_text(s)
