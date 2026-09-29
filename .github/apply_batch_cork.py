from pathlib import Path

BRANCH_WORKFLOW = Path('.github/workflows/apply-batch-cork.yml')
SELF = Path('.github/apply_batch_cork.py')


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    s = p.read_text()
    count = s.count(old)
    if count != 1:
        raise SystemExit(f'{path}: expected exactly one match, got {count}: {old[:120]!r}')
    p.write_text(s.replace(old, new, 1))


# Client: restore the original raw transport under uTLS. Create one batch-level
# CORK controller after authentication and call it once per data-plane batch.
replace_once(
    'client.go',
    '''\ttcpConn := asTCPConn(rawConn)\n\tpadRecordLimit := paddingRecordLimit(tcpConn)\n\tcarryMSS := ciphertextCarryMSS(rawConn)\n\tcipherTail := newCiphertextTailConn(rawConn)\n''',
    '''\ttcpConn := asTCPConn(rawConn)\n\tpadRecordLimit := paddingRecordLimit(tcpConn)\n''',
)
replace_once(
    'client.go',
    '''\ttlsConn, err := c.negotiateUTLS(runCtx, cipherTail, lv)\n''',
    '''\ttlsConn, err := c.negotiateUTLS(runCtx, rawConn, lv)\n''',
)
replace_once(
    'client.go',
    '''\t// Both TLS and TLSVPN authentication are complete. Enable carry only\n\t// before the data backend can receive real tunnel frames.\n\tcipherTail.Enable(carryMSS)\n\n\terrChan := make(chan error, 2)\n''',
    '''\terrChan := make(chan error, 2)\n''',
)
replace_once(
    'client.go',
    '''\tc.txPort.RegisterBackend(connTxChan, rttCache)\n\tdefer c.txPort.UnregisterBackend(connTxChan)\n\n\t// netifd represents the aggregate VPN session, not one TCP backend.\n''',
    '''\tc.txPort.RegisterBackend(connTxChan, rttCache)\n\tdefer c.txPort.UnregisterBackend(connTxChan)\n\n\tbatchCork := newTLSBatchCork(rawConn)\n\tdefer batchCork.Close()\n\n\t// netifd represents the aggregate VPN session, not one TCP backend.\n''',
)
replace_once(
    'client.go',
    '''\t\t\t\tpadTotal := uint64(tailPad)\n\t\t\t\trefreshWriteDeadline()\n\t\t\t\tif _, err := tlsConn.Write(sendBuffer); err != nil {\n''',
    '''\t\t\t\tpadTotal := uint64(tailPad)\n\t\t\t\trefreshWriteDeadline()\n\t\t\t\tbatchCork.BeforeWrite(len(sendBuffer))\n\t\t\t\tif _, err := tlsConn.Write(sendBuffer); err != nil {\n''',
)

# Server: restore crypto/tls directly on PrefixConn and the original handler
# signature. The accepted *net.TCPConn is already available in handleConnection,
# so the batch controller needs no wrapper-unwrapping changes.
replace_once(
    'server.go',
    '''\t\t\tcipherTail := newCiphertextTailConn(prefixConn)\n\t\t\ttlsConn := tls.Server(cipherTail, connTLSConfig)\n''',
    '''\t\t\ttlsConn := tls.Server(prefixConn, connTLSConfig)\n''',
)
replace_once(
    'server.go',
    '''\t\t\tsrv.handleConnection(ctx, prefixConn2, c, tlsInfo, cipherTail)\n''',
    '''\t\t\tsrv.handleConnection(ctx, prefixConn2, c, tlsInfo)\n''',
)
replace_once(
    'server.go',
    '''func (s *Server) handleConnection(parentCtx context.Context, conn net.Conn, tcpConn *net.TCPConn, tlsInfo *TLSHandshakeInfo, cipherTail *ciphertextTailConn) {\n''',
    '''func (s *Server) handleConnection(parentCtx context.Context, conn net.Conn, tcpConn *net.TCPConn, tlsInfo *TLSHandshakeInfo) {\n''',
)
replace_once(
    'server.go',
    '''\t// HandshakeResp has already been written. Enable carry now, before this\n\t// physical backend can receive data-plane frames.\n\tif cipherTail != nil {\n\t\tcipherTail.Enable(ciphertextCarryMSS(tcpConn))\n\t}\n\n\trttCache := new(uint32)\n''',
    '''\trttCache := new(uint32)\n''',
)
replace_once(
    'server.go',
    '''\tport.RegisterBackend(connTxChan, rttCache)\n\tdefer port.UnregisterBackend(connTxChan)\n\n\tgo func() {\n''',
    '''\tport.RegisterBackend(connTxChan, rttCache)\n\tdefer port.UnregisterBackend(connTxChan)\n\n\tbatchCork := newTLSBatchCork(tcpConn)\n\tdefer batchCork.Close()\n\n\tgo func() {\n''',
)
replace_once(
    'server.go',
    '''\t\t\t\tpadTotal := uint64(tailPad)\n\t\t\t\trefreshWriteDeadline()\n\t\t\t\t_, werr := conn.Write(sendBuffer)\n''',
    '''\t\t\t\tpadTotal := uint64(tailPad)\n\t\t\t\trefreshWriteDeadline()\n\t\t\t\tbatchCork.BeforeWrite(len(sendBuffer))\n\t\t\t\t_, werr := conn.Write(sendBuffer)\n''',
)

# Restore direct internal handler tests to the pre-wrapper signature.
replace_once(
    'fec_policy_test.go',
    '''\t\tgo srv.handleConnection(ctx, srvConn, srvConn, nil, nil)\n''',
    '''\t\tgo srv.handleConnection(ctx, srvConn, srvConn, nil)\n''',
)

# Wrapper experiment is superseded by batch-level CORK.
for dead in ('ciphertext_tail_conn.go', 'ciphertext_tail_conn_test.go', 'prefix_conn_unwrap.go'):
    p = Path(dead)
    if p.exists():
        p.unlink()

# Staging machinery must not remain in the PR.
if BRANCH_WORKFLOW.exists():
    BRANCH_WORKFLOW.unlink()
if SELF.exists():
    SELF.unlink()
