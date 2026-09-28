#!/usr/bin/env python3
from pathlib import Path
import re


def replace_once(text: str, old: str, new: str, label: str) -> str:
    n = text.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected exactly one anchor, found {n}")
    return text.replace(old, new, 1)


def regex_once(text: str, pattern: str, repl: str, label: str) -> str:
    out, n = re.subn(pattern, repl, text, count=1, flags=re.S)
    if n != 1:
        raise SystemExit(f"{label}: expected one regex match, found {n}")
    return out

client_path = Path("client.go")
client = client_path.read_text()

# Coalescing now belongs at the persistent connection stream layer. Sleeping in
# AsyncPort as well would stack two independent latency budgets.
old_sleep = '''\t\t\t// Sparse bursts get an adaptive coalescing opportunity before we snapshot
\t\t\t// and drain p.ch. Tiny one-frame bursts may wait up to 500us so later TAP
\t\t\t// frames can fill the batch naturally; medium batches wait less, while
\t\t\t// sustained traffic (queue already non-empty) never sleeps here.
\t\t\tif len(p.ch) == 0 && batchBytes < MaxBatchBytes {
\t\t\t\tif delay := streamCoalesceDelay(batchBytes); delay > 0 {
\t\t\t\t\ttime.Sleep(delay)
\t\t\t\t}
\t\t\t}

'''
client = replace_once(client, old_sleep, '', 'remove AsyncPort coalescing')

client = replace_once(
    client,
    '\tgo func() {\n\t\tsendBuffer := make([]byte, 0, 64*1024+4096)\n',
    '\tgo func() {\n\t\tsendBuffer := make([]byte, 0, 64*1024+4096)\n\t\tstreamPacker := newTunnelStreamPacker(padRecordLimit)\n',
    'client stream packer init',
)

client_case = '''\t\t\tcase frames := <-connTxChan:
\t\t\t\tstreamPacker.appendOwnedFrames(frames, icTx)
\t\t\t\tfor {
\t\t\t\t\t// Drain everything already queued before deciding whether this is a
\t\t\t\t\t// sparse tail. Multiple AsyncPort batches become one continuous
\t\t\t\t\t// TLSVPN byte stream; frame boundaries no longer constrain writes.
\t\t\t\tdrainReady:
\t\t\t\t\tfor {
\t\t\t\t\t\tselect {
\t\t\t\t\t\tcase more := <-connTxChan:
\t\t\t\t\t\t\tstreamPacker.appendOwnedFrames(more, icTx)
\t\t\t\t\t\tdefault:
\t\t\t\t\t\t\tbreak drainReady
\t\t\t\t\t\t}
\t\t\t\t\t}

\t\t\t\t\t// Under sustained load emit the largest <=16KiB plaintext chunk
\t\t\t\t\t// whose conservative ciphertext size is N*TCP_MAXSEG. This slice
\t\t\t\t\t// may end in the middle of a VPN frame; FrameScanner reassembles it.
\t\t\t\t\tchunkSize := streamPacker.fullChunkSize()
\t\t\t\t\tfor streamPacker.available() >= chunkSize {
\t\t\t\t\t\tchunk := streamPacker.peek(chunkSize)
\t\t\t\t\t\trefreshWriteDeadline()
\t\t\t\t\t\tif err := writeFull(tlsConn, chunk); err != nil {
\t\t\t\t\t\t\terrChan <- err
\t\t\t\t\t\t\treturn
\t\t\t\t\t\t}
\t\t\t\t\t\tcompleted := streamPacker.consume(chunkSize)
\t\t\t\t\t\trecordPadBytes(uint64(chunkSize), 0)
\t\t\t\t\t\tatomic.AddUint64(&c.TxBytes, uint64(chunkSize))
\t\t\t\t\t\tatomic.AddUint64(&c.TxPackets, uint64(completed))
\t\t\t\t\t\tatomic.AddUint64(&ci.txBytes, uint64(chunkSize))
\t\t\t\t\t\tdailyTraffic.Add(uint64(chunkSize), 0)
\t\t\t\t\t}
\t\t\t\t\tif streamPacker.available() == 0 {
\t\t\t\t\t\tbreak
\t\t\t\t\t}

\t\t\t\t\t// Only an actually sparse remainder waits. The deadline is bounded
\t\t\t\t\t// and is not reset repeatedly, so a single packet cannot be held
\t\t\t\t\t// indefinitely waiting for a perfect MSS multiple.
\t\t\t\t\tdelay := streamCoalesceDelay(streamPacker.available())
\t\t\t\t\tif delay > 0 && len(connTxChan) == 0 {
\t\t\t\t\t\ttimer := time.NewTimer(delay)
\t\t\t\t\t\tgotMore := false
\t\t\t\t\t\tselect {
\t\t\t\t\t\tcase more := <-connTxChan:
\t\t\t\t\t\t\tif !timer.Stop() {
\t\t\t\t\t\t\t\tselect { case <-timer.C: default: }
\t\t\t\t\t\t\t}
\t\t\t\t\t\t\tstreamPacker.appendOwnedFrames(more, icTx)
\t\t\t\t\t\t\tgotMore = true
\t\t\t\t\t\tcase <-timer.C:
\t\t\t\t\t\tcase <-c.ctx.Done():
\t\t\t\t\t\t\tif !timer.Stop() {
\t\t\t\t\t\t\t\tselect { case <-timer.C: default: }
\t\t\t\t\t\t\t}
\t\t\t\t\t\t\treturn
\t\t\t\t\t\t}
\t\t\t\t\t\tif gotMore {
\t\t\t\t\t\t\tcontinue
\t\t\t\t\t\t}
\t\t\t\t\t}

\t\t\t\t\t// Deadline reached: preserve latency. A tiny explicit cover frame may
\t\t\t\t\t// close the MSS gap only when it fits the 10%/512B budget; otherwise
\t\t\t\t\t// flush the real bytes unchanged. This is where sparse traffic exits.
\t\t\t\t\tcover := streamPacker.appendIdleCover()
\t\t\t\t\tn := streamPacker.available()
\t\t\t\t\tif n > 0 {
\t\t\t\t\t\tchunk := streamPacker.peek(n)
\t\t\t\t\t\trefreshWriteDeadline()
\t\t\t\t\t\tif err := writeFull(tlsConn, chunk); err != nil {
\t\t\t\t\t\t\terrChan <- err
\t\t\t\t\t\t\treturn
\t\t\t\t\t\t}
\t\t\t\t\t\tcompleted := streamPacker.consume(n)
\t\t\t\t\t\trecordPadBytes(uint64(n), uint64(cover))
\t\t\t\t\t\tatomic.AddUint64(&c.TxBytes, uint64(n))
\t\t\t\t\t\tatomic.AddUint64(&c.TxPackets, uint64(completed))
\t\t\t\t\t\tatomic.AddUint64(&ci.txBytes, uint64(n))
\t\t\t\t\t\tdailyTraffic.Add(uint64(n), 0)
\t\t\t\t\t}
\t\t\t\t\tbreak
\t\t\t\t}
'''

client_pattern = r'''\t\t\tcase frames := <-connTxChan:\n.*?\t\t\t\tdailyTraffic\.Add\(uint64\(len\(sendBuffer\)\), 0\) // 上行 = client→server\n'''
client = regex_once(client, client_pattern, client_case, 'client writer case')
client_path.write_text(client)

server_path = Path("server.go")
server = server_path.read_text()
server = replace_once(
    server,
    '\tgo func() {\n\t\tsendBuffer := make([]byte, 0, 64*1024+4096)\n',
    '\tgo func() {\n\t\tsendBuffer := make([]byte, 0, 64*1024+4096)\n\t\tstreamPacker := newTunnelStreamPacker(padRecordLimit)\n',
    'server stream packer init',
)

server_case = '''\t\t\tcase frames := <-connTxChan:
\t\t\t\tstreamPacker.appendOwnedFrames(frames, icTx)
\t\t\t\tfor {
\t\t\t\tdrainReady:
\t\t\t\t\tfor {
\t\t\t\t\t\tselect {
\t\t\t\t\t\tcase more := <-connTxChan:
\t\t\t\t\t\t\tstreamPacker.appendOwnedFrames(more, icTx)
\t\t\t\t\t\tdefault:
\t\t\t\t\t\t\tbreak drainReady
\t\t\t\t\t\t}
\t\t\t\t\t}
\t\t\t\t\tchunkSize := streamPacker.fullChunkSize()
\t\t\t\t\tfor streamPacker.available() >= chunkSize {
\t\t\t\t\t\tchunk := streamPacker.peek(chunkSize)
\t\t\t\t\t\trefreshWriteDeadline()
\t\t\t\t\t\tif err := writeFull(conn, chunk); err != nil {
\t\t\t\t\t\t\tlog.Debugf("[%s] downstream write failed, closing the connection: %v", clientID, err)
\t\t\t\t\t\t\tconn.Close()
\t\t\t\t\t\t\treturn
\t\t\t\t\t\t}
\t\t\t\t\t\tcompleted := streamPacker.consume(chunkSize)
\t\t\t\t\t\trecordPadBytes(uint64(chunkSize), 0)
\t\t\t\t\t\tatomic.AddUint64(&session.TxBytes, uint64(chunkSize))
\t\t\t\t\t\tatomic.AddUint64(&session.TxPackets, uint64(completed))
\t\t\t\t\t\tatomic.AddUint64(&ci.txBytes, uint64(chunkSize))
\t\t\t\t\t\tatomic.AddUint64(&ci.txPackets, uint64(completed))
\t\t\t\t\t\tdailyTraffic.Add(0, uint64(chunkSize))
\t\t\t\t\t}
\t\t\t\t\tif streamPacker.available() == 0 {
\t\t\t\t\t\tbreak
\t\t\t\t\t}
\t\t\t\t\tdelay := streamCoalesceDelay(streamPacker.available())
\t\t\t\t\tif delay > 0 && len(connTxChan) == 0 {
\t\t\t\t\t\ttimer := time.NewTimer(delay)
\t\t\t\t\t\tgotMore := false
\t\t\t\t\t\tselect {
\t\t\t\t\t\tcase more := <-connTxChan:
\t\t\t\t\t\t\tif !timer.Stop() {
\t\t\t\t\t\t\t\tselect { case <-timer.C: default: }
\t\t\t\t\t\t\t}
\t\t\t\t\t\t\tstreamPacker.appendOwnedFrames(more, icTx)
\t\t\t\t\t\t\tgotMore = true
\t\t\t\t\t\tcase <-timer.C:
\t\t\t\t\t\tcase <-ctx.Done():
\t\t\t\t\t\t\tif !timer.Stop() {
\t\t\t\t\t\t\t\tselect { case <-timer.C: default: }
\t\t\t\t\t\t\t}
\t\t\t\t\t\t\treturn
\t\t\t\t\t\t}
\t\t\t\t\t\tif gotMore {
\t\t\t\t\t\t\tcontinue
\t\t\t\t\t\t}
\t\t\t\t\t}
\t\t\t\t\tcover := streamPacker.appendIdleCover()
\t\t\t\t\tn := streamPacker.available()
\t\t\t\t\tif n > 0 {
\t\t\t\t\t\tchunk := streamPacker.peek(n)
\t\t\t\t\t\trefreshWriteDeadline()
\t\t\t\t\t\tif err := writeFull(conn, chunk); err != nil {
\t\t\t\t\t\t\tlog.Debugf("[%s] downstream write failed, closing the connection: %v", clientID, err)
\t\t\t\t\t\t\tconn.Close()
\t\t\t\t\t\t\treturn
\t\t\t\t\t\t}
\t\t\t\t\t\tcompleted := streamPacker.consume(n)
\t\t\t\t\t\trecordPadBytes(uint64(n), uint64(cover))
\t\t\t\t\t\tatomic.AddUint64(&session.TxBytes, uint64(n))
\t\t\t\t\t\tatomic.AddUint64(&session.TxPackets, uint64(completed))
\t\t\t\t\t\tatomic.AddUint64(&ci.txBytes, uint64(n))
\t\t\t\t\t\tatomic.AddUint64(&ci.txPackets, uint64(completed))
\t\t\t\t\t\tdailyTraffic.Add(0, uint64(n))
\t\t\t\t\t}
\t\t\t\t\tbreak
\t\t\t\t}
'''
server_pattern = r'''\t\t\tcase frames := <-connTxChan:\n.*?\t\t\t\tdailyTraffic\.Add\(0, uint64\(len\(sendBuffer\)\)\) // 下行 = server→client\n'''
server = regex_once(server, server_pattern, server_case, 'server writer case')
server_path.write_text(server)
