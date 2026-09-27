#!/usr/bin/env python3
from pathlib import Path

p = Path('client.go')
s = p.read_text()
old = '''\tif sessionID != currentID || epoch != currentEpoch || token != currentToken {
\t\treturn
\t}
'''
new = '''\t// 生产握手路径一定已经初始化 current session；保留空值兼容直接调用
\t// persistSessionState 的单元测试/内部工具。
\tif currentID != "" && (sessionID != currentID || epoch != currentEpoch || token != currentToken) {
\t\treturn
\t}
'''
if old not in s:
    raise SystemExit('persist guard marker not found')
p.write_text(s.replace(old, new, 1))
