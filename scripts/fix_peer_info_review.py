from pathlib import Path
p=Path('client.go')
s=p.read_text()
old='''\tif resp.PeerInfo != nil {\n\t\tc.sessionMu.Lock()\n\t\tc.peerInfo = normalizePeerInfo(resp.PeerInfo)\n\t\tc.sessionMu.Unlock()\n\t}\n'''
new='''\tc.sessionMu.Lock()\n\tif resp.PeerInfo != nil {\n\t\tc.peerInfo = normalizePeerInfo(resp.PeerInfo)\n\t} else {\n\t\t// Rolling upgrade: an authenticated old server omits peer_info. Clear the\n\t\t// previous node's metadata instead of showing stale identity in WebUI.\n\t\tc.peerInfo = PeerInfo{}\n\t}\n\tc.sessionMu.Unlock()\n'''
if s.count(old)!=1:
    raise SystemExit(f'expected one peer-info response block, got {s.count(old)}')
p.write_text(s.replace(old,new,1))
