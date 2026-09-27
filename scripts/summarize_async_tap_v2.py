#!/usr/bin/env python3
import csv
import statistics
import sys
from collections import defaultdict
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])

samples = defaultdict(list)
with src.open(newline='') as f:
    for row in csv.DictReader(f, delimiter='\t'):
        key = (row['conns'], row['enc_algo'], row['pad_mode'], row['direction'], row['variant'])
        samples[key].append(float(row['mbps']))

def pct(vals, q):
    vals = sorted(vals)
    if not vals:
        return 0.0
    if len(vals) == 1:
        return vals[0]
    pos = (len(vals) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(vals) - 1)
    frac = pos - lo
    return vals[lo] * (1 - frac) + vals[hi] * frac

configs = sorted({k[:4] for k in samples}, key=lambda k: (int(k[0]), k[1], k[2], k[3]))
rows = []
for cfg in configs:
    main = samples.get((*cfg, 'main'), [])
    cand = samples.get((*cfg, 'candidate'), [])
    if not main or not cand:
        raise SystemExit(f'missing paired samples for {cfg}: main={len(main)} candidate={len(cand)}')
    m_med = statistics.median(main)
    c_med = statistics.median(cand)
    delta = ((c_med / m_med) - 1.0) * 100.0 if m_med else 0.0
    rows.append((*cfg, len(main), len(cand), m_med, c_med, delta,
                 pct(main, .25), pct(main, .75), pct(cand, .25), pct(cand, .75)))

with dst.open('w', newline='') as f:
    w = csv.writer(f, delimiter='\t')
    w.writerow(('conns','enc_algo','pad_mode','direction','main_n','candidate_n',
                'main_median_mbps','candidate_median_mbps','delta_pct',
                'main_p25','main_p75','candidate_p25','candidate_p75'))
    for r in rows:
        w.writerow((*r[:6], f'{r[6]:.1f}', f'{r[7]:.1f}', f'{r[8]:+.2f}',
                    f'{r[9]:.1f}', f'{r[10]:.1f}', f'{r[11]:.1f}', f'{r[12]:.1f}'))

print(dst.read_text())

single = [r[8] for r in rows if r[0] == '1']
if single:
    print(f'single-connection median-of-config deltas: median={statistics.median(single):+.2f}% mean={statistics.mean(single):+.2f}%')
