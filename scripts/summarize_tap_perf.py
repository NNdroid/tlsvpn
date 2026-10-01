"""Summarize paired same-runner samples; CI success is not a merge decision."""
import json
import random
import statistics
import sys
from pathlib import Path

root = Path(sys.argv[1])
print('| variant | direction | median Mbps | paired change | bootstrap 95% interval | retransmits |')
print('|---|---|---:|---:|---:|---:|')
for direction in ('upload', 'download'):
    values = {}
    retransmits = {}
    for variant in ('baseline', 'single', 'flag', 'q2', 'q4'):
        samples, retries = [], []
        for round in range(1, 6):
            data = json.loads((root / variant / str(round) / f'iperf-{direction}.json').read_text())
            if data.get('error'):
                raise SystemExit(data['error'])
            samples.append(data['end']['sum_received']['bits_per_second'] / 1e6)
            retries.append(data['end']['sum_sent'].get('retransmits', 0))
        values[variant] = samples
        retransmits[variant] = sum(retries)
    for variant, samples in values.items():
        ratios = [(v / b - 1) * 100 for v, b in zip(samples, values['baseline'])]
        rng = random.Random(42)
        boot = sorted(statistics.median(rng.choices(ratios, k=5)) for _ in range(10000))
        print(f'| {variant} | {direction} | {statistics.median(samples):.1f} | '
              f'{statistics.median(ratios):+.1f}% | [{boot[250]:+.1f}%, {boot[9749]:+.1f}%] | {retransmits[variant]} |')
print('\nIntervals use five paired rounds and are exploratory. A merge requires a '
      'repeatable >=5% gain on multi-flow workloads, no material single-flow regression, '
      'correctness/race/E2E success, and review of retransmits and profiles. '
      'Hosted-runner results do not establish OpenWrt device performance or kernel support.')
