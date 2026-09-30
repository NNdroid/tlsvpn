#!/usr/bin/env python3
from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one target, found {count}: {old!r}")
    p.write_text(text.replace(old, new, 1))


# real_tap_perf.sh: make FEC explicit so single-path RX fast bypass can be
# measured end-to-end instead of only via the in-process microbenchmark.
replace_once(
    "scripts/real_tap_perf.sh",
    '''#   PERF_PAD_MODE       bucket | off (default: bucket)\n#   PERF_DIRECTION      upload | download | both (default: both)\n''',
    '''#   PERF_PAD_MODE       bucket | off (default: bucket)\n#   PERF_FEC            true | false (default: false)\n#   PERF_FEC_GROUP      XOR group K when PERF_FEC=true (default: 4)\n#   PERF_DIRECTION      upload | download | both (default: both)\n''',
)
replace_once(
    "scripts/real_tap_perf.sh",
    '''PERF_PAD_MODE="${PERF_PAD_MODE:-bucket}"\nPERF_DIRECTION="${PERF_DIRECTION:-both}"\n''',
    '''PERF_PAD_MODE="${PERF_PAD_MODE:-bucket}"\nPERF_FEC="${PERF_FEC:-false}"\nPERF_FEC_GROUP="${PERF_FEC_GROUP:-4}"\nPERF_DIRECTION="${PERF_DIRECTION:-both}"\n''',
)
replace_once(
    "scripts/real_tap_perf.sh",
    '''  case "$PERF_PAD_MODE" in bucket|off) ;; *) die "PERF_PAD_MODE must be bucket or off" ;; esac\n  case "$PERF_DIRECTION" in upload|download|both) ;; *) die "PERF_DIRECTION must be upload, download or both" ;; esac\n''',
    '''  case "$PERF_PAD_MODE" in bucket|off) ;; *) die "PERF_PAD_MODE must be bucket or off" ;; esac\n  case "$PERF_FEC" in true|false) ;; *) die "PERF_FEC must be true or false" ;; esac\n  [[ "$PERF_FEC_GROUP" =~ ^[0-9]+$ ]] || die "PERF_FEC_GROUP must be an integer"\n  (( PERF_FEC_GROUP >= 2 && PERF_FEC_GROUP <= 64 )) || die "PERF_FEC_GROUP must be in [2,64]"\n  case "$PERF_DIRECTION" in upload|download|both) ;; *) die "PERF_DIRECTION must be upload, download or both" ;; esac\n''',
)
replace_once(
    "scripts/real_tap_perf.sh",
    '''    "conns": $PERF_CONNS,\n    "cert_sha256": "$fp",\n''',
    '''    "conns": $PERF_CONNS,\n    "fec": $PERF_FEC,\n    "fec_group": $PERF_FEC_GROUP,\n    "cert_sha256": "$fp",\n''',
)

# perf.yml: profiles now exercise the actual static-single RX bypass, while the
# existing broad FEC-off matrix remains comparable to historical runs. Add a
# focused paired FEC-on run so main vs candidate quantifies this PR directly.
replace_once(
    ".github/workflows/perf.yml",
    '''          PERF_PAD_MODE: bucket\n          PERF_DIRECTION: upload\n''',
    '''          PERF_PAD_MODE: bucket\n          PERF_FEC: 'true'\n          PERF_FEC_GROUP: '4'\n          PERF_DIRECTION: upload\n''',
)
replace_once(
    ".github/workflows/perf.yml",
    '''          PERF_PAD_MODE: bucket\n          PERF_DIRECTION: download\n''',
    '''          PERF_PAD_MODE: bucket\n          PERF_FEC: 'true'\n          PERF_FEC_GROUP: '4'\n          PERF_DIRECTION: download\n''',
)

marker = '''          sudo chown -R "$USER:$USER" perf-artifacts\n\n      - name: Compare candidate against main on the same runner\n'''
insert = '''          sudo chown -R "$USER:$USER" perf-artifacts\n\n      - name: Run paired single-path FEC throughput\n        env:\n          MAIN_BIN: ${{ github.workspace }}/perf-bin/tlsvpn-main\n          CANDIDATE_BIN: ${{ github.workspace }}/perf-bin/tlsvpn-candidate\n          MAIN_RESULTS: ${{ github.workspace }}/perf-artifacts/fec-main.tsv\n          CANDIDATE_RESULTS: ${{ github.workspace }}/perf-artifacts/fec-candidate.tsv\n        run: |\n          set -euo pipefail\n          printf 'conns\\tenc_algo\\tpad_mode\\tdirection\\tmbps\\n' > "$MAIN_RESULTS"\n          printf 'conns\\tenc_algo\\tpad_mode\\tdirection\\tmbps\\n' > "$CANDIDATE_RESULTS"\n\n          echo "=== main: conns=1 fec=K4 enc=gcm256 pad=bucket ==="\n          sudo -E env \\\n            BIN="$MAIN_BIN" PERF_CONNS=1 PERF_ENC_ALGO=gcm256 PERF_PAD_MODE=bucket \\\n            PERF_FEC=true PERF_FEC_GROUP=4 PERF_DIRECTION=both PERF_SECONDS=5 \\\n            PERF_MIN_MBPS=500 PERF_RESULT_FILE="$MAIN_RESULTS" \\\n            bash scripts/real_tap_perf.sh\n\n          echo "=== candidate: conns=1 fec=K4 enc=gcm256 pad=bucket ==="\n          sudo -E env \\\n            BIN="$CANDIDATE_BIN" PERF_CONNS=1 PERF_ENC_ALGO=gcm256 PERF_PAD_MODE=bucket \\\n            PERF_FEC=true PERF_FEC_GROUP=4 PERF_DIRECTION=both PERF_SECONDS=5 \\\n            PERF_MIN_MBPS=500 PERF_RESULT_FILE="$CANDIDATE_RESULTS" \\\n            bash scripts/real_tap_perf.sh\n          sudo chown -R "$USER:$USER" perf-artifacts\n\n      - name: Compare candidate against main on the same runner\n'''
replace_once(".github/workflows/perf.yml", marker, insert)

compare_marker = '''          print((root / 'comparison.tsv').read_text())\n          PY\n\n      - name: Upload real-TAP performance artifacts\n'''
compare_insert = '''          print((root / 'comparison.tsv').read_text())\n          PY\n\n      - name: Compare single-path FEC candidate against main\n        run: |\n          python3 - <<'PY'\n          import csv\n          from pathlib import Path\n\n          root = Path('perf-artifacts')\n          key_fields = ('conns', 'enc_algo', 'pad_mode', 'direction')\n\n          def load(path):\n              out = {}\n              with path.open(newline='') as f:\n                  for row in csv.DictReader(f, delimiter='\\t'):\n                      out[tuple(row[k] for k in key_fields)] = float(row['mbps'])\n              return out\n\n          base = load(root / 'fec-main.tsv')\n          cand = load(root / 'fec-candidate.tsv')\n          if set(base) != set(cand):\n              raise SystemExit(f'FEC matrix mismatch: {sorted(set(base) ^ set(cand))}')\n\n          rows = []\n          for key in sorted(base):\n              b = base[key]\n              c = cand[key]\n              delta = ((c / b) - 1.0) * 100.0 if b else 0.0\n              rows.append((*key, b, c, delta))\n\n          with (root / 'fec-comparison.tsv').open('w', newline='') as f:\n              w = csv.writer(f, delimiter='\\t')\n              w.writerow((*key_fields, 'main_mbps', 'candidate_mbps', 'delta_pct'))\n              for row in rows:\n                  w.writerow((*row[:4], f'{row[4]:.1f}', f'{row[5]:.1f}', f'{row[6]:+.2f}'))\n\n          print((root / 'fec-comparison.tsv').read_text())\n          PY\n\n      - name: Upload real-TAP performance artifacts\n'''
replace_once(".github/workflows/perf.yml", compare_marker, compare_insert)

print("Real-TAP FEC performance coverage patched")
