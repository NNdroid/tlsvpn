#!/usr/bin/env python3
from pathlib import Path


def replace_once(path, old, new):
    p = Path(path)
    s = p.read_text()
    n = s.count(old)
    if n != 1:
        raise SystemExit(f"{path}: expected exactly one match, got {n}: {old[:80]!r}")
    p.write_text(s.replace(old, new, 1))

# Backend keeps data-scheduler counters separate from FEC parity telemetry.
replace_once("client.go",
'''\tassignedBytes   atomic.Uint64 // actual data bytes accepted by this backend (after fallback)\n\tassignedBatches atomic.Uint64 // actual data batches accepted by this backend\n\tvirtualFinishNS atomic.Int64  // scheduler-only service debt, published atomically for race safety\n''',
'''\tassignedBytes      atomic.Uint64 // actual data bytes accepted by this backend (after fallback)\n\tassignedBatches    atomic.Uint64 // actual data batches accepted by this backend\n\tfecAssignedBytes   atomic.Uint64 // FEC parity payload bytes accepted by this backend\n\tfecAssignedBatches atomic.Uint64 // FEC parity batches accepted by this backend\n\tvirtualFinishNS    atomic.Int64  // scheduler-only service debt, published atomically for race safety\n''')

replace_once("client.go",
'''\tselect {\n\tcase b.ch <- out:\n\t\treturn 0\n\tdefault:\n\t\tb.completeQueuedBytes(n)\n\t\tfreeFrames(out)\n\t\tputVPNFrameBatch(out)\n\t\treturn 1\n\t}\n}\n\n// sendFrameTo 保留给需要独立副本的兼容/测试路径。\n''',
'''\tselect {\n\tcase b.ch <- out:\n\t\tb.fecAssignedBytes.Add(n)\n\t\tb.fecAssignedBatches.Add(1)\n\t\treturn 0\n\tdefault:\n\t\tb.completeQueuedBytes(n)\n\t\tfreeFrames(out)\n\t\tputVPNFrameBatch(out)\n\t\treturn 1\n\t}\n}\n\n// sendFrameTo 保留给需要独立副本的兼容/测试路径。\n''')

replace_once("adaptive_multipath.go",
'''\tAssignedBytes   uint64  `json:"assigned_bytes"`\n\tAssignedBatches uint64  `json:"assigned_batches"`\n''',
'''\tAssignedBytes      uint64  `json:"assigned_bytes"`\n\tAssignedBatches    uint64  `json:"assigned_batches"`\n\tFECAssignedBytes   uint64  `json:"fec_assigned_bytes"`\n\tFECAssignedBatches uint64  `json:"fec_assigned_batches"`\n''')

replace_once("adaptive_multipath.go",
'''\t\tAssignedBytes:   b.assignedBytes.Load(),\n\t\tAssignedBatches: b.assignedBatches.Load(),\n''',
'''\t\tAssignedBytes:      b.assignedBytes.Load(),\n\t\tAssignedBatches:    b.assignedBatches.Load(),\n\t\tFECAssignedBytes:   b.fecAssignedBytes.Load(),\n\t\tFECAssignedBatches: b.fecAssignedBatches.Load(),\n''')

p = Path("webui/metrics.js")
s = p.read_text()
start = s.index("  // assigned_bytes/assigned_batches are lifetime monotonic counters.")
end = s.rindex("})();")
new_block = r'''  // Data scheduler counters and FEC parity counters are lifetime monotonic.
  // Convert both into deltas over the actual snapshot interval. assigned_* keeps
  // its original data-only meaning for scheduler tests; the WebUI displays the
  // actual transport assignment (DATA + FEC), so standby parity paths no longer
  // look idle while they are carrying real bytes.
  const schedPrev = {};
  const schedView = {};
  let schedLastAt = 0;

  function schedulerKey(mode, c, i) {
    if (c.conn_id) return c.conn_id;
    return mode === 'server'
      ? String(c.client_id || '') + '|' + String(c.remote || '')
      : String(i) + '|' + String(c.target || '') + '|' + String(c.remote || '');
  }

  function annotateSchedulers(data, fresh) {
    const mode = data && data.mode;
    const list = mode === 'server' ? (data.server_conns || []) : (data.conns || []);
    const now = performance.now();
    const dt = fresh && schedLastAt ? Math.max(0.001, (now - schedLastAt) / 1000) : 0;
    const samples = [];
    let totalDelta = 0;

    list.forEach(function (c, i) {
      const s = c.scheduler || (c.scheduler = {});
      const key = schedulerKey(mode, c, i);
      if (fresh) {
        const assigned = num(s.assigned_bytes);
        const batches = num(s.assigned_batches);
        const fecAssigned = num(s.fec_assigned_bytes);
        const fecBatches = num(s.fec_assigned_batches);
        const p = schedPrev[key];
        const valid = !!p && dt > 0 &&
          assigned >= p.assigned && batches >= p.batches &&
          fecAssigned >= p.fecAssigned && fecBatches >= p.fecBatches;
        const dDataBytes = valid ? assigned - p.assigned : 0;
        const dDataBatches = valid ? batches - p.batches : 0;
        const dFecBytes = valid ? fecAssigned - p.fecAssigned : 0;
        const dFecBatches = valid ? fecBatches - p.fecBatches : 0;
        const dBytes = dDataBytes + dFecBytes;
        const dBatches = dDataBatches + dFecBatches;
        schedPrev[key] = {assigned: assigned, batches: batches, fecAssigned: fecAssigned, fecBatches: fecBatches};
        const view = {
          sampled: valid,
          assignBps: valid ? dBytes / dt : 0,
          batchPs: valid ? dBatches / dt : 0,
          dataBps: valid ? dDataBytes / dt : 0,
          dataBatchPs: valid ? dDataBatches / dt : 0,
          fecBps: valid ? dFecBytes / dt : 0,
          fecBatchPs: valid ? dFecBatches / dt : 0,
          deltaBytes: dBytes,
          share: 0
        };
        schedView[key] = view;
        samples.push({s: s, view: view});
        totalDelta += dBytes;
      } else {
        samples.push({s: s, view: schedView[key] || {
          sampled: false, assignBps: 0, batchPs: 0, dataBps: 0, dataBatchPs: 0,
          fecBps: 0, fecBatchPs: 0, deltaBytes: 0, share: 0
        }});
      }
    });

    if (fresh) {
      samples.forEach(function (x) { x.view.share = totalDelta > 0 ? x.view.deltaBytes / totalDelta * 100 : 0; });
      schedLastAt = now;
    }

    let totalAssignBps = 0;
    samples.forEach(function (x) {
      const s = x.s, v = x.view;
      s._sampled = v.sampled;
      s._assign_bps = v.assignBps;
      s._batch_ps = v.batchPs;
      s._data_assign_bps = v.dataBps;
      s._data_batch_ps = v.dataBatchPs;
      s._fec_assign_bps = v.fecBps;
      s._fec_batch_ps = v.fecBatchPs;
      s._share_pct = v.share;
      // backend eta_us is the last scheduling-decision estimate and can remain
      // stale after a drain. Show queue-drain ETA from current queue + rate EWMA.
      // Before the first rate sample, mirror the scheduler's 200 Mbps fallback.
      const rateBytes = num(s.rate_mbps) > 0 ? num(s.rate_mbps) * 1000000 / 8 : 25000000;
      s._queue_eta_us = rateBytes > 0 ? num(s.queued_bytes) * 1000000 / rateBytes : 0;
      totalAssignBps += v.assignBps;
    });
    return totalAssignBps;
  }

  const legacyRenderConnsTable = renderConnsTable;
  renderConnsTable = function (data, fresh) {
    const totalAssignBps = annotateSchedulers(data || {}, !!fresh);
    const out = legacyRenderConnsTable(data, fresh);
    const ss = document.getElementById('scheduler-summary');
    if (ss && totalAssignBps > 0) ss.textContent += ' · ' + t('sched.alloc_total') + ' ' + fmtBytes(totalAssignBps, true);
    return out;
  };

  schedulerCell = function (s) {
    if (!s) return '<span class="dim">-</span>';
    const cls = s.active ? 'b-on' : 'b-off';
    const state = s.active ? t('sched.active') : t('sched.standby');
    const capacity = num(s.rate_mbps);
    const sampled = !!s._sampled;
    const alloc = sampled ? fmtBytes(num(s._assign_bps), true) : '-';
    const share = sampled ? num(s._share_pct).toFixed(1) + '%' : '-';
    const batchRate = sampled ? num(s._batch_ps).toFixed(num(s._batch_ps) < 10 ? 1 : 0) + '/s' : '-';
    const eta = fmtSchedulerEta(num(s._queue_eta_us));
    const meta = t('sched.queue') + ' ' + fmtBytes(num(s.queued_bytes)) + ' · ' +
      t('sched.assign') + ' ' + alloc + ' (' + share + ') · ' +
      t('sched.capacity') + ' ' + (capacity ? capacity.toFixed(capacity < 10 ? 1 : 0) + ' Mbps' : '-') + ' · ' +
      t('sched.qeta') + ' ' + eta + ' · ' + t('sched.batches') + ' ' + batchRate +
      (s.carry_pending ? ' · ' + t('sched.carry') : '');
    const totalBytes = num(s.assigned_bytes) + num(s.fec_assigned_bytes);
    const totalBatches = num(s.assigned_batches) + num(s.fec_assigned_batches);
    const tip = t('sched.cumulative') + ': ' + fmtBytes(totalBytes) + ' / ' + totalBatches + ' ' + t('sched.batch_unit') +
      ' | DATA ' + fmtBytes(num(s.assigned_bytes)) + ' / ' + num(s.assigned_batches) +
      ' | FEC ' + fmtBytes(num(s.fec_assigned_bytes)) + ' / ' + num(s.fec_assigned_batches);
    return '<div class="sched-cell" title="' + esc(tip) + '"><span class="badge ' + cls + '">' + esc(state) + '</span><small class="dim">' + esc(meta) + '</small></div>';
  };
'''
p.write_text(s[:start] + new_block + s[end:])

Path("scheduler_fec_telemetry_test.go").write_text(r'''package main

import "testing"

func TestFECParitySchedulerTelemetry(t *testing.T) {
	b := &Backend{ch: make(chan []VPNFrame, 1)}
	payload := []byte{1, 2, 3, 4, 5}
	if dropped := sendOwnedFrameTo(b, VPNFrame{Seq: 0, Data: payload}); dropped != 0 {
		t.Fatalf("sendOwnedFrameTo dropped=%d, want 0", dropped)
	}
	s := schedulerSnapshot(b)
	if s.AssignedBytes != 0 || s.AssignedBatches != 0 {
		t.Fatalf("data counters changed for FEC parity: bytes=%d batches=%d", s.AssignedBytes, s.AssignedBatches)
	}
	if s.FECAssignedBytes != uint64(len(payload)) || s.FECAssignedBatches != 1 {
		t.Fatalf("FEC telemetry bytes/batches=%d/%d, want %d/1", s.FECAssignedBytes, s.FECAssignedBatches, len(payload))
	}
}
''')
