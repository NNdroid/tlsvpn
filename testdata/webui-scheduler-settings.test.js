'use strict';
/* scheduler-settings.js 的 DOM 级测试：
   - fromEditor 读**顶层** cfg.routing_algo / fec_strategy / fec_near_window_ms
     （迁移后位置），而非旧 client 块。若误读 client 块，下拉/输入框将为空。
   - toEditor(true) 写**顶层**字段（而非 cfg.client）。
   用最小 DOM stub 加载真实脚本，断言初始化后的 DOM 值 + change 后的 editor JSON。 */

const vm = require('vm');
const fs = require('fs');
const path = require('path');

// ---- 最小 DOM stub ----
function makeOption(value) { return { value, textContent: '' }; }
function makeSelect() {
  return {
    value: '',
    options: [
      'auto', 'latency_strict', 'latency_sticky', 'min_rtt_strict',
      'min_rtt_adaptive', 'roundtrip_strict', 'near',
    ].map(makeOption),
    style: {},
    querySelector(sel) {
      const m = /^option\[value="(.+)"\]$/.exec(sel);
      return m ? makeOption(m[1]) : null;
    },
    addEventListener() {},
  };
}
function makeInput() { return { value: '', style: {}, addEventListener() {} }; }

const elements = {
  'pane-settings': { style: {} },
  'routing-algo': makeSelect(),
  'fec-strategy': makeSelect(),
  'fec-near-window': makeInput(),
  'sched-envelope': {
    value: '',
    options: ['rtt', 'fwd'].map(makeOption),
    style: {},
    querySelector(sel) {
      const m = /^option\[value="(.+)"\]$/.exec(sel);
      return m ? makeOption(m[1]) : null;
    },
    addEventListener() {},
  },
  'sched-envelope-window': makeInput(),
  'probe-min-half-rtt': makeInput(),
};
const editor = { value: '', parentNode: { insertBefore() {} } };
editor.addEventListener = (ev, fn) => { if (ev === 'input') editorInputHandler = fn; };
elements['cfg-editor'] = editor;

let changeHandler = null;
// 脚本会给 cfg-editor 加 input 监听：JSON 编辑器（唯一事实来源）手动编辑时
// 下拉/输入框实时跟随。捕获该处理器以验证「改 JSON → fromEditor 回填 DOM」。
let editorInputHandler = null;
// translate() 会把文案写进 [data-rts-t] 元素；预定义这些捕获元素以验证 zh-TW 生效。
const i18nKeys = ['title','sub','labelAlgo','labelFec','labelWindow','hint','fecHint','windowHint','labelProbe','probeHint'];
const i18nEls = i18nKeys.map(k => ({ dataset: { rtsT: k }, textContent: '' }));
const rootStub = {
  className: '', innerHTML: '', style: {},
  querySelectorAll(sel) {
    if (sel === '[data-rts-t]') return i18nEls;
    return []; // [data-fec-near] 等
  },
  appendChild() {},
  addEventListener(ev, fn) { if (ev === 'change') changeHandler = fn; },
};

global.document = {
  // 模拟繁体中文面板：lang() 读 documentElement.lang，translate() 须用 zh-TW 字典。
  documentElement: { lang: 'zh-TW' },
  head: { appendChild() {} },
  createElement(tag) {
    if (tag === 'style') return { textContent: '' };
    // 脚本内的 root（div）必须是同一个对象，这样测试才能捕获它的 change 处理器。
    if (tag === 'div') return rootStub;
    return { className: '', innerHTML: '', style: {}, appendChild() {}, querySelectorAll() { return []; }, addEventListener() {} };
  },
  getElementById(id) { return id === 'cfg-editor' ? editor : (elements[id] || null); },
};
// 脚本会包装 window.loadConfig / window.saveConfig（保存前 toEditor(false) 补空、
// 加载后 fromEditor 回填）。预置这两个入口的 stub，包装器才会安装上，
// 下面的异步用例才能通过它们触发 fromEditor / toEditor(false)。
global.window = { loadConfig() {}, saveConfig() {} };

// ---- 加载脚本**前**注入顶层 JSON：首次 fromEditor 必须读顶层 ----
editor.value = JSON.stringify({
  routing_algo: 'latency_strict',
  fec_strategy: 'near',
  fec_near_window_ms: 25,
  sched_envelope: 'fwd',
  sched_envelope_ms: 35,
});

// 脚本在 testdata/，目标脚本在 ../webui/（相对本文件）。
const src = fs.readFileSync(path.join(__dirname, '..', 'webui', 'scheduler-settings.js'), 'utf8');
vm.runInThisContext(src);

let failures = 0;
function assert(cond, msg) {
  if (!cond) { console.error('FAIL: ' + msg); failures++; }
  else { console.log('ok: ' + msg); }
}

// ---- 用例 1：fromEditor 读顶层字段 ----
const algo = elements['routing-algo'];
const fec = elements['fec-strategy'];
const windowEl = elements['fec-near-window'];
const gateEl = elements['sched-envelope'];
const gateWindowEl = elements['sched-envelope-window'];
const probeEl = elements['probe-min-half-rtt'];
assert(algo.value === 'latency_strict', 'fromEditor reads top-level routing_algo, got "' + algo.value + '"');
assert(fec.value === 'near', 'fromEditor reads top-level fec_strategy, got "' + fec.value + '"');
assert(windowEl.value === '25', 'fromEditor reads top-level fec_near_window_ms, got "' + windowEl.value + '"');
assert(gateEl.value === 'fwd', 'fromEditor reads top-level sched_envelope, got "' + gateEl.value + '"');
assert(gateWindowEl.value === '35', 'fromEditor reads top-level sched_envelope_ms, got "' + gateWindowEl.value + '"');
// 初始 JSON 没有 probe_min_half_rtt_us：显示后端默认 1000（而非空）。
assert(probeEl.value === '1000', 'fromEditor shows backend default 1000 when probe_min_half_rtt_us is absent, got "' + probeEl.value + '"');

// ---- 用例 2：toEditor(true) 写顶层字段（而非 cfg.client） ----
algo.value = 'min_rtt_adaptive';
fec.value = 'near';
windowEl.value = '40';
gateEl.value = 'fwd';
gateWindowEl.value = '45';
changeHandler && changeHandler({ target: algo });
let out = JSON.parse(editor.value);
assert(out.routing_algo === 'min_rtt_adaptive', 'toEditor writes top-level routing_algo, got "' + out.routing_algo + '"');
assert(out.fec_strategy === 'near', 'toEditor writes top-level fec_strategy, got "' + out.fec_strategy + '"');
assert(out.fec_near_window_ms === 40, 'toEditor writes top-level fec_near_window_ms, got "' + out.fec_near_window_ms + '"');
assert(out.sched_envelope === 'fwd', 'toEditor writes top-level sched_envelope, got "' + out.sched_envelope + '"');
assert(out.sched_envelope_ms === 45, 'toEditor writes top-level sched_envelope_ms, got "' + out.sched_envelope_ms + '"');
assert(out.client === undefined, 'toEditor must NOT create a client block, got ' + JSON.stringify(out.client));

// ---- 用例 3：toEditor 边界值（窗口越界回退 10） ----
algo.value = 'auto';
fec.value = 'auto';
windowEl.value = '500'; // 越界
changeHandler && changeHandler({ target: windowEl });
out = JSON.parse(editor.value);
assert(out.fec_near_window_ms === 10, 'toEditor clamps out-of-range window to 10, got "' + out.fec_near_window_ms + '"');

// ---- 用例 3b：sched_envelope_ms 越界回退 20（fwd 门窗口范围 1-500） ----
gateWindowEl.value = '9000'; // 越界
changeHandler && changeHandler({ target: gateWindowEl });
out = JSON.parse(editor.value);
assert(out.sched_envelope_ms === 20, 'toEditor clamps out-of-range sched_envelope_ms to 20, got "' + out.sched_envelope_ms + '"');
gateWindowEl.value = '0'; // 下界外
changeHandler && changeHandler({ target: gateWindowEl });
out = JSON.parse(editor.value);
assert(out.sched_envelope_ms === 20, 'toEditor clamps below-range sched_envelope_ms to 20, got "' + out.sched_envelope_ms + '"');

// ---- 用例 3c：空值不写入非法枚举 ----
// 真实契约：toEditor 对 select 取值，空值必须落回合法默认 rtt，
// 而不是把空串写进配置（后端 ValidSchedEnvelope 会拒空串以外的未知值，
// 但空串会被 applyDefaults 归一——面板侧就该自己兜住）。
gateEl.value = '';
changeHandler && changeHandler({ target: gateEl });
out = JSON.parse(editor.value);
assert(out.sched_envelope === 'rtt', 'empty sched_envelope must fall back to rtt, got "' + out.sched_envelope + '"');

// ---- 用例 4：zh-TW（繁中）翻译生效 ----
// documentElement.lang='zh-TW'，translate() 必须用 zh-TW 字典而非回退 en。
function txt(key) { const e = i18nEls.find(x => x.dataset.rtsT === key); return e ? e.textContent : ''; }
assert(txt('title') === '排程設定', 'zh-TW title translated, got "' + txt('title') + '"');
assert(txt('labelAlgo') === '選路演算法', 'zh-TW labelAlgo translated, got "' + txt('labelAlgo') + '"');
assert(txt('labelFec') === 'FEC 同位元分發策略', 'zh-TW labelFec translated, got "' + txt('labelFec') + '"');
assert(txt('labelWindow') === 'near 視窗 (ms)', 'zh-TW labelWindow translated, got "' + txt('labelWindow') + '"');
assert(txt('labelProbe') === 'probe_min 錨定下界 (µs)', 'zh-TW labelProbe translated, got "' + txt('labelProbe') + '"');
assert(txt('probeHint').indexOf('預設 1000') !== -1, 'zh-TW probeHint translated, got "' + txt('probeHint') + '"');
// 下拉选项的 textContent 也须为繁中（而非英文/原值）。
const autoOpt = algo.options.find(o => o.value === 'auto');
assert(autoOpt && autoOpt.textContent.indexOf('預設') !== -1, 'zh-TW auto option label uses traditional Chinese, got "' + (autoOpt && autoOpt.textContent) + '"');

// ---- 用例 5-8（异步）：经包装的 window.loadConfig / window.saveConfig 触发 ----
// fromEditor（加载后回填）与 toEditor(false)（保存前补空）在真实面板里分别挂在
// loadConfig / saveConfig 包装器上，这里走同样的入口。
async function runAsyncCases() {
  // ---- 用例 5：fromEditor 越界值显示原值，不再静默置空 ----
  // 越界值显示进输入框（number input 接受任意值）：保存时后端 400 显示真实错误。
  editor.value = JSON.stringify({ fec_near_window_ms: 500, sched_envelope_ms: 0, probe_min_half_rtt_us: -1 });
  await window.loadConfig();
  assert(windowEl.value === '500', 'fromEditor shows out-of-range fec_near_window_ms as-is, got "' + windowEl.value + '"');
  assert(gateWindowEl.value === '0', 'fromEditor shows out-of-range sched_envelope_ms as-is, got "' + gateWindowEl.value + '"');
  assert(probeEl.value === '-1', 'fromEditor shows out-of-range probe_min_half_rtt_us as-is, got "' + probeEl.value + '"');
  // 键缺失才落显示默认：probe 显示后端默认 1000，near/envelope 输入框留空。
  editor.value = JSON.stringify({ routing_algo: 'auto' });
  await window.loadConfig();
  assert(probeEl.value === '1000', 'missing probe_min_half_rtt_us displays default 1000 after reload, got "' + probeEl.value + '"');
  assert(windowEl.value === '', 'missing fec_near_window_ms leaves the input empty, got "' + windowEl.value + '"');
  assert(gateWindowEl.value === '', 'missing sched_envelope_ms leaves the input empty, got "' + gateWindowEl.value + '"');

  // ---- 用例 6：toEditor(true) 对 probe_min_half_rtt_us —— 0 合法可写，非法删键 ----
  probeEl.value = '0';
  changeHandler({ target: probeEl });
  out = JSON.parse(editor.value);
  assert(out.probe_min_half_rtt_us === 0, 'toEditor keeps explicit 0 (anchoring disabled), got "' + out.probe_min_half_rtt_us + '"');
  probeEl.value = '2500';
  changeHandler({ target: probeEl });
  out = JSON.parse(editor.value);
  assert(out.probe_min_half_rtt_us === 2500, 'toEditor writes in-range probe_min_half_rtt_us, got "' + out.probe_min_half_rtt_us + '"');
  probeEl.value = '-5';
  changeHandler({ target: probeEl });
  out = JSON.parse(editor.value);
  assert(!('probe_min_half_rtt_us' in out), 'negative probe_min_half_rtt_us deletes the key, got ' + JSON.stringify(out.probe_min_half_rtt_us));
  probeEl.value = '3600001';
  changeHandler({ target: probeEl });
  out = JSON.parse(editor.value);
  assert(!('probe_min_half_rtt_us' in out), 'above-range probe_min_half_rtt_us deletes the key, got ' + JSON.stringify(out.probe_min_half_rtt_us));
  probeEl.value = '';
  changeHandler({ target: probeEl });
  out = JSON.parse(editor.value);
  assert(!('probe_min_half_rtt_us' in out), 'empty probe input deletes the key (backend default 1000), got ' + JSON.stringify(out.probe_min_half_rtt_us));

  // ---- 用例 7：toEditor(false) 补空 —— DOM 合法值优先（与枚举字段语义一致） ----
  editor.value = JSON.stringify({ routing_algo: 'auto' });
  windowEl.value = '30';
  gateWindowEl.value = '300';
  probeEl.value = '2500';
  await window.saveConfig(false);
  out = JSON.parse(editor.value);
  assert(out.fec_near_window_ms === 30, 'toEditor(false) fills missing fec_near_window_ms from DOM, got "' + out.fec_near_window_ms + '"');
  assert(out.sched_envelope_ms === 300, 'toEditor(false) fills missing sched_envelope_ms from DOM, got "' + out.sched_envelope_ms + '"');
  assert(out.probe_min_half_rtt_us === 2500, 'toEditor(false) fills missing probe_min_half_rtt_us from DOM, got "' + out.probe_min_half_rtt_us + '"');

  // ---- 用例 7b：DOM 无合法值 → near/envelope 落硬编码缺省 10/20，probe 不写键 ----
  editor.value = JSON.stringify({ routing_algo: 'auto' });
  windowEl.value = 'abc';
  gateWindowEl.value = '';
  probeEl.value = '';
  await window.saveConfig(false);
  out = JSON.parse(editor.value);
  assert(out.fec_near_window_ms === 10, 'toEditor(false) falls back to 10 when DOM value is illegal, got "' + out.fec_near_window_ms + '"');
  assert(out.sched_envelope_ms === 20, 'toEditor(false) falls back to 20 when DOM value is illegal, got "' + out.sched_envelope_ms + '"');
  assert(!('probe_min_half_rtt_us' in out), 'toEditor(false) omits probe_min_half_rtt_us when DOM has no legal value, got ' + JSON.stringify(out.probe_min_half_rtt_us));

  // ---- 用例 7c：编辑器已有的非法值原样保留（送后端校验），DOM 值不覆盖 ----
  editor.value = JSON.stringify({ routing_algo: 'auto', fec_near_window_ms: 'oops', sched_envelope_ms: 9999, probe_min_half_rtt_us: -3 });
  windowEl.value = '40';
  gateWindowEl.value = '40';
  probeEl.value = '40';
  await window.saveConfig(false);
  out = JSON.parse(editor.value);
  assert(out.fec_near_window_ms === 'oops', 'toEditor(false) keeps existing illegal fec_near_window_ms for backend validation, got "' + out.fec_near_window_ms + '"');
  assert(out.sched_envelope_ms === 9999, 'toEditor(false) keeps existing out-of-range sched_envelope_ms, got "' + out.sched_envelope_ms + '"');
  assert(out.probe_min_half_rtt_us === -3, 'toEditor(false) keeps existing illegal probe_min_half_rtt_us, got "' + out.probe_min_half_rtt_us + '"');

  // ---- 用例 8：JSON 编辑器手动编辑（input 事件）→ 下拉/输入框实时跟随 ----
  // 回归：此前只在 loadConfig/saveConfig 包装里回填，用户直接在 cfg-editor 里
  // 键入/粘贴改字段时下拉框停在旧值，造成「渲染旧值、JSON 新值」分裂。
  algo.value = 'auto'; fec.value = 'auto'; gateEl.value = 'rtt';
  windowEl.value = ''; gateWindowEl.value = ''; probeEl.value = '';
  editor.value = JSON.stringify({ routing_algo: 'min_rtt_adaptive', fec_strategy: 'near',
    fec_near_window_ms: 33, sched_envelope: 'fwd', sched_envelope_ms: 44, probe_min_half_rtt_us: 2500 });
  assert(typeof editorInputHandler === 'function', 'cfg-editor input listener is installed');
  editorInputHandler && editorInputHandler();
  assert(algo.value === 'min_rtt_adaptive', 'editor input syncs routing_algo dropdown, got "' + algo.value + '"');
  assert(fec.value === 'near', 'editor input syncs fec_strategy dropdown, got "' + fec.value + '"');
  assert(gateEl.value === 'fwd', 'editor input syncs sched_envelope dropdown, got "' + gateEl.value + '"');
  assert(windowEl.value === '33', 'editor input syncs fec_near_window_ms input, got "' + windowEl.value + '"');
  assert(gateWindowEl.value === '44', 'editor input syncs sched_envelope_ms input, got "' + gateWindowEl.value + '"');
  assert(probeEl.value === '2500', 'editor input syncs probe_min_half_rtt_us input, got "' + probeEl.value + '"');
  // 编辑器里的合法枚举值不因 input 回填被改写（唯一事实来源仍为编辑器）
  out = JSON.parse(editor.value);
  assert(out.routing_algo === 'min_rtt_adaptive' && out.fec_strategy === 'near' && out.sched_envelope === 'fwd',
    'editor input does not rewrite valid JSON enum values');
}

runAsyncCases().then(() => {
  console.log(failures === 0 ? 'ALL PASS' : failures + ' FAILURES');
  process.exit(failures === 0 ? 0 : 1);
}).catch(e => {
  console.error('FAIL: async test crashed: ' + ((e && e.stack) || e));
  process.exit(1);
});
