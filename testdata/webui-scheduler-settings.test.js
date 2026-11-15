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
};
const editor = { value: '', parentNode: { insertBefore() {} } };
elements['cfg-editor'] = editor;

let changeHandler = null;
// translate() 会把文案写进 [data-rts-t] 元素；预定义这些捕获元素以验证 zh-TW 生效。
const i18nKeys = ['title','sub','labelAlgo','labelFec','labelWindow','hint','fecHint','windowHint'];
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
global.window = {};

// ---- 加载脚本**前**注入顶层 JSON：首次 fromEditor 必须读顶层 ----
editor.value = JSON.stringify({
  routing_algo: 'latency_strict',
  fec_strategy: 'near',
  fec_near_window_ms: 25,
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
assert(algo.value === 'latency_strict', 'fromEditor reads top-level routing_algo, got "' + algo.value + '"');
assert(fec.value === 'near', 'fromEditor reads top-level fec_strategy, got "' + fec.value + '"');
assert(windowEl.value === '25', 'fromEditor reads top-level fec_near_window_ms, got "' + windowEl.value + '"');

// ---- 用例 2：toEditor(true) 写顶层字段（而非 cfg.client） ----
algo.value = 'min_rtt_adaptive';
fec.value = 'near';
windowEl.value = '40';
changeHandler && changeHandler({ target: algo });
let out = JSON.parse(editor.value);
assert(out.routing_algo === 'min_rtt_adaptive', 'toEditor writes top-level routing_algo, got "' + out.routing_algo + '"');
assert(out.fec_strategy === 'near', 'toEditor writes top-level fec_strategy, got "' + out.fec_strategy + '"');
assert(out.fec_near_window_ms === 40, 'toEditor writes top-level fec_near_window_ms, got "' + out.fec_near_window_ms + '"');
assert(out.client === undefined, 'toEditor must NOT create a client block, got ' + JSON.stringify(out.client));

// ---- 用例 3：toEditor 边界值（窗口越界回退 10） ----
algo.value = 'auto';
fec.value = 'auto';
windowEl.value = '500'; // 越界
changeHandler && changeHandler({ target: windowEl });
out = JSON.parse(editor.value);
assert(out.fec_near_window_ms === 10, 'toEditor clamps out-of-range window to 10, got "' + out.fec_near_window_ms + '"');

// ---- 用例 4：zh-TW（繁中）翻译生效 ----
// documentElement.lang='zh-TW'，translate() 必须用 zh-TW 字典而非回退 en。
function txt(key) { const e = i18nEls.find(x => x.dataset.rtsT === key); return e ? e.textContent : ''; }
assert(txt('title') === '排程設定', 'zh-TW title translated, got "' + txt('title') + '"');
assert(txt('labelAlgo') === '選路演算法', 'zh-TW labelAlgo translated, got "' + txt('labelAlgo') + '"');
assert(txt('labelFec') === 'FEC 同位元分發策略', 'zh-TW labelFec translated, got "' + txt('labelFec') + '"');
assert(txt('labelWindow') === 'near 視窗 (ms)', 'zh-TW labelWindow translated, got "' + txt('labelWindow') + '"');
// 下拉选项的 textContent 也须为繁中（而非英文/原值）。
const autoOpt = algo.options.find(o => o.value === 'auto');
assert(autoOpt && autoOpt.textContent.indexOf('預設') !== -1, 'zh-TW auto option label uses traditional Chinese, got "' + (autoOpt && autoOpt.textContent) + '"');

console.log(failures === 0 ? 'ALL PASS' : failures + ' FAILURES');
process.exit(failures === 0 ? 0 : 1);
