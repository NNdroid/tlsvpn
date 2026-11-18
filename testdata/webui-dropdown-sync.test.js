'use strict';
/* app.js 自定义下拉 ↔ scheduler-settings.js 联动的 DOM 级回归，复现线上故障：
   「/api/config 返回 latency_sticky/near/fwd，但调度设置三个下拉显示默认值，
   而 near/fwd 条件字段与数值输入框都正确」。

   故障机理：showPane('settings') 里 loadConfig()（异步 fetch）先启动，随后的
   syncSelects() 同步执行——自定义下拉按钮按**当时的默认值**构建文案；fetch 返回后
   scheduler-settings 的 fromEditor 对原生 select.value 做 programmatic 赋值，不派发
   change，按钮文案没人刷新 →「原生新值、按钮旧值」分裂。数值输入框与条件字段可见性
   都读原生值，所以只有下拉按钮显示错。

   修复：app.js 在 HTMLSelectElement.prototype 上劫持 value setter，任何来源的赋值
   都自动 syncSelect。本测试按真实时序（加载两个真实脚本 → syncSelects 构建默认文案
   → wrapped loadConfig 注入配置）断言按钮文案跟随。 */

const vm = require('vm');
const fs = require('fs');
const path = require('path');

// ---- HTMLSelectElement 假原型：先装原生语义的 value accessor，patch 会包装它 ----
global.HTMLSelectElement = { prototype: {} };
const selStore = new WeakMap();
Object.defineProperty(HTMLSelectElement.prototype, 'value', {
  configurable: true, enumerable: true,
  get() { const s = selStore.get(this); return s ? s.nativeValue : ''; },
  set(v) {
    const s = selStore.get(this); if (!s) return;
    s.nativeValue = String(v);
    // 原生语义：命中选项更新 selectedIndex，否则 -1
    this.selectedIndex = s.options.findIndex(o => o.value === s.nativeValue);
  },
});

// 深层属性兜底代理：get/apply 都返回自身，任意链式访问不抛；
// Symbol.toPrimitive 返回空串，字符串拼接/算术不会炸
const chain = new Proxy(function () {}, {
  get(t, k) {
    if (k === Symbol.toPrimitive) return () => '';
    if (typeof k === 'symbol') return undefined;
    return chain;
  },
  apply: () => chain,
  set: () => true,
});

function __remove(p, c) { const i = p.children.indexOf(c); if (i >= 0) p.children.splice(i, 1); }
function makeClassList() {
  const s = new Set();
  return { add(c) { s.add(c); }, remove(c) { s.delete(c); }, toggle(c, f) { if (f === undefined) { s.has(c) ? s.delete(c) : s.add(c); } else if (f) s.add(c); else s.delete(c); }, contains(c) { return s.has(c); }, forEach(f) { s.forEach(f); } };
}
function makeFakeEl(tag) {
  const el = {
    tagName: (tag || 'DIV').toUpperCase(), className: '', id: '', children: [], parentNode: null,
    style: {}, dataset: {}, classList: makeClassList(), value: '', textContent: '', innerHTML: '', disabled: false, tabIndex: 0,
    clientWidth: 0, scrollWidth: 0, scrollLeft: 0, offsetLeft: 0, offsetWidth: 0, innerText: '',
    options: [], selectedIndex: 0,
    appendChild(c) { if (c.parentNode) __remove(c.parentNode, c); c.parentNode = this; this.children.push(c); return c; },
    insertBefore(c, ref) { if (c.parentNode) __remove(c.parentNode, c); c.parentNode = this; const i = ref ? this.children.indexOf(ref) : -1; if (i < 0) this.children.push(c); else this.children.splice(i, 0, c); return c; },
    remove() { if (this.parentNode) __remove(this.parentNode, this); },
    setAttribute() {}, getAttribute() { return null; },
    addEventListener() {}, removeEventListener() {}, focus() {}, click() {},
    closest() { return null; }, scrollBy() {},
    querySelector() { return chain; }, querySelectorAll() { return []; },
    getBoundingClientRect() { return { left: 0, top: 0, right: 0, bottom: 0, width: 0, height: 0 }; },
    getContext() { return chain; },
  };
  return el;
}
// 假 select：必须是 HTMLSelectElement 的实例（prototype value accessor 才生效）
function makeFakeSelect(values) {
  const sel = Object.create(HTMLSelectElement.prototype);
  const opts = values.map(v => ({ value: v, textContent: '' }));
  selStore.set(sel, { nativeValue: '', options: opts });
  sel.options = opts;
  sel.selectedIndex = 0;
  sel.disabled = false;
  sel.classList = makeClassList();
  sel.setAttribute = () => {}; sel.getAttribute = () => null;
  sel.addEventListener = () => {}; sel.dispatchEvent = () => {};
  sel.parentNode = makeFakeEl('LABEL'); // buildSelect 的 host（非 LABEL 才跳过 label 联动）
  sel.parentNode.tagName = 'DIV';
  return sel;
}

// ---- 调度面板元素：真实 scheduler-settings.js 用 getElementById 抓取 ----
const algo = makeFakeSelect(['auto', 'latency_strict', 'latency_sticky', 'min_rtt_strict', 'min_rtt_adaptive', 'roundtrip_strict']);
const fec = makeFakeSelect(['auto', 'near']);
const windowEl = makeFakeEl('INPUT');
const gate = makeFakeSelect(['rtt', 'fwd']);
const gateWindow = makeFakeEl('INPUT');
const probe = makeFakeEl('INPUT');
const nearField = makeFakeEl('DIV'); nearField.style.display = 'none';
const fwdField = makeFakeEl('DIV'); fwdField.style.display = 'none';

const registry = {};
registry['routing-algo'] = algo;
registry['fec-strategy'] = fec;
registry['fec-near-window'] = windowEl;
registry['sched-envelope'] = gate;
registry['sched-envelope-window'] = gateWindow;
registry['probe-min-half-rtt'] = probe;
// 首项 info：保证「写入 debug 后文案变化」断言不是空过（构建时文案=首项）
registry['loglevel'] = makeFakeSelect(['info', 'debug', 'warn', 'error']);
const editor = { value: '', parentNode: { insertBefore() {} }, addEventListener() {} };
registry['cfg-editor'] = editor;

let editorInputHandler = null;
editor.addEventListener = (ev, fn) => { if (ev === 'input') editorInputHandler = fn; };

const allSelects = ['routing-algo', 'fec-strategy', 'sched-envelope', 'loglevel'].map(id => registry[id]);

// scheduler-settings 的 rts-box：querySelectorAll 按键名返回条件字段/i18n 桩
const rtsT = {};
function makeDivElement() {
  const el = makeFakeEl('DIV');
  el.querySelectorAll = function (sel) {
    if (el.className === 'rts-box') {
      if (sel === '[data-fec-near]') return [nearField];
      if (sel === '[data-sched-fwd]') return [fwdField];
      if (sel === '[data-rts-t]') return Object.keys(rtsT).map(k => rtsT[k]);
    }
    return [];
  };
  return el;
}

global.document = {
  documentElement: { lang: 'zh-CN', dataset: {} },
  head: { appendChild() {} },
  body: makeFakeEl('BODY'),
  activeElement: null,
  createElement(tag) {
    if (tag === 'style') return { textContent: '' };
    if (tag === 'div') return makeDivElement();
    return makeFakeEl(tag);
  },
  getElementById(id) { return registry[id] || (registry[id] = makeFakeEl('DIV')); },
  querySelector() { return chain; },
  querySelectorAll(sel) { return sel === 'select' ? allSelects.slice() : []; },
  addEventListener() {},
};
global.window = { addEventListener() {}, devicePixelRatio: 1 };
global.location = { protocol: 'http:', origin: 'http://127.0.0.1:8080', host: '127.0.0.1:8080', username: '', password: '' };
global.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
global.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
global.getComputedStyle = () => chain;
global.MutationObserver = function () { this.observe = () => {}; };
global.t = k => k;
global.LANG = 'zh-CN';
// loadConfig 的 /api/config 固定返回用户线上那份配置
const userCfg = JSON.stringify({
  pad_mode: 'bucket', brutal: true, brutal_up: 50, brutal_down: 200,
  priority_control: 10, priority_data: 5, probe_min_half_rtt_us: 1000,
  routing_algo: 'latency_sticky', sched_envelope: 'fwd', sched_envelope_ms: 20,
  fec_strategy: 'near', fec_near_window_ms: 15,
  traffic_days: 30, traffic_file: '/usr/local/etc/tlsvpn/tlsvpn-traffic.json', web: {},
});
global.fetch = async () => ({ ok: true, text: async () => userCfg });

// ---- 加载真实脚本：app.js（含自定义下拉 + value setter 劫持）→ scheduler-settings ----
vm.runInThisContext(fs.readFileSync(path.join(__dirname, '..', 'webui', 'app.js'), 'utf8'));
// 浏览器里 window===globalThis，app.js 顶层的 loadConfig/saveConfig 就是 window 的；
// harness 的 window 是独立对象，这里显式挂上，让 scheduler-settings 包装到真实现。
window.loadConfig = loadConfig;
window.saveConfig = saveConfig;
vm.runInThisContext(fs.readFileSync(path.join(__dirname, '..', 'webui', 'scheduler-settings.js'), 'utf8'));

let failures = 0;
function assert(cond, msg) {
  if (!cond) { console.error('FAIL: ' + msg); failures++; }
  else { console.log('ok: ' + msg); }
}

// 从假 DOM 里找自定义下拉按钮文案：buildSelect 已把 select 移进 .dl 外壳，
// 结构为 .dl → [.dl-btn(内含 .dl-lab → .dl-cur), .dl-menu, select]
function labelOf(sel) {
  const wrap = sel.parentNode;
  if (!wrap || wrap.className !== 'dl') return null;
  const btn = wrap.children.find(c => String(c.className).indexOf('dl-btn') >= 0);
  const lab = btn && btn.children.find(c => c.className === 'dl-lab');
  const cur = lab && lab.children.find(c => c.className === 'dl-cur');
  return cur ? cur.textContent : null;
}

(async () => {
  // ---- 前置：页面加载完成（app.js 顶层 applyI18n 已 syncSelects，scheduler translate
  // 已填选项文案）。再补一次 syncSelects 模拟「切到设置页」：此刻 fetch 未返回，
  // 下拉按默认值构建——复现故障的起始状态。 ----
  syncSelects();
  assert(labelOf(algo) === 'auto（默认，粘滞+WFQ）',
    'precondition: custom label built from default, got "' + labelOf(algo) + '"');
  assert(labelOf(fec) === 'auto（所有健康后端轮转）',
    'precondition: fec custom label built from default, got "' + labelOf(fec) + '"');
  assert(labelOf(gate) === 'rtt（内核往返地板，默认）',
    'precondition: gate custom label built from default, got "' + labelOf(gate) + '"');

  // ---- 故障时序：wrapped loadConfig 完成 → fromEditor programmatic 写原生值 ----
  await window.loadConfig();

  // 原生值必须正确（此前就正确）
  assert(algo.value === 'latency_sticky', 'native routing_algo synced, got "' + algo.value + '"');
  assert(fec.value === 'near', 'native fec_strategy synced, got "' + fec.value + '"');
  assert(gate.value === 'fwd', 'native sched_envelope synced, got "' + gate.value + '"');
  assert(windowEl.value === '15' && gateWindow.value === '20' && probe.value === '1000',
    'numeric inputs synced, got ' + [windowEl.value, gateWindow.value, probe.value].join('/'));
  assert(nearField.style.display === '' && fwdField.style.display === '',
    'near/fwd conditional fields visible (native values drive visibility)');

  // 修复点：自定义下拉按钮文案必须跟随 programmatic 赋值（故障时停在上面前置的旧文案）
  assert(labelOf(algo) === 'latency_sticky（最低去程+粘滞）',
    'custom routing label follows programmatic value, got "' + labelOf(algo) + '"');
  assert(labelOf(fec) === 'near（去程时延 ≤ 数据路径 + 窗口）',
    'custom fec label follows programmatic value, got "' + labelOf(fec) + '"');
  assert(labelOf(gate) === 'fwd（本端去程排名键）',
    'custom gate label follows programmatic value, got "' + labelOf(gate) + '"');
  assert(editor.value === userCfg, 'fromEditor must not rewrite the editor JSON');

  // ---- 菜单高亮同步：syncSelect 重建菜单，当前项带 .on ----
  const dlShell = algo.parentNode;
  const menu = dlShell && dlShell.children.find(c => c.className === 'dl-menu');
  const onOpt = menu && menu.innerHTML.indexOf('dl-opt on') >= 0;
  assert(!!onOpt, 'menu rebuilt with highlighted current option');

  // ---- loglevel 回归：轮询 programmatic 写值（app.js stats 快照路径）同样自动同步 ----
  const lv = registry['loglevel'];
  lv.value = 'debug';
  assert(labelOf(lv) === 'debug', 'loglevel programmatic write syncs custom label, got "' + labelOf(lv) + '"');

  // ---- 未注册（未被 buildSelect 包装）的 select：赋值零开销且不抛 ----
  const bare = makeFakeSelect(['a', 'b']);
  bare.value = 'b';
  assert(bare.value === 'b' && bare.selectedIndex === 1, 'unregistered select assignment still works natively');

  console.log(failures === 0 ? 'ALL PASS' : failures + ' FAILURES');
  process.exit(failures === 0 ? 0 : 1);
})().catch(e => {
  console.error('FAIL: test crashed: ' + ((e && e.stack) || e));
  process.exit(1);
});
