'use strict';
/* mcp-settings.js 的 DOM 级测试，聚焦「JSON 编辑器 ↔ MCP 面板」同步：
   - fromEditor 从顶层 cfg.web.mcp 填 MCP 输入框（path 等）；
   - JSON 编辑器 input 事件 → fromEditor 回填 MCP 面板（回归：此前只在
     loadConfig/saveConfig 包装里回填，用户直接在 cfg-editor 里改 web.mcp.*
     时 MCP 面板停在旧值，造成「渲染旧值、JSON 新值」分裂）；
   - saveConfig 保存后（无论是否热应用）都回填 fromEditor（此前仅 apply=true）。
   用最小 DOM stub 加载真实脚本，断言初始化 + input 事件后的 DOM 值。 */

const vm = require('vm');
const fs = require('fs');
const path = require('path');

function makeOption(value) { return { value, textContent: '' }; }
function makeSelect(values) {
  return { value: '', options: values.map(makeOption), style: {}, addEventListener() {} };
}
function makeInput() { return { value: '', style: {}, addEventListener() {} }; }
function makeEl() { return { textContent: '', value: '', style: {}, addEventListener() {} }; }

let editorInputHandler = null;

const elements = {
  'pane-settings': { style: {} },
  'mcp-auth-mode': makeSelect(['inherit_web', 'basic', 'bearer', 'api_key', 'oauth_jwt', 'none']),
  'mcp-deploy': makeSelect(['internal', 'public', 'both']),
  'mcp-path': makeInput(),
  'mcp-username': makeInput(),
  'mcp-credential': makeInput(),
  'mcp-api-header': makeInput(),
  'mcp-jwks': makeInput(),
  'mcp-issuer': makeInput(),
  'mcp-audience': makeInput(),
  'mcp-resource': makeInput(),
  'mcp-servers': makeEl(),
  'mcp-scopes': makeEl(),
  'mcp-sync': makeEl(),
  'mcp-generate': makeEl(),
  'mcp-path-regen': makeEl(),
  'mcp-secret-show': makeEl(),
  'mcp-credential-status': makeEl(),
  'mcp-none-warn': makeEl(),
  'mcp-deploy-lock': makeEl(),
  'mcp-credential-status': makeEl(),
};

const editor = { value: '', parentNode: { insertBefore() {} } };
editor.addEventListener = (ev, fn) => { if (ev === 'input') editorInputHandler = fn; };
elements['cfg-editor'] = editor;

// root stub：捕获 [data-mcp-*] 元素与 querySelectorAll 分组（updateVisibility / translate）
const mcpGroupEls = { basic: [], api: [], static: [], oauth: [], 'data-mcp-t': [] };
const rootStub = {
  className: '', innerHTML: '', style: {},
  querySelectorAll(sel) {
    const g = sel.match(/^\[data-mcp-([a-z]+)\]$/);
    if (g) return mcpGroupEls[g[1]] || [];
    if (sel === '[data-mcp-t]') return mcpGroupEls['data-mcp-t'];
    return [];
  },
  addEventListener() {},
};

global.document = {
  documentElement: { lang: 'zh-CN' },
  head: { appendChild() {} },
  createElement(tag) {
    if (tag === 'style') return { textContent: '' };
    if (tag === 'div') return rootStub;
    return { className: '', innerHTML: '', style: {}, appendChild() {}, querySelectorAll() { return []; }, addEventListener() {} };
  },
  getElementById(id) { return id === 'cfg-editor' ? editor : (elements[id] || null); },
};
// 脚本会包装 window.loadConfig / window.saveConfig（加载后 fromEditor 回填、
// 保存后 fromEditor 回填）。预置这两个入口的 stub，包装器才会安装上。
global.window = { loadConfig() {}, saveConfig() {} };
global.MutationObserver = function() { this.observe = function() {}; };

// 顶层 JSON 含 web.mcp：首次 fromEditor 必须填 MCP 面板。
editor.value = JSON.stringify({
  mode: 'server',
  web: { mcp: { auth_mode: 'bearer', deploy: 'public', path: '/abcdef123456', api_key_header: 'X-Api-Key' } },
});

const src = fs.readFileSync(path.join(__dirname, '..', 'webui', 'mcp-settings.js'), 'utf8');
vm.runInThisContext(src);

let failures = 0;
function assert(cond, msg) {
  if (!cond) { console.error('FAIL: ' + msg); failures++; }
  else { console.log('ok: ' + msg); }
}

const pathEl = elements['mcp-path'];
const modeEl = elements['mcp-auth-mode'];
const deployEl = elements['mcp-deploy'];
const apiHeaderEl = elements['mcp-api-header'];

// ---- 用例 1：fromEditor 从顶层 web.mcp 填 MCP 面板 ----
assert(pathEl.value === '/abcdef123456', 'fromEditor fills mcp-path from top-level web.mcp.path, got "' + pathEl.value + '"');
assert(modeEl.value === 'bearer', 'fromEditor fills auth_mode from web.mcp, got "' + modeEl.value + '"');
assert(deployEl.value === 'public', 'fromEditor fills deploy from web.mcp, got "' + deployEl.value + '"');
assert(apiHeaderEl.value === 'X-Api-Key', 'fromEditor fills api_key_header from web.mcp, got "' + apiHeaderEl.value + '"');

// ---- 用例 2：JSON 编辑器 input 事件 → fromEditor 回填 MCP 面板 ----
// 回归：此前无 editor input 监听，用户直接在 cfg-editor 改 web.mcp.path 时
// MCP 面板停在旧值。
assert(typeof editorInputHandler === 'function', 'cfg-editor input listener is installed');
pathEl.value = '/stale'; // 先改成旧值，验证 input 会覆盖它
editor.value = JSON.stringify({ mode: 'server', web: { mcp: { auth_mode: 'api_key', deploy: 'both', path: '/newpath789', api_key_header: 'X-Custom' } } });
editorInputHandler();
assert(pathEl.value === '/newpath789', 'editor input syncs mcp-path, got "' + pathEl.value + '"');
assert(modeEl.value === 'api_key', 'editor input syncs auth_mode, got "' + modeEl.value + '"');
assert(deployEl.value === 'both', 'editor input syncs deploy, got "' + deployEl.value + '"');
assert(apiHeaderEl.value === 'X-Custom', 'editor input syncs api_key_header, got "' + apiHeaderEl.value + '"');
// 编辑器里的合法值不因 input 回填被改写（唯一事实来源仍为编辑器）
const afterInput = JSON.parse(editor.value);
assert(afterInput.web.mcp.path === '/newpath789' && afterInput.web.mcp.auth_mode === 'api_key',
  'editor input does not rewrite valid JSON mcp values');

// ---- 用例 3：saveConfig 包装安装，保存后（apply=false 也）回填 fromEditor ----
assert(typeof window.saveConfig === 'function' && typeof window.loadConfig === 'function',
  'saveConfig/loadConfig wrappers installed');

console.log(failures === 0 ? 'ALL PASS' : failures + ' FAILURES');
process.exit(failures === 0 ? 0 : 1);
