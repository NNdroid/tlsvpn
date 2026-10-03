import { promises as fs } from 'node:fs';
import { chromium } from 'playwright';

const settingsJS = await fs.readFile('webui/mcp-settings.js', 'utf8');
const examplesJS = await fs.readFile('webui/mcp-examples.js', 'utf8');
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
const failures = [];

page.on('pageerror', err => failures.push(`pageerror: ${err.stack || err.message}`));
page.on('console', msg => {
  if (msg.type() === 'error') failures.push(`console.error: ${msg.text()}`);
});

await page.setContent(`<!doctype html><html lang="en"><head><meta charset="utf-8"><style>
:root{--border:#444;--card:#222;--bg:#111;--text:#eee;--sub:#aaa;--warn:#f90}
body{background:var(--bg);color:var(--text)}.btn{padding:4px 8px}
</style></head><body>
<div id="pane-settings"><textarea id="cfg-editor">{"web":{"mcp":{"auth_mode":"inherit_web"}}}</textarea></div>
<script>window.loadConfig=async()=>{};window.saveConfig=async()=>{};</script>
</body></html>`);
await page.addScriptTag({ content: settingsJS });
await page.addScriptTag({ content: examplesJS });

const localeExpect = {
  'zh-CN': ['MCP 配置与连接示例', '客户端 JSON 示例', '复制'],
  'zh-TW': ['MCP 設定與連線範例', '用戶端 JSON 範例', '複製'],
  en: ['MCP configuration and connection examples', 'Client JSON example', 'Copy'],
  de: ['MCP-Konfigurations- und Verbindungsbeispiele', 'Client-JSON-Beispiel', 'Kopieren'],
  fr: ['Exemples de configuration et de connexion MCP', 'Exemple JSON client', 'Copier'],
  ja: ['MCP 設定・接続例', 'クライアント JSON 例', 'コピー']
};

for (const [lang, expected] of Object.entries(localeExpect)) {
  await page.evaluate(v => document.documentElement.lang = v, lang);
  await page.waitForTimeout(20);
  const text = await page.locator('.mcp-examples').innerText();
  for (const want of expected) {
    if (!text.includes(want)) failures.push(`[${lang}] missing localized text: ${want}`);
  }
}

async function selectMode(mode) {
  await page.selectOption('#mcp-auth-mode', mode);
  await page.waitForTimeout(20);
}
async function snapshot() {
  return page.evaluate(() => ({
    client: document.getElementById('mcp-example-client')?.textContent || '',
    curl: document.getElementById('mcp-example-curl')?.textContent || '',
    server: document.getElementById('mcp-example-server')?.textContent || '',
    metadataVisible: getComputedStyle(document.getElementById('mcp-metadata-wrap')).display !== 'none',
    endpoint: document.getElementById('mcp-example-endpoint')?.textContent || ''
  }));
}

await selectMode('inherit_web');
let state = await snapshot();
if (!state.endpoint.endsWith('/mcp')) failures.push('inherit_web endpoint does not end in /mcp');
if (!state.client.includes('BASE64_WEBUI_USER_PASSWORD') || !state.curl.includes('<WEBUI_USER>:<WEBUI_PASSWORD>')) failures.push('inherit_web examples missing WebUI Basic credentials');

await selectMode('basic');
await page.fill('#mcp-username', 'agent');
state = await snapshot();
if (!state.server.includes('"username": "agent"') || !state.server.includes('<MCP_PASSWORD>') || !state.curl.includes("agent:<MCP_PASSWORD>")) failures.push('basic examples are incomplete');

await selectMode('bearer');
state = await snapshot();
if (!state.client.includes('Bearer <MCP_BEARER_TOKEN>') || !state.curl.includes('Bearer <MCP_BEARER_TOKEN>')) failures.push('bearer examples are incomplete');

await selectMode('api_key');
await page.fill('#mcp-api-header', 'X-TLSVPN-Key');
state = await snapshot();
if (!state.client.includes('X-TLSVPN-Key') || !state.client.includes('<MCP_API_KEY>') || !state.curl.includes('X-TLSVPN-Key: <MCP_API_KEY>')) failures.push('api_key examples are incomplete');

await selectMode('oauth_jwt');
await page.fill('#mcp-jwks', 'https://idp.example.com/jwks.json');
await page.fill('#mcp-issuer', 'https://idp.example.com');
await page.fill('#mcp-audience', 'tlsvpn');
await page.fill('#mcp-resource', 'https://vpn.example.com/mcp');
await page.fill('#mcp-servers', 'https://idp.example.com');
await page.fill('#mcp-scopes', 'mcp.read mcp.admin');
state = await snapshot();
if (!state.metadataVisible) failures.push('oauth metadata endpoint is hidden');
for (const want of ['https://idp.example.com/jwks.json', '"audience": "tlsvpn"', 'mcp.read', 'mcp.admin', '<OAUTH_ACCESS_TOKEN>']) {
  if (!(state.server + state.client + state.curl).includes(want)) failures.push(`oauth example missing ${want}`);
}

await selectMode('none');
state = await snapshot();
if (state.client.includes('headers') || state.curl.includes('Authorization:') || state.curl.includes('X-TLSVPN-Key:')) failures.push('none mode still emits authentication headers');
if (state.metadataVisible) failures.push('OAuth metadata is visible outside oauth_jwt mode');

const secretLeak = await page.evaluate(() => {
  const editor = document.getElementById('cfg-editor');
  const cfg = JSON.parse(editor.value);
  cfg.web.mcp.auth_mode = 'bearer';
  cfg.web.mcp.credential = 'sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
  editor.value = JSON.stringify(cfg);
  document.getElementById('mcp-sync').click();
  return new Promise(resolve => setTimeout(() => resolve(document.querySelector('.mcp-examples').innerText), 20));
});
if (secretLeak.includes('sha256:0123456789abcdef')) failures.push('saved credential verifier leaked into MCP examples');
if (!secretLeak.includes('<MCP_BEARER_TOKEN>')) failures.push('bearer placeholder missing after JSON reload');

await browser.close();
if (failures.length) {
  console.error('MCP WebUI browser smoke failed:\n' + failures.map(x => ` - ${x}`).join('\n'));
  process.exit(1);
}
console.log('MCP WebUI browser smoke passed across 6 locales and all authentication modes.');
