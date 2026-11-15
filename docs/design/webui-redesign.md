# WebUI 美化设计方案

> **状态：已实施并推送**（`webui/` 三文件已按本设计稿重做，含过滤交互升级；`docs/` 目录不入库，本文档仅留档）。
> 高保真交互设计稿：[`webui-mockup.html`](./webui-mockup.html)（双击即可在浏览器打开，内含暗/亮主题、中英文切换、全部标签页与样例数据，无任何外部依赖）。

## 〇、工程结构（已落地）

面板资源已从 `api.go` 的巨型字符串拆分为独立目录，编译期嵌入二进制：

```
webui/
├── index.html   # DOM 骨架，仅 <link style.css> + <script src="app.js">
├── style.css    # 全部样式（旧版视觉，待按本设计稿重做）
└── app.js       # 全部脚本：i18n、轮询、渲染、控制

webui.go         # //go:embed webui + webuiHandler()（no-store、禁目录列表）
```

- 服务端：`mux.Handle("/", auth(webuiHandler().ServeHTTP))`，`/` 返回 index.html，`/app.js`、`/style.css` 直出；`no-store` 保证升级后浏览器不拿旧面板打新 API；目录列表与未知路径一律 404。
- 测试守护（`dashboard_script_test.go`）：括号配平、相邻字符串、三元配平、TLS 字段转义全部改为针对 `webui/app.js`，行号与浏览器报错的 `app.js:N` 直接对齐；新增 `TestDashboardNoInlineScript` 保证 index.html 不出现内联脚本（词法测试无覆盖死角）；`web_test.go` 新增 `TestWebUIServesEmbeddedAssets` 验证资产路由。
- 约定：`app.js` 继续不使用模板字符串（反引号）与含花括号/引号的正则字面量，词法检查依赖这一前提。

## 〇½、关键字过滤交互（设计定稿）

旧版问题：裸 `<input>`，每次按键都重新 `fetchStats()` 打一次 API；无清除按钮、无命中反馈；"无数据"和"无匹配"混为一句提示。

新设计（设计稿已实现，落地同款行为）：

- **搜索框组件**：放大镜图标 + 无边框内嵌输入 + 圆形 × 清除按钮（有内容才出现）+ `命中/总数` 计数徽章（如 `1 / 3`，无查询词时隐藏）；聚焦时边框染品牌紫。
- **纯本地过滤 + 防抖 140ms**：输入只对最近一次 `/api/stats` 的缓存数据重渲染，不再打 API（旧版 `oninput=fetchStats` 的行为废弃）。
- **命中高亮**：匹配片段以 `<mark>`（紫罗兰软底）标出，ID/IP/MAC 等关键列均生效。
- **空态分级**：数据为空显示"暂无客户端"等原提示；有数据但过滤后为空则显示"无匹配结果 + 清除过滤按钮"。
- **键盘支持**：`/` 聚焦当前页签过滤框，`Esc` 或 × 一键清空。
- **覆盖范围**：客户端、连接明细、MAC 表三个页签（封禁页的输入是"添加封禁"表单，不是过滤，保持独立样式）。
- i18n 新增 key：`filter_none` / `filter_clear` / `filter_tip`（zh/en 同步）。

## 一、目标

- 保留现有面板的**全部功能与信息架构**（KPI、吞吐图、客户端/连接/MAC/封禁/状态/日志/设置七个页签、中英文、暗亮主题、刷新间隔），只做视觉与布局质感升级。
- 视觉方向：现代运维控制台——深色优先、克制的玻璃拟态顶栏、渐变品牌色、语义化配色（上行=翠绿、下行=紫罗兰、警告=琥珀、错误=玫红）。
- 零依赖：继续纯内联 HTML/CSS/JS 单文件（编译进二进制），不引入任何框架或外链资源。

## 二、布局变化

| 区域 | 现状 | 新设计 |
| --- | --- | --- |
| 页头 | `h1` 标题行内嵌 3 个原生 `<select>` | 吸顶玻璃顶栏：渐变 Logo 盾牌 + 模式徽章（呼吸灯圆点）+ 协商信息；语言/主题/刷新改为**分段按钮组**（一眼可见全部选项，少一次点击） |
| KPI | 7 张卡片，纯文字 | 图标徽章 + 大数字 + 语义色速率行；桌面 4+3 网格（`minmax(256px,1fr)`），移动端单列 |
| 图表 | 170px 折线 | 216px 平滑曲线 + **渐变面积填充**（DPR 适配更清晰），卡片头右侧常驻实时速率 ↑↓ |
| 页签 | 方角贴边按钮 | 分段胶囊容器，激活态紫罗兰软底，内容淡入动画 |
| 表格 | 通用表格 | 大写小字号字距表头、行悬停高亮、数值 `tabular-nums` 等宽对齐、IP/MAC/ID 等宽字体、圆点徽章、幽灵按钮 |
| 状态页 | 四块 kv 表 | 卡中卡（`--card2` 子面板），虚线行分隔，标签左值右 |
| 日志 | 纯文本行 | 终端风格（暗色恒定），级别渲染为彩色徽标，时间戳弱化 |
| 设置 | 裸 textarea | 工具栏（说明文案 + 重新加载/保存/保存并应用）+ 终端风编辑器，主操作用渐变主按钮 |
| 背景 | 纯色 | 两团极淡的品牌色光晕（fixed 伪元素），暗色下氛围、亮色下几乎不可见 |

## 三、设计令牌

### 暗色（默认跟随系统）

```css
--bg:#0a0e16; --card:#111726; --card2:#0d1320; --term:#0a0f1a;
--border:#1f2739; --border2:#2a3550; --grid:#1b2334;
--fg:#e8ecf4; --muted:#9aa2b5; --sub:#6c7488;
--accent:#8b7bff;      /* 紫罗兰：品牌/交互/下行 */
--up:#3ddba4;          /* 翠绿：上行/健康 */
--warn:#f2c94c; --err:#ff6b8b; --cyan:#38cfe8; --amber:#f0b13e;
--grad:linear-gradient(135deg,#6d5df6 0%,#9a6bff 100%);
```

### 亮色

```css
--bg:#f3f5fa; --card:#ffffff; --border:#e4e8f1;
--accent:#6a5cf5; --up:#0da271; --warn:#9a6d00; --err:#d3315a;
```

- 字体：`-apple-system / Segoe UI / PingFang SC / Microsoft YaHei`，数字 `font-variant-numeric: tabular-nums`；等宽 `Cascadia Mono / Consolas`。
- 圆角体系：卡片 14px、子面板 11px、控件 8-9px、徽章全圆。
- 阴影：暗色 `0 1px 2px rgba(0,0,0,.35), 0 10px 30px -14px rgba(0,0,0,.55)`；亮色更轻。
- 徽章语义：`b-on` 绿=生效/up、`b-dup` 琥珀=降级/connecting、`b-off` 灰=关闭、`b-info` 紫=中性高亮（如封禁剩余时长）。

## 四、落地方式（剩余工作：按本设计稿重做 webui/ 三个文件的视觉）

资源已在 `webui/` 目录（见"〇、工程结构"），**JS 业务逻辑不动**，具体：

1. 重写 `webui/style.css` 为新令牌与组件样式。
2. 调整 `webui/index.html` DOM：页头结构（保留 `#mode/#meta/#lang/#theme/#refresh` 的功能语义，`select` → 分段按钮 + `setLang/setTheme/setRefresh` 适配）、KPI 卡加图标徽章、图表卡加实时速率角标、三个页签的过滤框换成搜索组件。
3. `webui/app.js`：`drawChart()` 升级（平滑贝塞尔 + 渐变填充 + devicePixelRatio 适配，保留 `--grid/--up/--down` 令牌取色）；过滤改为本地缓存过滤 + 防抖 + 高亮（见"〇½"）；表格行模板加 class（`num`、`speed`、徽章、按钮），数据字段与列**保持不变**。
4. i18n 字典沿用现有 key，仅新增少量键（过滤/主题分段按钮等），zh/en 同步。

### 必须遵守的既有测试约束（`dashboard_script_test.go`）

- `app.js` 禁用模板字符串（反引号）与含花括号/引号的正则字面量；index.html 禁止内联 `<script>`（`TestDashboardNoInlineScript` 守护）。
- 括号配平、无相邻字符串字面量、`?:` 三元平衡检查改为针对 `webui/app.js`，行号与浏览器 `app.js:N` 对齐。
- 修改后跑 `go test -run 'TestDashboard|TestWebUI'`。

### 风险与对策

- 旧浏览器不支持 `color-mix()`：仅影响顶栏背景透明度，回退为纯色即可（设计稿已用，落地时加一行 `@supports` 或直接用 rgba 兜底）。
- 表格列在移动端仍靠 `hide-sm` 折叠，与现网一致。

## 五、验收清单

- [ ] 暗色/亮色/跟随系统三态正确，图表重绘正常
- [ ] 中英切换覆盖所有新增文案
- [ ] 过滤：防抖本地过滤、命中高亮、计数徽章、无匹配空态、`/` 与 `Esc` 快捷键
- [ ] server/client 两种模式下 KPI（地址池卡）、页签内容正确显隐
- [ ] `go test ./...` 全绿（尤其 dashboard 词法与 webui 资产路由测试）
- [ ] 1440px 桌面 / 390px 移动端两档布局检查
