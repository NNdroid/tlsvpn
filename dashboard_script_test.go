package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
)

// dashboardJS 返回面板脚本正文（webui/app.js）。脚本已从 Go 字符串拆出为独立
// 文件、经 go:embed 打进二进制；这里的行号与浏览器报错的 app.js:N 直接对齐。
func dashboardJS(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("webui/app.js")
	if err != nil {
		t.Fatalf("读取 webui/app.js: %v", err)
	}
	return string(b)
}

// TestDashboardNoInlineScript 保证 index.html 只以 <script src="app.js"> 引用
// 外部脚本、不出现内联代码：全部 JS 集中在 app.js，上面的词法守护测试才没有
// 覆盖死角。
func TestDashboardNoInlineScript(t *testing.T) {
	b, err := os.ReadFile("webui/index.html")
	if err != nil {
		t.Fatalf("读取 webui/index.html: %v", err)
	}
	html := string(b)
	if !strings.Contains(html, `<script src="app.js"></script>`) {
		t.Fatal(`webui/index.html 必须以 <script src="app.js"></script> 引用外部脚本`)
	}
	for _, m := range regexp.MustCompile(`(?s)(<script[^>]*>)(.*?)(</script>)`).FindAllStringSubmatch(html, -1) {
		if strings.TrimSpace(m[2]) != "" {
			t.Fatalf("webui/index.html 出现内联 <script> 代码（不在词法测试覆盖内）: %.60s…", strings.TrimSpace(m[2]))
		}
	}
}

// TestDashboardInlineJSSyntax 守护面板脚本 webui/app.js 的括号配平。
//
// I18N 对象曾少两个闭合括号：整段脚本 SyntaxError，面板只剩静态骨架，
// 而浏览器控制台只给一行 "(索引):165 Unexpected token ';'" —— 那行分号
// 本身没问题，真正错的地方在上游几十行。这里做词法层面的配平检查
// （跳过字符串与注释。脚本约定不用模板字符串——checkTernary 依赖这一点；
// 现有的两处正则字面量 /</g 与 /[:.]/g 不含花括号与引号，因此计数可靠。
// 新增正则时请保持"不含花括号与引号"这一点），
// 失败时报出每个未闭合左括号所在的文件行号，和浏览器的 "app.js:N" 对齐。
func TestDashboardInlineJSSyntax(t *testing.T) {
	js := dashboardJS(t)
	if js == "" {
		t.Fatal("webui/app.js 是空的")
	}

	openOf := map[byte]byte{'}': '{', ')': '(', ']': '['}
	stack := map[byte][]int{} // 每类未闭合左括号打开时的文件行号，顺序即嵌套顺序
	var inString byte
	line := 1
	for i := 0; i < len(js); {
		c := js[i]
		if inString != 0 {
			if c == '\\' {
				i += 2
				continue
			}
			if c == inString {
				inString = 0
			}
			if c == '\n' {
				line++
			}
			i++
			continue
		}
		switch c {
		case '\n':
			line++
		case '\'', '"', '`':
			inString = c
		case '/':
			if i+1 < len(js) && js[i+1] == '/' {
				for i += 2; i < len(js) && js[i] != '\n'; i++ {
				}
				continue
			}
			if i+1 < len(js) && js[i+1] == '*' {
				for i += 2; i+1 < len(js) && !(js[i] == '*' && js[i+1] == '/'); i++ {
					if js[i] == '\n' {
						line++
					}
				}
				i += 2
				continue
			}
		case '{', '(', '[':
			stack[c] = append(stack[c], line)
		case '}', ')', ']':
			o := openOf[c]
			if len(stack[o]) == 0 {
				t.Fatalf("文档行 %d: 多余的 '%c'（括号配平错误）", line, c)
			}
			stack[o] = stack[o][:len(stack[o])-1]
		}
		i++
	}
	if inString != 0 {
		t.Fatalf("文档行 %d: 字符串未闭合", line)
	}
	for c, lines := range stack {
		if len(lines) == 0 {
			continue
		}
		t.Errorf("文档行 %v 处的 '%c' 从未闭合（对应浏览器 (索引):N Unexpected token）", lines, c)
	}
}

// TestDashboardNoAdjacentStrings 守护"两个字符串字面量直接相邻"。
//
// 这类写法在 JS 里永远是语法错误，浏览器报 "(索引):N Unexpected string"，
// 整段脚本失效、面板只剩静态骨架。
//
// 它真的发生过：dashboardHTML 是 Go 原始字符串（反引号定界），不做任何转义，
// 于是想往 onclick 属性里输出 \' 时写成了 \\ '。JS 把 \\ 读成一个反斜杠，
// 紧随的那个 ' 就提前结束了字符串字面量，剩下的内容变成一串裸字面量：
//
//	'<button ... kickClient(\'   +id+   \')"  )  "  >   ...
//
// 括号恰好仍然配平，TestDashboardInlineJSSyntax 抓不到，面板就是这么坏的。
func TestDashboardNoAdjacentStrings(t *testing.T) {
	js := dashboardJS(t)
	if js == "" {
		t.Fatal("webui/app.js 是空的")
	}

	// skipInsignificant 跳过空白与注释，返回下一个有效字符的位置；到结尾返回 -1。
	// 注释要跳过，否则 "'a' /* x */ 'b'" 这种合法写法会被误判为相邻字面量。
	skipInsignificant := func(from, line int) (int, int) {
		i := from
		for i < len(js) {
			switch {
			case js[i] == ' ' || js[i] == '\t' || js[i] == '\r':
				i++
			case js[i] == '\n':
				line++
				i++
			case js[i] == '/' && i+1 < len(js) && js[i+1] == '/':
				for i < len(js) && js[i] != '\n' {
					i++
				}
			case js[i] == '/' && i+1 < len(js) && js[i+1] == '*':
				i += 2
				for i+1 < len(js) && !(js[i] == '*' && js[i+1] == '/') {
					if js[i] == '\n' {
						line++
					}
					i++
				}
				i += 2
			default:
				return i, line
			}
		}
		return -1, line
	}

	var inString byte
	line := 1
	for i := 0; i < len(js); {
		c := js[i]
		if inString != 0 {
			switch {
			case c == '\\': // 转义对：整体跳过，不触碰反斜杠后的字符
				i += 2
			case c == '\n':
				line++
				i++
			case c == inString:
				inString = 0
				j, nl := skipInsignificant(i+1, line)
				if j >= 0 && (js[j] == '\'' || js[j] == '"' || js[j] == '`') {
					t.Fatalf("文档行 %d: 字符串字面量后紧跟另一个字符串字面量（浏览器报 Unexpected string，整段脚本失效）", nl)
				}
				i++
			default:
				i++
			}
			continue
		}
		switch {
		case c == '\n':
			line++
		case c == '\'' || c == '"' || c == '`':
			inString = c
		}
		i++
	}
	if inString != 0 {
		t.Fatalf("文档行 %d: 字符串未闭合", line)
	}
}

func TestDashboardEscapesHTMLAndAttributeDelimiters(t *testing.T) {
	js := dashboardJS(t)
	for _, token := range []string{`replace(/&/g,'&amp;')`, `replace(/</g,'&lt;')`, `replace(/>/g,'&gt;')`, `replace(/\x22/g,'&quot;')`, `replace(/\x27/g,'&#39;')`} {
		if !strings.Contains(js, token) {
			t.Fatalf("dashboard esc() missing %q", token)
		}
	}
}

func TestDashboardRendersServerObservedTLS(t *testing.T) {
	js := dashboardJS(t)
	for _, token := range []string{
		"fingerprint_sha256", "fingerprint_kind", "cipher_suite_id", "offered_cipher_suites",
		"ClientHello fingerprint (not JA3/JA4)",
	} {
		if !strings.Contains(js, token) {
			t.Fatalf("dashboard does not render server-observed TLS field %q", token)
		}
	}
	// 这些值来自对端 ClientHello，必须经过 mtxt/esc 后才允许进入 innerHTML。
	for _, token := range []string{"mtxt(tls.fingerprint_kind+':'+tls.fingerprint_sha256)", "mtxt(tls.cipher_suite", "mtxt(tls.sni)"} {
		if !strings.Contains(js, token) {
			t.Fatalf("server-observed TLS value is not HTML escaped via %q", token)
		}
	}
}

// TestDashboardThemeSyncRedrawsBothCharts 守护主题切换时两张画布都会被重画。
//
// 画布颜色是烘焙进像素的：cssv 把 CSS 变量读出来写死进 canvas，主题一变不重画
// 就继续顶着旧配色。系统偏好变更这条分支只调过 redrawChart()——它只画趋势图，
// 流量图会一直显示旧主题，直到下一轮轮询或用户手动操作。手动点亮/暗不受影响
// （setTheme 两张都画），所以这个错只藏在 Auto 跟随系统的路径里，只有操作系统
// 自己切深浅色时才现形。
//
// 修法是把 dataset.theme 的赋值收进 applyTheme 一处，并让它同时重画两张；手动
// 切换、系统偏好变更、applyI18n 三条入口都收敛到 applyTheme，没有第四处能改主题。
func TestDashboardThemeSyncRedrawsBothCharts(t *testing.T) {
	js := dashboardJS(t)

	// 唯一赋值点：任何绕过 applyTheme 直接改主题的写法都会被这里挡住
	if n := strings.Count(js, "dataset.theme="); n != 1 {
		t.Fatalf("dataset.theme 应只在 applyTheme 里赋值一次，实际 %d 处", n)
	}

	// 重画必须覆盖两张画布：趋势图在 #chart，流量图在 #traffic-chart
	if !strings.Contains(js, "function redrawCharts(){redrawChart();if(lastTraffic)drawTrafficChart(lastTraffic.daily||[]);}") {
		t.Fatal("redrawCharts 必须同时重画趋势图与流量图")
	}
	// 系统偏好变更要经过 applyTheme，而不是自己挑一张图画
	if !strings.Contains(js, "if(THEME==='system')applyTheme();") {
		t.Fatal("prefers-color-scheme 变更必须走 applyTheme，否则只重画一张画布")
	}

	start := strings.Index(js, "function applyTheme(){")
	if start < 0 {
		t.Fatal("app.js 缺少 applyTheme")
	}
	block := js[start : strings.Index(js[start:], "\nfunction ")+start]
	for _, token := range []string{"dataset.theme=", "setSeg('theme-seg',THEME);", "redrawCharts();"} {
		if !strings.Contains(block, token) {
			t.Fatalf("applyTheme 必须同时完成 %q", token)
		}
	}
}

// TestDashboardAbsentFieldsDoNotAssertEmptyState 守护"字段缺位"和"确实为空"的区分。
//
// 服务端不下发的字段与"下发但为空"是两回事：前者是能力缺失（含老版本二进制），
// 后者是运行结果。混为一谈的后果很具体——客户端表明确列着 2 个 MAC 的同屏上，
// MAC 表却写着"尚未学习到 MAC"；Brutal 面板更糟，按缺省值补齐成开关=否、
// 已生效 0/0，同时挂着一个"全部生效"的绿灯。
func TestDashboardAbsentFieldsDoNotAssertEmptyState(t *testing.T) {
	js := dashboardJS(t)

	// Brutal 的"配置意图 + 内核实际状态"是整份数据，缺位时必须走空态
	if !strings.Contains(js, "kv(document.getElementById('st-brutal'),!!neg.brutal?[") {
		t.Fatal("st-brutal 必须用 !!neg.brutal 判断字段是否存在，缺位时不能渲染缺省值")
	}
	if !strings.Contains(js, "[[t('ov.no_data'),ntxt()]]);") {
		t.Fatal("Brutal 缺位时应渲染 no_data 空态")
	}

	// "全部生效"只在确实有连接被塑形时成立：报错列表空只是 omitempty 把字段丢了
	start := strings.Index(js, "function brutErrCell(b){")
	if start < 0 {
		t.Fatal("app.js 缺少 brutErrCell")
	}
	block := js[start : strings.Index(js[start:], "\nfunction ")+start]
	if !strings.Contains(block, "if(b.total_conns>0)return") {
		t.Fatal("brutErrCell 应只在 total_conns>0 时给绿灯")
	}
	if !strings.Contains(block, "b.errors&&b.errors.length") {
		t.Fatal("brutErrCell 应先展示非空报错列表")
	}
	if !strings.Contains(js, "[t('stt.brut.errs'),brutErrCell(b)],") {
		t.Fatal("Brutal 失败原因行必须走 brutErrCell")
	}

	// MAC 表与封禁表：字段缺位走 no_data，真的为空才走 no_macs / no_bans
	if !strings.Contains(js, "emptyTableRow(data.mac_table?'macs':'nodata',3,all.length)") {
		t.Fatal("macs 空态必须区分字段缺位与真的为空")
	}
	if !strings.Contains(js, "emptyRow('bans',3,data.banned?t('no_bans'):t('ov.no_data'))") {
		t.Fatal("bans 空态必须区分字段缺位与真的为空")
	}
	if !strings.Contains(js, "nodata:'ov.no_data'") {
		// 键名必须是 ov.no_data：no_data 只定义在 ov 块里，裸键 t() 会原样泄漏成 "no_data"
		t.Fatal("NO_TXT 缺少 nodata:'ov.no_data'")
	}

	// 最近错误列没有错误时给占位符，而不是留一个看得见但没内容的格子
	if !strings.Contains(js, "const cerr=r.err||r.brutErr;") {
		t.Fatal("最近错误列缺少 cerr 取值")
	}
	if !strings.Contains(js, `errCell=cerr?'<span style="color:var(--err)"`) {
		t.Fatal("最近错误列有错误时未走红色样式")
	}
}

// TestDashboardTernaryBalance 守护三元条件的括号深度配平。
//
// 这类错配平检查完全放过：`((a||0)>0?((b).toFixed(1)+' MB':'-')` 里 `?` 留在外层
// 括号、`:` 被推进内层括号，括号和引号全都配平，而 V8 报
// "(索引):N Unexpected token ':'" 直接判死整段脚本，面板只剩静态骨架、
// 一次网络请求都不发（Rust 仓库真出过这个事故）。
//
// 合法 JS 里 `?` 和它的 `:` 必定处在同一层括号深度上，所以每层括号单独计数、
// 互不继承——继承了就把错层配平当成合法。三种不是三元冒号的情况要排除：
//   - 对象字面量的属性冒号，以及 switch 的 case/default 标签；
//   - 可选链 ?. 与空值合并 ??（两个 '?' 都不是条件运算）。
//
// 对象字面量里的属性冒号和三元冒号在同一括号深度上长得一模一样
// （`{a: x?y:z}` 与 `?{a:1}` 都有深度 0 的 ':'），靠"开这个字面量时同层已经
// 有多少未配对的 ?"分开：字面量里自己开出来的 '?' 才算三元。
func TestDashboardTernaryBalance(t *testing.T) {
	js := dashboardJS(t)
	if err := checkTernary(js, 1); err != "" {
		t.Fatalf("webui/app.js 三元配对错误：%s", err)
	}

	cases := []struct {
		name    string
		js      string
		wantErr bool
	}{
		{"错层三元", "[\n  ['a',(m||0)>0?((m).toFixed(1)+' MB':'-')+' / '+(n>0?n:'-')],\n];\n", true},
		{"配平正确", "[\n  ['a',(m>0?m.toFixed(1)+' MB':'-')+' / '+(n>0?n:'-')],\n];\n", false},
		{"分支加括号", "const s=(a?(b):(c))+' / '+(d?e:f);\n", false},
		{"分支是对象字面量", "const H=(u||p)?{A:'x'+u}:{};\n", false},
		{"属性值是三元", "const k={a:b!==undefined?b:c,d:e?f:g};\n", false},
		{"标签与可选链", "switch(k){case 1:a;break;default:a;break;}\nb?.c\nc??d\n", false},
		{"正则含冒号", "s.replace(/[:.]/g,'-')+' / '+(b?c:d);\n", false},
		// 下面这一组钉住「除号之后那个字符被跳掉」这类漏字符缺陷：Rust 仓库的检查器
		// 在 '/' 分支里自己递增过下标，循环末尾又递增一次，把 `i/(MAXPTS-1)*W` 的 `(`
		// 整个吃掉，于是它配对的 `)` 落到空栈上，误报「多余的 )」——脚本文本本身合法。
		// 这里保持 '/' 分支只在注释/正则时递增、普通除法一律落到循环末尾那一次 i++。
		{"除法后紧跟括号", "const x=i/(MAXPTS-1)*W;\n", false},
		{"嵌套除法", "const x=a/(b/(c-1))*2;\n", false},
		{"连续除法", "const x=a/b/c*(d+e);\n", false},
		{"括号后接属性", "const x=a/(b).toFixed(1);\n", false},
		{"括号后接下标", "const x=a/(b)[0];\n", false},
		{"除号后接注释与正则", "a/=b;// 注释(里有\na/=b;/* 注释(里有 */s.replace(/[:.]/g,'-')\n", false},
		{"多余冒号", "const s=(a:b);\n", true},
		{"漏了冒号", "const s=a?b;\n", true},
		{"括号配平但漏了冒号", "const s=(a?b);\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkTernary(tc.js, 1)
			if (err != "") != tc.wantErr {
				t.Fatalf("期望 err=%v，实际 %q", tc.wantErr, err)
			}
		})
	}
}

// checkTernary 返回第一个三元配对错误的描述，没有错误返回空串。docLine0 是脚本
// 正文第一行对应的文档行号，报错行号从它开始算。
//
// 前提（与 TestDashboardInlineJSSyntax 一致）：脚本约定不用模板字符串；
// 正则字面量不含花括号与引号，按普通字符处理即可。
func checkTernary(js string, docLine0 int) string {
	// qOpen[d] = 第 d 层括号里还没配上 ':' 的 '?' 所在文档行号。
	// 新开括号必须另起一层，不能继承外层——合法 JS 里 '?' 和它的 ':' 一定在同一层。
	qOpen := [][]int{{}}
	// braceScope 记录每个花括号的作用域。obj 为真表示它在自己的括号深度上抑制 ':'
	// （对象字面量的属性冒号 / switch 的 case 标签），qAtOpen 是开它时同层已有的
	// 未配对 '?' 数，用来把属性冒号和字面量内部的三元冒号分开。
	type braceScope struct {
		depth   int
		obj     bool
		qAtOpen int
	}
	var scopes []braceScope
	var lastSig byte
	var ident strings.Builder
	casePending := -1 // `case` 出现的括号深度，-1 = 没有
	switchPending := false
	var inString byte
	inLineCT, inBlockCT := false, false
	line := docLine0

	for i := 0; i < len(js); {
		c := js[i]
		if c == '\n' {
			line++
		}
		if inString != 0 {
			if c == '\\' {
				i += 2
				continue
			}
			if c == inString {
				inString = 0
			}
			i++
			continue
		}
		if inLineCT {
			if c == '\n' {
				inLineCT = false
			}
			i++
			continue
		}
		if inBlockCT {
			if c == '*' && i+1 < len(js) && js[i+1] == '/' {
				inBlockCT = false
				i += 2
				continue
			}
			i++
			continue
		}

		// 标识符字符先累积：case / default / return / switch 都要靠它们区分
		if isIdentChar(c) {
			ident.WriteByte(c)
			lastSig = c
			i++
			continue
		}
		prevIdent := ident.String()
		ident.Reset()
		// 花括号分类要看「上一个有效字符」，而下面的赋值会把它覆盖成当前字符
		prevSig := lastSig
		depth := len(qOpen) - 1
		if !isBlank(c) {
			lastSig = c
		}

		// `case` 后面是 case 表达式，再接的 ':' 是标签；语句结束符让两个
		// pending 状态失效，别把它们带出当前语句
		if prevIdent == "case" {
			casePending = depth
		}
		if c == ';' {
			casePending = -1
			switchPending = false
		}

		if c == '?' {
			nxt := byte(0)
			if i+1 < len(js) {
				nxt = js[i+1]
			}
			if nxt == '?' {
				// ?? 是空值合并，两个 '?' 一起跳过，否则第二个会被当成条件运算
				i += 2
				continue
			}
			if nxt != '.' {
				top := len(qOpen) - 1
				qOpen[top] = append(qOpen[top], line)
			}
		} else if c == ':' {
			label := prevIdent == "default" || casePending == depth
			casePending = -1
			prop := false
			if n := len(scopes); n > 0 {
				s := scopes[n-1]
				prop = s.obj && s.depth == depth && len(qOpen[depth]) <= s.qAtOpen
			}
			if !label && !prop {
				top := len(qOpen) - 1
				if len(qOpen[top]) == 0 {
					return fmt.Sprintf(
						"文档行 %d: 多余的 ':'（三元的 `?` 不在同一层括号里，V8 报 Unexpected token ':' 并使整段脚本失效）…%s",
						line, ctx(js, i))
				}
				qOpen[top] = qOpen[top][:len(qOpen[top])-1]
			}
		} else if c == '\'' || c == '"' || c == '`' {
			inString = c
		} else if c == '/' {
			if i+1 < len(js) && js[i+1] == '/' {
				inLineCT = true
				i += 2
				continue
			}
			if i+1 < len(js) && js[i+1] == '*' {
				inBlockCT = true
				i += 2
				continue
			}
			// 正则字面量：字面量本体里可以出现 ':' 与 '?'（本脚本就有
			// replace(/[:.]/g,…)），按除法处理会把字符类里的冒号算成三元冒号
			if startsRegex(prevSig, prevIdent) {
				i++
				inClass := false
				for i < len(js) {
					cc := js[i]
					if cc == '\\' {
						i += 2
						continue
					}
					if cc == '\n' {
						line++
					}
					if inClass {
						inClass = cc != ']'
						i++
						continue
					}
					i++
					if cc == '/' {
						break
					}
					if cc == '[' {
						inClass = true
					}
				}
				continue
			}
		} else if c == '{' {
			// 控制流块的花括号跟在 ) ; } > 或标识符（if/for/else/catch…）后面；
			// 跟在 ( = , : ? ! & | + - * 后面的才是对象字面量
			isObj := prevSig == '(' || prevSig == '=' || prevSig == ',' || prevSig == ':' ||
				prevSig == '?' || prevSig == '!' || prevSig == '&' || prevSig == '|' ||
				prevSig == '+' || prevSig == '-' || prevSig == '*' ||
				prevIdent == "return" || prevIdent == "yield"
			sw := switchPending
			switchPending = false
			scopes = append(scopes, braceScope{
				depth:   depth,
				obj:     isObj || sw,
				qAtOpen: len(qOpen[depth]),
			})
		} else if c == '(' {
			qOpen = append(qOpen, []int{})
			// `switch(k){` 到这里时标识符已经消耗掉了，先记着等花括号用
			switchPending = prevIdent == "switch"
		} else if c == '}' {
			if n := len(scopes); n > 0 {
				scopes = scopes[:n-1]
			}
			casePending = -1
			switchPending = false
		} else if c == ')' {
			if len(qOpen) > 1 {
				// 这层括号关闭时 '?' 还没配上 ':'。合法 JS 里 '?' 和 ':' 同层，
				// 所以一定是漏了 ':'（`(a?b)`）。错层的 ':' 在上面那个分支先报，
				// 到这里还剩下的就是纯粹没写完的三元
				leftover := qOpen[len(qOpen)-1]
				qOpen = qOpen[:len(qOpen)-1]
				if len(leftover) > 0 {
					return fmt.Sprintf("文档行 %v: 未闭合的三元条件（`?` 之后没有配对的 `:`）", leftover)
				}
			}
		}
		i++
	}

	if inString != 0 {
		return fmt.Sprintf("文档行 %d: 字符串未闭合", line)
	}
	if inBlockCT {
		return fmt.Sprintf("文档行 %d: 块注释未闭合", line)
	}
	if last := qOpen[len(qOpen)-1]; len(last) > 0 {
		return fmt.Sprintf("文档行 %v: 未闭合的三元条件（`?` 之后没有配对的 `:`）", last)
	}
	return ""
}

func isIdentChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

func isBlank(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

// startsRegex 判断这个 '/' 是正则字面量的开头还是除法运算符。正则的本体可以含 ':' 与 '?'，
// 当成除号处理就会把三元冒号算错。
//
// 规则：前面一个 token 是标识符或数字、或者由 ) ] 收尾时是除法（H*i/4、a&&b/c）；
// 其余情况按正则处理。前面是 return / typeof 这类关键字时也是正则——它们虽然是
// 标识符，但语法上后面只能是表达式。
func startsRegex(prevSig byte, prevIdent string) bool {
	if prevSig == ')' || prevSig == ']' {
		return false
	}
	switch prevIdent {
	case "", "return", "typeof", "instanceof", "case", "delete", "void", "new",
		"in", "of", "do", "else", "throw", "yield", "await":
		return true
	}
	return false
}

// ctx 返回 pos 附近的一段脚本原文，换行折成空格，方便把报错行号对到具体代码
func ctx(js string, pos int) string {
	from := pos - 60
	if from < 0 {
		from = 0
	}
	to := pos + 60
	if to > len(js) {
		to = len(js)
	}
	s := js[from:to]
	s = strings.ReplaceAll(s, "\n", " ")
	return " " + s + " "
}
