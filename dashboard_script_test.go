package main

import (
	"regexp"
	"strings"
	"testing"
)

// TestDashboardInlineJSSyntax 守护面板内联 <script> 的括号配平。
//
// I18N 对象曾少两个闭合括号：整段脚本 SyntaxError，面板只剩静态骨架，
// 而浏览器控制台只给一行 "(索引):165 Unexpected token ';'" —— 那行分号
// 本身没问题，真正错的地方在上游几十行。这里做词法层面的配平检查
// （跳过字符串与注释。本脚本不可能有模板字符串——dashboardHTML 由反引号定界，
// 内含反引号就无法编译；仅有的两处正则字面量 /</g 与 /[:.]/g 不含花括号与引号，
// 因此计数可靠。新增正则时请保持"不含花括号与引号"这一点），
// 失败时报出每个未闭合左括号所在的文档行号，和浏览器的 "(索引):N" 对齐。
func TestDashboardInlineJSSyntax(t *testing.T) {
	js := extractInlineScript(dashboardHTML)
	if js == "" {
		t.Fatal("dashboardHTML 里没有 <script> 块")
	}

	openOf := map[byte]byte{'}': '{', ')': '(', ']': '['}
	stack := map[byte][]int{} // 每类未闭合左括号打开时的文档行号，顺序即嵌套顺序
	var inString byte
	line := scriptDocLine(dashboardHTML, js)
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
	js := extractInlineScript(dashboardHTML)
	if js == "" {
		t.Fatal("dashboardHTML 里没有 <script> 块")
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
	line := scriptDocLine(dashboardHTML, js)
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

// extractInlineScript 取出 HTML 里第一个 <script>...</script> 的脚本正文（不含标签）。
func extractInlineScript(html string) string {
	m := regexp.MustCompile(`(?s)(<script[^>]*>)(.*?)(</script>)`).FindStringSubmatch(html)
	if m == nil {
		return ""
	}
	return m[2]
}

// scriptDocLine 返回脚本正文第一个字符（通常是标签后的换行）所在的文档行号，
// 调用方从这一行开始逐行计数。
func scriptDocLine(html, js string) int {
	return strings.Count(html[:strings.Index(html, js)], "\n") + 1
}
