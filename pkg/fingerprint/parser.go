package fingerprint

import (
	"regexp"
	"strconv"
	"strings"
	"veo/pkg/utils/logger"
)

var (
	snippetSpaceRegex   = regexp.MustCompile(`[ \t]+`)
	snippetNewlineRegex = regexp.MustCompile(`\n+`)
)

// DSL解析器实现

// NewDSLParser 创建DSL解析器
func NewDSLParser() *DSLParser {
	return &DSLParser{}
}

// EvaluateDSL 评估DSL表达式
func (p *DSLParser) EvaluateDSL(dsl string, ctx *DSLContext) bool {
	// 预处理DSL表达式
	dsl = strings.TrimSpace(dsl)
	if dsl == "" {
		return false
	}

	// 移除外层引号
	if (strings.HasPrefix(dsl, "\"") && strings.HasSuffix(dsl, "\"")) ||
		(strings.HasPrefix(dsl, "'") && strings.HasSuffix(dsl, "'")) {
		dsl = dsl[1 : len(dsl)-1]
	}

	// 处理逻辑运算符
	if result, ok := p.evaluateLogicalOperators(dsl, ctx); ok {
		return result
	}

	// 处理单个函数调用
	return p.evaluateSingleFunction(dsl, ctx)
}

// evaluateLogicalOperators 处理逻辑运算符 (&&, ||)
func (p *DSLParser) evaluateLogicalOperators(dsl string, ctx *DSLContext) (bool, bool) {
	// 处理 || (OR) 运算符
	if strings.Contains(dsl, "||") {
		parts := strings.Split(dsl, "||")
		for _, part := range parts {
			if p.EvaluateDSL(strings.TrimSpace(part), ctx) {
				return true, true
			}
		}
		return false, true
	}

	// 处理 && (AND) 运算符
	if strings.Contains(dsl, "&&") {
		parts := strings.Split(dsl, "&&")
		for _, part := range parts {
			if !p.EvaluateDSL(strings.TrimSpace(part), ctx) {
				return false, true
			}
		}
		return true, true
	}

	return false, false
}

// evaluateSingleFunction 处理单个函数调用
func (p *DSLParser) evaluateSingleFunction(dsl string, ctx *DSLContext) bool {
	// contains() 函数
	if result, ok := p.evaluateContains(dsl, ctx); ok {
		return result
	}

	// regex() 函数
	if result, ok := p.evaluateRegex(dsl, ctx); ok {
		return result
	}

	// status_code 比较
	if result, ok := p.evaluateStatusCode(dsl, ctx); ok {
		return result
	}

	// icon() 函数
	if result, ok := p.evaluateIcon(dsl, ctx); ok {
		return result
	}

	// title() 函数
	if result, ok := p.evaluateTitle(dsl, ctx); ok {
		return result
	}

	// server() 函数
	if result, ok := p.evaluateServer(dsl, ctx); ok {
		return result
	}

	// header() 函数
	if result, ok := p.evaluateHeader(dsl, ctx); ok {
		return result
	}

	// contains_all() 函数
	if result, ok := p.evaluateContainsAll(dsl, ctx); ok {
		return result
	}

	return false
}

// evaluateContains 处理 contains() 函数
func (p *DSLParser) evaluateContains(dsl string, ctx *DSLContext) (bool, bool) {
	// contains(body, 'text') 或 contains(body, 'text1', 'text2', 'text3') - 支持多个搜索文本的OR逻辑
	if strings.HasPrefix(dsl, "contains(") && strings.HasSuffix(dsl, ")") {
		content := dsl[9 : len(dsl)-1] // 移除 "contains(" 和 ")"
		parts := p.parseParameters(content)
		if len(parts) >= 2 {
			source := strings.TrimSpace(parts[0])

			var target string
			switch source {
			case "body":
				target = ctx.Body
			case "header":
				target = p.headersToString(ctx.Headers)
			case "title":
				target = ctx.Response.Title
			case "server":
				target = ctx.Response.Server
			case "url": // 新增：支持URL参数
				target = ctx.URL
			default:
				return false, true
			}

			// 转换为小写进行大小写不敏感匹配
			targetLower := strings.ToLower(target)

			// 遍历所有搜索文本，任意一个匹配即返回true（OR逻辑）
			for i := 1; i < len(parts); i++ {
				searchText := p.cleanQuotes(strings.TrimSpace(parts[i]))
				if strings.Contains(targetLower, strings.ToLower(searchText)) {
					return true, true
				}
			}

			// 所有搜索文本都不匹配
			return false, true
		}
	}
	return false, false
}

// evaluateRegex 处理 regex() 函数
func (p *DSLParser) evaluateRegex(dsl string, ctx *DSLContext) (bool, bool) {
	// regex(body, 'pattern') 或 regex('pattern')
	if strings.HasPrefix(dsl, "regex(") && strings.HasSuffix(dsl, ")") {
		content := dsl[6 : len(dsl)-1] // 移除 "regex(" 和 ")"
		parts := p.parseParameters(content)

		var target, pattern string
		if len(parts) >= 2 {
			source := strings.TrimSpace(parts[0])
			pattern = p.cleanQuotes(strings.TrimSpace(parts[1]))

			switch source {
			case "body":
				target = ctx.Body
			case "header":
				target = p.headersToString(ctx.Headers)
			case "title":
				target = ctx.Response.Title
			default:
				return false, true
			}
		} else if len(parts) == 1 {
			// 默认在body中搜索
			target = ctx.Body
			pattern = p.cleanQuotes(strings.TrimSpace(parts[0]))
		} else {
			return false, true
		}

		if compiled, err := regexp.Compile(pattern); err == nil {
			return compiled.MatchString(target), true
		}
	}
	return false, false
}

// evaluateStatusCode 处理状态码比较
func (p *DSLParser) evaluateStatusCode(dsl string, ctx *DSLContext) (bool, bool) {
	// status_code == 200, status_code != 404, etc.
	if strings.Contains(dsl, "status_code") {
		dsl = strings.ReplaceAll(dsl, " ", "")

		operators := []string{"==", "!=", ">=", "<=", ">", "<"}
		for _, op := range operators {
			if strings.Contains(dsl, "status_code"+op) {
				parts := strings.Split(dsl, "status_code"+op)
				if len(parts) == 2 {
					expectedStr := strings.TrimSpace(parts[1])
					if expected, err := strconv.Atoi(expectedStr); err == nil {
						actual := ctx.Response.StatusCode
						return p.compareNumbers(actual, expected, op), true
					}
				}
			}
		}
	}
	return false, false
}

// evaluateIcon 处理 icon() 函数（主动探测实现）
func (p *DSLParser) evaluateIcon(dsl string, ctx *DSLContext) (bool, bool) {
	// icon('/favicon.ico', 'hash')
	if strings.HasPrefix(dsl, "icon(") && strings.HasSuffix(dsl, ")") {
		content := dsl[5 : len(dsl)-1] // 移除 "icon(" 和 ")"
		parts := p.parseParameters(content)

		if len(parts) >= 2 {
			iconPath := p.cleanQuotes(strings.TrimSpace(parts[0]))
			expectedHash := p.cleanQuotes(strings.TrimSpace(parts[1]))

			// 检查是否有HTTP客户端、基础URL和Engine实例（主动探测必需）
			if ctx.HTTPClient == nil || ctx.BaseURL == "" || ctx.Engine == nil {
				logger.Debugf("icon()函数缺少必要组件，跳过主动探测")
				return false, false
			}

			// 构造完整的图标URL
			iconURL := ctx.BaseURL + iconPath

			// 先检查匹配结果缓存，避免重复比较
			if cachedMatch, exists := ctx.Engine.getIconMatchCache(iconURL, expectedHash); exists {
				logger.Debugf("icon()匹配缓存命中: %s (%s) -> %v", iconURL, expectedHash, cachedMatch)
				return cachedMatch, true
			}

			// 使用Engine的缓存机制获取图标哈希值
			actualHash, err := ctx.Engine.getIconHash(iconURL, ctx.HTTPClient)
			if err != nil {
				logger.Debugf("获取图标失败: %s, 错误: %v", iconURL, err)
				return false, false
			}

			// 比较哈希值
			match := actualHash == expectedHash
			ctx.Engine.setIconMatchCache(iconURL, expectedHash, match)
			logger.Debugf("icon()匹配: %s -> %v", iconURL, match)
			return match, true
		}
	}
	return false, false
}

// evaluateTitle 处理 title() 函数
func (p *DSLParser) evaluateTitle(dsl string, ctx *DSLContext) (bool, bool) {
	// title('text')
	if strings.HasPrefix(dsl, "title(") && strings.HasSuffix(dsl, ")") {
		content := dsl[6 : len(dsl)-1] // 移除 "title(" 和 ")"
		searchText := p.cleanQuotes(strings.TrimSpace(content))
		return strings.Contains(strings.ToLower(ctx.Response.Title), strings.ToLower(searchText)), true
	}
	return false, false
}

// evaluateServer 处理 server() 函数
func (p *DSLParser) evaluateServer(dsl string, ctx *DSLContext) (bool, bool) {
	// server('Apache')
	if strings.HasPrefix(dsl, "server(") && strings.HasSuffix(dsl, ")") {
		content := dsl[7 : len(dsl)-1] // 移除 "server(" 和 ")"
		searchText := p.cleanQuotes(strings.TrimSpace(content))
		return strings.Contains(strings.ToLower(ctx.Response.Server), strings.ToLower(searchText)), true
	}
	return false, false
}

// evaluateHeader 处理 header() 函数
func (p *DSLParser) evaluateHeader(dsl string, ctx *DSLContext) (bool, bool) {
	// header('header-name', 'value') 或 header('header-name')
	if strings.HasPrefix(dsl, "header(") && strings.HasSuffix(dsl, ")") {
		content := dsl[7 : len(dsl)-1] // 移除 "header(" 和 ")"
		parts := p.parseParameters(content)

		if len(parts) >= 1 {
			headerName := p.cleanQuotes(strings.TrimSpace(parts[0]))
			headerValue := ""
			if len(parts) >= 2 {
				headerValue = p.cleanQuotes(strings.TrimSpace(parts[1]))
			}

			values := p.getHeaderValues(ctx.Headers, headerName)
			if len(values) == 0 {
				return false, true
			}
			if headerValue == "" {
				return true, true // 只检查header是否存在
			}

			expected := strings.ToLower(headerValue)
			for _, v := range values {
				if strings.Contains(strings.ToLower(v), expected) {
					return true, true
				}
			}
			return false, true
		}
	}
	return false, false
}

// evaluateContainsAll 处理 contains_all() 函数
func (p *DSLParser) evaluateContainsAll(dsl string, ctx *DSLContext) (bool, bool) {
	// contains_all('body', 'text1', 'text2') - 检查body中是否包含所有指定文本
	if strings.HasPrefix(dsl, "contains_all(") && strings.HasSuffix(dsl, ")") {
		content := dsl[13 : len(dsl)-1] // 移除 "contains_all(" 和 ")"
		parts := p.parseParameters(content)

		if len(parts) < 2 {
			return false, true
		}

		source := strings.TrimSpace(parts[0])
		var target string

		switch source {
		case "body":
			target = ctx.Body
		case "header":
			target = p.headersToString(ctx.Headers)
		case "title":
			target = ctx.Response.Title
		case "server":
			target = ctx.Response.Server
		case "url":
			target = ctx.URL
		default:
			return false, true
		}

		targetLower := strings.ToLower(target)

		// 检查所有文本是否都在target中
		for i := 1; i < len(parts); i++ {
			searchText := p.cleanQuotes(strings.TrimSpace(parts[i]))
			if !strings.Contains(targetLower, strings.ToLower(searchText)) {
				return false, true // 有一个不包含就返回false
			}
		}

		return true, true // 所有文本都包含
	}
	return false, false
}

// 辅助方法

// parseParameters 解析函数参数
func (p *DSLParser) parseParameters(content string) []string {
	var params []string
	var current strings.Builder
	var inQuotes bool
	var quoteChar byte

	for i := 0; i < len(content); i++ {
		char := content[i]

		if !inQuotes && (char == '"' || char == '\'') {
			inQuotes = true
			quoteChar = char
			current.WriteByte(char)
		} else if inQuotes && char == quoteChar {
			inQuotes = false
			current.WriteByte(char)
		} else if !inQuotes && char == ',' {
			params = append(params, current.String())
			current.Reset()
		} else {
			current.WriteByte(char)
		}
	}

	if current.Len() > 0 {
		params = append(params, current.String())
	}

	return params
}

// cleanQuotes 清理引号
func (p *DSLParser) cleanQuotes(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"")) ||
			(strings.HasPrefix(s, "'") && strings.HasSuffix(s, "'")) {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// ExtractSnippet 根据DSL提取匹配内容片段
func (p *DSLParser) ExtractSnippet(dsl string, ctx *DSLContext) string {
	if ctx == nil {
		return ""
	}

	expr := strings.TrimSpace(dsl)
	if expr == "" {
		return ""
	}

	if (strings.HasPrefix(expr, "\"") && strings.HasSuffix(expr, "\"")) ||
		(strings.HasPrefix(expr, "'") && strings.HasSuffix(expr, "'")) {
		expr = expr[1 : len(expr)-1]
	}

	lower := strings.ToLower(expr)
	switch {
	case strings.HasPrefix(lower, "contains(") && strings.HasSuffix(expr, ")"):
		content := expr[len("contains(") : len(expr)-1]
		params := p.parseParameters(content)
		if len(params) < 2 {
			return ""
		}
		source := strings.TrimSpace(params[0])
		target := p.getTargetBySource(source, ctx)
		if target == "" {
			return ""
		}
		targetLower := strings.ToLower(target)
		for i := 1; i < len(params); i++ {
			search := p.cleanQuotes(strings.TrimSpace(params[i]))
			if search == "" {
				continue
			}
			index := strings.Index(targetLower, strings.ToLower(search))
			if index == -1 {
				continue
			}
			return p.buildSnippet(target, index, index+len(search))
		}
	case strings.HasPrefix(lower, "contains_all(") && strings.HasSuffix(expr, ")"):
		content := expr[len("contains_all(") : len(expr)-1]
		params := p.parseParameters(content)
		if len(params) < 2 {
			return ""
		}
		source := strings.TrimSpace(params[0])
		target := p.getTargetBySource(source, ctx)
		if target == "" {
			return ""
		}
		targetLower := strings.ToLower(target)
		for i := 1; i < len(params); i++ {
			search := p.cleanQuotes(strings.TrimSpace(params[i]))
			if search == "" {
				continue
			}
			index := strings.Index(targetLower, strings.ToLower(search))
			if index == -1 {
				continue
			}
			snippet := p.buildSnippet(target, index, index+len(search))
			if snippet != "" {
				return snippet
			}
		}
	case strings.HasPrefix(lower, "regex(") && strings.HasSuffix(expr, ")"):
		content := expr[len("regex(") : len(expr)-1]
		params := p.parseParameters(content)
		var target string
		var pattern string
		if len(params) >= 2 {
			source := strings.TrimSpace(params[0])
			target = p.getTargetBySource(source, ctx)
			pattern = p.cleanQuotes(strings.TrimSpace(params[1]))
		} else if len(params) == 1 {
			target = ctx.Body
			pattern = p.cleanQuotes(strings.TrimSpace(params[0]))
		}
		if target == "" || pattern == "" {
			return ""
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return ""
		}
		loc := re.FindStringIndex(target)
		if loc == nil {
			return ""
		}
		return p.buildSnippet(target, loc[0], loc[1])
	}

	return ""
}

func (p *DSLParser) getTargetBySource(source string, ctx *DSLContext) string {
	if ctx == nil {
		return ""
	}
	src := strings.ToLower(strings.TrimSpace(p.cleanQuotes(source)))
	switch src {
	case "header", "headers":
		return p.headersToString(ctx.Headers)
	case "title":
		if ctx.Response != nil {
			return ctx.Response.Title
		}
		return ""
	case "server":
		if ctx.Response != nil {
			return ctx.Response.Server
		}
		return ""
	case "url":
		return ctx.URL
	case "method":
		return ctx.Method
	default:
		return ctx.Body
	}
}

func (p *DSLParser) buildSnippet(content string, start, end int) string {
	if start < 0 || end <= start || start >= len(content) {
		return ""
	}
	if end > len(content) {
		end = len(content)
	}

	before := start - 100
	if before < 0 {
		before = 0
	}
	after := end + 100
	if after > len(content) {
		after = len(content)
	}

	var builder strings.Builder
	if before > 0 {
		builder.WriteString("...")
	}
	builder.WriteString(content[before:start])
	builder.WriteString(content[start:end])
	builder.WriteString(content[end:after])
	if after < len(content) {
		builder.WriteString("...")
	}

	return normalizeSnippet(builder.String())
}

func normalizeSnippet(snippet string) string {
	snippet = strings.ReplaceAll(snippet, "\r\n", "\n")
	snippet = strings.ReplaceAll(snippet, "\r", "\n")
	snippet = strings.ReplaceAll(snippet, "\t", " ")
	snippet = snippetSpaceRegex.ReplaceAllString(snippet, " ")
	snippet = snippetNewlineRegex.ReplaceAllString(snippet, "\n")
	return strings.TrimSpace(snippet)
}

// headersToString 将headers转换为字符串
func (p *DSLParser) headersToString(headers map[string][]string) string {
	if len(headers) == 0 {
		return ""
	}
	var sb strings.Builder
	for name, values := range headers {
		for _, value := range values {
			sb.WriteString(name)
			sb.WriteString(": ")
			sb.WriteString(value)
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

func (p *DSLParser) getHeaderValues(headers map[string][]string, name string) []string {
	if len(headers) == 0 {
		return nil
	}
	target := strings.ToLower(strings.TrimSpace(name))
	for k, values := range headers {
		if strings.ToLower(k) == target {
			return values
		}
	}
	return nil
}

// compareNumbers 比较数字
func (p *DSLParser) compareNumbers(actual, expected int, operator string) bool {
	switch operator {
	case "==":
		return actual == expected
	case "!=":
		return actual != expected
	case ">":
		return actual > expected
	case "<":
		return actual < expected
	case ">=":
		return actual >= expected
	case "<=":
		return actual <= expected
	default:
		return false
	}
}
