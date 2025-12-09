package redirect

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
	"veo/pkg/utils/shared"
)

var (
	scriptContentRe        = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script>`)
	scriptStripRe          = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script>`)
	htmlTagRe              = regexp.MustCompile(`(?is)<[^>]+>`)
	jsSingleLineCommentRe  = regexp.MustCompile(`(?m)//.*$`)
	jsMultiLineCommentRe   = regexp.MustCompile(`(?s)/\*.*?\*/`)
	jsLocationAssignRe     = regexp.MustCompile(`(?is)(?:window|self|top|parent|document)\s*\.\s*location(?:\.href)?\s*=\s*['"]([^'"]+)['"]`)
	jsBareLocationAssignRe = regexp.MustCompile(`(?is)\blocation(?:\.href)?\s*=\s*['"]([^'"]+)['"]`)
	jsLocationFuncRe       = regexp.MustCompile(`(?is)(?:window|self|top|parent|document)\s*\.\s*location\.(?:replace|assign)\(\s*['"]([^'"]+)['"]\s*\)`)

	redirectTextIndicators    = []string{"redirect", "redirecting", "object moved", "click", "这里", "点击", "跳转", "正在跳转", "即将跳转", "页面跳转"}
	scriptExecutionIndicators = []string{
		"settimeout",
		"setinterval",
		"window.onload",
		"document.onreadystatechange",
		"addEventListener('load",
		"attachEvent('onload",
	}
	scriptUserActionIndicators = []string{
		"onclick",
		"ondblclick",
		"onchange",
		"onsubmit",
		"onkeydown",
		"onkeyup",
		"addEventListener('click",
		"addEventListener('submit",
	}
	maxRedirectTextRuneCount  = 160
	maxTrustedScriptRuneCount = 240
)

// HTTPFetcher 定义最小化HTTP客户端接口，供重定向跟随使用。
type HTTPFetcher interface {
	MakeRequest(rawURL string) (body string, statusCode int, err error)
}

// HTTPFetcherFull 扩展的HTTP客户端接口，支持返回响应头。
type HTTPFetcherFull interface {
	MakeRequestFull(rawURL string) (body string, statusCode int, headers map[string][]string, err error)
}

// Config 跳转跟随配置
type Config struct {
	MaxRedirects   int  // 最大跳转次数
	FollowRedirect bool // 是否跟随跳转
	SameHostOnly   bool // 是否限制同域名/子域名跳转
}

// DefaultConfig 默认配置
func DefaultConfig() *Config {
	return &Config{
		MaxRedirects:   5,
		FollowRedirect: true,
		SameHostOnly:   true,
	}
}

// IsRedirectStatus checks if the status code indicates a redirect.
func IsRedirectStatus(code int) bool {
	return code == 301 || code == 302 || code == 303 || code == 307 || code == 308
}

// GetHeaderFirst safely retrieves the first value for a header key.
func GetHeaderFirst(headers map[string][]string, key string) string {
	if headers == nil {
		return ""
	}
	if vals, ok := headers[key]; ok && len(vals) > 0 {
		return vals[0]
	}
	lowerKey := strings.ToLower(key)
	for k, vals := range headers {
		if strings.ToLower(k) == lowerKey && len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

// detectJSRedirectURL 提取脚本中的跳转URL，并通过启发式降低误判
func detectJSRedirectURL(body string) string {
	scripts := scriptContentRe.FindAllStringSubmatch(body, -1)
	if len(scripts) == 0 {
		return ""
	}

	hasIndicator := hasRedirectIndicators(body)

	for _, match := range scripts {
		if len(match) < 2 {
			continue
		}
		script := strings.TrimSpace(match[1])
		if script == "" {
			continue
		}

		cleaned := stripJSComments(script)
		if cleaned == "" {
			continue
		}

		if !shouldTrustJSRedirect(cleaned, hasIndicator) {
			continue
		}

		if url := extractLocationFromScript(cleaned); url != "" {
			return url
		}
	}

	return ""
}

func stripJSComments(script string) string {
	noSingle := jsSingleLineCommentRe.ReplaceAllString(script, "")
	noMulti := jsMultiLineCommentRe.ReplaceAllString(noSingle, "")
	return strings.TrimSpace(noMulti)
}

func extractLocationFromScript(script string) string {
	patterns := []*regexp.Regexp{
		jsLocationFuncRe,
		jsLocationAssignRe,
		jsBareLocationAssignRe,
	}

	for _, re := range patterns {
		if re == nil {
			continue
		}
		if idx := re.FindStringSubmatch(script); len(idx) >= 2 {
			// idx[1] contains the captured URL because regexp patterns only use a single capturing group now.
			return strings.TrimSpace(idx[1])
		}
	}

	return ""
}

func shouldTrustJSRedirect(script string, hasIndicator bool) bool {
	runeCount := utf8.RuneCountInString(script)
	if runeCount == 0 || runeCount > maxTrustedScriptRuneCount {
		return false
	}

	lower := strings.ToLower(script)

	if hasIndicator {
		return true
	}

	if containsAny(lower, scriptExecutionIndicators) {
		return true
	}

	if looksLikeImmediateLocationAssign(script, lower) {
		return true
	}

	return false
}

func looksLikeImmediateLocationAssign(script, lower string) bool {
	if !(jsLocationAssignRe.MatchString(script) || jsBareLocationAssignRe.MatchString(script) || jsLocationFuncRe.MatchString(script)) {
		return false
	}

	if containsAny(lower, scriptUserActionIndicators) {
		return false
	}

	if strings.Contains(lower, "=>") {
		return false
	}

	if strings.Contains(lower, "function") {
		// 允许 IIFE 或显式 onload 触发器
		hasIIFE := strings.Contains(lower, "function(){") && strings.Contains(lower, "}();")
		hasWrappedIIFE := strings.Contains(lower, "(function") && strings.Contains(lower, "})(")
		hasLoadHook := containsAny(lower, scriptExecutionIndicators)
		if !(hasIIFE || hasWrappedIIFE || hasLoadHook) {
			return false
		}
	}

	return true
}

func containsAny(haystack string, needles []string) bool {
	if haystack == "" {
		return false
	}
	for _, needle := range needles {
		if needle == "" {
			continue
		}
		if strings.Contains(haystack, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func hasRedirectIndicators(body string) bool {
	withoutScripts := scriptStripRe.ReplaceAllString(body, " ")
	plain := htmlTagRe.ReplaceAllString(withoutScripts, " ")
	plain = strings.ToLower(strings.TrimSpace(plain))

	if plain == "" {
		return false
	}

	runes := []rune(plain)
	if len(runes) > maxRedirectTextRuneCount {
		plain = string(runes[:maxRedirectTextRuneCount])
	}

	for _, indicator := range redirectTextIndicators {
		if strings.Contains(plain, strings.ToLower(indicator)) {
			return true
		}
	}

	return false
}

// ResolveRedirectURL 将相对/协议相对URL解析为绝对地址。
func ResolveRedirectURL(baseRaw, ref string) string {
	ref = strings.TrimSpace(ref)
	if baseRaw == "" || ref == "" {
		return ""
	}

	// If already absolute, return as is
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}

	base, err := url.Parse(baseRaw)
	if err != nil {
		return ""
	}

	if strings.HasPrefix(ref, "//") {
		ref = base.Scheme + ":" + ref
	}

	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}

	return base.ResolveReference(u).String()
}

// ShouldFollowRedirect 判断是否应该跟随重定向（同主机/域名检查）
func ShouldFollowRedirect(currentURL, nextURL string) bool {
	u1, err := url.Parse(currentURL)
	if err != nil {
		return false
	}
	u2, err := url.Parse(nextURL)
	if err != nil {
		return false
	}

	h1 := strings.ToLower(u1.Hostname())
	h2 := strings.ToLower(u2.Hostname())

	// 1. 完全相同
	if h1 == h2 {
		return true
	}

	// 2. 检查是否为主域名相同的子域名关系 (Containment)
	// 满足需求：example.com -> sub.example.com (h2 ends with .h1)
	// 反向也允许：sub.example.com -> example.com (h1 ends with .h2)
	if strings.HasSuffix(h2, "."+h1) || strings.HasSuffix(h1, "."+h2) {
		return true
	}

	return false
}

// Execute 执行请求并处理跳转逻辑（整合了HTTP 3xx和客户端跳转）
func Execute(rawURL string, fetcher HTTPFetcherFull, config *Config) (*interfaces.HTTPResponse, error) {
	if config == nil {
		config = DefaultConfig()
	}

	currentURL := rawURL
	var response *interfaces.HTTPResponse
	var redirectCount int

	// 循环处理跳转
	for {
		// 1. 发起请求
		body, statusCode, headers, err := fetcher.MakeRequestFull(currentURL)
		if err != nil {
			return nil, err
		}

		// 构建基础响应对象
		response = &interfaces.HTTPResponse{
			URL:             currentURL,
			Method:          "GET",
			StatusCode:      statusCode,
			Body:            body,
			ResponseBody:    body,
			ResponseHeaders: headers,
			ContentLength:   int64(len(body)),
			Length:          int64(len(body)),
			IsDirectory:     strings.HasSuffix(currentURL, "/"),
			ContentType:     GetHeaderFirst(headers, "Content-Type"),
		}

		// 提取标题
		titleExtractor := shared.NewTitleExtractor()
		response.Title = titleExtractor.ExtractTitle(body)

		// 如果不跟随重定向，直接返回
		if !config.FollowRedirect {
			return response, nil
		}

		// 检查是否达到最大重定向次数
		if redirectCount >= config.MaxRedirects {
			logger.Warnf("超过最大重定向次数(%d): %s", config.MaxRedirects, currentURL)
			return response, nil
		}

		var nextURL string
		isRedirect := false

		// 2. 检查 HTTP 3xx 重定向
		if IsRedirectStatus(statusCode) {
			loc := GetHeaderFirst(headers, "Location")
			if loc != "" {
				nextURL = ResolveRedirectURL(currentURL, loc)
				if nextURL != "" {
					isRedirect = true
					logger.Debugf("捕获HTTP重定向 %d: %s -> %s", statusCode, currentURL, nextURL)
				}
			}
		}

		// 3. 如果不是HTTP重定向，检查客户端跳转 (Meta/JS)
		// 对所有非 3xx（isRedirect=false）且有Body的响应进行检查
		if !isRedirect && statusCode >= 200 {
			redirectLink := DetectClientRedirectURL(body)
			if redirectLink != "" {
				resolvedURL := ResolveRedirectURL(currentURL, redirectLink)
				if resolvedURL != "" {
					nextURL = resolvedURL
					isRedirect = true
					logger.Debugf("捕获客户端重定向: %s -> %s", currentURL, nextURL)
				}
			}
		}

		// 如果没有检测到任何跳转，结束
		if !isRedirect {
			return response, nil
		}

		// 4. 安全检查：同域/子域限制
		if config.SameHostOnly && !ShouldFollowRedirect(currentURL, nextURL) {
			logger.Debugf("放弃跨主机重定向: %s -> %s", currentURL, nextURL)
			return response, nil
		}

		// 5. 准备下一次循环
		redirectCount++
		currentURL = nextURL
	}
}

// FollowClientRedirect 检测并跟随客户端（HTML/JS）重定向，返回新的HTTP响应。
// 若未检测到重定向或获取失败，返回nil。
// Deprecated: Use Execute instead for comprehensive redirect handling.
func FollowClientRedirect(response *interfaces.HTTPResponse, fetcher HTTPFetcher) (*interfaces.HTTPResponse, error) {
	if response == nil || fetcher == nil {
		return nil, nil
	}

	redirectBody := response.ResponseBody
	if redirectBody == "" {
		redirectBody = response.Body
	}
	if strings.TrimSpace(redirectBody) == "" {
		return nil, nil
	}

	redirectURL := DetectClientRedirectURL(redirectBody)
	if redirectURL == "" {
		return nil, nil
	}

	absoluteURL := ResolveRedirectURL(response.URL, redirectURL)
	if absoluteURL == "" {
		return nil, fmt.Errorf("无法解析客户端重定向URL: %s", redirectURL)
	}

	var body string
	var statusCode int
	var headers map[string][]string
	var err error

	if fullFetcher, ok := fetcher.(HTTPFetcherFull); ok {
		body, statusCode, headers, err = fullFetcher.MakeRequestFull(absoluteURL)
	} else {
		body, statusCode, err = fetcher.MakeRequest(absoluteURL)
	}

	if err != nil {
		return nil, fmt.Errorf("跟随客户端重定向失败: %w", err)
	}
	if strings.TrimSpace(body) == "" {
		return nil, fmt.Errorf("客户端重定向响应为空: %s", absoluteURL)
	}

	titleExtractor := shared.NewTitleExtractor()
	title := titleExtractor.ExtractTitle(body)

	redirected := &interfaces.HTTPResponse{
		URL:             absoluteURL,
		Method:          "GET",
		StatusCode:      statusCode,
		Body:            body,
		ResponseBody:    body,
		ContentType:     GetHeaderFirst(headers, "Content-Type"),
		ContentLength:   int64(len(body)),
		Length:          int64(len(body)),
		Title:           title,
		ResponseHeaders: headers,
		IsDirectory:     strings.HasSuffix(absoluteURL, "/"),
	}

	return redirected, nil
}

// DetectClientRedirectURL 检测HTML/JS中的客户端重定向URL。
func DetectClientRedirectURL(body string) string {
	if strings.TrimSpace(body) == "" {
		return ""
	}

	// Matches: <meta http-equiv="refresh" content="0;url=http://example.com">
	// Also handles attribute swapping: <meta content="0;url=..." http-equiv="refresh">
	// Strategy: Find <meta ...> tag, then check if it contains http-equiv="refresh" (or 'refresh') and extract url from content.
	// Since regex for unordered attributes is complex, we use a two-step approach or a more generic one.
	// Simplified approach: Look for <meta ... content="..." ...> where content contains "url=".
	// We also need to ensure it's a refresh meta tag.

	// Try standard order first
	metaRe1 := regexp.MustCompile(`(?is)<meta\s+[^>]*http-equiv\s*=\s*['"]?refresh['"]?[^>]*content\s*=\s*['"]\s*\d*\s*;\s*url\s*=\s*([^'"\s>]+)`)
	if m := metaRe1.FindStringSubmatch(body); len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}

	// Try swapped order (content first)
	metaRe2 := regexp.MustCompile(`(?is)<meta\s+[^>]*content\s*=\s*['"]\s*\d*\s*;\s*url\s*=\s*([^'"\s>]+)['"][^>]*http-equiv\s*=\s*['"]?refresh['"]?`)
	if m := metaRe2.FindStringSubmatch(body); len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}

	// Fallback: minimal match for content="...url=..." without strict http-equiv check (risky but effective for broken HTML)
	// Only if it looks like a refresh tag context
	metaRe3 := regexp.MustCompile(`(?is)<meta\s+[^>]*content\s*=\s*['"]\s*\d*\s*;\s*url\s*=\s*([^'"\s>]+)`)
	if m := metaRe3.FindStringSubmatch(body); len(m) >= 2 {
		// Verify it's likely a refresh tag by checking for "refresh" keyword in the tag
		// fullTag := m[0] // Note: this might not capture the full tag if regex is partial, but context is key.
		// Actually, let's just check if "refresh" appears in the vicinity if we want to be strict.
		// For now, let's trust url= inside a meta content is likely a redirect.
		return strings.TrimSpace(m[1])
	}

	// JavaScript-based redirect detection（增加准确性控制）
	if url := detectJSRedirectURL(body); url != "" {
		return url
	}

	// Fallback: 某些服务器直接返回文本提示 "Moved to: <a href="...">"，需要解析其中的链接
	movedToRe := regexp.MustCompile(`(?is)moved\s+to:?\s*<a\s+href=['"]([^'"]+)['"]`)
	if m := movedToRe.FindStringSubmatch(body); len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}

	return ""
}
