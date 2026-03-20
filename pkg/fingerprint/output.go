package fingerprint

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"veo/pkg/formatter"
	"veo/pkg/logger"

	"golang.org/x/net/html/charset"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// OutputFormatter 输出格式化器接口
// 负责指纹匹配结果的输出和展示,将输出职责从Engine中分离
type OutputFormatter interface {
	// FormatMatch 格式化并输出指纹匹配结果
	// matches: 匹配到的指纹列表
	// response: 对应的HTTP响应
	// tags: 可选的标签(如"主动探测"、"404探测")
	FormatMatch(matches []*FingerprintMatch, response *HTTPResponse, tags ...string)

	// FormatNoMatch 格式化并输出无匹配结果的信息
	// response: 对应的HTTP响应
	FormatNoMatch(response *HTTPResponse)

	// ShouldOutput 判断是否应该输出(用于去重控制)
	// 返回true表示应该输出,false表示应该跳过
	ShouldOutput(url string, fingerprintNames []string) bool
}

// uniqueMatchesByRuleName 对 matches 按 RuleName 去重（保留首次出现的匹配）
// 这用于修复输出层偶发的重复指纹打印问题。
func uniqueMatchesByRuleName(matches []*FingerprintMatch) []*FingerprintMatch {
	if len(matches) <= 1 {
		return matches
	}

	seen := make(map[string]struct{}, len(matches))
	unique := make([]*FingerprintMatch, 0, len(matches))
	for _, m := range matches {
		if m == nil {
			continue
		}
		name := strings.TrimSpace(m.RuleName)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		unique = append(unique, m)
	}
	return unique
}

func collectFingerprintRuleNames(matches []*FingerprintMatch) []string {
	if len(matches) == 0 {
		return nil
	}

	names := make([]string, 0, len(matches))
	for _, match := range matches {
		if match == nil {
			continue
		}
		name := strings.TrimSpace(match.RuleName)
		if name == "" {
			continue
		}
		names = append(names, name)
	}
	return names
}

// ConsoleOutputFormatter 控制台输出格式化器
// 实现基于当前逻辑的控制台输出,包含去重、日志格式化等功能
type ConsoleOutputFormatter struct {
	// 输出控制
	logMatches            bool // 是否记录匹配日志
	showSnippet           bool // 是否输出指纹匹配片段
	showRules             bool // 是否输出匹配规则内容
	consoleSnippetEnabled bool // 控制是否在控制台输出指纹匹配片段

	// 去重组件
	deduplicator *Deduplicator // 结果去重器
	onOutput     func(response *HTTPResponse, matches []*FingerprintMatch, tags []string)
}

// NewConsoleOutputFormatter 创建控制台输出格式化器
func NewConsoleOutputFormatter(logMatches, showSnippet, showRules, consoleSnippet bool) *ConsoleOutputFormatter {
	return &ConsoleOutputFormatter{
		logMatches:            logMatches,
		showSnippet:           showSnippet,
		showRules:             showRules,
		consoleSnippetEnabled: consoleSnippet,
		deduplicator:          NewDeduplicator(),
	}
}

// FormatMatch 实现OutputFormatter接口
func (f *ConsoleOutputFormatter) FormatMatch(matches []*FingerprintMatch, response *HTTPResponse, tags ...string) {
	if !f.logMatches || len(matches) == 0 || response == nil {
		return
	}

	uniqueMatches := uniqueMatchesByRuleName(matches)
	if len(uniqueMatches) == 0 {
		return
	}

	// 去重检查
	if !f.ShouldOutput(response.URL, collectFingerprintRuleNames(uniqueMatches)) {
		return
	}

	if f.onOutput != nil {
		f.onOutput(response, uniqueMatches, tags)
	}

	// 构建指纹显示列表
	fingerprintDisplays := f.buildFingerprintDisplays(uniqueMatches)

	displayURL, detailURL := formatter.SplitURLForLog(response.URL, 60)
	line := formatter.FormatLogLineWithURLSuffix(
		displayURL,
		detailURL,
		response.StatusCode,
		response.Title,
		response.ContentLength,
		response.ContentType,
		fingerprintDisplays,
		true,
		tags...,
	)

	logger.Info(line)

	// 输出snippet(如果启用)
	if f.consoleSnippetEnabled && f.showSnippet {
		f.outputSnippets(uniqueMatches)
	}
}

// FormatNoMatch 实现OutputFormatter接口
func (f *ConsoleOutputFormatter) FormatNoMatch(response *HTTPResponse) {
	if !f.logMatches {
		return
	}

	// 去重检查(无指纹的URL)
	if !f.ShouldOutput(response.URL, nil) {
		return
	}

	if f.onOutput != nil {
		f.onOutput(response, nil, nil)
	}

	displayURL, detailURL := formatter.SplitURLForLog(response.URL, 60)
	line := formatter.FormatLogLineWithURLSuffix(
		displayURL,
		detailURL,
		response.StatusCode,
		response.Title,
		response.ContentLength,
		response.ContentType,
		nil,
		false,
	)

	logger.Info(line)
}

// ShouldOutput 实现OutputFormatter接口
func (f *ConsoleOutputFormatter) ShouldOutput(urlStr string, fingerprintNames []string) bool {
	return f.deduplicator.ShouldOutput(urlStr, fingerprintNames)
}

// buildFingerprintDisplays 构建指纹显示列表
func (f *ConsoleOutputFormatter) buildFingerprintDisplays(matches []*FingerprintMatch) []string {
	displays := make([]string, 0, len(matches))
	for _, match := range matches {
		if match == nil {
			continue
		}
		display := f.formatFingerprintDisplay(match.RuleName, match.DSLMatched)
		if display == "" {
			continue
		}
		displays = append(displays, display)
	}
	return displays
}

// formatFingerprintDisplay 格式化单个指纹显示
func (f *ConsoleOutputFormatter) formatFingerprintDisplay(name, rule string) string {
	return formatter.FormatFingerprintDisplay(name, rule, f.showRules)
}

// outputSnippets 输出匹配片段
func (f *ConsoleOutputFormatter) outputSnippets(matches []*FingerprintMatch) {
	for _, match := range matches {
		if match == nil || match.Snippet == "" {
			continue
		}

		lines := highlightedSnippetLines(match.Snippet, match.DSLMatched)
		if len(lines) > 0 {
			logger.Infof("  [Snippet] %s:", match.RuleName)
			for _, line := range lines {
				logger.Infof("    %s", line)
			}
		}
	}
}

// highlightedSnippetLines 处理snippet显示
func highlightedSnippetLines(snippet, matcher string) []string {
	if snippet == "" {
		return nil
	}
	snippet = strings.ReplaceAll(snippet, "\r\n", "\n")
	snippet = strings.ReplaceAll(snippet, "\r", "\n")
	rawLines := strings.Split(snippet, "\n")
	var lines []string
	for _, line := range rawLines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		highlighted := formatter.HighlightSnippet(line, matcher)
		if highlighted != "" {
			lines = append(lines, highlighted)
		}
	}
	if len(lines) == 0 {
		if highlighted := formatter.HighlightSnippet(strings.TrimSpace(snippet), matcher); highlighted != "" {
			lines = append(lines, highlighted)
		}
	}
	return lines
}

// SetShowRules 动态控制规则显示
func (f *ConsoleOutputFormatter) SetShowRules(enabled bool) {
	f.showRules = enabled
}

// SetOutputHook 设置输出回调（仅在实际输出时触发）
func (f *ConsoleOutputFormatter) SetOutputHook(hook func(response *HTTPResponse, matches []*FingerprintMatch, tags []string)) {
	f.onOutput = hook
}

type JSONOutputFormatter struct {
	deduplicator *Deduplicator
	onOutput     func(response *HTTPResponse, matches []*FingerprintMatch, tags []string)
	suppress     bool
}

func NewJSONOutputFormatter() *JSONOutputFormatter {
	return &JSONOutputFormatter{
		deduplicator: NewDeduplicator(),
	}
}

type JSONResult struct {
	Timestamp     string              `json:"timestamp"`
	URL           string              `json:"url"`
	StatusCode    int                 `json:"status_code"`
	Title         string              `json:"title"`
	ContentLength int64               `json:"content_length"`
	ContentType   string              `json:"content_type"`
	Fingerprints  []*FingerprintMatch `json:"fingerprints,omitempty"`
	Tags          []string            `json:"tags,omitempty"`
}

func buildJSONResult(response *HTTPResponse, matches []*FingerprintMatch, tags []string) JSONResult {
	return JSONResult{
		Timestamp:     formatJSONTimestamp(response.Timestamp),
		URL:           response.URL,
		StatusCode:    response.StatusCode,
		Title:         response.Title,
		ContentLength: response.ContentLength,
		ContentType:   response.ContentType,
		Fingerprints:  matches,
		Tags:          tags,
	}
}

const jsonOutputTimestampLayout = "2006/01/02 15:04:05"

func formatJSONTimestamp(ts time.Time) string {
	if ts.IsZero() {
		ts = time.Now()
	}
	return ts.Local().Format(jsonOutputTimestampLayout)
}

func (f *JSONOutputFormatter) FormatMatch(matches []*FingerprintMatch, response *HTTPResponse, tags ...string) {
	if len(matches) == 0 || response == nil {
		return
	}

	uniqueMatches := uniqueMatchesByRuleName(matches)
	if len(uniqueMatches) == 0 {
		return
	}

	f.outputResult(response, uniqueMatches, tags, collectFingerprintRuleNames(uniqueMatches))
}

func (f *JSONOutputFormatter) FormatNoMatch(response *HTTPResponse) {
	if response == nil {
		return
	}
	f.outputResult(response, nil, nil, nil)
}

func (f *JSONOutputFormatter) ShouldOutput(urlStr string, fingerprintNames []string) bool {
	return f.deduplicator.ShouldOutput(urlStr, fingerprintNames)
}

func (f *JSONOutputFormatter) SetOutputHook(hook func(response *HTTPResponse, matches []*FingerprintMatch, tags []string)) {
	f.onOutput = hook
}

func (f *JSONOutputFormatter) SetSuppressOutput(suppress bool) {
	f.suppress = suppress
}

func (f *JSONOutputFormatter) outputResult(response *HTTPResponse, matches []*FingerprintMatch, tags []string, fingerprintNames []string) {
	if !f.ShouldOutput(response.URL, fingerprintNames) {
		return
	}
	if f.onOutput != nil {
		f.onOutput(response, matches, tags)
	}
	if f.suppress {
		return
	}
	f.emitJSONResult(buildJSONResult(response, matches, tags))
}

func (f *JSONOutputFormatter) emitJSONResult(result JSONResult) {
	data, err := json.Marshal(result)
	if err != nil {
		logger.Errorf("Failed to marshal JSON: %v", err)
		return
	}
	fmt.Println(string(data))
}

type Deduplicator struct {
	cache map[string]bool
	mu    sync.RWMutex
}

func NewDeduplicator() *Deduplicator {
	return &Deduplicator{
		cache: make(map[string]bool),
	}
}

func (d *Deduplicator) ShouldOutput(urlStr string, fingerprintNames []string) bool {
	cacheKey := d.generateCacheKey(urlStr, fingerprintNames)

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.cache[cacheKey] {
		return false
	}

	d.cache[cacheKey] = true
	return true
}

func (d *Deduplicator) Clear() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cache = make(map[string]bool)
}

func (d *Deduplicator) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.cache)
}

func (d *Deduplicator) generateCacheKey(rawURL string, fingerprintNames []string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	scheme := strings.TrimSpace(parsedURL.Scheme)
	if scheme == "" {
		scheme = "unknown"
	}

	var builder strings.Builder
	builder.Grow(len(scheme) + len(parsedURL.Host) + len(parsedURL.Path) + 50)

	builder.WriteString(scheme)
	builder.WriteString("://")
	builder.WriteString(parsedURL.Host)
	builder.WriteByte('|')
	builder.WriteString(parsedURL.Path)
	builder.WriteByte('|')

	if len(fingerprintNames) == 0 {
		return builder.String()
	}
	if len(fingerprintNames) == 1 {
		builder.WriteString(strings.TrimSpace(fingerprintNames[0]))
		return builder.String()
	}

	sortedNames := make([]string, 0, len(fingerprintNames))
	for _, name := range fingerprintNames {
		name = strings.TrimSpace(name)
		if name != "" {
			sortedNames = append(sortedNames, name)
		}
	}
	if len(sortedNames) == 0 {
		return builder.String()
	}

	sort.Strings(sortedNames)
	unique := make([]string, 0, len(sortedNames))
	for _, name := range sortedNames {
		if len(unique) == 0 || unique[len(unique)-1] != name {
			unique = append(unique, name)
		}
	}

	builder.WriteString(strings.Join(unique, ","))
	return builder.String()
}

type EncodingDetector struct{}

func NewEncodingDetector() *EncodingDetector {
	return &EncodingDetector{}
}

func (ed *EncodingDetector) DetectAndConvert(body, contentType string) string {
	if body == "" {
		return body
	}

	if charsetName := ed.extractCharsetFromContentType(contentType); charsetName != "" {
		if converted := ed.convertCharset(body, charsetName); converted != "" {
			logger.Debugf("使用Content-Type检测到编码: %s", charsetName)
			return converted
		}
	}

	if charsetName := ed.extractCharsetFromMeta(body); charsetName != "" {
		if converted := ed.convertCharset(body, charsetName); converted != "" {
			logger.Debugf("使用Meta标签检测到编码: %s", charsetName)
			return converted
		}
	}

	if detectedCharset, confidence := ed.detectCharsetFromContent(body); confidence > 0.8 {
		if converted := ed.convertCharset(body, detectedCharset); converted != "" {
			logger.Debugf("自动检测到编码: %s (置信度: %.2f)", detectedCharset, confidence)
			return converted
		}
	}

	return body
}

func (ed *EncodingDetector) extractCharsetFromContentType(contentType string) string {
	if contentType == "" {
		return ""
	}

	charsetRegex := regexp.MustCompile(`charset=([^;,\s]+)`)
	matches := charsetRegex.FindStringSubmatch(strings.ToLower(contentType))
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

func (ed *EncodingDetector) extractCharsetFromMeta(body string) string {
	charsetRegex := regexp.MustCompile(`(?i)<meta\s+charset\s*=\s*["']?([^"'>\s]+)`)
	matches := charsetRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.ToLower(strings.TrimSpace(matches[1]))
	}

	httpEquivRegex := regexp.MustCompile(`(?i)<meta\s+http-equiv\s*=\s*["']?content-type["']?\s+content\s*=\s*["']?[^"'>]*charset=([^"'>\s;]+)`)
	matches = httpEquivRegex.FindStringSubmatch(body)
	if len(matches) > 1 {
		return strings.ToLower(strings.TrimSpace(matches[1]))
	}

	return ""
}

func (ed *EncodingDetector) detectCharsetFromContent(body string) (string, float64) {
	_, name, certain := charset.DetermineEncoding([]byte(body), "")
	confidence := 0.5
	if certain {
		confidence = 0.9
	}
	return name, confidence
}

func (ed *EncodingDetector) convertCharset(body, charsetName string) string {
	charsetName = strings.ToLower(charsetName)
	if charsetName == "utf-8" || charsetName == "utf8" {
		return body
	}

	if charsetName == "gbk" || charsetName == "gb2312" || charsetName == "gb18030" {
		return ed.convertFromGBK(body)
	}
	if charsetName == "big5" {
		return ed.convertFromBig5(body)
	}

	logger.Debugf("不支持的编码格式: %s, 返回原始内容", charsetName)
	return body
}

func (ed *EncodingDetector) convertFromGBK(gbkStr string) string {
	reader := transform.NewReader(strings.NewReader(gbkStr), simplifiedchinese.GBK.NewDecoder())
	utf8Bytes, err := io.ReadAll(reader)
	if err != nil {
		logger.Debugf("GBK转换失败: %v", err)
		return gbkStr
	}
	return string(utf8Bytes)
}

func (ed *EncodingDetector) convertFromBig5(big5Str string) string {
	logger.Debugf("Big5编码检测，暂时返回原始内容")
	return big5Str
}

var globalEncodingDetector *EncodingDetector

func GetEncodingDetector() *EncodingDetector {
	if globalEncodingDetector == nil {
		globalEncodingDetector = NewEncodingDetector()
	}
	return globalEncodingDetector
}
