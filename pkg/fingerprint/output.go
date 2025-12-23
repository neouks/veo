package fingerprint

import (
	"fmt"
	"strings"

	"veo/pkg/utils/formatter"
	"veo/pkg/utils/logger"
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

	// 收集指纹名称(用于去重)
	fingerprintNames := make([]string, 0, len(uniqueMatches))
	for _, match := range uniqueMatches {
		fingerprintNames = append(fingerprintNames, match.RuleName)
	}

	// 去重检查
	if !f.ShouldOutput(response.URL, fingerprintNames) {
		return
	}

	// 构建指纹显示列表
	fingerprintDisplays := f.buildFingerprintDisplays(uniqueMatches)

	// 格式化日志行
	line := formatter.FormatLogLine(
		response.URL,
		response.StatusCode,
		response.Title,
		response.ContentLength,
		response.ContentType,
		fingerprintDisplays,
		true,
		tags...,
	)

	// 如果URL过长,在下一行输出完整URL方便复制
	if len(response.URL) > 60 {
		line += "\n  └─ " + formatter.FormatFullURL(response.URL)
	}

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

	line := formatter.FormatLogLine(
		response.URL,
		response.StatusCode,
		response.Title,
		response.ContentLength,
		response.ContentType,
		nil,
		false,
	)

	// 如果URL过长,在下一行输出完整URL方便复制
	if len(response.URL) > 60 {
		line += "\n  └─ " + response.URL
	}

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

// NullOutputFormatter 空输出格式化器
// 不进行任何输出,用于需要静默处理的场景
type NullOutputFormatter struct{}

// NewNullOutputFormatter 创建空输出格式化器
func NewNullOutputFormatter() *NullOutputFormatter {
	return &NullOutputFormatter{}
}

// FormatMatch 实现OutputFormatter接口(空实现)
func (f *NullOutputFormatter) FormatMatch(matches []*FingerprintMatch, response *HTTPResponse, tags ...string) {
	// 不输出
}

// FormatNoMatch 实现OutputFormatter接口(空实现)
func (f *NullOutputFormatter) FormatNoMatch(response *HTTPResponse) {
	// 不输出
}

// ShouldOutput 实现OutputFormatter接口(总是返回false)
func (f *NullOutputFormatter) ShouldOutput(url string, fingerprintNames []string) bool {
	return false // 不输出
}

// SetOutputFormatter 为向后兼容提供的全局设置函数
// 用于在不修改Engine构造函数的情况下设置输出器
var globalOutputFormatter OutputFormatter

// SetShowRules 动态控制规则显示
func (f *ConsoleOutputFormatter) SetShowRules(enabled bool) {
	f.showRules = enabled
}

// GetGlobalOutputFormatter 获取全局输出格式化器
func GetGlobalOutputFormatter() OutputFormatter {
	return globalOutputFormatter
}

// GetOutputStats 获取输出统计信息
func (f *ConsoleOutputFormatter) GetOutputStats() map[string]interface{} {
	return map[string]interface{}{
		"cached_urls":  f.deduplicator.Count(),
		"log_matches":  f.logMatches,
		"show_snippet": f.showSnippet,
		"show_rules":   f.showRules,
	}
}

// ClearCache 清空去重缓存(用于测试或重置)
func (f *ConsoleOutputFormatter) ClearCache() {
	f.deduplicator.Clear()
}

// String 实现Stringer接口
func (f *ConsoleOutputFormatter) String() string {
	stats := f.GetOutputStats()
	return fmt.Sprintf("ConsoleOutputFormatter{cached=%d, logMatches=%v, snippet=%v, rules=%v}",
		stats["cached_urls"], stats["log_matches"], stats["show_snippet"], stats["show_rules"])
}
