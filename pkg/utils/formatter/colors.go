package formatter

import (
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
)

// ANSI颜色代码常量
const (
	ColorReset    = "\033[0m"  // 重置
	ColorGreen    = "\033[32m" // 绿色
	ColorLightRed = "\033[91m" // 浅红色
	ColorRed      = "\033[31m" // 红色
	ColorYellow   = "\033[33m" // 黄色
	ColorBlue     = "\033[34m" // 蓝色
	ColorBold     = "\033[1m"  // 加粗
	ColorUnder    = "\033[4m"  // 下划线

	// 保留的颜色常量（用于其他功能）
	ColorMagenta = "\033[35m" // 紫色（保留用于其他功能）
	ColorGray    = "\033[90m" // 灰色（保留用于其他功能）
	ColorDim     = "\033[2m"  // 暗淡（用于DSL规则显示）

	// 品牌绿色（#0eb83a）常量，统一应用于URL、状态码、指纹名称
	ColorBrandGreen         = "\033[38;2;14;184;58m" // 品牌绿色 (#0eb83a) - 24位真彩色
	ColorBrandGreenFallback = "\033[32m"             // 降级方案 - 标准绿色（16色兼容）

	// 指纹名称专用颜色（#44cef6）
	ColorFingerprintCyan         = "\033[38;2;68;206;246m" // 天青色 (#44cef6)
	ColorFingerprintCyanFallback = "\033[36m"              // 降级方案 - 青色

	// 指纹标题专用颜色（#3eede7）
	ColorFingerprintTitleCyan         = "\033[38;2;62;237;231m"
	ColorFingerprintTitleCyanFallback = "\033[36m"

	// 标签专用颜色（#ff2121）
	ColorTagHighlight         = "\033[38;2;255;33;33m"
	ColorTagHighlightFallback = "\033[31m"
)

// FormatURL 格式化URL显示（使用深绿色，右侧填充对齐）
func FormatURL(url string) string {
	// 截断过长的URL
	displayURL := url
	if len(url) > 60 {
		displayURL = url[:57] + "..."
	}

	padding := 0
	if len(displayURL) < 60 {
		padding = 60 - len(displayURL)
	}

	if !shouldUseColors() {
		return fmt.Sprintf("%s%s", displayURL, strings.Repeat(" ", padding))
	}
	// 使用品牌绿色显示URL，填充在颜色代码之外
	return getBrandGreenColor() + displayURL + ColorReset + strings.Repeat(" ", padding)
}

// FormatFullURL 格式化完整URL显示（使用深绿色，不截断，无填充）
func FormatFullURL(url string) string {
	if !shouldUseColors() {
		return url
	}
	// 使用品牌绿色显示完整URL
	return getBrandGreenColor() + url + ColorReset
}

// FormatFingerprintName 格式化指纹名称显示（统一蓝色显示，无加粗）
func FormatFingerprintName(name string) string {
	if !shouldUseColors() {
		return name // 如果禁用彩色输出，直接返回指纹名称
	}

	// 使用指定天青色显示指纹信息
	return getFingerprintColor() + name + ColorReset
}

// FormatStatusCode 格式化状态码显示（根据状态码类别使用不同颜色）
func FormatStatusCode(statusCode int) string {
	statusStr := fmt.Sprintf("[%d]", statusCode)

	if !shouldUseColors() {
		return statusStr // 如果禁用彩色输出，直接返回状态码
	}

	var color string

	switch {
	case statusCode == 403:
		color = ColorBold + ColorLightRed
	case statusCode == 404 || (statusCode >= 500 && statusCode < 600):
		color = ColorBold + ColorYellow
	default:
		color = ColorBold + getBrandGreenColor()
	}

	return color + statusStr + ColorReset
}

// FormatTitle 格式化标题显示
func FormatTitle(title string) string {
	finalTitle := title
	if !strings.HasPrefix(title, "[") || !strings.HasSuffix(title, "]") {
		finalTitle = fmt.Sprintf("[%s]", title)
	}

	if !shouldUseColors() {
		return finalTitle
	}
	return finalTitle + ColorReset
}

// FormatFingerprintTitle 格式化指纹匹配后的标题显示（青色，不加粗）
func FormatFingerprintTitle(title string) string {
	// 检查标题是否已经包含方括号
	finalTitle := title
	if !strings.HasPrefix(title, "[") || !strings.HasSuffix(title, "]") {
		finalTitle = fmt.Sprintf("[%s]", title)
	}

	if !shouldUseColors() {
		return finalTitle
	}
	// 使用统一青色显示匹配标题
	return getFingerprintTitleColor() + finalTitle + ColorReset
}

// FormatContentLength 格式化内容长度显示
func FormatContentLength(length int) string {
	lenStr := fmt.Sprintf("[%d]", length)

	if !shouldUseColors() {
		return lenStr // 如果禁用彩色输出，直接返回内容长度
	}
	// 修改：内容长度使用加粗默认颜色显示
	return fmt.Sprintf("%s%s", lenStr, ColorReset)
}

// FormatContentType 格式化内容类型显示（简化格式，只保留主要类型）
func FormatContentType(contentType string) string {
	// 简化Content-Type：只保留分号前的主要类型
	simplifiedType := simplifyContentType(contentType)

	displayType := fmt.Sprintf("[%s]", simplifiedType)

	if !shouldUseColors() {
		return displayType // 如果禁用彩色输出，直接返回简化的内容类型
	}
	return displayType + ColorReset
}

// simplifyContentType 简化Content-Type，只保留分号前的主要类型
// 例如：application/json;charset=utf-8 -> application/json
func simplifyContentType(contentType string) string {
	if contentType == "" {
		return contentType
	}

	// 查找第一个分号的位置
	if semicolonIndex := strings.Index(contentType, ";"); semicolonIndex != -1 {
		// 返回分号前的内容，并去除前后空格
		return strings.TrimSpace(contentType[:semicolonIndex])
	}

	// 如果没有分号，返回原始内容（去除前后空格）
	return strings.TrimSpace(contentType)
}

// FormatDSLRule 格式化DSL规则显示（指纹识别专用）
func FormatDSLRule(dslRule string) string {
	if !shouldUseColors() {
		return dslRule // 如果禁用彩色输出，直接返回DSL规则
	}
	// DSL规则使用灰色显示，不过于突出
	return ColorDim + dslRule + ColorReset
}

// FormatFingerprintPair 将指纹名称与匹配规则格式化为 "<名称> <规则>" 的统一输出
func FormatFingerprintPair(name, rule string) string {
	name = strings.TrimSpace(name)
	rule = strings.TrimSpace(rule)
	if name == "" || rule == "" {
		return ""
	}
	return "<" + FormatFingerprintName(name) + "> <" + FormatDSLRule(rule) + ">"
}

// FormatFingerprintDisplay 根据开关决定是否携带规则内容
func FormatFingerprintDisplay(name, rule string, showRule bool) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if showRule {
		if formatted := FormatFingerprintPair(name, rule); formatted != "" {
			return formatted
		}
	}
	return "<" + FormatFingerprintName(name) + ">"

}

// FormatFingerprintTag 格式化指纹标签显示（指纹识别专用）
func FormatFingerprintTag(tag string) string {
	display := fmt.Sprintf("[%s]", strings.TrimSpace(tag))

	if !shouldUseColors() {
		return display // 如果禁用彩色输出，直接返回标签
	}

	// 根据标签类型选择颜色
	var color string
	switch tag {
	case "主动探测", "404探测":
		color = ColorBold + getTagHighlightColor()
	case "被动识别":
		// 被动识别：加粗绿色
		color = ColorBold + ColorGreen
	default:
		// 其他标签：加粗默认颜色
		color = ColorBold
	}

	return color + display + ColorReset
}

// FormatSnippetArrow 返回用于指纹匹配片段前缀的箭头（加粗绿色高亮）
// 示例："➜ "（带尾随空格）
// 参数：无
// 返回：带颜色（或不带颜色）的箭头字符串
func FormatSnippetArrow() string {
	arrow := "➜ "
	if !shouldUseColors() {
		return arrow
	}
	return ColorBold + ColorGreen + arrow + ColorReset
}

// shouldUseColors 检查是否应该使用颜色
func shouldUseColors() bool {
	return atomic.LoadInt32(&globalColorEnabled) == 1
}

var globalColorEnabled int32 = 1

// SetColorEnabled 控制全局颜色输出
func SetColorEnabled(enabled bool) {
	if enabled {
		atomic.StoreInt32(&globalColorEnabled, 1)
	} else {
		atomic.StoreInt32(&globalColorEnabled, 0)
	}
}

// ColorsEnabled 返回当前颜色输出状态
func ColorsEnabled() bool {
	return atomic.LoadInt32(&globalColorEnabled) == 1
}

// getBrandGreenColor 获取品牌绿色颜色代码（支持降级）
// 返回适合当前终端环境的品牌绿色ANSI代码
func getBrandGreenColor() string {
	if !shouldUseColors() {
		return ""
	}
	return ColorBrandGreenFallback
}

// getFingerprintColor 获取指纹名称专用颜色代码（支持降级）
func getFingerprintColor() string {
	if !shouldUseColors() {
		return ""
	}
	return ColorFingerprintCyanFallback
}

// getFingerprintTitleColor 获取指纹匹配标题颜色（支持降级）
func getFingerprintTitleColor() string {
	if !shouldUseColors() {
		return ""
	}
	return ColorFingerprintTitleCyanFallback
}

// getTagHighlightColor 获取标签高亮颜色（支持降级）
func getTagHighlightColor() string {
	if !shouldUseColors() {
		return ""
	}
	return ColorTagHighlightFallback
}

// ============================================================================
// 目录扫描指纹识别专用格式化函数
// ============================================================================
var quotedValueRegexp = regexp.MustCompile(`['"]([^'"` + "`" + `]+)['"]`)

// HighlightSnippet 根据匹配DSL中的字符串常量，对片段中的关键字进行高亮显示
func HighlightSnippet(snippet, matcher string) string {
	snippet = strings.TrimSpace(snippet)
	if snippet == "" {
		return ""
	}

	if !shouldUseColors() {
		return snippet
	}

	values := quotedValueRegexp.FindAllStringSubmatch(matcher, -1)
	if len(values) == 0 {
		return snippet
	}

	highlighted := snippet
	seen := make(map[string]struct{})
	for _, match := range values {
		if len(match) < 2 {
			continue
		}
		value := strings.TrimSpace(match[1])
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		highlight := ColorYellow + value + ColorReset
		highlighted = strings.ReplaceAll(highlighted, value, highlight)
	}
	return highlighted
}
