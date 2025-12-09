package formatter

import "strings"

// FormatTitleForMatch 根据是否命中指纹选择标题颜色
func FormatTitleForMatch(title string, matched bool) string {
	if strings.TrimSpace(title) == "" {
		title = "无标题"
	}
	if matched {
		return FormatFingerprintTitle(title)
	}
	return FormatTitle(title)
}

// FormatLogLine 构造统一的日志输出格式：URL 状态码 标题 Content-Length Content-Type 指纹
func FormatLogLine(url string, statusCode int, title string, contentLength int64, contentType string, fingerprints []string, matched bool, tags ...string) string {
	if contentLength < 0 {
		contentLength = 0
	}

	parts := []string{
		FormatURL(url),
		FormatStatusCode(statusCode),
		FormatTitleForMatch(title, matched),
		FormatContentLength(int(contentLength)),
		FormatContentType(contentType),
	}

	fp := strings.TrimSpace(strings.Join(fingerprints, " "))
	if fp == "" {
		fp = "-"
	}
	parts = append(parts, fp)

	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		parts = append(parts, FormatFingerprintTag(tag))
	}

	return strings.Join(parts, " ")
}
