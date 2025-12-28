package processor

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
)

// ============================================================================
// HTTP请求辅助方法
// ============================================================================

// getDefaultHeaders 获取默认请求头（集成认证头部）
func (rp *RequestProcessor) getDefaultHeaders() map[string]string {
	// 获取基础头部
	headers := map[string]string{
		"User-Agent":                rp.getRandomUserAgent(), // 使用随机UserAgent
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language":           "zh-CN,zh;q=0.9,en;q=0.8",
		"Accept-Encoding":           "gzip, deflate",
		"Connection":                "keep-alive",
		"Upgrade-Insecure-Requests": "1",
		"Cookie":                    "rememberMe=1",
	}

	// 合并认证头部
	authHeaders := rp.getAuthHeaders()
	for key, value := range authHeaders {
		headers[key] = value
	}

	return headers
}

func (rp *RequestProcessor) getAuthHeaders() map[string]string {
	rp.mu.RLock()
	defer rp.mu.RUnlock()

	authHeaders := make(map[string]string, len(rp.customHeaders))
	for key, value := range rp.customHeaders {
		authHeaders[key] = value
	}
	return authHeaders
}

// ============================================================================
// Response Processing Helpers
// ============================================================================

// processResponseBody 处理响应体，应用大小限制（内存优化）
func (rp *RequestProcessor) processResponseBody(rawBody string) string {
	// 获取配置的最大响应体大小
	maxSize := rp.config.MaxBodySize
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024 // 默认10MB
	}

	// 如果响应体超过限制，进行截断
	if len(rawBody) > maxSize {
		truncatedBody := rawBody[:maxSize]

		// 添加截断标记
		origSize := strconv.Itoa(len(rawBody))
		var builder strings.Builder
		builder.Grow(len(truncatedBody) + len(origSize) + len("\n...[响应体已截断，原始大小:  bytes]"))
		builder.WriteString(truncatedBody)
		builder.WriteString("\n...[响应体已截断，原始大小: ")
		builder.WriteString(origSize)
		builder.WriteString(" bytes]")

		logger.Debugf("响应体已截断: %d bytes -> %d bytes",
			len(rawBody), maxSize)

		return builder.String()
	}

	return rawBody
}

// processResponse 处理响应，构建HTTPResponse结构体
func (rp *RequestProcessor) processResponse(url string, statusCode int, body string, responseHeaders, requestHeaders map[string][]string, startTime time.Time) (*interfaces.HTTPResponse, error) {
	// 响应体截断处理
	finalBody := rp.processResponseBody(body)

	// 提取信息
	title := rp.extractTitleSafely(url, finalBody)
	contentLength := int64(len(finalBody))

	// 提取 Content-Type
	contentType := "unknown"
	if ct, ok := responseHeaders["Content-Type"]; ok && len(ct) > 0 {
		contentType = ct[0]
		if idx := strings.Index(contentType, ";"); idx != -1 {
			contentType = contentType[:idx]
		}
		contentType = strings.TrimSpace(contentType)
	}

	// 提取 Server
	server := "unknown"
	if s, ok := responseHeaders["Server"]; ok && len(s) > 0 {
		server = s[0]
	}

	duration := time.Since(startTime).Milliseconds()

	// 构建响应对象
	response := &interfaces.HTTPResponse{
		URL:             url,
		Method:          "GET",
		StatusCode:      statusCode,
		Title:           title,
		ContentLength:   contentLength,
		ContentType:     contentType,
		Body:            finalBody,
		ResponseHeaders: responseHeaders,
		RequestHeaders:  requestHeaders,
		Server:          server,
		IsDirectory:     rp.isDirectoryURL(url),
		Length:          contentLength,
		Duration:        duration,
		Depth:           0, // 深度信息需要外部设置
		ResponseBody:    finalBody,
	}

	// 记录处理完成日志
	logger.Debug(fmt.Sprintf("响应处理完成: %s [%d] %s, 响应头数量: %d, 耗时: %dms",
		url, statusCode, title, len(responseHeaders), duration))

	return response, nil
}

// extractTitleSafely 安全地提取页面标题
func (rp *RequestProcessor) extractTitleSafely(url, body string) string {
	var title string
	func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Warnf("标题提取发生panic，URL: %s, 错误: %v", url, r)
				title = "标题提取失败"
			}
		}()
		title = rp.titleExtractor.ExtractTitle(body)
	}()
	return title
}

// isDirectoryURL 判断URL是否可能是目录
// 通过URL结构特征判断：以斜杠结尾或不包含文件扩展名
func (rp *RequestProcessor) isDirectoryURL(url string) bool {
	return strings.HasSuffix(url, "/") || !rp.hasFileExtension(url)
}

// hasFileExtension 判断URL是否包含文件扩展名
// 检查最后一个点号是否在最后一个斜杠之后，以确定是否为文件
func (rp *RequestProcessor) hasFileExtension(url string) bool {
	lastSlash := strings.LastIndex(url, "/")
	lastDot := strings.LastIndex(url, ".")

	// 如果没有点号，或者点号在最后一个斜杠之前，则认为没有扩展名
	return lastDot > lastSlash && lastDot > 0
}
