package processor

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"

	"github.com/valyala/fasthttp"
	netproxy "golang.org/x/net/proxy"
)

// ============================================================================
// 响应处理工具方法 (原response.go有用部分)
// ============================================================================

// getContentLength 获取内容长度
func getContentLength(resp *fasthttp.Response, body string) int64 {
	contentLength := resp.Header.ContentLength()
	if contentLength >= 0 {
		return int64(contentLength)
	}
	return int64(len(body))
}

// getContentType 获取内容类型
func getContentType(resp *fasthttp.Response) string {
	contentTypeBytes := resp.Header.ContentType()
	if contentTypeBytes == nil {
		return "unknown"
	}
	contentType := string(contentTypeBytes)

	if idx := strings.Index(contentType, ";"); idx != -1 {
		contentType = contentType[:idx]
	}

	return strings.TrimSpace(contentType)
}

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

// getAuthHeaders 获取认证头部（CLI自定义头部优先，否则使用自动检测的头部）
func (rp *RequestProcessor) getAuthHeaders() map[string]string {
	rp.mu.RLock()
	defer rp.mu.RUnlock()

	authHeaders := make(map[string]string)

	// 优先使用CLI指定的自定义头部
	if len(rp.customHeaders) > 0 {
		for key, value := range rp.customHeaders {
			authHeaders[key] = value
		}
		return authHeaders
	}

	// 如果没有自定义头部，使用自动检测的头部
	if rp.authDetector.IsEnabled() && rp.authDetector.HasDetectedSchemes() {
		detectedHeaders := rp.authDetector.GetDetectedSchemes()
		for key, value := range detectedHeaders {
			if value != "" { // 只使用有值的头部
				authHeaders[key] = value
			}
		}
	}

	return authHeaders
}

// handleAuthDetection 处理认证检测（仅在未设置自定义头部时）
func (rp *RequestProcessor) handleAuthDetection(resp *fasthttp.Response, url string) {
	// 如果设置了自定义头部，跳过自动检测
	if rp.HasCustomHeaders() {
		return
	}

	// 只处理401和403响应
	if resp.StatusCode() != 401 && resp.StatusCode() != 403 {
		return
	}

	// 将fasthttp.Response转换为http.Response以便认证检测器使用
	httpResp := rp.convertToHTTPResponse(resp)
	if httpResp == nil {
		return
	}

	// 执行认证检测
	detectedHeaders := rp.authDetector.DetectAuthRequirements(httpResp, url)
	if len(detectedHeaders) > 0 {
		logger.Debugf("检测到认证要求，将应用到后续请求: %s", url)
	}
}

// convertToHTTPResponse 将fasthttp.Response转换为http.Response（用于认证检测）
func (rp *RequestProcessor) convertToHTTPResponse(resp *fasthttp.Response) *http.Response {
	httpResp := &http.Response{
		StatusCode: resp.StatusCode(),
		Header:     make(http.Header),
	}

	// 转换响应头
	resp.Header.VisitAll(func(key, value []byte) {
		httpResp.Header.Add(string(key), string(value))
	})

	return httpResp
}

// setRequestHeaders 设置请求头
func (rp *RequestProcessor) setRequestHeaders(h *fasthttp.RequestHeader) {
	headers := rp.getDefaultHeaders()
	for key, value := range headers {
		h.Set(key, value)
	}
}

// ============================================================================
// Response Processing Helpers
// ============================================================================

// processResponseBody 处理响应体，应用大小限制（内存优化）
func (rp *RequestProcessor) processResponseBody(rawBody []byte) string {
	// 获取配置的最大响应体大小
	maxSize := rp.config.MaxBodySize
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024 // 默认10MB
	}

	// 如果响应体超过限制，进行截断
	if len(rawBody) > maxSize {
		truncatedBody := make([]byte, maxSize)
		copy(truncatedBody, rawBody[:maxSize])

		// 添加截断标记
		truncatedStr := string(truncatedBody) + "\n...[响应体已截断，原始大小: " +
			fmt.Sprintf("%d bytes", len(rawBody)) + "]"

		logger.Debugf("响应体已截断: %d bytes -> %d bytes",
			len(rawBody), maxSize)

		return truncatedStr
	}

	return string(rawBody)
}

// processResponse 处理fasthttp响应，构建HTTPResponse结构体
func (rp *RequestProcessor) processResponse(url string, resp *fasthttp.Response, requestHeaders map[string][]string, startTime time.Time) (*interfaces.HTTPResponse, error) {
	// 尝试解压响应体（如果启用了压缩且服务器返回了压缩数据）
	// fasthttp.Response.Body() 返回原始内容，如果Content-Encoding是gzip，则需要手动解压
	// 这对于后续的正则匹配（如重定向检测）至关重要
	var rawBody []byte
	contentEncoding := resp.Header.Peek("Content-Encoding")

	if bytes.EqualFold(contentEncoding, []byte("gzip")) {
		var err error
		rawBody, err = resp.BodyGunzip()
		if err != nil {
			logger.Debugf("Gzip解压失败: %s, 错误: %v, 使用原始Body", url, err)
			rawBody = resp.Body()
		}
	} else if bytes.EqualFold(contentEncoding, []byte("deflate")) {
		var err error
		rawBody, err = resp.BodyInflate()
		if err != nil {
			logger.Debugf("Deflate解压失败: %s, 错误: %v, 使用原始Body", url, err)
			rawBody = resp.Body()
		}
	} else {
		rawBody = resp.Body()
	}

	// 提取响应基本信息
	body := rp.processResponseBody(rawBody)
	title := rp.extractTitleSafely(url, body)
	contentLength := rp.getContentLength(resp, body)
	contentType := rp.getContentType(resp)
	responseHeaders := rp.extractResponseHeadersSafely(url, resp)
	server := rp.extractServerInfoSafely(url, resp)
	duration := time.Since(startTime).Milliseconds()

	// 构建响应对象
	response := rp.buildResponseObject(url, resp, title, contentLength, contentType, body, responseHeaders, requestHeaders, server, duration)

	// 新增：处理认证检测（仅在401/403响应时且未设置自定义头部时）
	rp.handleAuthDetection(resp, url)

	// 记录处理完成日志
	logger.Debug(fmt.Sprintf("响应处理完成: %s [%d] %s, 响应头数量: %d, 耗时: %dms",
		url, resp.StatusCode(), title, len(responseHeaders), duration))

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

// getContentLength 获取内容长度 (method wrapper)
func (rp *RequestProcessor) getContentLength(resp *fasthttp.Response, body string) int64 {
	// 优先返回实际body长度，因为可能经过了解压或截断，此时Content-Length头部可能不再准确
	return int64(len(body))
}

// getContentType 获取内容类型 (method wrapper)
func (rp *RequestProcessor) getContentType(resp *fasthttp.Response) string {
	contentType := string(resp.Header.ContentType())
	if contentType == "" {
		contentType = "unknown"
	}
	return contentType
}

// extractResponseHeadersSafely 安全地提取响应头
func (rp *RequestProcessor) extractResponseHeadersSafely(url string, resp *fasthttp.Response) map[string][]string {
	var responseHeaders map[string][]string
	func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Warnf("响应头提取发生panic，URL: %s, 错误: %v", url, r)
				responseHeaders = make(map[string][]string)
			}
		}()

		if resp == nil {
			logger.Warnf("响应对象为空，URL: %s", url)
			responseHeaders = make(map[string][]string)
			return
		}

		responseHeaders = make(map[string][]string)
		resp.Header.VisitAll(func(key, value []byte) {
			if key == nil || value == nil {
				return
			}
			keyStr := string(key)
			valueStr := string(value)
			if _, exists := responseHeaders[keyStr]; !exists {
				responseHeaders[keyStr] = make([]string, 0)
			}
			responseHeaders[keyStr] = append(responseHeaders[keyStr], valueStr)
		})
	}()
	return responseHeaders
}

// extractServerInfoSafely 安全地提取服务器信息
func (rp *RequestProcessor) extractServerInfoSafely(url string, resp *fasthttp.Response) string {
	var server string
	if resp != nil {
		func() {
			defer func() {
				if r := recover(); r != nil {
					logger.Warnf("Server头提取发生panic，URL: %s, 错误: %v", url, r)
					server = "unknown"
				}
			}()
			server = string(resp.Header.Peek("Server"))
		}()
	} else {
		server = "unknown"
	}
	return server
}

// buildResponseObject 构建响应对象
func (rp *RequestProcessor) buildResponseObject(url string, resp *fasthttp.Response, title string, contentLength int64, contentType, body string, responseHeaders, requestHeaders map[string][]string, server string, duration int64) *interfaces.HTTPResponse {
	return &interfaces.HTTPResponse{
		URL:             url,
		Method:          "GET",
		StatusCode:      resp.StatusCode(),
		Title:           title,
		ContentLength:   contentLength,
		ContentType:     contentType,
		Body:            body,
		ResponseHeaders: responseHeaders,
		RequestHeaders:  requestHeaders,
		Server:          server,
		IsDirectory:     rp.isDirectoryURL(url),
		Length:          contentLength,
		Duration:        duration,
		Depth:           0,    // 深度信息需要外部设置
		ResponseBody:    body, // 报告用响应体
	}
}

// extractRequestHeaders 提取请求头信息
// 将fasthttp的RequestHeader转换为标准的map[string][]string格式
func (rp *RequestProcessor) extractRequestHeaders(header *fasthttp.RequestHeader) map[string][]string {
	requestHeaders := make(map[string][]string)
	header.VisitAll(func(key, value []byte) {
		keyStr := string(key)
		valueStr := string(value)
		if _, exists := requestHeaders[keyStr]; !exists {
			requestHeaders[keyStr] = make([]string, 0)
		}
		requestHeaders[keyStr] = append(requestHeaders[keyStr], valueStr)
	})
	return requestHeaders
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

// ============================================================================
// Client Creation
// ============================================================================

// createFastHTTPClient 创建fasthttp客户端
func createFastHTTPClient(config *RequestConfig) *fasthttp.Client {
	client := &fasthttp.Client{
		TLSConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: true,
		},
		ReadTimeout:                   config.Timeout,           // 读取超时：配置文件的timeout_seconds
		WriteTimeout:                  config.Timeout,           // 写入超时：配置文件的timeout_seconds
		MaxIdleConnDuration:           30 * time.Second,         // 性能优化：延长连接保持时间，提升连接复用率
		MaxConnsPerHost:               config.MaxConcurrent * 2, // 性能优化：连接池大小为并发数的2倍，减少连接竞争
		MaxResponseBodySize:           config.MaxBodySize,       // 最大响应体大小
		DisablePathNormalizing:        true,
		DisableHeaderNamesNormalizing: true,
		NoDefaultUserAgentHeader:      true,
		ReadBufferSize:                16384, // 16k
	}

	// 配置代理
	if config.ProxyURL != "" {
		u, err := url.Parse(config.ProxyURL)
		if err == nil {
			var dialer netproxy.Dialer
			// 支持SOCKS5
			if strings.HasPrefix(config.ProxyURL, "socks5") {
				dialer, err = netproxy.FromURL(u, netproxy.Direct)
				if dialer != nil {
					client.Dial = func(addr string) (net.Conn, error) {
						return dialer.Dial("tcp", addr)
					}
					logger.Debugf("Fasthttp使用SOCKS5代理: %s", config.ProxyURL)
				}
			} else if strings.HasPrefix(config.ProxyURL, "http") {
				// 手动实现HTTP代理的CONNECT隧道支持
				proxyAddr := u.Host
				client.Dial = func(addr string) (net.Conn, error) {
					// 1. 连接到代理服务器
					conn, err := net.DialTimeout("tcp", proxyAddr, config.ConnectTimeout)
					if err != nil {
						return nil, err
					}

					// 2. 发送CONNECT请求（即使是HTTP目标，使用CONNECT隧道也是最可靠的通用方法）
					// 注意：某些HTTP代理可能不支持对80端口的CONNECT，但现代代理通常都支持
					connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr)
					if _, err := conn.Write([]byte(connectReq)); err != nil {
						conn.Close()
						return nil, err
					}

					// 3. 读取代理响应
					// 简单读取直到遇到\r\n\r\n，并检查状态码
					// 这里做一个简单的缓冲读取
					buf := make([]byte, 1024)
					n, err := conn.Read(buf)
					if err != nil {
						conn.Close()
						return nil, err
					}

					response := string(buf[:n])
					if !strings.Contains(response, "200 Connection established") && !strings.Contains(response, "200 OK") {
						conn.Close()
						return nil, fmt.Errorf("代理连接失败: %s", response)
					}

					// 4. 连接建立成功，返回连接
					return conn, nil
				}
				logger.Debugf("Fasthttp使用HTTP代理(CONNECT模式): %s", config.ProxyURL)
			}
		} else {
			logger.Warnf("无效的代理URL: %s, 错误: %v", config.ProxyURL, err)
		}
	}

	return client
}
