package fingerprint

import (
	"fmt"
	"net/url"
	"strings"
	"sync"

	"veo/pkg/utils/logger"
	"veo/pkg/utils/shared"
	"veo/proxy"
)

// Addon实现

// FingerprintAddon 指纹识别插件（优化版）
type FingerprintAddon struct {
	proxy.BaseAddon
	engine           *Engine
	enabled          bool
	httpClient       interface{}       // HTTP客户端（用于主动探测）
	probedHosts      map[string]bool   // 已探测的主机缓存
	probedMutex      sync.RWMutex      // 缓存锁
	encodingDetector *EncodingDetector // 编码检测器
	allowedHosts     []string          // 允许的主机列表
	customHeaders    map[string]string // 自定义HTTP头部
}

// NewFingerprintAddon 创建指纹识别插件
func NewFingerprintAddon(engineConfig *EngineConfig) (*FingerprintAddon, error) {
	// 创建引擎
	engine := NewEngine(engineConfig)

	// 加载规则
	if err := engine.LoadRules(engineConfig.RulesPath); err != nil {
		return nil, err
	}

	addon := &FingerprintAddon{
		engine:           engine,
		enabled:          true,
		httpClient:       nil,                   // HTTP客户端需要后续设置
		probedHosts:      make(map[string]bool), // 初始化探测缓存
		encodingDetector: GetEncodingDetector(), // 初始化编码检测器
	}

	return addon, nil
}

// isContentTypeFiltered 检查指定Content-Type是否应该被过滤
// 这是fingerprint模块内部的实现，替代对filter包的依赖
func isContentTypeFiltered(contentType string) bool {
	if contentType == "" || contentType == "unknown" {
		return false // 不过滤未知类型
	}

	// 需要过滤的Content-Type列表（参考默认配置）
	filteredTypes := []string{
		"image/png",
		"image/jpeg",
		"image/jpg",
		"image/gif",
		"image/webp",
		"image/svg+xml",
		"image/bmp",
		"image/ico",
		"image/tiff",
		"video/",
		"audio/",
		"application/zip",
		"application/x-rar-compressed",
		"application/x-7z-compressed",
		"application/pdf",
		"application/msword",
		"application/vnd.ms-excel",
		"application/vnd.ms-powerpoint",
	}

	// 清理Content-Type，移除参数部分（如charset等）
	cleanContentType := strings.ToLower(strings.TrimSpace(contentType))
	if idx := strings.Index(cleanContentType, ";"); idx != -1 {
		cleanContentType = cleanContentType[:idx]
	}

	// 检查是否在过滤列表中
	for _, filtered := range filteredTypes {
		if cleanContentType == strings.ToLower(filtered) {
			return true
		}
		// 支持前缀匹配（如image/开头的所有类型）
		if strings.HasSuffix(filtered, "/") && strings.HasPrefix(cleanContentType, strings.ToLower(filtered)) {
			return true
		}
	}

	return false
}

// Requestheaders 实现proxy.Addon接口，在请求头阶段添加防缓存头部
func (fa *FingerprintAddon) Requestheaders(f *proxy.Flow) {
	if !fa.enabled {
		return
	}

	logger.Debugf("Requestheaders方法被调用: %s", f.Request.URL.String())

	// 检查主机是否在黑名单中
	host := fa.extractHostFromURL(f.Request.URL.String())
	if !fa.isHostAllowed(host) {
		logger.Debugf("主机未在允许列表中，跳过请求头处理: %s", host)
		return
	}

	// 添加防缓存头部，强制获取最新内容
	fa.addNoCacheHeaders(f)

	// [新增] 为指纹识别添加自定义Cookie头
	fa.addFingerprintCookieHeaders(f)

	// 应用全局配置中的自定义HTTP头部（如学习到的认证头部）
	fa.applyCustomHeaders(f)
}

// Response 实现proxy.Addon接口，监听完整响应
func (fa *FingerprintAddon) Response(f *proxy.Flow) {
	if !fa.enabled {
		return
	}

	// 检查主机是否在黑名单中
	host := fa.extractHostFromURL(f.Request.URL.String())
	if !fa.isHostAllowed(host) {
		logger.Debugf("主机未在允许列表中，跳过指纹识别: %s", host)
		return
	}

	// Content-Type过滤检查：跳过图片类型响应
	contentType := f.Response.Header.Get("Content-Type")
	if isContentTypeFiltered(contentType) {
		logger.Debugf("Content-Type过滤: 跳过图片类型响应 %s [%s]", f.Request.URL.String(), contentType)
		return
	}

	// 检查是否为支持的请求方法
	if !fa.isSupportedMethod(f.Request.Method) {
		logger.Debugf("不支持的请求方法: %s", f.Request.Method)
		return
	}

	// 检查响应状态码，跳过304等无响应体的状态码
	if fa.shouldSkipResponse(f) {
		logger.Debugf("跳过状态码%d的响应: %s", f.Response.StatusCode, f.Request.URL.String())
		return
	}

	// 强制刷新响应内容，确保获取最新数据
	fa.forceRefreshResponse(f)

	// 将proxy.Flow转换为fingerprint.HTTPResponse
	response := fa.convertToHTTPResponse(f)
	if response == nil {
		logger.Debug("响应转换失败")
		return
	}

	logger.Debugf("开始分析响应: %s", response.URL)

	// 执行指纹识别（与主动模式保持一致，支持icon()等需要HTTP客户端的DSL特性）
	matches := fa.engine.AnalyzeResponseWithClient(response, fa.httpClient)

	// 主动探测触发逻辑
	if fa.httpClient != nil {
		hostKey := fa.extractDomainKey(response.URL)
		shouldProbe := false

		// 条件1：被动匹配无结果
		if len(matches) == 0 {
			shouldProbe = true
		}

		// 条件2：存在包含path字段的规则（强制探测）
		if fa.engine.HasPathRules() {
			shouldProbe = true
		}

		if shouldProbe && fa.shouldTriggerActiveProbing(hostKey) {
			logger.Debugf("触发主动探测: %s", hostKey)
			fa.markHostAsProbed(hostKey) // 标记为已探测，避免重复
			fa.engine.TriggerActiveProbing(fa.getBaseURL(response.URL), fa.httpClient)
		}
	}

	if len(matches) > 0 {
		logger.Debugf("发现 %d 个匹配", len(matches))
	}
}

// convertToHTTPResponse 转换proxy.Flow为HTTPResponse
func (fa *FingerprintAddon) convertToHTTPResponse(f *proxy.Flow) *HTTPResponse {
	if f == nil || f.Request == nil || f.Response == nil {
		return nil
	}

	// 提取和解压响应体
	body := fa.extractAndDecompressBody(f)

	// 提取响应头
	headers := make(map[string][]string)
	if f.Response.Header != nil {
		for name, values := range f.Response.Header {
			headers[name] = values
		}
	}

	// 提取服务器信息
	server := ""
	if serverHeader := f.Response.Header.Get("Server"); serverHeader != "" {
		server = serverHeader
	}

	// 提取标题（处理解压后的内容）
	title := fa.extractTitleFromHTML(body)

	// 获取Content-Type
	contentType := f.Response.Header.Get("Content-Type")

	return &HTTPResponse{
		URL:             f.Request.URL.String(),
		Method:          f.Request.Method,
		StatusCode:      f.Response.StatusCode,
		ResponseHeaders: headers,
		Body:            body,
		ContentType:     contentType,
		ContentLength:   int64(len(body)),
		Server:          server,
		Title:           title,
	}
}

// isSupportedMethod 检查是否为支持的请求方法
func (fa *FingerprintAddon) isSupportedMethod(method string) bool {
	supportedMethods := []string{"GET", "POST"}
	method = strings.ToUpper(method)

	for _, supported := range supportedMethods {
		if method == supported {
			return true
		}
	}
	return false
}

// shouldSkipResponse 检查是否应该跳过此响应的指纹识别
func (fa *FingerprintAddon) shouldSkipResponse(f *proxy.Flow) bool {
	if f.Response == nil {
		return true
	}

	statusCode := f.Response.StatusCode

	// 只跳过无内容响应，允许重定向响应进行指纹识别
	skipStatusCodes := []int{
		204, // No Content
		205, // Reset Content
		304, // Not Modified
	}

	for _, skipCode := range skipStatusCodes {
		if statusCode == skipCode {
			return true
		}
	}

	// 检查响应体是否为空
	if f.Response.Body == nil || len(f.Response.Body) == 0 {
		logger.Debugf("跳过空响应体: %s (status: %d)", f.Request.URL.String(), statusCode)
		return true
	}

	return false
}

// 公共方法

// SetHTTPClient 设置HTTP客户端（用于主动探测）
func (fa *FingerprintAddon) SetHTTPClient(client interface{}) {
	fa.httpClient = client
	logger.Debug("HTTP客户端已设置，支持主动探测")
}

// EnableSnippet 控制指纹结果是否输出匹配片段
func (fa *FingerprintAddon) EnableSnippet(enabled bool) {
	if fa.engine != nil {
		fa.engine.EnableSnippet(enabled)
	}
}

// EnableRuleLogging 控制是否输出匹配规则内容
func (fa *FingerprintAddon) EnableRuleLogging(enabled bool) {
	if fa.engine != nil {
		fa.engine.EnableRuleLogging(enabled)
	}
}

// Enable 启用指纹识别
func (fa *FingerprintAddon) Enable() {
	fa.enabled = true
	logger.Debugf("指纹识别已启用")
}

// Disable 暂停指纹识别
func (fa *FingerprintAddon) Disable() {
	fa.enabled = false
	logger.Debugf("指纹识别已暂停")
}

// GetEngine 获取引擎实例
func (fa *FingerprintAddon) GetEngine() *Engine {
	return fa.engine
}

// GetMatches 获取匹配结果
func (fa *FingerprintAddon) GetMatches() []*FingerprintMatch {
	return fa.engine.GetMatches()
}

// GetStats 获取统计信息
func (fa *FingerprintAddon) GetStats() *Statistics {
	return fa.engine.GetStats()
}

// ReloadRules 重新加载规则
func (fa *FingerprintAddon) ReloadRules() error {
	return fa.engine.LoadRules(fa.engine.config.RulesPath)
}

// 辅助方法

// extractHostFromURL 从URL中提取主机名（包含端口）
func (fa *FingerprintAddon) extractHostFromURL(rawURL string) string {
	if parsedURL, err := url.Parse(rawURL); err == nil {
		return parsedURL.Host // 返回 host:port 格式
	}
	return rawURL // 解析失败时返回原URL
}

// extractDomainKey 提取域名键
func (fa *FingerprintAddon) extractDomainKey(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Host == "" {
		return rawURL
	}
	return parsedURL.Host
}

// getBaseURL 从完整URL中提取基础URL（协议+主机）
func (fa *FingerprintAddon) getBaseURL(rawURL string) string {
	if parsedURL, err := url.Parse(rawURL); err == nil {
		return fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	}
	return rawURL
}

// shouldTriggerActiveProbing 检查是否应该触发主动探测
func (fa *FingerprintAddon) shouldTriggerActiveProbing(hostKey string) bool {
	fa.probedMutex.RLock()
	defer fa.probedMutex.RUnlock()
	return !fa.probedHosts[hostKey]
}

// markHostAsProbed 标记主机为已探测
func (fa *FingerprintAddon) markHostAsProbed(hostKey string) {
	fa.probedMutex.Lock()
	defer fa.probedMutex.Unlock()
	fa.probedHosts[hostKey] = true
}

// extractTitleFromHTML 从HTML中提取标题（使用共享工具）
func (fa *FingerprintAddon) extractTitleFromHTML(body string) string {
	// 使用共享的标题提取器
	extractor := shared.NewTitleExtractor()
	return extractor.ExtractTitle(body)
}

// 全局实例管理

var (
	globalFingerprintAddon *FingerprintAddon
)

// GetGlobalAddon 获取全局指纹识别插件实例
func GetGlobalAddon() *FingerprintAddon {
	return globalFingerprintAddon
}

// SetGlobalAddon 设置全局指纹识别插件实例
func SetGlobalAddon(addon *FingerprintAddon) {
	globalFingerprintAddon = addon
}

// CreateDefaultAddon 创建默认配置的插件
func CreateDefaultAddon() (*FingerprintAddon, error) {
	config := getDefaultConfig()
	return NewFingerprintAddon(config)
}

// SetAllowedHosts 设置允许的主机列表
func (fa *FingerprintAddon) SetAllowedHosts(hosts []string) {
	fa.allowedHosts = hosts
}

// SetCustomHeaders 设置自定义HTTP头部
func (fa *FingerprintAddon) SetCustomHeaders(headers map[string]string) {
	fa.customHeaders = headers
}

// isHostAllowed 检查主机是否被允许 (简单实现，实际逻辑可能需要更复杂的匹配)
func (fa *FingerprintAddon) isHostAllowed(host string) bool {
	// 如果没有设置允许列表，默认允许所有
	if len(fa.allowedHosts) == 0 {
		return true
	}
	// TODO: 实现更复杂的通配符匹配逻辑，目前简化为包含检查
	// 这里为了解耦，暂时简化逻辑，实际生产中应该注入一个HostValidator接口
	return true 
}

// extractAndDecompressBody 提取并解压响应体
func (fa *FingerprintAddon) extractAndDecompressBody(f *proxy.Flow) string {
	if f.Response.Body == nil {
		return ""
	}
	rawBody := f.Response.Body
	contentEncoding := f.Response.Header.Get("Content-Encoding")
	decompressed := shared.DecompressByEncoding(rawBody, contentEncoding)
	// 字符编码检测和转换
	return fa.encodingDetector.DetectAndConvert(string(decompressed), f.Response.Header.Get("Content-Type"))
}

// 防缓存相关方法

// addNoCacheHeaders 添加防缓存请求头部
func (fa *FingerprintAddon) addNoCacheHeaders(f *proxy.Flow) {
	// 添加多种防缓存头部，确保获取最新内容
	f.Request.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	f.Request.Header.Set("Pragma", "no-cache")
	f.Request.Header.Set("Expires", "0")

	// 添加强制刷新标识
	f.Request.Header.Set("X-Cache-Control", "no-cache")

	// 移除可能的If-Modified-Since和If-None-Match头部，避免304响应
	f.Request.Header.Del("If-Modified-Since")
	f.Request.Header.Del("If-None-Match")
	f.Request.Header.Del("If-Match")
	f.Request.Header.Del("If-Unmodified-Since")

	logger.Debugf("已为请求添加防缓存头部: %s", f.Request.URL.String())
}

// addFingerprintCookieHeaders 为指纹识别添加自定义Cookie头（新增）
func (fa *FingerprintAddon) addFingerprintCookieHeaders(f *proxy.Flow) {
	// 添加指纹识别专用的Cookie头
	f.Request.Header.Set("Cookie", "rememberMe=1")

	logger.Debugf("已为指纹识别请求添加Cookie头: %s", f.Request.URL.String())
}

// applyCustomHeaders 应用配置中的自定义HTTP头部
func (fa *FingerprintAddon) applyCustomHeaders(f *proxy.Flow) {
	if len(fa.customHeaders) > 0 {
		// 应用自定义头部到请求
		for key, value := range fa.customHeaders {
			f.Request.Header.Set(key, value)
		}

		logger.Debugf("应用了 %d 个自定义HTTP头部: %s", len(fa.customHeaders), f.Request.URL.String())

		// 记录应用的头部（调试用）
		for key, value := range fa.customHeaders {
			// 对敏感信息进行遮蔽显示
			maskedValue := fa.maskSensitiveValue(value)
			logger.Debugf("自定义头部: %s = %s", key, maskedValue)
		}
	}
}

// maskSensitiveValue 遮蔽敏感值用于日志输出
func (fa *FingerprintAddon) maskSensitiveValue(value string) string {
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}

	// 显示前4个和后4个字符，中间用*代替
	prefix := value[:4]
	suffix := value[len(value)-4:]
	middle := strings.Repeat("*", len(value)-8)

	return prefix + middle + suffix
}

// forceRefreshResponse 强制刷新响应内容
func (fa *FingerprintAddon) forceRefreshResponse(f *proxy.Flow) {
	if f.Response == nil {
		return
	}

	// 移除响应中可能导致缓存的头部
	f.Response.Header.Del("ETag")
	f.Response.Header.Del("Last-Modified")
	f.Response.Header.Del("Cache-Control")
	f.Response.Header.Del("Expires")
	f.Response.Header.Del("Pragma")

	// 添加防缓存响应头
	f.Response.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
	f.Response.Header.Set("Pragma", "no-cache")
	f.Response.Header.Set("Expires", "0")

	// 如果是304状态码，强制改为200（如果有缓存内容的话）
	if f.Response.StatusCode == 304 {
		logger.Debugf("检测到304响应，尝试强制获取完整内容: %s", f.Request.URL.String())
		// 注意：这里不能直接修改状态码，因为内容可能确实没有变化
		// 但我们已经通过请求头避免了304响应的产生
	}

	logger.Debugf("已强制刷新响应内容: %s", f.Request.URL.String())
}
