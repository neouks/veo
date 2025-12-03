package fingerprint

import (
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"veo/pkg/utils/formatter"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
	"veo/pkg/utils/redirect"
	"veo/pkg/utils/shared"

	"gopkg.in/yaml.v3"
)

// ProbeResult 用于收集主动探测的匹配结果和响应对象
type ProbeResult struct {
	Response *HTTPResponse
	Matches  []*FingerprintMatch
}

type headerAwareHTTPClient interface {
	MakeRequestWithHeaders(string, map[string]string) (string, int, error)
}

// ===========================================
// 引擎实现
// ===========================================

// NewEngine 创建新的指纹识别引擎
func NewEngine(config *EngineConfig) *Engine {
	if config == nil {
		config = getDefaultConfig()
	}

	engine := &Engine{
		config:      config,
		rules:       make(map[string]*FingerprintRule),
		matches:     make([]*FingerprintMatch, 0),
		dslParser:   NewDSLParser(),
		outputCache: make(map[string]bool),
		iconCache:   make(map[string]string), // 初始化图标缓存
		stats: &Statistics{
			StartTime: time.Now(),
		},
		staticExtensions:         append([]string(nil), StaticFileExtensions...),
		staticContentTypes:       append([]string(nil), StaticContentTypes...),
		staticFileFilterEnabled:  true,
		contentTypeFilterEnabled: true,
	}

	return engine
}

// SetStaticContentTypes 设置自定义静态Content-Type列表
func (e *Engine) SetStaticContentTypes(contentTypes []string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if contentTypes == nil {
		e.staticContentTypes = append([]string(nil), StaticContentTypes...)
	} else {
		e.staticContentTypes = cloneStringSlice(contentTypes)
	}
}

// SetStaticFileExtensions 设置自定义静态文件扩展名列表
func (e *Engine) SetStaticFileExtensions(extensions []string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if extensions == nil {
		e.staticExtensions = append([]string(nil), StaticFileExtensions...)
	} else {
		e.staticExtensions = cloneStringSlice(extensions)
	}
}

// EnableSnippet 控制是否输出指纹匹配片段
func (e *Engine) EnableSnippet(enabled bool) {
	e.mu.Lock()
	e.showSnippet = enabled
	e.mu.Unlock()
}

// EnableRuleLogging 控制是否输出匹配规则内容
func (e *Engine) EnableRuleLogging(enabled bool) {
	e.mu.Lock()
	e.showRules = enabled
	e.mu.Unlock()
}

// IsSnippetEnabled 返回是否启用指纹匹配片段输出
func (e *Engine) IsSnippetEnabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.showSnippet
}

// SetStaticFileFilterEnabled 控制是否启用静态文件过滤
func (e *Engine) SetStaticFileFilterEnabled(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.staticFileFilterEnabled = enabled
}

// SetContentTypeFilterEnabled 控制是否启用Content-Type过滤
func (e *Engine) SetContentTypeFilterEnabled(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.contentTypeFilterEnabled = enabled
}

// LoadRules 加载指纹识别规则（支持单文件或目录）
func (e *Engine) LoadRules(rulesPath string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	logger.Debugf("开始加载指纹规则: %s", rulesPath)

	// 检查路径是文件还是目录
	fileInfo, err := os.Stat(rulesPath)
	if err != nil {
		return fmt.Errorf("规则路径不存在: %v", err)
	}

	var yamlFiles []string

	if fileInfo.IsDir() {
		// 目录模式：扫描所有.yaml文件
		logger.Debugf("检测到目录路径，扫描所有YAML文件: %s", rulesPath)

		files, err := ioutil.ReadDir(rulesPath)
		if err != nil {
			return fmt.Errorf("读取目录失败: %v", err)
		}

		for _, file := range files {
			if !file.IsDir() && strings.HasSuffix(strings.ToLower(file.Name()), ".yaml") {
				yamlFiles = append(yamlFiles, filepath.Join(rulesPath, file.Name()))
			}
		}

		if len(yamlFiles) == 0 {
			return fmt.Errorf("目录中没有找到YAML文件: %s", rulesPath)
		}

		logger.Debugf("找到 %d 个YAML文件", len(yamlFiles))
	} else {
		// 文件模式：加载单个文件
		yamlFiles = append(yamlFiles, rulesPath)
	}

	// 加载所有YAML文件
	e.loadedSummaries = nil
	totalRulesLoaded := 0
	for _, yamlFile := range yamlFiles {
		count, err := e.loadSingleYAMLFile(yamlFile)
		if err != nil {
			logger.Warnf("加载指纹库文件失败: %s, 错误: %v", filepath.Base(yamlFile), err)
			continue
		}
		summary := fmt.Sprintf("%s:%d", filepath.Base(yamlFile), count)
		e.loadedSummaries = append(e.loadedSummaries, summary)
		// 降级为调试日志，避免在模块启动前重复打印
		logger.Debugf("Loaded FingerPrint Rules: %s", summary)
		totalRulesLoaded += count
	}
	e.stats.RulesLoaded = totalRulesLoaded
	return nil
}

// GetLoadedSummaryString 返回已加载规则文件的摘要字符串
// 例如："finger.yaml:754 sensitive.yaml:47"
// 参数：无
// 返回：摘要字符串，若无则返回空字符串
func (e *Engine) GetLoadedSummaryString() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return strings.Join(e.loadedSummaries, " ")
}

// loadSingleYAMLFile 加载单个YAML文件
func (e *Engine) loadSingleYAMLFile(filePath string) (int, error) {
	// 读取YAML文件
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return 0, fmt.Errorf("读取文件失败: %v", err)
	}

	// 解析YAML
	var rulesMap map[string]*FingerprintRule
	if err := yaml.Unmarshal(data, &rulesMap); err != nil {
		return 0, fmt.Errorf("解析YAML失败: %v", err)
	}

	// 处理规则
	loadedCount := 0
	isSensitiveFile := strings.Contains(strings.ToLower(filepath.Base(filePath)), "sensitive")
	for ruleName, rule := range rulesMap {
		if rule != nil {
			rule.ID = ruleName
			rule.Name = ruleName
			if isSensitiveFile && strings.TrimSpace(rule.Category) == "" {
				rule.Category = "sensitive"
			}

			// 检查规则ID冲突
			if existingRule, exists := e.rules[ruleName]; exists {
				logger.Warnf("规则ID冲突: %s (文件: %s 覆盖了之前的规则)",
					ruleName, filepath.Base(filePath))
				logger.Debugf("  原规则DSL: %v", existingRule.DSL)
				logger.Debugf("  新规则DSL: %v", rule.DSL)
			}

			e.rules[ruleName] = rule
			loadedCount++
		}
	}

	return loadedCount, nil
}

// AnalyzeResponse 分析响应包并进行指纹识别（基础版本，用于向后兼容）
func (e *Engine) AnalyzeResponse(response *HTTPResponse) []*FingerprintMatch {
	return e.AnalyzeResponseWithClient(response, nil)
}

// AnalyzeResponseWithClient 分析响应包并进行指纹识别（增强版，支持icon()函数主动探测）
func (e *Engine) AnalyzeResponseWithClient(response *HTTPResponse, httpClient interface{}) []*FingerprintMatch {
	// 检查是否应该过滤此响应
	if e.config.EnableFiltering && e.shouldFilterResponse(response) {
		atomic.AddInt64(&e.stats.FilteredRequests, 1)
		return nil
	}

	// 更新统计
	atomic.AddInt64(&e.stats.TotalRequests, 1)

	// 性能优化：移除信号量控制，统一在RequestProcessor层管理并发
	// 指纹匹配本身是CPU密集型操作，不需要额外的并发限制
	// HTTP请求的并发控制已在RequestProcessor层实现

	// 创建DSL上下文（支持主动探测）
	var ctx *DSLContext
	if httpClient != nil {
		// 从响应URL中提取基础URL
		baseURL := ""
		if parsedURL, err := url.Parse(response.URL); err == nil {
			baseURL = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
		}
		ctx = e.createDSLContextWithClient(response, httpClient, baseURL)
		logger.Debugf("创建增强DSL上下文，支持icon()主动探测: %s (HTTPClient: %v)", baseURL, httpClient != nil)
	} else {
		ctx = e.createDSLContext(response)
		logger.Debugf("创建基础DSL上下文，不支持icon()主动探测")
	}

	var matches []*FingerprintMatch

	// 遍历所有规则进行匹配
	e.mu.RLock()
	rules := make(map[string]*FingerprintRule)
	for k, v := range e.rules {
		rules[k] = v
	}
	e.mu.RUnlock()

	for _, rule := range rules {
		if match := e.matchRule(rule, ctx); match != nil {
			matches = append(matches, match)
		}
	}

	// 更新匹配统计和输出日志
	if len(matches) > 0 {
		atomic.AddInt64(&e.stats.MatchedRequests, 1)
		e.mu.Lock()
		e.stats.LastMatchTime = time.Now()
		e.matches = append(e.matches, matches...)
		e.mu.Unlock()

		// 使用统一的输出方法（消除重复代码）
		e.outputFingerprintMatches(matches, response, "")
	} else {
		// 没有匹配到指纹时，输出基本信息（标题+状态码）
		e.outputNoMatchInfo(response)
	}

	if fetcher, ok := httpClient.(redirect.HTTPFetcher); ok {
		if redirected, err := redirect.FollowClientRedirect(convertToInterfacesResponse(response), fetcher); err == nil && redirected != nil {
			converted := convertFromInterfacesResponse(redirected)
			if converted != nil {
				rMatches := e.AnalyzeResponseWithClientSilent(converted, httpClient)
				if len(rMatches) > 0 {
					e.outputFingerprintMatches(rMatches, converted, "")
					matches = append(matches, rMatches...)
				}
			}
		} else if err != nil {
			logger.Debugf("客户端重定向抓取失败: %v", err)
		}
	}

	return matches
}

func convertToInterfacesResponse(resp *HTTPResponse) *interfaces.HTTPResponse {
	if resp == nil {
		return nil
	}
	return &interfaces.HTTPResponse{
		URL:             resp.URL,
		Method:          resp.Method,
		StatusCode:      resp.StatusCode,
		Title:           resp.Title,
		ContentType:     resp.ContentType,
		ContentLength:   resp.ContentLength,
		Body:            resp.Body,
		ResponseHeaders: resp.ResponseHeaders,
	}
}

func convertFromInterfacesResponse(resp *interfaces.HTTPResponse) *HTTPResponse {
	if resp == nil {
		return nil
	}
	return &HTTPResponse{
		URL:             resp.URL,
		Method:          resp.Method,
		StatusCode:      resp.StatusCode,
		Body:            resp.Body,
		ContentType:     resp.ContentType,
		ContentLength:   resp.ContentLength,
		Server:          resp.Server,
		Title:           resp.Title,
		ResponseHeaders: resp.ResponseHeaders,
	}
}

// AnalyzeResponseWithClientSilent 分析响应包并进行指纹识别（静默版本，不自动输出结果）
// 专用于404页面等需要自定义输出格式的场景
func (e *Engine) AnalyzeResponseWithClientSilent(response *HTTPResponse, httpClient interface{}) []*FingerprintMatch {
	// 检查是否应该过滤此响应
	if e.config.EnableFiltering && e.shouldFilterResponse(response) {
		atomic.AddInt64(&e.stats.FilteredRequests, 1)
		return nil
	}

	// 更新统计
	atomic.AddInt64(&e.stats.TotalRequests, 1)

	// 创建DSL上下文（支持主动探测）
	var ctx *DSLContext
	if httpClient != nil {
		// 从响应URL中提取基础URL
		baseURL := ""
		if parsedURL, err := url.Parse(response.URL); err == nil {
			baseURL = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
		}
		ctx = e.createDSLContextWithClient(response, httpClient, baseURL)
		logger.Debugf("创建增强DSL上下文（静默模式），支持icon()主动探测: %s (HTTPClient: %v)", baseURL, httpClient != nil)
	} else {
		ctx = e.createDSLContext(response)
		logger.Debugf("创建基础DSL上下文（静默模式），不支持icon()主动探测")
	}

	var matches []*FingerprintMatch

	// 遍历所有规则进行匹配
	e.mu.RLock()
	rules := make(map[string]*FingerprintRule)
	for k, v := range e.rules {
		rules[k] = v
	}
	e.mu.RUnlock()

	for _, rule := range rules {
		if match := e.matchRule(rule, ctx); match != nil {
			matches = append(matches, match)
		}
	}

	// 更新匹配统计但不输出日志（静默模式）
	if len(matches) > 0 {
		atomic.AddInt64(&e.stats.MatchedRequests, 1)
		e.mu.Lock()
		e.stats.LastMatchTime = time.Now()
		e.matches = append(e.matches, matches...)
		e.mu.Unlock()

		// [关键] 静默模式：不调用 outputFingerprintMatches，由调用方负责输出
		logger.Debugf("静默模式匹配完成，匹配数量: %d，跳过自动输出", len(matches))
	}

	return matches
}

// matchRule 匹配单个规则
func (e *Engine) matchRule(rule *FingerprintRule, ctx *DSLContext) *FingerprintMatch {
	// 如果没有DSL表达式，直接返回nil
	if len(rule.DSL) == 0 {
		return nil
	}

	// 获取条件类型，默认为"or"
	condition := strings.ToLower(strings.TrimSpace(rule.Condition))
	if condition == "" {
		condition = "or"
	}

	matchedDSLs := make([]string, 0)

	// 根据条件类型执行匹配
	switch condition {
	case "and":
		// AND条件：所有DSL表达式都必须匹配
		for _, dsl := range rule.DSL {
			if e.dslParser.EvaluateDSL(dsl, ctx) {
				matchedDSLs = append(matchedDSLs, dsl)
			} else {
				// 有一个不匹配就返回nil
				return nil
			}
		}
		// 所有表达式都匹配成功
		if len(matchedDSLs) == len(rule.DSL) {
			snippet := ""
			if e.shouldCaptureSnippet(rule) {
				for _, dsl := range matchedDSLs {
					snippet = e.extractSnippetForDSL(dsl, ctx)
					if snippet != "" {
						break
					}
				}
			}
			return &FingerprintMatch{
				URL:        ctx.URL,
				RuleName:   rule.Name,
				Technology: rule.Name,
				DSLMatched: fmt.Sprintf("AND(%s)", strings.Join(matchedDSLs, " && ")),
				Timestamp:  time.Now(),
				Snippet:    snippet,
			}
		}
	case "or":
		fallthrough // OR和default使用相同逻辑
	default:
		if condition != "or" {
			logger.Warnf("不支持的条件类型: %s, 使用默认OR条件", condition)
		}
		// OR条件：任意一个DSL表达式匹配即可
		for _, dsl := range rule.DSL {
			if e.dslParser.EvaluateDSL(dsl, ctx) {
				snippet := ""
				if e.shouldCaptureSnippet(rule) {
					snippet = e.extractSnippetForDSL(dsl, ctx)
				}
				return &FingerprintMatch{
					URL:        ctx.URL,
					RuleName:   rule.Name,
					Technology: rule.Name,
					DSLMatched: dsl,
					Timestamp:  time.Now(),
					Snippet:    snippet,
				}
			}
		}
	}

	return nil
}

func (e *Engine) shouldCaptureSnippet(rule *FingerprintRule) bool {
	if rule == nil {
		return false
	}
	return e.IsSnippetEnabled()
}

func (e *Engine) extractSnippetForDSL(dsl string, ctx *DSLContext) string {
	if ctx == nil || strings.TrimSpace(dsl) == "" {
		return ""
	}
	snippet := e.dslParser.ExtractSnippet(dsl, ctx)
	return snippet
}

// createDSLContext 创建DSL解析上下文（基础版本，用于被动识别）
func (e *Engine) createDSLContext(response *HTTPResponse) *DSLContext {
	return e.createDSLContextWithClient(response, nil, "")
}

// createDSLContextWithClient 创建DSL解析上下文（增强版，支持主动探测）
func (e *Engine) createDSLContextWithClient(response *HTTPResponse, httpClient interface{}, baseURL string) *DSLContext {
	// 构建http.Header
	headers := make(http.Header)
	for name, values := range response.ResponseHeaders {
		headers[name] = values
	}

	// 如果没有提供baseURL，尝试从response.URL中提取
	if baseURL == "" && response.URL != "" {
		if parsedURL, err := url.Parse(response.URL); err == nil {
			baseURL = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
		}
	}

	return &DSLContext{
		Response:   response,
		Headers:    headers,
		Body:       response.Body,
		URL:        response.URL,
		Method:     response.Method,
		HTTPClient: httpClient,
		BaseURL:    baseURL,
		Engine:     e, // 传递Engine实例以访问图标缓存
	}
}

// shouldFilterResponse 检查是否应该过滤响应
func (e *Engine) shouldFilterResponse(response *HTTPResponse) bool {
	// 检查响应体大小
	if e.config.MaxBodySize > 0 && len(response.Body) > e.config.MaxBodySize {
		logger.Debugf("过滤大响应体: %s (大小: %d bytes, 限制: %d bytes)",
			response.URL, len(response.Body), e.config.MaxBodySize)
		return true
	}

	// 检查是否为静态文件（基于URL路径）
	if e.isStaticFile(response.URL) {
		logger.Debugf("过滤静态文件: %s", response.URL)
		return true
	}

	// 检查Content-Type
	if e.isStaticContentType(response.ContentType) {
		logger.Debugf("过滤静态内容类型: %s (Content-Type: %s)",
			response.URL, response.ContentType)
		return true
	}

	return false
}

// isStaticFile 检查URL是否指向静态文件（使用共享工具）
func (e *Engine) isStaticFile(rawURL string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.staticFileFilterEnabled || len(e.staticExtensions) == 0 {
		return false
	}

	lowerURL := strings.ToLower(rawURL)
	for _, ext := range e.staticExtensions {
		if ext == "" {
			continue
		}
		if strings.HasSuffix(lowerURL, strings.ToLower(ext)) {
			return true
		}
	}

	return false
}

// isStaticContentType 检查Content-Type是否为静态类型
func (e *Engine) isStaticContentType(contentType string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.contentTypeFilterEnabled || len(e.staticContentTypes) == 0 {
		return false
	}

	contentType = strings.ToLower(contentType)

	for _, staticType := range e.staticContentTypes {
		if staticType == "" {
			continue
		}
		if strings.HasPrefix(contentType, strings.ToLower(staticType)) {
			return true
		}
	}

	return false
}

func cloneStringSlice(values []string) []string {
	if values == nil {
		return nil
	}
	clone := make([]string, len(values))
	copy(clone, values)
	return clone
}

// GetMatches 获取所有匹配结果
func (e *Engine) GetMatches() []*FingerprintMatch {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// 返回副本避免并发修改
	matches := make([]*FingerprintMatch, len(e.matches))
	copy(matches, e.matches)
	return matches
}

// GetStats 获取统计信息
func (e *Engine) GetStats() *Statistics {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// 返回副本
	stats := &Statistics{
		TotalRequests:    atomic.LoadInt64(&e.stats.TotalRequests),
		MatchedRequests:  atomic.LoadInt64(&e.stats.MatchedRequests),
		FilteredRequests: atomic.LoadInt64(&e.stats.FilteredRequests),
		RulesLoaded:      e.stats.RulesLoaded,
		StartTime:        e.stats.StartTime,
		LastMatchTime:    e.stats.LastMatchTime,
	}

	return stats
}

// GetRulesCount 获取加载的规则数量
func (e *Engine) GetRulesCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// ===========================================
// 配置和辅助方法
// ===========================================

// getDefaultConfig 获取默认配置
func getDefaultConfig() *EngineConfig {
	maxConcurrency := 20 // 默认最小并发数

	return &EngineConfig{
		RulesPath:       "config/fingerprint/", // [修改] 改为目录路径，自动加载所有YAML文件
		MaxConcurrency:  maxConcurrency,
		EnableFiltering: true,
		MaxBodySize:     1024 * 1024, // 1MB
		LogMatches:      true,
	}
}

// ===========================================
// 缓存和去重相关方法
// ===========================================

// generateFingerprintCacheKey 生成细粒度缓存键（域名+端口+路径+指纹组合）
// 优化版本：减少内存分配，使用strings.Builder提高性能
// [修复] 包含完整路径信息，避免不同路径的相同指纹被错误过滤
func (e *Engine) generateFingerprintCacheKey(rawURL string, fingerprintNames []string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return rawURL // 解析失败时使用原URL
	}

	// 使用strings.Builder减少内存分配
	var builder strings.Builder
	builder.WriteString(parsedURL.Host)
	builder.WriteByte('|')
	// [修复] 添加路径信息，确保不同路径的指纹不会被错误缓存
	builder.WriteString(parsedURL.Path)
	builder.WriteByte('|')

	// 对指纹名称进行排序以确保一致性（仅在多个指纹时）
	if len(fingerprintNames) == 0 {
		return builder.String()
	} else if len(fingerprintNames) == 1 {
		builder.WriteString(fingerprintNames[0])
	} else {
		// 创建排序副本，避免修改原始切片
		sortedNames := make([]string, len(fingerprintNames))
		copy(sortedNames, fingerprintNames)
		sort.Strings(sortedNames)

		// 使用strings.Join一次性拼接
		builder.WriteString(strings.Join(sortedNames, ","))
	}

	return builder.String()
}

// checkAndMarkFingerprint 检查并标记指纹输出状态（封装常见模式）
// 返回true表示应该输出，false表示已重复
func (e *Engine) checkAndMarkFingerprint(cacheKey string) bool {
	e.outputMutex.Lock()
	defer e.outputMutex.Unlock()

	// 检查是否已输出
	if e.outputCache[cacheKey] {
		return false // 已重复，不应输出
	}

	// 标记为已输出
	e.outputCache[cacheKey] = true
	return true // 应该输出
}

func (e *Engine) formatFingerprintDisplay(name, rule string) string {
	e.mu.RLock()
	showRule := e.showRules
	e.mu.RUnlock()
	return formatter.FormatFingerprintDisplay(name, rule, showRule)
}

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

// ===========================================
// 图标缓存相关方法
// ===========================================

// getIconHash 获取图标哈希值（带缓存，包括失败结果缓存）
func (e *Engine) getIconHash(iconURL string, httpClient interface{}) (string, error) {
	// 先检查缓存
	e.iconMutex.RLock()
	if cachedValue, exists := e.iconCache[iconURL]; exists {
		e.iconMutex.RUnlock()

		// 检查是否为失败缓存（使用特殊标记 "FAILED" 表示请求失败）
		if cachedValue == "FAILED" {
			logger.Debugf("图标失败缓存命中: %s (之前请求失败)", iconURL)
			return "", fmt.Errorf("图标请求失败（缓存结果）")
		}

		// 成功缓存命中
		logger.Debugf("图标成功缓存命中: %s -> %s", iconURL, cachedValue)
		return cachedValue, nil
	}
	e.iconMutex.RUnlock()

	// 缓存未命中，发起HTTP请求
	logger.Debugf("图标缓存未命中，开始请求: %s", iconURL)

	// 类型断言检查httpClient是否实现了MakeRequest方法
	if client, ok := httpClient.(interface {
		MakeRequest(string) (string, int, error)
	}); ok {
		body, statusCode, err := client.MakeRequest(iconURL)

		// 处理网络错误
		if err != nil {
			// 缓存网络错误，避免重复请求
			e.iconMutex.Lock()
			e.iconCache[iconURL] = "FAILED"
			e.iconMutex.Unlock()

			logger.Debugf("图标网络请求失败并缓存: %s, 错误: %v", iconURL, err)
			return "", fmt.Errorf("请求图标失败: %v", err)
		}

		// 处理非200状态码
		if statusCode != 200 {
			// 缓存HTTP错误状态码，避免重复请求
			e.iconMutex.Lock()
			e.iconCache[iconURL] = "FAILED"
			e.iconMutex.Unlock()

			logger.Debugf("图标HTTP错误并缓存: %s, 状态码: %d", iconURL, statusCode)
			return "", fmt.Errorf("图标请求返回非200状态码: %d", statusCode)
		}

		// 计算MD5哈希值
		hash := fmt.Sprintf("%x", md5.Sum([]byte(body)))

		// 存入成功缓存
		e.iconMutex.Lock()
		e.iconCache[iconURL] = hash
		e.iconMutex.Unlock()

		logger.Debugf("图标哈希计算并缓存: %s -> %s", iconURL, hash)
		return hash, nil
	} else {
		// httpClient不支持MakeRequest方法
		logger.Debugf("HTTP客户端不支持MakeRequest方法，跳过图标请求: %s", iconURL)
		return "", fmt.Errorf("HTTP客户端不支持MakeRequest方法")
	}
}

// outputNoMatchInfo 输出无指纹匹配时的默认信息（URL、标题、状态码）
func (e *Engine) outputNoMatchInfo(response *HTTPResponse) {
	if !e.config.LogMatches {
		return
	}

	// 生成细粒度缓存键（无指纹）
	cacheKey := e.generateFingerprintCacheKey(response.URL, nil)

	// 使用优化的检查-标记方法
	if e.checkAndMarkFingerprint(cacheKey) {
		var logMsg strings.Builder
		logMsg.WriteString(formatter.FormatURL(response.URL))
		logMsg.WriteString(" ")

		title := response.Title
		if title == "" {
			title = "无标题"
		}
		logMsg.WriteString(formatter.FormatTitle(title))

		logMsg.WriteString(" ")
		logMsg.WriteString(formatter.FormatStatusCode(response.StatusCode))
		logMsg.WriteString(" ")
		logMsg.WriteString(formatter.FormatContentType(response.ContentType))

		logger.Info(logMsg.String())
	}
}

// outputFingerprintMatches 统一的指纹匹配结果输出方法
// 消除被动识别和主动探测中的重复代码，提供统一的日志输出和去重逻辑
func (e *Engine) outputFingerprintMatches(matches []*FingerprintMatch, response *HTTPResponse, tag string) {
	if !e.config.LogMatches || len(matches) == 0 {
		return
	}

	// 收集指纹名称和DSL规则（优化：预分配切片容量）
	fingerprintNames := make([]string, 0, len(matches))
	dslRules := make([]string, 0, len(matches))

	for _, match := range matches {
		fingerprintNames = append(fingerprintNames, match.RuleName)
		dslRules = append(dslRules, match.DSLMatched)
	}

	// 生成细粒度缓存键
	cacheKey := e.generateFingerprintCacheKey(response.URL, fingerprintNames)

	// 使用优化的检查-标记方法
	if e.checkAndMarkFingerprint(cacheKey) {
		// 构建高亮日志消息（新增：添加标题显示，与目录扫描格式保持一致）
		var logMsg strings.Builder
		logMsg.WriteString(formatter.FormatURL(response.URL))
		logMsg.WriteString(" ")

		// 添加标题显示（与目录扫描格式保持一致）
		title := response.Title
		if title == "" {
			title = "无标题"
		}
		logMsg.WriteString(formatter.FormatFingerprintTitle(title))
		logMsg.WriteString(" ")
		logMsg.WriteString(formatter.FormatContentType(response.ContentType))

		for _, match := range matches {
			if match == nil {
				continue
			}
			display := e.formatFingerprintDisplay(match.RuleName, match.DSLMatched)
			if display == "" {
				continue
			}
			logMsg.WriteString(" ")
			logMsg.WriteString(display)
		}

		// 添加标签（如果提供）
		if tag != "" {
			logMsg.WriteString(" [")
			logMsg.WriteString(formatter.FormatFingerprintTag(tag))
			logMsg.WriteString("]")
		}

		if e.showSnippet {
			var snippetLines []string
			for _, match := range matches {
				if match == nil {
					continue
				}
				for _, line := range highlightedSnippetLines(match.Snippet, match.DSLMatched) {
					snippetLines = append(snippetLines, line)
				}
			}
			if len(snippetLines) > 0 {
				logMsg.WriteString("\n")
				for idx, snippetLine := range snippetLines {
					if idx > 0 {
						logMsg.WriteString("\n")
					}
					logMsg.WriteString("  ")
					logMsg.WriteString(formatter.FormatSnippetArrow())
					logMsg.WriteString(snippetLine)
				}
			}
		}

		logger.Info(logMsg.String())
	} else {
		// 调试日志：跳过重复输出
		tagSuffix := ""
		if tag != "" {
			tagSuffix = " [" + tag + "]"
		}
		logger.Debugf("跳过重复输出: %s (缓存键: %s)%s", response.URL, cacheKey, tagSuffix)
	}
}

// ===========================================
// 主动探测相关方法
// ===========================================

// TriggerActiveProbing 触发主动探测（异步）
// 参数: baseURL - 基础URL（如 https://example.com）
//
//	httpClient - HTTP客户端接口
func (e *Engine) TriggerActiveProbing(baseURL string, httpClient interface{}) {
	if httpClient == nil {
		logger.Debug("HTTP客户端未设置，跳过主动探测")
		return
	}

	// 异步执行主动探测，避免阻塞主流程
	go e.performActiveProbing(baseURL, httpClient)
}

// performActiveProbing 执行主动探测
func (e *Engine) performActiveProbing(baseURL string, httpClient interface{}) {
	logger.Debugf("开始主动探测: %s", baseURL)

	// 获取所有包含path字段的规则
	e.mu.RLock()
	var pathRules []*FingerprintRule
	var headerOnlyRules []*FingerprintRule
	totalPaths := 0
	for _, rule := range e.rules {
		if rule == nil {
			continue
		}
		if rule.HasPaths() {
			pathRules = append(pathRules, rule)
			totalPaths += len(rule.Paths)
			continue
		}
		if rule.HasHeaders() {
			headerOnlyRules = append(headerOnlyRules, rule)
		}
	}
	e.mu.RUnlock()

	if totalPaths == 0 && len(headerOnlyRules) == 0 {
		logger.Debug("没有需要主动探测的规则，跳过主动探测")
		return
	}

	if totalPaths > 0 {
		logger.Debugf("找到 %d 个包含path字段的规则，共 %d 条路径", len(pathRules), totalPaths)
	}
	if len(headerOnlyRules) > 0 {
		logger.Debugf("找到 %d 个包含header字段的规则需要主动探测", len(headerOnlyRules))
	}

	// 解析baseURL获取协议和主机
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		logger.Debugf("URL解析失败: %s, 错误: %v", baseURL, err)
		return
	}

	scheme := parsedURL.Scheme
	host := parsedURL.Host

	// 遍历所有path规则进行探测
	for _, rule := range pathRules {
		e.performRuleProbing(rule, scheme, host, baseURL, httpClient)
	}

	// 处理仅包含header的规则（默认探测根路径）
	for _, rule := range headerOnlyRules {
		defaultURL := buildProbeURLFromParts(scheme, host, "/")
		e.performRuleRequest(rule, defaultURL, baseURL, httpClient, true)
	}

	// [新增] 404页面指纹识别（保持独立调用）
	e.perform404PageProbing(baseURL, httpClient)

	logger.Debugf("主动探测完成: %s (共探测 %d 条路径)", baseURL, totalPaths)
}

func (e *Engine) performRuleProbing(rule *FingerprintRule, scheme, host, baseURL string, httpClient interface{}) {
	if rule == nil {
		return
	}
	headers := rule.GetHeaderMap()
	for _, rawPath := range rule.Paths {
		probePath := strings.TrimSpace(rawPath)
		if probePath == "" {
			continue
		}
		probeURL := buildProbeURLFromParts(scheme, host, probePath)
		e.performRuleRequest(rule, probeURL, baseURL, httpClient, false, headers)
	}
}

func (e *Engine) performRuleRequest(rule *FingerprintRule, probeURL, baseURL string, httpClient interface{}, logDefault bool, headerArgs ...map[string]string) {
	if rule == nil {
		return
	}
	var headers map[string]string
	if len(headerArgs) > 0 && headerArgs[0] != nil {
		headers = headerArgs[0]
	} else if rule.HasHeaders() {
		headers = rule.GetHeaderMap()
	}

	if logDefault {
		logger.Debugf("主动探测URL: %s (Header规则: %s)", probeURL, rule.Name)
	} else {
		logger.Debugf("主动探测URL: %s (规则: %s)", probeURL, rule.Name)
	}

	body, statusCode, err := makeRequestWithOptionalHeaders(httpClient, probeURL, headers)
	if err != nil {
		logger.Debugf("主动探测请求失败: %s, 错误: %v", probeURL, err)
		return
	}

	response := &HTTPResponse{
		URL:             probeURL,
		Method:          "GET",
		StatusCode:      statusCode,
		ResponseHeaders: make(map[string][]string),
		Body:            body,
		ContentType:     "text/html",
		ContentLength:   int64(len(body)),
		Server:          "",
		Title:           shared.ExtractTitle(body),
	}

	ctx := e.createDSLContextWithClient(response, httpClient, baseURL)
	if match := e.matchRule(rule, ctx); match != nil {
		atomic.AddInt64(&e.stats.MatchedRequests, 1)
		e.mu.Lock()
		e.stats.LastMatchTime = time.Now()
		e.matches = append(e.matches, match)
		e.mu.Unlock()

		e.outputFingerprintMatches([]*FingerprintMatch{match}, response, "主动探测")
		logger.Debugf("主动探测实时输出: %s (规则: %s)", probeURL, rule.Name)
	}
}

// perform404PageProbing 执行404页面指纹识别
// [修改] 移除urlResults参数，简化为独立的实时输出
func (e *Engine) perform404PageProbing(baseURL string, httpClient interface{}) {
	logger.Debugf("开始404页面指纹识别: %s", baseURL)

	// 解析baseURL获取协议和主机
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		logger.Debugf("URL解析失败: %s, 错误: %v", baseURL, err)
		return
	}

	scheme := parsedURL.Scheme
	host := parsedURL.Host

	// 构造404测试URL
	notFoundURL := fmt.Sprintf("%s://%s/404test", scheme, host)
	logger.Debugf("404页面探测URL: %s", notFoundURL)

	// 发起HTTP请求
	if client, ok := httpClient.(interface {
		MakeRequest(string) (string, int, error)
	}); ok {
		body, statusCode, err := client.MakeRequest(notFoundURL)
		if err != nil {
			logger.Debugf("404页面探测请求失败: %s, 错误: %v", notFoundURL, err)
			return
		}

		// 构造模拟的HTTPResponse用于DSL匹配
		response := &HTTPResponse{
			URL:             notFoundURL,
			Method:          "GET",
			StatusCode:      statusCode,
			ResponseHeaders: make(map[string][]string), // 简化版，暂不解析响应头
			Body:            body,
			ContentType:     "text/html", // 简化假设
			ContentLength:   int64(len(body)),
			Server:          "",
			Title:           shared.ExtractTitle(body),
		}

		logger.Debugf("404页面响应: 状态码=%d, 标题='%s', 内容长度=%d",
			statusCode, response.Title, len(body))

		// 对404页面进行全量指纹规则匹配
		matches := e.match404PageFingerprints(response, httpClient, baseURL)

		if len(matches) > 0 {
			// 更新统计
			for range matches {
				atomic.AddInt64(&e.stats.MatchedRequests, 1)
				e.mu.Lock()
				e.stats.LastMatchTime = time.Now()
				e.mu.Unlock()
			}

			// 保存匹配结果
			e.mu.Lock()
			e.matches = append(e.matches, matches...)
			e.mu.Unlock()

			// [关键] 实时输出404页面的匹配结果
			e.outputFingerprintMatches(matches, response, "404页面")

			logger.Debugf("404页面实时输出: 匹配到 %d 个指纹", len(matches))
		} else {
			logger.Debugf("404页面未匹配到任何指纹")
		}
	} else {
		logger.Debugf("HTTP客户端不支持MakeRequest方法，跳过404页面探测")
	}
}

// match404PageFingerprints 对404页面进行全量指纹规则匹配
func (e *Engine) match404PageFingerprints(response *HTTPResponse, httpClient interface{}, baseURL string) []*FingerprintMatch {
	logger.Debugf("开始404页面全量指纹匹配")

	// 创建DSL上下文（支持主动探测）
	ctx := e.createDSLContextWithClient(response, httpClient, baseURL)

	var matches []*FingerprintMatch

	// 获取所有指纹规则进行匹配
	e.mu.RLock()
	rules := make(map[string]*FingerprintRule)
	for k, v := range e.rules {
		rules[k] = v
	}
	e.mu.RUnlock()

	// 遍历所有规则进行匹配
	for _, rule := range rules {
		if match := e.matchRule(rule, ctx); match != nil {
			matches = append(matches, match)
			logger.Debugf("404页面匹配到指纹: %s (规则: %s)",
				match.Technology, match.RuleName)
		}
	}

	logger.Debugf("404页面全量匹配完成，共匹配到 %d 个指纹", len(matches))
	return matches
}

func makeRequestWithOptionalHeaders(httpClient interface{}, targetURL string, headers map[string]string) (string, int, error) {
	if len(headers) > 0 {
		if headerClient, ok := httpClient.(headerAwareHTTPClient); ok {
			return headerClient.MakeRequestWithHeaders(targetURL, headers)
		}
		logger.Debugf("HTTP客户端不支持自定义头部，使用默认请求: %s", targetURL)
	}

	if client, ok := httpClient.(interface {
		MakeRequest(string) (string, int, error)
	}); ok {
		return client.MakeRequest(targetURL)
	}

	return "", 0, fmt.Errorf("HTTP客户端不支持MakeRequest方法")
}

func buildProbeURLFromParts(scheme, host, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	trimmed := path
	if trimmed == "" {
		trimmed = "/"
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, trimmed)
}

// HasPathRules 检查是否有包含path字段的规则
func (e *Engine) HasPathRules() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, rule := range e.rules {
		if rule != nil && rule.HasPaths() {
			return true
		}
	}
	return false
}

// GetPathRulesCount 获取包含path字段的规则数量
func (e *Engine) GetPathRulesCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	count := 0
	for _, rule := range e.rules {
		if rule == nil {
			continue
		}
		count += len(rule.Paths)
	}
	return count
}

// GetPathRules 获取所有包含path字段的规则（公共方法，供CLI使用）
func (e *Engine) GetPathRules() []*FingerprintRule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var pathRules []*FingerprintRule
	for _, rule := range e.rules {
		if rule != nil && rule.HasPaths() {
			pathRules = append(pathRules, rule)
		}
	}
	return pathRules
}

// MatchSpecificRule 匹配指定的单个规则（公开方法，供CLI使用）
func (e *Engine) MatchSpecificRule(rule *FingerprintRule, response *HTTPResponse, httpClient interface{}, baseURL string) *FingerprintMatch {
	// 创建DSL上下文（支持主动探测）
	ctx := e.createDSLContextWithClient(response, httpClient, baseURL)
	// 匹配指定规则
	return e.matchRule(rule, ctx)
}
