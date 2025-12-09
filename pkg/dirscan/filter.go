package dirscan

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"veo/pkg/utils/formatter"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
	sharedutils "veo/pkg/utils/shared"
)

// FilterConfig 过滤器配置（独立配置，不依赖外部config包）
type FilterConfig struct {
	ValidStatusCodes     []int // 有效状态码列表
	InvalidPageThreshold int   // 无效页面阈值（主要筛选）
	SecondaryThreshold   int   // 二次筛选阈值
	EnableStatusFilter   bool  // 是否启用状态码过滤
	DisableHashFilter    bool  // 是否禁用哈希过滤

	// Content-Type过滤相关配置
	EnableContentTypeFilter bool     // 是否启用Content-Type过滤
	FilteredContentTypes    []string // 需要过滤的Content-Type列表

	// 相似页面过滤容错阈值配置
	FilterTolerance int64 // 相似页面过滤容错阈值（字节），0表示禁用过滤
}

// DefaultFilterConfig 获取默认过滤器配置
func DefaultFilterConfig() *FilterConfig {
	return &FilterConfig{
		ValidStatusCodes:     []int{200, 403, 500, 302, 301, 405},
		InvalidPageThreshold: 3,
		SecondaryThreshold:   1,
		EnableStatusFilter:   true,
		DisableHashFilter:    false,

		// Content-Type过滤默认配置
		EnableContentTypeFilter: true,
		FilteredContentTypes: []string{
			"image/png",
			"image/jpeg",
			"image/jpg",
			"image/gif",
			"image/webp",
			"image/svg+xml",
			"image/bmp",
			"image/ico",
			"image/tiff",
		},

		// 相似页面过滤容错阈值默认配置
		// [优化] 增加默认容错阈值到 100 字节，以便更好地聚合包含随机ID/时间戳的WAF页面/403页面
		FilterTolerance: 100, // 默认100字节容错
	}
}

// CloneFilterConfig 创建过滤器配置的深拷贝
func CloneFilterConfig(cfg *FilterConfig) *FilterConfig {
	if cfg == nil {
		return nil
	}

	clone := *cfg
	if cfg.ValidStatusCodes != nil {
		clone.ValidStatusCodes = append([]int(nil), cfg.ValidStatusCodes...)
	}
	if cfg.FilteredContentTypes != nil {
		clone.FilteredContentTypes = append([]string(nil), cfg.FilteredContentTypes...)
	}

	return &clone
}

// SetGlobalFilterConfig 设置全局默认过滤配置（SDK可用）
func SetGlobalFilterConfig(cfg *FilterConfig) {
	if cfg == nil {
		globalFilterConfig.Store((*FilterConfig)(nil))
		return
	}
	globalFilterConfig.Store(CloneFilterConfig(cfg))
}

func getGlobalFilterConfig() *FilterConfig {
	if value := globalFilterConfig.Load(); value != nil {
		if cfg, ok := value.(*FilterConfig); ok {
			return CloneFilterConfig(cfg)
		}
	}
	return nil
}

// ResponseFilter 响应过滤器（重构版，使用策略模式）
type ResponseFilter struct {
	config            *FilterConfig             // 过滤器配置
	statusCodeFilter  StatusCodeFilterStrategy  // 状态码过滤策略
	hashFilter        HashFilterStrategy        // 哈希过滤策略
	secondaryFilter   SecondaryFilterStrategy   // 二次筛选策略
	contentTypeFilter ContentTypeFilterStrategy // Content-Type过滤策略
	mu                sync.RWMutex              // 读写锁

	// [新增] 可选的指纹识别引擎（用于目录扫描结果的二次识别）
	fingerprintEngine      interfaces.FingerprintAnalyzer
	showFingerprintSnippet bool
	showFingerprintRule    bool
}

// NewResponseFilter 创建新的响应过滤器
func NewResponseFilter(config *FilterConfig) *ResponseFilter {
	if config == nil {
		config = DefaultFilterConfig()
	}

	// 创建过滤策略（传递容错阈值）
	statusCodeFilter := NewStatusCodeFilter(config.ValidStatusCodes)
	var hashFilter HashFilterStrategy
	var secondaryFilter SecondaryFilterStrategy
	if !config.DisableHashFilter {
		hashFilter = NewHashFilter(config.InvalidPageThreshold, config.FilterTolerance)
		secondaryFilter = NewSecondaryFilter(config.SecondaryThreshold, config.FilterTolerance)
	} else {
		logger.Infof("哈希过滤已禁用 (--no-filter)，将保留所有目录扫描响应")
	}
	contentTypeFilter := NewContentTypeFilter(config.FilteredContentTypes)

	rf := &ResponseFilter{
		config:            config,
		statusCodeFilter:  statusCodeFilter,
		hashFilter:        hashFilter,
		secondaryFilter:   secondaryFilter,
		contentTypeFilter: contentTypeFilter,
	}

	logger.Debugf("响应过滤器创建完成 - 容错阈值: %d 字节", config.FilterTolerance)
	return rf
}

// SetFingerprintEngine 设置指纹识别引擎（可选，用于目录扫描结果的二次识别）
func (rf *ResponseFilter) SetFingerprintEngine(engine interfaces.FingerprintAnalyzer) {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	rf.fingerprintEngine = engine
	logger.Debug("响应过滤器已设置指纹识别引擎，启用二次识别")
}

func (rf *ResponseFilter) EnableFingerprintSnippet(enabled bool) {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	rf.showFingerprintSnippet = enabled
}

func (rf *ResponseFilter) EnableFingerprintRuleDisplay(enabled bool) {
	rf.mu.Lock()
	defer rf.mu.Unlock()
	rf.showFingerprintRule = enabled
}

// FilterResponses 过滤响应列表
func (rf *ResponseFilter) FilterResponses(responses []interfaces.HTTPResponse) *interfaces.FilterResult {
	rf.mu.RLock()
	config := rf.config
	rf.mu.RUnlock()

	result := &interfaces.FilterResult{
		StatusFilteredPages:  make([]interfaces.HTTPResponse, 0),
		PrimaryFilteredPages: make([]interfaces.HTTPResponse, 0),
		ValidPages:           make([]interfaces.HTTPResponse, 0),
		InvalidPageHashes:    make([]interfaces.PageHash, 0),
		SecondaryHashResults: make([]interfaces.PageHash, 0),
		TotalProcessed:       len(responses),
	}

	currentResponses := responses

	// 步骤1: 状态码过滤
	if config.EnableStatusFilter && rf.statusCodeFilter != nil {
		currentResponses = rf.statusCodeFilter.Filter(currentResponses)
		result.StatusFilteredPages = currentResponses
		result.StatusFiltered = len(currentResponses)
	} else {
		result.StatusFilteredPages = currentResponses
		result.StatusFiltered = len(currentResponses)
	}

	// 步骤2: Content-Type过滤
	if config.EnableContentTypeFilter && rf.contentTypeFilter != nil {
		currentResponses = rf.contentTypeFilter.Filter(currentResponses)
		logger.Debugf("Content-Type过滤后剩余响应数量: %d", len(currentResponses))
	}

	// 步骤3: 主要无效页面过滤
	if rf.hashFilter != nil {
		currentResponses = rf.hashFilter.Filter(currentResponses)
		result.PrimaryFilteredPages = currentResponses
		result.PrimaryFiltered = len(currentResponses)
	} else {
		result.PrimaryFilteredPages = currentResponses
		result.PrimaryFiltered = len(currentResponses)
	}

	// 步骤4: 二次筛选
	if rf.secondaryFilter != nil {
		currentResponses = rf.secondaryFilter.Filter(currentResponses)
		result.ValidPages = currentResponses
		result.SecondaryFiltered = len(currentResponses)
	} else {
		result.ValidPages = currentResponses
		result.SecondaryFiltered = len(currentResponses)
	}

	// 步骤5: 收集哈希统计
	if rf.hashFilter != nil {
		result.InvalidPageHashes = rf.hashFilter.GetInvalidPageHashes()
	}
	if rf.secondaryFilter != nil {
		result.SecondaryHashResults = rf.secondaryFilter.GetSecondaryHashResults()
	}

	// 步骤6: 结果去重 (基于URL)
	// 解决多个不同Payload重定向到同一个最终URL导致的结果重复问题
	result.ValidPages = rf.deduplicateValidPages(result.ValidPages)

	// 步骤7: 对所有页面执行指纹识别（包括被过滤的页面）
	// 这样在报告中所有页面都能显示指纹信息
	rf.mu.RLock()
	hasEngine := rf.fingerprintEngine != nil
	rf.mu.RUnlock()

	if hasEngine {
		// 对 ValidPages 执行指纹识别
		for i := range result.ValidPages {
			matches, _ := rf.performFingerprintRecognition(&result.ValidPages[i])
			if len(matches) > 0 {
				result.ValidPages[i].Fingerprints = matches
			}
		}

		// 对 PrimaryFilteredPages 执行指纹识别
		for i := range result.PrimaryFilteredPages {
			matches, _ := rf.performFingerprintRecognition(&result.PrimaryFilteredPages[i])
			if len(matches) > 0 {
				result.PrimaryFilteredPages[i].Fingerprints = matches
			}
		}

		// 对 StatusFilteredPages 执行指纹识别
		for i := range result.StatusFilteredPages {
			matches, _ := rf.performFingerprintRecognition(&result.StatusFilteredPages[i])
			if len(matches) > 0 {
				result.StatusFilteredPages[i].Fingerprints = matches
			}
		}

		logger.Debugf("指纹识别完成 - ValidPages: %d, PrimaryFiltered: %d, StatusFiltered: %d",
			len(result.ValidPages), len(result.PrimaryFilteredPages), len(result.StatusFilteredPages))
	}

	return result
}

// deduplicateValidPages 对有效页面进行去重（基于URL）
func (rf *ResponseFilter) deduplicateValidPages(pages []interfaces.HTTPResponse) []interfaces.HTTPResponse {
	if len(pages) == 0 {
		return pages
	}

	uniquePages := make([]interfaces.HTTPResponse, 0, len(pages))
	seen := make(map[string]struct{})

	for _, page := range pages {
		if _, exists := seen[page.URL]; !exists {
			seen[page.URL] = struct{}{}
			uniquePages = append(uniquePages, page)
		}
	}

	if len(uniquePages) < len(pages) {
		logger.Debugf("结果去重: %d -> %d (移除重复 %d 个)", len(pages), len(uniquePages), len(pages)-len(uniquePages))
	}

	return uniquePages
}

// UpdateConfig 更新过滤器配置
func (rf *ResponseFilter) UpdateConfig(config *FilterConfig) {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	rf.config = config

	// 更新各个策略的配置
	if rf.statusCodeFilter != nil {
		rf.statusCodeFilter.UpdateValidStatusCodes(config.ValidStatusCodes)
	}
	if rf.hashFilter != nil {
		rf.hashFilter.UpdateThreshold(config.InvalidPageThreshold)
	}
	if rf.secondaryFilter != nil {
		rf.secondaryFilter.UpdateThreshold(config.SecondaryThreshold)
	}
}

// GetConfig 获取当前配置
func (rf *ResponseFilter) GetConfig() *FilterConfig {
	rf.mu.RLock()
	defer rf.mu.RUnlock()

	// 返回配置副本
	return &FilterConfig{
		ValidStatusCodes:     rf.config.ValidStatusCodes,
		InvalidPageThreshold: rf.config.InvalidPageThreshold,
		SecondaryThreshold:   rf.config.SecondaryThreshold,
		EnableStatusFilter:   rf.config.EnableStatusFilter,
	}
}

// Reset 重置过滤器状态
func (rf *ResponseFilter) Reset() {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	if rf.hashFilter != nil {
		rf.hashFilter.Reset()
	}
	if rf.secondaryFilter != nil {
		rf.secondaryFilter.Reset()
	}

	logger.Debug("过滤器状态已重置")
}

// GetStatusCodeFilter 获取状态码过滤策略
func (rf *ResponseFilter) GetStatusCodeFilter() StatusCodeFilterStrategy {
	rf.mu.RLock()
	defer rf.mu.RUnlock()
	return rf.statusCodeFilter
}

// GetHashFilter 获取哈希过滤策略
func (rf *ResponseFilter) GetHashFilter() HashFilterStrategy {
	rf.mu.RLock()
	defer rf.mu.RUnlock()
	return rf.hashFilter
}

// GetSecondaryFilter 获取二次筛选策略
func (rf *ResponseFilter) GetSecondaryFilter() SecondaryFilterStrategy {
	rf.mu.RLock()
	defer rf.mu.RUnlock()
	return rf.secondaryFilter
}

// SetStatusCodeFilter 设置状态码过滤策略
func (rf *ResponseFilter) SetStatusCodeFilter(filter StatusCodeFilterStrategy) {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	rf.statusCodeFilter = filter
}

// SetHashFilter 设置哈希过滤策略
func (rf *ResponseFilter) SetHashFilter(filter HashFilterStrategy) {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	rf.hashFilter = filter
}

// SetSecondaryFilter 设置二次筛选策略
func (rf *ResponseFilter) SetSecondaryFilter(filter SecondaryFilterStrategy) {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	rf.secondaryFilter = filter
}

// GetPageHashCount 获取页面哈希统计数量（兼容旧接口）
func (rf *ResponseFilter) GetPageHashCount() int {
	rf.mu.RLock()
	defer rf.mu.RUnlock()

	if rf.hashFilter != nil {
		return rf.hashFilter.GetPageHashCount()
	}
	return 0
}

// ============================================================================
// CreateFilterConfigFromExternal 便捷方法：从外部配置创建过滤器配置
func CreateFilterConfigFromExternal() *FilterConfig {
	if cfg := getGlobalFilterConfig(); cfg != nil {
		return cfg
	}
	return DefaultFilterConfig()
}

// ============================================================================
// 全局过滤函数 (用于被动模式模块集成)
// ============================================================================

// IsContentTypeFiltered 检查指定Content-Type是否应该被过滤
// 这是一个全局函数，供各模块在被动代理模式下使用
func IsContentTypeFiltered(contentType string) bool {
	// 获取过滤器配置
	config := CreateFilterConfigFromExternal()
	if !config.EnableContentTypeFilter {
		return false // 如果未启用Content-Type过滤，则不过滤
	}

	// 执行Content-Type检查逻辑
	return checkContentTypeAgainstRules(contentType, config.FilteredContentTypes)
}

// IsContentTypeFilteredWithConfig 使用指定配置检测Content-Type是否应该过滤
func IsContentTypeFilteredWithConfig(contentType string, cfg *FilterConfig) bool {
	if cfg == nil {
		return IsContentTypeFiltered(contentType)
	}

	if !cfg.EnableContentTypeFilter {
		return false
	}

	return checkContentTypeAgainstRules(contentType, cfg.FilteredContentTypes)
}

// checkContentTypeAgainstRules 检查Content-Type是否匹配过滤规则
func checkContentTypeAgainstRules(contentType string, filteredTypes []string) bool {
	if contentType == "" || contentType == "unknown" {
		return false // 不过滤未知类型
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

// CreateResponseFilterFromExternal 便捷方法：从外部配置创建响应过滤器
func CreateResponseFilterFromExternal() *ResponseFilter {
	filterCfg := CreateFilterConfigFromExternal()
	responseFilter := NewResponseFilter(filterCfg)
	return responseFilter
}

// ============================================================================
// 打印相关方法 (原printer.go内容)
// ============================================================================

// 使用formatter包中的格式化函数
var (
	formatURL        = formatter.FormatURL
	formatStatusCode = formatter.FormatStatusCode
	formatTitle      = formatter.FormatTitle
	// formatResultNumber 已废弃，不再使用序号显示
	formatContentLength = formatter.FormatContentLength
	formatContentType   = formatter.FormatContentType
)

// PrintFilterResult 打印过滤结果
func (rf *ResponseFilter) PrintFilterResult(result *interfaces.FilterResult) {

	// 打印统计信息
	rf.printFilterStatistics(result)

	// 打印状态码过滤后的页面
	if len(result.StatusFilteredPages) > 0 {
		rf.printStatusFilteredPages(result.StatusFilteredPages)
	}

	// 打印主要筛选后的页面
	if len(result.PrimaryFilteredPages) > 0 {
		rf.printPrimaryFilteredPages(result.PrimaryFilteredPages)
	}

	// 打印最终有效页面
	if len(result.ValidPages) > 0 {
		rf.printValidPages(result.ValidPages)
	}

	// 打印主要筛选无效页面统计
	if len(result.InvalidPageHashes) > 0 {
		rf.printInvalidPageStatistics(result.InvalidPageHashes)
	}

	// 打印二次筛选统计
	if len(result.SecondaryHashResults) > 0 {
		rf.printSecondaryFilterStatistics(result.SecondaryHashResults)
	}
}

var globalFilterConfig atomic.Value

// formatNumber 格式化数字显示（加粗）
func formatNumber(num int) string {
	return formatter.FormatNumber(num)
}

// formatPercentage 格式化百分比显示
func formatPercentage(percentage float64) string {
	return formatter.FormatPercentage(percentage)
}

// printFilterStatistics 打印过滤统计信息
func (rf *ResponseFilter) printFilterStatistics(result *interfaces.FilterResult) {
	logger.Debugf("%s", fmt.Sprintf("  总处理数量: %s", formatNumber(result.TotalProcessed)))
	logger.Debugf("%s", fmt.Sprintf("  状态码有效页面: %s", formatNumber(result.StatusFiltered)))
	logger.Debugf("%s", fmt.Sprintf("  主要筛选后页面: %s", formatNumber(result.PrimaryFiltered)))
	logger.Debugf("%s", fmt.Sprintf("  二次筛选后页面: %s", formatNumber(result.SecondaryFiltered)))
	logger.Debugf("%s", fmt.Sprintf("  最终有效页面: %s", formatNumber(len(result.ValidPages))))

	if result.TotalProcessed > 0 {
		validPercentage := float64(len(result.ValidPages)) / float64(result.TotalProcessed) * 100
		logger.Debugf("%s", fmt.Sprintf("  有效页面比例: %s", formatPercentage(validPercentage)))
	}
}

// printStatusFilteredPages 打印通过状态码过滤的页面（移除序号显示）
func (rf *ResponseFilter) printStatusFilteredPages(pages []interfaces.HTTPResponse) {
	logger.Debug("通过状态码过滤的页面（状态码有效）")

	for _, page := range pages {
		logger.Debug(fmt.Sprintf("%s %s %s",
			formatURL(page.URL),
			formatStatusCode(page.StatusCode),
			formatTitle(page.Title)))
	}
}

// printPrimaryFilteredPages 打印主要筛选后的页面（移除序号显示）
func (rf *ResponseFilter) printPrimaryFilteredPages(pages []interfaces.HTTPResponse) {
	logger.Debug("主要筛选后的页面（通过主要hash过滤）")

	for _, page := range pages {
		logger.Debug(fmt.Sprintf("%s %s %s %s %s",
			formatURL(page.URL),
			formatStatusCode(page.StatusCode),
			formatTitle(page.Title),
			formatContentLength(int(page.ContentLength)),
			formatContentType(page.ContentType)))
	}
}

// printValidPages 打印最终有效页面（支持指纹识别）
func (rf *ResponseFilter) printValidPages(pages []interfaces.HTTPResponse) {
	for idx := range pages {
		page := &pages[idx]

		// 使用已经识别好的指纹信息（在 FilterResponses 中已完成）
		matches := page.Fingerprints
		var fingerprintUnion string

		// 格式化指纹显示
		if len(matches) > 0 {
			// 转换为指针列表以便使用 formatFingerprintMatches
			matchPtrs := make([]*interfaces.FingerprintMatch, len(matches))
			for i := range matches {
				matchPtrs[i] = &matches[i]
			}
			fingerprintUnion = rf.formatFingerprintMatches(matchPtrs)
		}

		fingerprintParts := []string{}
		if strings.TrimSpace(fingerprintUnion) != "" {
			fingerprintParts = append(fingerprintParts, fingerprintUnion)
		}

		line := formatter.FormatLogLine(
			page.URL,
			page.StatusCode,
			page.Title,
			page.ContentLength,
			page.ContentType,
			fingerprintParts,
			len(matches) > 0,
		)

		var messageBuilder strings.Builder
		messageBuilder.WriteString(line)

		// 如果 URL 过长（超过 60 字符），在下一行输出完整 URL 方便复制
		if len(page.URL) > 60 {
			messageBuilder.WriteString("\n")
			messageBuilder.WriteString("  └─ ")
			messageBuilder.WriteString(page.URL)
		}

		if rf.showFingerprintSnippet && len(matches) > 0 {
			var snippetLines []string
			for _, m := range matches {
				snippet := strings.TrimSpace(m.Snippet)
				if snippet == "" {
					continue
				}
				highlighted := formatter.HighlightSnippet(snippet, m.Matcher)
				if highlighted == "" {
					continue
				}
				snippetLines = append(snippetLines, highlighted)
			}
			if len(snippetLines) > 0 {
				messageBuilder.WriteString("\n")
				for idx, snippetLine := range snippetLines {
					if idx > 0 {
						messageBuilder.WriteString("\n")
					}
					messageBuilder.WriteString("  ")
					messageBuilder.WriteString(formatter.FormatSnippetArrow())
					messageBuilder.WriteString(snippetLine)
				}
			}
		}

		logger.Info(messageBuilder.String())
	}
}

// performFingerprintRecognition 对单个响应执行指纹识别
func (rf *ResponseFilter) performFingerprintRecognition(page *interfaces.HTTPResponse) ([]interfaces.FingerprintMatch, string) {
	if page == nil {
		return nil, ""
	}

	rf.mu.RLock()
	engine := rf.fingerprintEngine
	rf.mu.RUnlock()

	if engine == nil {
		logger.Debugf("指纹引擎为nil，跳过识别")
		return nil, ""
	}

	// 转换响应格式（解压响应体）
	// 注意：这里不再需要 convertToFingerprintResponse，因为接口已统一使用 interfaces.HTTPResponse
	// 但我们需要确保响应体是解压后的
	decompressedBody := rf.decompressResponseBody(page.Body, page.ResponseHeaders)

	// 创建临时响应对象，避免修改原始对象
	analysisResp := *page
	analysisResp.Body = decompressedBody

	logger.Debugf("开始识别: %s", page.URL)

	// 直接调用接口方法
	matches := engine.AnalyzeResponseWithClientSilent(&analysisResp, nil)

	logger.Debugf("识别完成: %s, 匹配数量: %d", page.URL, len(matches))

	// 将 []*FingerprintMatch 转换为 []FingerprintMatch
	convertedMatches := make([]interfaces.FingerprintMatch, len(matches))
	for i, m := range matches {
		if m != nil {
			convertedMatches[i] = *m
		}
	}

	// 格式化指纹信息
	return convertedMatches, rf.formatFingerprintMatches(matches)
}

// formatFingerprintMatches 格式化指纹匹配结果
func (rf *ResponseFilter) formatFingerprintMatches(matches []*interfaces.FingerprintMatch) string {
	if len(matches) == 0 {
		return ""
	}

	logger.Debugf("格式化 %d 个匹配结果", len(matches))

	var parts []string
	for _, match := range matches {
		if match == nil {
			continue
		}

		display := formatter.FormatFingerprintDisplay(match.RuleName, match.Matcher, rf.showFingerprintRule)
		if display != "" {
			parts = append(parts, display)
			logger.Debugf("匹配: %s - %s", match.RuleName, match.Matcher)
		}
	}

	result := strings.Join(parts, " ")
	logger.Debugf("格式化结果: %s", result)
	return result
}

// printInvalidPageStatistics 打印无效页面统计（主要筛选，移除序号显示）
func (rf *ResponseFilter) printInvalidPageStatistics(invalidHashes []interfaces.PageHash) {
	logger.Debug("主要筛选无效页面统计")

	for _, hash := range invalidHashes {
		logger.Debug(fmt.Sprintf("哈希: %s", hash.Hash[:16]))
		logger.Debug(fmt.Sprintf("    出现次数: %d", hash.Count))
		logger.Debug(fmt.Sprintf("    状态码: %d", hash.StatusCode))
		logger.Debug(fmt.Sprintf("    标题: %s", hash.Title))
		logger.Debug(fmt.Sprintf("    内容长度: %d字节", hash.ContentLength))
		logger.Debug(fmt.Sprintf("    内容类型: %s", hash.ContentType))
	}
}

// printSecondaryFilterStatistics 打印二次筛选统计
func (rf *ResponseFilter) printSecondaryFilterStatistics(secondaryHashes []interfaces.PageHash) {
	logger.Debug("二次筛选无效页面统计")

	for i, hash := range secondaryHashes {
		logger.Debug(fmt.Sprintf("🔄 [%d] 哈希: %s", i+1, hash.Hash[:16]))
		logger.Debug(fmt.Sprintf("    出现次数: %d", hash.Count))
		logger.Debug(fmt.Sprintf("    状态码: %d", hash.StatusCode))
		logger.Debug(fmt.Sprintf("    标题: %s", hash.Title))
		logger.Debug(fmt.Sprintf("    内容长度: %d字节", hash.ContentLength))
		logger.Debug(fmt.Sprintf("    内容类型: %s", hash.ContentType))
	}
}

// ============================================================================
// 响应体解压缩辅助方法（用于二次指纹识别）
// ============================================================================

// decompressResponseBody 解压缩响应体
func (rf *ResponseFilter) decompressResponseBody(body string, headers map[string][]string) string {
	if body == "" {
		return ""
	}

	// 获取Content-Encoding头部
	var contentEncoding string
	if encodingHeaders, exists := headers["Content-Encoding"]; exists && len(encodingHeaders) > 0 {
		contentEncoding = strings.ToLower(encodingHeaders[0])
	}

	// 如果没有压缩，直接返回
	if contentEncoding == "" {
		return body
	}

	logger.Debugf("检测到压缩编码: %s", contentEncoding)
	decompressed := sharedutils.DecompressByEncoding([]byte(body), contentEncoding)
	return string(decompressed)
}
