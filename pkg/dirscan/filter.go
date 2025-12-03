package dirscan

import (
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
	filterChain       *FilterChain              // 过滤链
	mu                sync.RWMutex              // 读写锁

	// [新增] 可选的指纹识别引擎（用于目录扫描结果的二次识别）
	fingerprintEngine      interface{}
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
	hashFilter := NewHashFilter(config.InvalidPageThreshold, config.FilterTolerance)
	secondaryFilter := NewSecondaryFilter(config.SecondaryThreshold, config.FilterTolerance)
	contentTypeFilter := NewContentTypeFilter(config.FilteredContentTypes)

	// 创建过滤链
	filterChain := NewFilterChain()

	rf := &ResponseFilter{
		config:            config,
		statusCodeFilter:  statusCodeFilter,
		hashFilter:        hashFilter,
		secondaryFilter:   secondaryFilter,
		contentTypeFilter: contentTypeFilter,
		filterChain:       filterChain,
	}

	// 根据配置添加过滤策略到过滤链
	rf.rebuildFilterChain()

	logger.Debugf("响应过滤器创建完成 - 容错阈值: %d 字节", config.FilterTolerance)
	return rf
}

// SetFingerprintEngine 设置指纹识别引擎（可选，用于目录扫描结果的二次识别）
func (rf *ResponseFilter) SetFingerprintEngine(engine interface{}) {
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

	return result
}

// rebuildFilterChain 根据配置重建过滤链
func (rf *ResponseFilter) rebuildFilterChain() {
	rf.filterChain.ClearStrategies()

	// 根据配置添加策略
	if rf.config.EnableStatusFilter && rf.statusCodeFilter != nil {
		rf.filterChain.AddStrategy(rf.statusCodeFilter)
	}
	if rf.hashFilter != nil {
		rf.filterChain.AddStrategy(rf.hashFilter)
	}
	if rf.secondaryFilter != nil {
		rf.filterChain.AddStrategy(rf.secondaryFilter)
	}
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

	// 重建过滤链
	rf.rebuildFilterChain()

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
	rf.filterChain.Reset()

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
	rf.rebuildFilterChain()
}

// SetHashFilter 设置哈希过滤策略
func (rf *ResponseFilter) SetHashFilter(filter HashFilterStrategy) {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	rf.hashFilter = filter
	rf.rebuildFilterChain()
}

// SetSecondaryFilter 设置二次筛选策略
func (rf *ResponseFilter) SetSecondaryFilter(filter SecondaryFilterStrategy) {
	rf.mu.Lock()
	defer rf.mu.Unlock()

	rf.secondaryFilter = filter
	rf.rebuildFilterChain()
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

		rf.mu.RLock()
		hasEngine := rf.fingerprintEngine != nil
		rf.mu.RUnlock()

		var (
			matches        []interfaces.FingerprintMatch
			fingerprintStr string
		)

		// 先执行指纹识别，以便根据结果决定标题颜色
		if hasEngine {
			matches, fingerprintStr = rf.performFingerprintRecognition(page)
			if len(matches) > 0 {
				page.Fingerprints = matches
			}
		}

		// 根据是否匹配到指纹选择不同的标题格式化函数
		var titleFormatted string
		if len(matches) > 0 {
			// 匹配到指纹：浅绿色，不加粗
			titleFormatted = formatter.FormatFingerprintTitle(page.Title)
		} else {
			// 未匹配到指纹：默认格式
			titleFormatted = formatTitle(page.Title)
		}

		baseInfo := fmt.Sprintf("%s %s %s %s %s",
			formatURL(page.URL),
			formatStatusCode(page.StatusCode),
			titleFormatted,
			formatContentLength(int(page.ContentLength)),
			formatContentType(page.ContentType),
		)

		var messageBuilder strings.Builder
		messageBuilder.WriteString(baseInfo)
		if fingerprintStr != "" {
			messageBuilder.WriteString(" ")
			messageBuilder.WriteString(fingerprintStr)
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

	// 使用反射调用指纹引擎的方法（避免循环依赖）
	engineValue := reflect.ValueOf(engine)

	// 检查是否有 AnalyzeResponseWithClientSilent 方法
	method := engineValue.MethodByName("AnalyzeResponseWithClientSilent")
	if !method.IsValid() {
		logger.Debugf("指纹引擎没有 AnalyzeResponseWithClientSilent 方法")
		return nil, ""
	}

	// 转换响应格式
	fpResponse := rf.convertToFingerprintResponse(page)
	if fpResponse == nil {
		logger.Debugf("响应转换失败: %s", page.URL)
		return nil, ""
	}

	logger.Debugf("开始识别: %s", page.URL)

	// 使用反射调用方法
	// 第二个参数是 httpClient，传递 nil
	var nilClient interface{} = nil
	args := []reflect.Value{
		reflect.ValueOf(fpResponse),
		reflect.ValueOf(&nilClient).Elem(), // nil interface{}
	}
	results := method.Call(args)

	// 检查返回值
	if len(results) == 0 {
		logger.Debugf("方法调用无返回值")
		return nil, ""
	}

	matchesInterface := results[0].Interface()

	// 使用反射获取切片长度
	matchesValue := reflect.ValueOf(matchesInterface)
	if matchesValue.Kind() != reflect.Slice {
		logger.Debugf("返回值不是切片类型: %v", matchesValue.Kind())
		return nil, ""
	}

	logger.Debugf("识别完成: %s, 匹配数量: %d", page.URL, matchesValue.Len())

	convertedMatches := rf.convertMatchesToInterfaces(matchesValue, rf.showFingerprintRule, rf.showFingerprintSnippet)

	// 格式化指纹信息
	return convertedMatches, rf.formatFingerprintMatches(matchesInterface)
}

// convertToFingerprintResponse 将interfaces.HTTPResponse转换为fingerprint.HTTPResponse
// 使用反射创建正确的类型，避免类型不匹配
func (rf *ResponseFilter) convertToFingerprintResponse(resp *interfaces.HTTPResponse) interface{} {
	if resp == nil {
		return nil
	}

	// 优先使用ResponseBody字段，如果为空则使用Body字段
	body := resp.ResponseBody
	if body == "" {
		body = resp.Body
	}

	// [关键修复] 解压缩响应体（如果被压缩）
	decompressedBody := rf.decompressResponseBody(body, resp.ResponseHeaders)

	// 截取前100个字符用于调试
	bodyPreview := decompressedBody
	if len(bodyPreview) > 100 {
		bodyPreview = bodyPreview[:100]
	}
	logger.Debugf("转换响应: %s, 原始长度: %d, 解压后长度: %d, 前100字符: %s",
		resp.URL, len(body), len(decompressedBody), bodyPreview)

	// 使用反射获取指纹引擎的类型
	rf.mu.RLock()
	engine := rf.fingerprintEngine
	rf.mu.RUnlock()

	if engine == nil {
		return nil
	}

	// 通过反射获取 fingerprint.HTTPResponse 类型
	engineValue := reflect.ValueOf(engine)
	engineType := engineValue.Type()

	// 查找 AnalyzeResponseWithClientSilent 方法
	method, found := engineType.MethodByName("AnalyzeResponseWithClientSilent")
	if !found {
		logger.Debugf("未找到 AnalyzeResponseWithClientSilent 方法")
		return nil
	}

	// 获取第一个参数的类型（应该是 *fingerprint.HTTPResponse）
	if method.Type.NumIn() < 2 { // 第0个是receiver
		logger.Debugf("方法参数数量不足")
		return nil
	}

	// 第1个参数（索引1，因为0是receiver）
	paramType := method.Type.In(1)

	// 如果是指针类型，获取元素类型
	if paramType.Kind() == reflect.Ptr {
		paramType = paramType.Elem()
	}

	// 创建该类型的新实例
	newResp := reflect.New(paramType)
	newRespElem := newResp.Elem()

	// 使用反射设置字段值
	if field := newRespElem.FieldByName("URL"); field.IsValid() && field.CanSet() {
		field.SetString(resp.URL)
	}
	if field := newRespElem.FieldByName("Method"); field.IsValid() && field.CanSet() {
		field.SetString("GET")
	}
	if field := newRespElem.FieldByName("StatusCode"); field.IsValid() && field.CanSet() {
		field.SetInt(int64(resp.StatusCode))
	}
	if field := newRespElem.FieldByName("ResponseHeaders"); field.IsValid() && field.CanSet() {
		field.Set(reflect.ValueOf(resp.ResponseHeaders))
	}
	if field := newRespElem.FieldByName("Body"); field.IsValid() && field.CanSet() {
		field.SetString(decompressedBody) // 使用解压缩后的内容
	}
	if field := newRespElem.FieldByName("ContentType"); field.IsValid() && field.CanSet() {
		field.SetString(resp.ContentType)
	}
	if field := newRespElem.FieldByName("ContentLength"); field.IsValid() && field.CanSet() {
		field.SetInt(resp.ContentLength)
	}
	if field := newRespElem.FieldByName("Server"); field.IsValid() && field.CanSet() {
		field.SetString(resp.Server)
	}
	if field := newRespElem.FieldByName("Title"); field.IsValid() && field.CanSet() {
		field.SetString(resp.Title)
	}

	logger.Debugf("成功创建类型: %v", newResp.Type())
	return newResp.Interface()
}

func (rf *ResponseFilter) convertMatchesToInterfaces(matchesValue reflect.Value, includeRule, includeSnippet bool) []interfaces.FingerprintMatch {
	count := matchesValue.Len()
	if count == 0 {
		return nil
	}
	_ = includeRule

	results := make([]interfaces.FingerprintMatch, 0, count)
	for i := 0; i < count; i++ {
		item := matchesValue.Index(i)
		if !item.IsValid() {
			continue
		}
		if item.Kind() == reflect.Pointer {
			if item.IsNil() {
				continue
			}
			item = item.Elem()
		}
		if item.Kind() != reflect.Struct {
			continue
		}

		match := interfaces.FingerprintMatch{}

		if field := item.FieldByName("URL"); field.IsValid() && field.Kind() == reflect.String {
			match.URL = field.String()
		}
		if field := item.FieldByName("RuleName"); field.IsValid() && field.Kind() == reflect.String {
			match.RuleName = field.String()
		}
		if field := item.FieldByName("DSLMatched"); field.IsValid() && field.Kind() == reflect.String {
			match.Matcher = field.String()
		}
		if field := item.FieldByName("Timestamp"); field.IsValid() {
			switch field.Kind() {
			case reflect.Int, reflect.Int64, reflect.Int32:
				match.Timestamp = time.Unix(field.Int(), 0)
			case reflect.Struct:
				if field.Type().String() == "time.Time" {
					if t, ok := field.Interface().(time.Time); ok {
						match.Timestamp = t
					}
				}
			}
		}
		if includeSnippet {
			if field := item.FieldByName("Snippet"); field.IsValid() && field.Kind() == reflect.String {
				match.Snippet = field.String()
			}
		}

		results = append(results, match)
	}

	return results
}

// formatFingerprintMatches 格式化指纹匹配结果（使用反射避免循环依赖）
func (rf *ResponseFilter) formatFingerprintMatches(matchesInterface interface{}) string {
	if matchesInterface == nil {
		return ""
	}

	// 使用反射处理切片
	matchesValue := reflect.ValueOf(matchesInterface)
	if matchesValue.Kind() != reflect.Slice {
		logger.Debugf("匹配结果不是切片类型")
		return ""
	}

	matchCount := matchesValue.Len()
	if matchCount == 0 {
		return ""
	}

	logger.Debugf("格式化 %d 个匹配结果", matchCount)

	var parts []string
	for i := 0; i < matchCount; i++ {
		match := matchesValue.Index(i)

		// 如果是指针，解引用
		if match.Kind() == reflect.Ptr {
			match = match.Elem()
		}

		// 使用反射读取字段
		ruleNameField := match.FieldByName("RuleName")
		dslMatchedField := match.FieldByName("DSLMatched")

		if !ruleNameField.IsValid() || !dslMatchedField.IsValid() {
			logger.Debugf("无法读取字段: RuleName或DSLMatched")
			continue
		}

		ruleName := ruleNameField.String()
		dslMatched := dslMatchedField.String()

		display := formatter.FormatFingerprintDisplay(ruleName, dslMatched, rf.showFingerprintRule)
		if display != "" {
			parts = append(parts, display)
			logger.Debugf("匹配: %s - %s", ruleName, dslMatched)
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
