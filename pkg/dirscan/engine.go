package dirscan

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
	requests "veo/pkg/utils/processor"
)

// 引擎实现

// NewEngine 创建新的目录扫描引擎
func NewEngine(config *EngineConfig) *Engine {
	if config == nil {
		config = getDefaultConfig()
	}

	engine := &Engine{
		config: config,
		stats: &Statistics{
			StartTime: time.Now(),
		},
	}

	logger.Debug("目录扫描引擎初始化完成")
	return engine
}

// SetProxy 设置代理
func (e *Engine) SetProxy(proxyURL string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.config.ProxyURL = proxyURL
}

// PerformScanWithFilter 执行扫描（支持自定义过滤器）
func (e *Engine) PerformScanWithFilter(ctx context.Context, collectorInstance interfaces.URLCollectorInterface, recursive bool, filter *ResponseFilter) (*ScanResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	e.mu.Lock()
	if e.stats == nil {
		e.stats = &Statistics{StartTime: time.Now()}
	}
	e.mu.Unlock()

	startTime := time.Now()

	// 1. 生成扫描URL
	scanURLs, err := e.generateScanURLs(collectorInstance, recursive)
	if err != nil {
		return nil, fmt.Errorf("生成扫描URL失败: %v", err)
	}

	if len(scanURLs) == 0 {
		return nil, fmt.Errorf("没有收集到URL，无法开始扫描")
	}

	logger.Debugf("生成扫描URL: %d个", len(scanURLs))
	atomic.StoreInt64(&e.stats.TotalGenerated, int64(len(scanURLs)))

	// 2. 初始化过滤器
	var responseFilter *ResponseFilter
	if filter != nil {
		responseFilter = filter
	} else {
		responseFilter = CreateResponseFilterFromExternal()
	}

	if responseFilter != nil {
		processor := e.getOrCreateRequestProcessor()
		responseFilter.SetHTTPClient(processor)
	}

	// 准备累积结果和锁
	finalFilterResult := &interfaces.FilterResult{
		ValidPages:           make([]*interfaces.HTTPResponse, 0),
		PrimaryFilteredPages: make([]*interfaces.HTTPResponse, 0),
		StatusFilteredPages:  make([]*interfaces.HTTPResponse, 0),
	}
	var resultMu sync.Mutex

	// 3. 执行HTTP请求（带实时过滤回调）
	actualConcurrency := e.getActualConcurrency()
	scanLabel := buildScanLabel(collectorInstance)
	if scanLabel != "" {
		logger.Infof("Scanning For %s, %d URL，Threads: %d，Random UA: true", scanLabel, len(scanURLs), actualConcurrency)
	} else {
		logger.Infof("%d URL，Threads: %d，Random UA: true", len(scanURLs), actualConcurrency)
	}

	responses, err := e.performHTTPRequestsWithCallback(ctx, scanURLs, func(resp *interfaces.HTTPResponse) {
		if resp == nil {
			return
		}
		// 转换并过滤
		// 注意：这里我们构造一个单元素的切片进行处理
		filterInput := []*interfaces.HTTPResponse{resp}
		singleResult := responseFilter.FilterResponses(filterInput)
		if singleResult == nil {
			logger.Warnf("ResponseFilter.FilterResponses returned nil for URL: %s", resp.URL)
			return
		}

		// 实时输出有效页面
		// 累积结果 (线程安全)
		resultMu.Lock()
		if len(singleResult.ValidPages) > 0 {
			finalFilterResult.ValidPages = append(finalFilterResult.ValidPages, singleResult.ValidPages...)
		}
		if len(singleResult.PrimaryFilteredPages) > 0 {
			finalFilterResult.PrimaryFilteredPages = append(finalFilterResult.PrimaryFilteredPages, singleResult.PrimaryFilteredPages...)
		}
		if len(singleResult.StatusFilteredPages) > 0 {
			finalFilterResult.StatusFilteredPages = append(finalFilterResult.StatusFilteredPages, singleResult.StatusFilteredPages...)
		}
		resultMu.Unlock()
	})

	if err != nil {
		return nil, fmt.Errorf("HTTP请求执行失败: %v", err)
	}

	if len(responses) == 0 {
		return nil, ErrNoValidHTTPResponse
	}

	logger.Debugf("HTTP扫描完成，收到 %d 个响应", len(responses))
	atomic.StoreInt64(&e.stats.TotalRequests, int64(len(responses)))

	// 补充：收集无效页面哈希统计 (从过滤器中获取最终状态)
	if responseFilter != nil {
		finalFilterResult.InvalidPageHashes = responseFilter.GetInvalidPageHashes()
	}
	// 注意：这里我们假设过滤器是 HashFilter，如果接口支持的话
	// 实际上 ResponseFilter 封装了这些细节，但 GetHashFilter 方法在 ResponseFilter 中有导出

	atomic.StoreInt64(&e.stats.FilteredResults, int64(len(finalFilterResult.ValidPages)))
	logger.Debugf("过滤完成 - 总响应: %d, 有效结果: %d",
		len(responses), len(finalFilterResult.ValidPages))

	// 4. 创建扫描结果
	endTime := time.Now()
	result := &ScanResult{
		Target:        e.extractTarget(responses),
		CollectedURLs: []string{}, // 不再维护收集的URL列表
		ScanURLs:      scanURLs,
		Responses:     responses,
		FilterResult:  finalFilterResult,
		StartTime:     startTime,
		EndTime:       endTime,
		Duration:      endTime.Sub(startTime),
	}

	// 5. 更新统计信息
	e.mu.Lock()
	e.stats.LastScanTime = endTime
	atomic.AddInt64(&e.stats.TotalScans, 1)
	atomic.StoreInt64(&e.stats.ValidResults, int64(len(finalFilterResult.ValidPages)))
	e.mu.Unlock()

	logger.Debugf("扫描执行完成，耗时: %v", result.Duration)
	return result, nil
}

// PerformScanWithOptions 执行扫描（支持选项）
func (e *Engine) PerformScanWithOptions(collectorInstance interfaces.URLCollectorInterface, recursive bool) (*ScanResult, error) {
	return e.PerformScanWithFilter(context.Background(), collectorInstance, recursive, nil)
}

// generateScanURLs 生成扫描URL
func (e *Engine) generateScanURLs(collectorInstance interfaces.URLCollectorInterface, recursive bool) ([]string, error) {
	logger.Debug("开始生成扫描URL")

	// 创建URL生成器
	generator := NewURLGenerator()

	// 生成扫描URL
	// [修改] 传递 recursive 参数
	scanURLs := generator.GenerateURLsFromCollector(collectorInstance, recursive)

	logger.Debugf("生成扫描URL完成，共%d个", len(scanURLs))
	return scanURLs, nil
}

// performHTTPRequestsWithCallback 执行HTTP请求（支持回调）
func (e *Engine) performHTTPRequestsWithCallback(ctx context.Context, scanURLs []string, callback func(*interfaces.HTTPResponse)) ([]*interfaces.HTTPResponse, error) {
	logger.Debug("开始执行HTTP扫描 (Callback模式)")

	// 获取或创建请求处理器
	processor := e.getOrCreateRequestProcessor()

	// 执行请求
	responses := processor.ProcessURLsWithCallbackWithContext(ctx, scanURLs, callback)

	atomic.StoreInt64(&e.stats.SuccessRequests, int64(len(responses)))

	return responses, nil
}

func buildScanLabel(collectorInstance interfaces.URLCollectorInterface) string {
	if collectorInstance == nil {
		return ""
	}
	urlMap := collectorInstance.GetURLMap()
	if len(urlMap) != 1 {
		return ""
	}
	for urlStr := range urlMap {
		return urlStr
	}
	return ""
}

// SetRequestProcessor 注入外部请求处理器（复用全局配置）
func (e *Engine) SetRequestProcessor(processor *requests.RequestProcessor) {
	if processor == nil {
		return
	}
	e.mu.Lock()
	e.requestProcessor = processor
	e.mu.Unlock()
}

// getOrCreateRequestProcessor 获取或创建请求处理器
func (e *Engine) getOrCreateRequestProcessor() *requests.RequestProcessor {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.requestProcessor == nil {
		logger.Debug("创建新的请求处理器")
		e.requestProcessor = requests.NewRequestProcessor(nil)
	}

	reqConfig := e.requestProcessor.GetConfig()

	// 统一应用引擎侧配置（仅覆盖必要项）
	if e.config.ProxyURL != "" {
		reqConfig.ProxyURL = e.config.ProxyURL
	}
	if e.config.MaxConcurrency > 0 {
		reqConfig.MaxConcurrent = e.config.MaxConcurrency
	}
	if e.config.RequestTimeout > 0 {
		reqConfig.Timeout = e.config.RequestTimeout
	}
	requests.ApplyRedirectPolicy(reqConfig)

	e.requestProcessor.UpdateConfig(reqConfig)

	return e.requestProcessor
}

// SetCustomHeaders 设置自定义HTTP头部
func (e *Engine) SetCustomHeaders(headers map[string]string) {
	processor := e.getOrCreateRequestProcessor()
	processor.SetCustomHeaders(headers)
	logger.Debugf("应用了 %d 个自定义HTTP头部到请求处理器", len(headers))
}

// getActualConcurrency 获取实际的并发数（用于日志显示）
func (e *Engine) getActualConcurrency() int {
	// 使用默认配置的并发数
	processor := e.getOrCreateRequestProcessor()
	if processor != nil {
		if cfg := processor.GetConfig(); cfg != nil && cfg.MaxConcurrent > 0 {
			return cfg.MaxConcurrent
		}
	}

	// 最后的备用值
	return 50
}

// extractTarget 提取目标信息
func (e *Engine) extractTarget(responses []*interfaces.HTTPResponse) string {
	if len(responses) == 0 {
		return "unknown"
	}

	// 从第一个响应中提取主机信息
	firstURL := responses[0].URL
	if firstURL == "" {
		return "unknown"
	}

	// 简单提取主机部分
	if len(firstURL) > 50 {
		return firstURL[:50] + "..."
	}
	return firstURL
}
