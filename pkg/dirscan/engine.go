package dirscan

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"veo/pkg/logger"
	requests "veo/pkg/processor"
	"veo/pkg/shared"
	scanstats "veo/pkg/stats"
	interfaces "veo/pkg/types"
)

var ErrNoValidHTTPResponse = errors.New("No Valid HTTP response received")

type ScanResult struct {
	Target        string                     `json:"target"`
	CollectedURLs []string                   `json:"collected_urls"`
	ScanURLs      []string                   `json:"scan_urls"`
	Responses     []*interfaces.HTTPResponse `json:"responses"`
	FilterResult  *interfaces.FilterResult   `json:"filter_result"`
	StartTime     time.Time                  `json:"start_time"`
	EndTime       time.Time                  `json:"end_time"`
	Duration      time.Duration              `json:"duration"`
}

type EngineConfig struct {
	MaxConcurrency   int           `yaml:"max_concurrency"`
	RequestTimeout   time.Duration `yaml:"request_timeout"`
	EnableCollection bool          `yaml:"enable_collection"`
	EnableFiltering  bool          `yaml:"enable_filtering"`
	ProxyURL         string        `yaml:"proxy_url"`
}

type Statistics struct {
	TotalCollected  int64     `json:"total_collected"`
	TotalGenerated  int64     `json:"total_generated"`
	TotalRequests   int64     `json:"total_requests"`
	SuccessRequests int64     `json:"success_requests"`
	FilteredResults int64     `json:"filtered_results"`
	ValidResults    int64     `json:"valid_results"`
	StartTime       time.Time `json:"start_time"`
	LastScanTime    time.Time `json:"last_scan_time"`
	TotalScans      int64     `json:"total_scans"`
}

type Engine struct {
	config           *EngineConfig
	stats            *Statistics
	mu               sync.RWMutex
	requestProcessor *requests.RequestProcessor
}

func getDefaultConfig() *EngineConfig {
	return &EngineConfig{
		MaxConcurrency:   20,
		RequestTimeout:   30 * time.Second,
		EnableCollection: true,
		EnableFiltering:  true,
	}
}

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
		return nil, fmt.Errorf("failed to generate scan URLs: %v", err)
	}

	if len(scanURLs) == 0 {
		return nil, fmt.Errorf("no collected URLs, unable to start scan")
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
	var firstResponseURL string

	// 3. 执行HTTP请求（带实时过滤回调）
	scanLabel := buildScanLabel(collectorInstance)
	totalRequests := int64(len(scanURLs))
	var progressTracker *scanstats.RequestProgress
	if scanLabel != "" && totalRequests > 0 {
		showProgress := true
		if processor := e.getOrCreateRequestProcessor(); processor != nil {
			if updater := processor.GetStatsUpdater(); updater != nil {
				if enabled, ok := updater.(interface{ IsEnabled() bool }); ok && enabled.IsEnabled() {
					showProgress = false
				}
			}
		}
		if showProgress {
			progressTracker = scanstats.NewRequestProgress(scanLabel, totalRequests, true)
			defer progressTracker.Stop()
		}
	}

	totalResponses, err := e.performHTTPRequestsWithCallback(ctx, scanURLs, progressTracker, func(resp *interfaces.HTTPResponse) {
		if resp == nil {
			return
		}
		if firstResponseURL == "" {
			firstResponseURL = resp.URL
		}
		filterInput := []*interfaces.HTTPResponse{resp}
		singleResult := responseFilter.FilterResponses(filterInput)
		if singleResult == nil {
			logger.Warnf("ResponseFilter.FilterResponses returned nil for URL: %s", resp.URL)
			return
		}

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
		return nil, fmt.Errorf("HTTP request execution failed: %v", err)
	}

	if totalResponses == 0 {
		return nil, ErrNoValidHTTPResponse
	}

	logger.Debugf("HTTP扫描完成，收到 %d 个响应", totalResponses)
	atomic.StoreInt64(&e.stats.TotalRequests, totalResponses)

	// 补充：收集无效页面哈希统计 (从过滤器中获取最终状态)
	if responseFilter != nil {
		finalFilterResult.InvalidPageHashes = responseFilter.GetInvalidPageHashes()
	}
	atomic.StoreInt64(&e.stats.FilteredResults, int64(len(finalFilterResult.ValidPages)))
	logger.Debugf("过滤完成 - 总响应: %d, 有效结果: %d",
		totalResponses, len(finalFilterResult.ValidPages))

	// 4. 创建扫描结果
	endTime := time.Now()
	target := "unknown"
	if firstResponseURL != "" {
		if len(firstResponseURL) > 50 {
			target = firstResponseURL[:50] + "..."
		} else {
			target = firstResponseURL
		}
	}

	result := &ScanResult{
		Target:        target,
		CollectedURLs: []string{}, // 不再维护收集的URL列表
		ScanURLs:      scanURLs,
		Responses:     finalFilterResult.ValidPages,
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
func (e *Engine) performHTTPRequestsWithCallback(ctx context.Context, scanURLs []string, progress *scanstats.RequestProgress, callback func(*interfaces.HTTPResponse)) (int64, error) {
	logger.Debug("开始执行HTTP扫描 (Callback模式)")

	// 获取或创建请求处理器
	processor := e.getOrCreateRequestProcessor()

	// 执行请求
	var totalResponses int64
	var onProcessed func()
	if progress != nil {
		onProcessed = progress.Increment
	}

	processor.ProcessURLsWithCallbackOnlyWithContextAndProgress(ctx, scanURLs, func(resp *interfaces.HTTPResponse) {
		if resp != nil {
			atomic.AddInt64(&totalResponses, 1)
		}
		if callback != nil {
			callback(resp)
		}
	}, onProcessed)

	atomic.StoreInt64(&e.stats.SuccessRequests, totalResponses)

	return totalResponses, nil
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
	reqConfig.DecompressResponse = false
	reqConfig.FollowRedirect = false
	reqConfig.MaxRedirects = 0

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

type LayerScanner func(targets []string, filter *ResponseFilter, depth int) ([]interfaces.HTTPResponse, error)

func RunRecursiveScan(
	ctx context.Context,
	initialTargets []string,
	maxDepth int,
	layerScanner LayerScanner,
	sharedFilter *ResponseFilter,
) ([]interfaces.HTTPResponse, error) {
	var allResults []interfaces.HTTPResponse

	currentTargets := initialTargets
	alreadyScanned := make(map[string]bool)

	for _, t := range initialTargets {
		alreadyScanned[t] = true
		if !strings.HasSuffix(t, "/") {
			alreadyScanned[t+"/"] = true
		}
	}

	for d := 0; d <= maxDepth; d++ {
		select {
		case <-ctx.Done():
			if maxDepth > 0 {
				logger.Warn("Recursive scan canceled")
			} else {
				logger.Warn("Scan canceled")
			}
			return allResults, nil
		default:
		}

		if len(currentTargets) == 0 {
			break
		}

		if d > 0 {
			logger.Infof("Running recursive dirscan depth %d, target count: %d", d, len(currentTargets))
			if len(currentTargets) <= 5 {
				for _, target := range currentTargets {
					logger.Debugf("  └─ 递归目标: %s", target)
				}
			}
		}

		var currentFilter *ResponseFilter
		if d > 0 {
			currentFilter = sharedFilter
		} else if sharedFilter != nil {
			currentFilter = sharedFilter
		}

		results, err := layerScanner(currentTargets, currentFilter, d)
		if err != nil {
			if errors.Is(err, ErrNoValidHTTPResponse) {
				target := ""
				if len(currentTargets) == 1 {
					target = currentTargets[0]
				}
				if target != "" {
					logger.Errorf("Scanning For %s Error，No Valid HTTP response received", target)
				} else {
					logger.Errorf("Scanning Error，No Valid HTTP response received")
				}
			} else {
				logger.Errorf("Dirscan error (depth %d): %v", d, err)
			}
		}

		if len(results) > 0 {
			allResults = append(allResults, results...)
		}

		if d < maxDepth {
			newTargets := ExtractNextLevelTargets(results, alreadyScanned)
			var finalTargets []string
			for _, nt := range newTargets {
				if !alreadyScanned[nt] {
					alreadyScanned[nt] = true
					finalTargets = append(finalTargets, nt)
				}
			}
			currentTargets = finalTargets
		}
	}

	return allResults, nil
}

func ExtractNextLevelTargets(results []interfaces.HTTPResponse, alreadyScanned map[string]bool) []string {
	var newTargets []string
	thisRoundTargets := make(map[string]struct{})
	fileChecker := shared.NewFileExtensionChecker()
	pathChecker := shared.NewPathChecker()

	for _, resp := range results {
		if resp.StatusCode != 200 && resp.StatusCode != 403 {
			continue
		}

		targetURL := resp.URL
		if targetURL == "" {
			continue
		}

		if fileChecker.IsStaticFile(targetURL) {
			continue
		}

		if pathChecker.IsStaticPath(targetURL) {
			logger.Debugf("跳过黑名单目录: %s", targetURL)
			continue
		}

		if !strings.HasSuffix(targetURL, "/") {
			targetURL += "/"
		}

		if alreadyScanned[targetURL] {
			continue
		}
		if _, ok := thisRoundTargets[targetURL]; ok {
			continue
		}

		thisRoundTargets[targetURL] = struct{}{}
		newTargets = append(newTargets, targetURL)
	}

	logger.Debugf("从 %d 个结果中提取到 %d 个新递归目标", len(results), len(newTargets))
	if len(newTargets) > 0 {
		count := 5
		if len(newTargets) < count {
			count = len(newTargets)
		}
		logger.Debugf("递归目标示例 (Top %d):", count)
		for i := 0; i < count; i++ {
			logger.Debugf("  -> %s", newTargets[i])
		}
	}
	return newTargets
}

type RecursionCollector struct {
	urls map[string]int
}

func NewRecursionCollector(targets []string) *RecursionCollector {
	urls := make(map[string]int, len(targets))
	for _, t := range targets {
		if t == "" {
			continue
		}
		urls[t] = 1
	}
	return &RecursionCollector{urls: urls}
}

func (rc *RecursionCollector) GetURLMap() map[string]int {
	return rc.urls
}

func (rc *RecursionCollector) GetURLCount() int {
	return len(rc.urls)
}
