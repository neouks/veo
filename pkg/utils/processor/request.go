package processor

import (
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"sync"
	"time"

	"veo/pkg/utils/httpclient"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/processor/auth"
	"veo/pkg/utils/shared"
	"veo/pkg/utils/useragent"
	"veo/proxy"
	"veo/pkg/utils/logger"
)

// RequestProcessor 请求处理器
type RequestProcessor struct {
	proxy.BaseAddon
	client         *httpclient.Client
	config         *RequestConfig
	mu             sync.RWMutex
	userAgentPool  []string               // UserAgent池
	titleExtractor *shared.TitleExtractor // 标题提取器
	moduleContext  string                 // 模块上下文标识（用于区分调用来源）
	statsUpdater   StatsUpdater           // 统计更新器
	batchMode      bool                   // 批量扫描模式标志

	// 新增：HTTP认证头部管理
	customHeaders        map[string]string  // CLI指定的自定义头部
	authDetector         *auth.AuthDetector // 认证检测器
	redirectSameHostOnly bool               // 是否限制重定向在同主机
}

// 构造函数

// NewRequestProcessor 创建新的请求处理器
func NewRequestProcessor(config *RequestConfig) *RequestProcessor {
	if config == nil {
		config = getDefaultConfig()
	}

	// 转换配置到 httpclient.Config
	clientConfig := &httpclient.Config{
		Timeout:        config.Timeout,
		FollowRedirect: config.FollowRedirect,
		MaxRedirects:   config.MaxRedirects,
		UserAgent:      "", // 动态设置
		SkipTLSVerify:  true,
		ProxyURL:       config.ProxyURL,
		SameHostOnly:   true, // 默认开启同源限制，后续可通过SetRedirectSameHostOnly修改
	}

	processor := &RequestProcessor{
		client:         httpclient.New(clientConfig),
		config:         config,
		userAgentPool:  initializeUserAgentPool(config),
		titleExtractor: shared.NewTitleExtractor(),

		// 新增：初始化认证头部管理
		customHeaders:        make(map[string]string),
		authDetector:         auth.NewAuthDetector(),
		redirectSameHostOnly: true,
	}

	return processor
}

// CloneWithContext 创建当前处理器的副本，复用底层Client，但使用新的上下文和超时设置
func (rp *RequestProcessor) CloneWithContext(moduleContext string, timeout time.Duration) *RequestProcessor {
	rp.mu.RLock()
	defer rp.mu.RUnlock()

	// 浅拷贝配置
	newConfig := *rp.config
	if timeout > 0 {
		newConfig.Timeout = timeout
	}

	clone := &RequestProcessor{
		client:               rp.client, // 复用Client
		config:               &newConfig,
		userAgentPool:        rp.userAgentPool,
		titleExtractor:       rp.titleExtractor,
		moduleContext:        moduleContext,
		statsUpdater:         rp.statsUpdater,
		batchMode:            true,
		customHeaders:        make(map[string]string),
		authDetector:         auth.NewAuthDetector(),
		redirectSameHostOnly: rp.redirectSameHostOnly,
	}

	// 复制自定义头部
	for k, v := range rp.customHeaders {
		clone.customHeaders[k] = v
	}

	return clone
}

// SetRedirectSameHostOnly 控制重定向是否限制同主机
func (rp *RequestProcessor) SetRedirectSameHostOnly(enabled bool) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	rp.redirectSameHostOnly = enabled
	// 同时更新client配置
	rp.client.SetSameHostOnly(enabled)
}

// IsRedirectSameHostOnly 返回当前同主机限制配置
func (rp *RequestProcessor) IsRedirectSameHostOnly() bool {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return rp.redirectSameHostOnly
}

// HTTP认证头部管理方法

// SetCustomHeaders 设置自定义HTTP头部（来自CLI参数）
func (rp *RequestProcessor) SetCustomHeaders(headers map[string]string) {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	rp.customHeaders = make(map[string]string)
	for key, value := range headers {
		rp.customHeaders[key] = value
	}

	// 如果设置了自定义头部，禁用自动检测
	if len(headers) > 0 {
		rp.authDetector.SetEnabled(false)
		logger.Debugf("设置了 %d 个自定义头部，禁用自动认证检测", len(headers))
	} else {
		rp.authDetector.SetEnabled(true)
		logger.Debug("未设置自定义头部，启用自动认证检测")
	}
}

// HasCustomHeaders 检查是否设置了自定义头部
func (rp *RequestProcessor) HasCustomHeaders() bool {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return len(rp.customHeaders) > 0
}

// 请求处理器核心方法

// ProcessURLs 处理URL列表，发起HTTP请求并返回响应结构体列表（Worker Pool优化版本）
func (rp *RequestProcessor) ProcessURLs(urls []string) []*interfaces.HTTPResponse {
	if len(urls) == 0 {
		return []*interfaces.HTTPResponse{}
	}

	// 初始化处理统计
	stats := rp.initializeProcessingStats(len(urls), rp.config.MaxConcurrent, rp.config.RandomUserAgent)

	// 更新统计显示器的总请求数
	if rp.statsUpdater != nil {
		if rp.IsBatchMode() {
			// 批量模式：累加请求数
			rp.statsUpdater.AddTotalRequests(int64(len(urls)))
		} else {
			// 单目标模式：设置请求数
			rp.statsUpdater.SetTotalRequests(int64(len(urls)))
		}
	}

	// 初始化响应收集
	responses := make([]*interfaces.HTTPResponse, 0, len(urls))
	var responsesMu sync.Mutex

	// 并发优化：使用 semaphore 模式直接处理
	rp.processURLsConcurrent(urls, &responses, &responsesMu, stats, nil)

	// 完成处理
	rp.finalizeProcessing(stats)

	return responses
}


// ProcessURLsWithCallback 处理URL列表，并对每个响应执行回调
func (rp *RequestProcessor) ProcessURLsWithCallback(urls []string, callback func(*interfaces.HTTPResponse)) []*interfaces.HTTPResponse {
	// 初始化统计
	stats := rp.initializeProcessingStats(len(urls), rp.config.MaxConcurrent, rp.config.RandomUserAgent)

	// 更新统计显示器（总请求数）
	if rp.statsUpdater != nil {
		if rp.IsBatchMode() {
			rp.statsUpdater.AddTotalRequests(int64(len(urls)))
		} else {
			rp.statsUpdater.SetTotalRequests(int64(len(urls)))
		}
	}

	// 初始化响应收集
	responses := make([]*interfaces.HTTPResponse, 0, len(urls))
	var responsesMu sync.Mutex

	// 使用 semaphore 模式直接处理
	rp.processURLsConcurrent(urls, &responses, &responsesMu, stats, callback)

	// 完成处理
	rp.finalizeProcessing(stats)

	return responses
}

// processURLsConcurrent 使用信号量并发处理URL列表
func (rp *RequestProcessor) processURLsConcurrent(urls []string, responses *[]*interfaces.HTTPResponse, responsesMu *sync.Mutex, stats *ProcessingStats, callback func(*interfaces.HTTPResponse)) {
	var wg sync.WaitGroup
	// 使用带缓冲的channel控制并发数
	sem := make(chan struct{}, rp.config.MaxConcurrent)

	for _, targetURL := range urls {
		wg.Add(1)
		go func(targetURL string) {
			defer wg.Done()

			// 获取信号量（阻塞直到有空位）
			sem <- struct{}{}
			defer func() { <-sem }()

			// 应用请求延迟
			if rp.config.Delay > 0 {
				time.Sleep(rp.config.Delay)
			}

			// 处理URL
			response := rp.processURL(targetURL)

			// 更新统计和收集响应
			rp.updateProcessingStats(response, targetURL, responses, responsesMu, stats)

			// 执行回调
			if callback != nil && response != nil {
				callback(response)
			}
		}(targetURL)
	}

	wg.Wait()
}

// processURL 处理单个URL
func (rp *RequestProcessor) processURL(url string) *interfaces.HTTPResponse {
	var response *interfaces.HTTPResponse
	var err error
	

	// 改进的重试逻辑（指数退避 + 抖动）
	for attempt := 0; attempt <= rp.config.MaxRetries; attempt++ {
		if attempt > 0 {
			logger.Debug(fmt.Sprintf("重试 %d/%d: %s", attempt, rp.config.MaxRetries, url))
		}

		// 执行请求（httpclient内部处理重定向）
		response, err = rp.makeRequest(url)

		if err == nil {
			return response
		}

		// 检查是否为可重试的错误
		if !rp.isRetryableError(err) {
			logger.Debugf("不可重试的错误，停止重试: %s, 错误: %v", url, err)
			break
		}

		// 改进的重试延迟：指数退避 + 随机抖动
		if attempt < rp.config.MaxRetries {
			// 优化：目录扫描需要高性能，减少重试等待时间
			// 原来是 1s, 2s, 4s... 对于扫描太慢了
			// 改为：100ms, 200ms, 400ms...
			baseDelay := time.Duration(100*(1<<uint(attempt))) * time.Millisecond
			if baseDelay > 2*time.Second {
				baseDelay = 2 * time.Second
			}

			jitter := time.Duration(rand.Intn(100)) * time.Millisecond // 减少抖动范围
			delay := baseDelay + jitter
			logger.Debugf("重试延迟: %v (基础: %v, 抖动: %v)", delay, baseDelay, jitter)
			time.Sleep(delay)
		}
	}

	logger.Debug(fmt.Sprintf("请求失败 (重试%d次): %s, 错误: %v",
		rp.config.MaxRetries, url, err))
	return nil
}

// HTTP请求相关方法

// DoRequest 对外暴露的单次HTTP请求能力（可选自定义头部）
func (rp *RequestProcessor) DoRequest(rawURL string, headers map[string]string) (*interfaces.HTTPResponse, error) {
	return rp.makeRequestWithHeaders(rawURL, headers)
}

// makeRequest 使用httpclient发起请求
func (rp *RequestProcessor) makeRequest(rawURL string) (*interfaces.HTTPResponse, error) {
	return rp.makeRequestWithHeaders(rawURL, nil)
}

func (rp *RequestProcessor) makeRequestWithHeaders(rawURL string, extraHeaders map[string]string) (*interfaces.HTTPResponse, error) {
	// 准备头部
	headers := rp.getDefaultHeaders()
	for k, v := range extraHeaders {
		headers[k] = v
	}

	startTime := time.Now()

	// 使用 httpclient 发起请求
	body, statusCode, respHeaders, err := rp.client.MakeRequestFullWithHeaders(rawURL, headers)
	if err != nil {
		rp.logRequestError(rawURL, err)
		return nil, fmt.Errorf("请求失败: %v", err)
	}

	// 还原 requestHeaders (近似值，用于报告)
	requestHeaders := make(map[string][]string)
	for k, v := range headers {
		requestHeaders[k] = []string{v}
	}

	return rp.processResponse(rawURL, statusCode, body, respHeaders, requestHeaders, startTime)
}

// logRequestError 记录请求错误日志
func (rp *RequestProcessor) logRequestError(rawURL string, err error) {
	if rp.isTimeoutOrCanceledError(err) {
		logger.Debugf("请求超时: %s, 耗时: >%v, 错误: %v", rawURL, rp.config.Timeout, err)
	} else if rp.isRedirectError(err) {
		logger.Warnf("重定向失败: %s, 错误: %v", rawURL, err)
	} else {
		logger.Debugf("请求异常: %s, 错误: %v", rawURL, err)
	}
}

// 公共接口方法

// GetConfig 获取当前配置
func (rp *RequestProcessor) GetConfig() *RequestConfig {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return rp.config
}

// UpdateConfig 更新配置
func (rp *RequestProcessor) UpdateConfig(config *RequestConfig) {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	rp.config = config
	
	clientConfig := &httpclient.Config{
		Timeout:        config.Timeout,
		FollowRedirect: config.FollowRedirect,
		MaxRedirects:   config.MaxRedirects,
		UserAgent:      "", // 动态设置
		SkipTLSVerify:  true,
		ProxyURL:       config.ProxyURL,
		SameHostOnly:   rp.redirectSameHostOnly,
	}
	rp.client = httpclient.New(clientConfig)

	// 更新UserAgent池
	rp.userAgentPool = initializeUserAgentPool(config)
}

// UpdateUserAgents 更新UserAgent列表
func (rp *RequestProcessor) UpdateUserAgents(userAgents []string) {
	rp.updateUserAgentPool(userAgents)
}

// SetModuleContext 设置模块上下文标识
func (rp *RequestProcessor) SetModuleContext(context string) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	rp.moduleContext = context
}

// GetModuleContext 获取模块上下文标识
func (rp *RequestProcessor) GetModuleContext() string {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return rp.moduleContext
}

// SetStatsUpdater 设置统计更新器
func (rp *RequestProcessor) SetStatsUpdater(updater StatsUpdater) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	rp.statsUpdater = updater
}

// GetStatsUpdater 获取统计更新器
func (rp *RequestProcessor) GetStatsUpdater() StatsUpdater {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return rp.statsUpdater
}

// SetBatchMode 设置批量扫描模式
func (rp *RequestProcessor) SetBatchMode(enabled bool) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	rp.batchMode = enabled
}

// IsBatchMode 检查是否为批量扫描模式
func (rp *RequestProcessor) IsBatchMode() bool {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return rp.batchMode
}

// Close 关闭请求处理器，清理资源
func (rp *RequestProcessor) Close() {
	// httpclient 通常不需要显式关闭，但在需要时可以扩展
	logger.Info("请求处理器已关闭")
}

// 性能优化：预编译的超时错误正则表达式
var timeoutErrorRegex = regexp.MustCompile(`(?i)(timeout|timed out|context canceled|context deadline exceeded|dial timeout|read timeout|write timeout|i/o timeout|deadline exceeded|operation was canceled)`)

// isTimeoutOrCanceledError 判断是否为超时或取消相关的错误（性能优化版）
func (rp *RequestProcessor) isTimeoutOrCanceledError(err error) bool {
	if err == nil {
		return false
	}

	// 性能优化：使用预编译正则表达式替代线性搜索，提升匹配效率
	return timeoutErrorRegex.MatchString(err.Error())
}

// isRetryableError 判断错误是否可重试（新增：改进重试策略）
func (rp *RequestProcessor) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())

	// 可重试的错误类型
	retryableErrors := []string{
		"timeout", "timed out", "connection reset", "connection refused",
		"temporary failure", "network unreachable", "host unreachable",
		"dial timeout", "read timeout", "write timeout", "i/o timeout",
		"context deadline exceeded", "server closed idle connection",
		"broken pipe", "connection aborted", "no route to host",
	}

	for _, retryableErr := range retryableErrors {
		if strings.Contains(errStr, retryableErr) {
			return true
		}
	}

	// 不可重试的错误类型
	nonRetryableErrors := []string{
		"certificate", "tls", "ssl", "x509", "invalid url",
		"malformed", "parse error", "unsupported protocol",
		"no such host", "dns", "name resolution",
	}

	for _, nonRetryableErr := range nonRetryableErrors {
		if strings.Contains(errStr, nonRetryableErr) {
			return false
		}
	}

	// 默认情况下，网络相关错误可重试
	return true
}

// isRedirectError 判断是否为重定向相关的错误（重定向优化）
func (rp *RequestProcessor) isRedirectError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())

	// 检查重定向相关的错误
	redirectKeywords := []string{
		"missing location header for http redirect",
		"location header",
		"redirect",
	}

	for _, keyword := range redirectKeywords {
		if strings.Contains(errStr, keyword) {
			return true
		}
	}

	return false
}

// UserAgent相关方法 (原useragent.go内容)

// updateUserAgentPool 更新UserAgent池
func (rp *RequestProcessor) updateUserAgentPool(userAgents []string) {
	rp.mu.Lock()
	defer rp.mu.Unlock()

	if len(userAgents) > 0 {
		rp.userAgentPool = userAgents
		logger.Debug(fmt.Sprintf("UserAgent池已更新，共 %d 个", len(userAgents)))
	} else {
		rp.userAgentPool = getDefaultUserAgents()
		logger.Debug("使用默认UserAgent池")
	}
}

// getRandomUserAgent 获取随机UserAgent
func (rp *RequestProcessor) getRandomUserAgent() string {
	rp.mu.RLock()
	defer rp.mu.RUnlock()

	if len(rp.userAgentPool) == 0 {
		return useragent.Primary()
	}

	if !rp.config.RandomUserAgent {
		return rp.userAgentPool[0]
	}

	index := rand.Intn(len(rp.userAgentPool))
	return rp.userAgentPool[index]
}

// GetUserAgent 返回当前配置下的User-Agent（供外部HTTP客户端复用）
func (rp *RequestProcessor) GetUserAgent() string {
	return rp.getRandomUserAgent()
}

// MakeRequest 实现 httpclient.HTTPClientInterface 接口
func (rp *RequestProcessor) MakeRequest(rawURL string) (string, int, error) {
	resp, err := rp.DoRequest(rawURL, nil)
	if err != nil {
		return "", 0, err
	}
	if resp == nil {
		return "", 0, fmt.Errorf("empty response")
	}
	return resp.ResponseBody, resp.StatusCode, nil
}

// MakeRequestWithHeaders 实现 httpclient.HeaderAwareClient 接口
func (rp *RequestProcessor) MakeRequestWithHeaders(rawURL string, headers map[string]string) (string, int, error) {
	resp, err := rp.DoRequest(rawURL, headers)
	if err != nil {
		return "", 0, err
	}
	if resp == nil {
		return "", 0, fmt.Errorf("empty response")
	}
	return resp.ResponseBody, resp.StatusCode, nil
}
