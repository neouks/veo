package processor

import (
	"context"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"sync"
	"time"

	"veo/pkg/utils/httpclient"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/processor/auth"
	"veo/pkg/utils/redirect"
	"veo/pkg/utils/shared"
	"veo/pkg/utils/useragent"
	"veo/proxy"
	"veo/pkg/utils/logger"

	"github.com/valyala/fasthttp"
)

// RequestProcessor 请求处理器
type RequestProcessor struct {
	proxy.BaseAddon
	client         *fasthttp.Client
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
	redirectClient       httpclient.HTTPClientInterface
	redirectSameHostOnly bool // 是否限制重定向在同主机
}

// 构造函数

// NewRequestProcessor 创建新的请求处理器
func NewRequestProcessor(config *RequestConfig) *RequestProcessor {
	if config == nil {
		config = getDefaultConfig()
	}

	processor := &RequestProcessor{
		client:         createFastHTTPClient(config),
		config:         config,
		userAgentPool:  initializeUserAgentPool(config),
		titleExtractor: shared.NewTitleExtractor(),

		// 新增：初始化认证头部管理
		customHeaders:        make(map[string]string),
		authDetector:         auth.NewAuthDetector(),
		redirectClient:       httpclient.New(nil),
		redirectSameHostOnly: true,
	}

	return processor
}

// SetRedirectSameHostOnly 控制重定向是否限制同主机
func (rp *RequestProcessor) SetRedirectSameHostOnly(enabled bool) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	rp.redirectSameHostOnly = enabled
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

	// 创建进度完成信号通道
	progressDone := make(chan struct{})

	// 并发优化：使用Worker Pool处理URL
	rp.processURLsWithWorkerPool(urls, &responses, &responsesMu, stats)

	// 完成处理
	rp.finalizeProcessing(progressDone, stats, len(responses))

	return responses
}

// URL处理相关方法

// processConcurrentURLs 并发处理URL列表（真正的并发控制）
func (rp *RequestProcessor) processConcurrentURLs(urls []string, responses *[]*interfaces.HTTPResponse, responsesMu *sync.Mutex, stats *ProcessingStats) {
	var wg sync.WaitGroup

	// 使用带缓冲的channel控制并发数
	sem := make(chan struct{}, rp.config.MaxConcurrent)

	for i, url := range urls {
		wg.Add(1)

		go func(index int, targetURL string) {
			// 获取信号量（这里会阻塞，直到有可用的槽位）
			sem <- struct{}{}

			defer func() {
				<-sem // 释放信号量
				wg.Done()
			}()

			rp.processURLWithStats(targetURL, responses, responsesMu, stats)
		}(i, url)
	}

	wg.Wait()
}

// processURLsWithWorkerPool 使用Worker Pool处理URL列表
func (rp *RequestProcessor) processURLsWithWorkerPool(urls []string, responses *[]*interfaces.HTTPResponse, responsesMu *sync.Mutex, stats *ProcessingStats) {
	// 创建并启动工作池
	workerPool := rp.createAndStartWorkerPool()
	defer workerPool.Stop()

	// 提交任务并收集结果
	taskSubmissionDone := rp.submitTasksAsync(workerPool, urls)
	rp.collectResults(workerPool, urls, responses, responsesMu, stats, taskSubmissionDone)
}

// createAndStartWorkerPool 创建并启动工作池
func (rp *RequestProcessor) createAndStartWorkerPool() *WorkerPool {
	workerPool := NewWorkerPool(rp.config.MaxConcurrent, rp)
	workerPool.Start()
	return workerPool
}

// submitTasksAsync 异步提交所有任务
func (rp *RequestProcessor) submitTasksAsync(workerPool *WorkerPool, urls []string) <-chan struct{} {
	taskSubmissionDone := make(chan struct{})

	go func() {
		defer close(taskSubmissionDone)
		for i, url := range urls {
			// 检查Worker Pool是否已停止
			if rp.shouldStopTaskSubmission(workerPool) {
				logger.Debugf("Worker Pool已停止，停止提交新任务")
				return
			}

			task := WorkerTask{
				URL:       url,
				Index:     i,
				TotalURLs: len(urls),
			}
			workerPool.SubmitTask(task)
		}
	}()

	return taskSubmissionDone
}

// shouldStopTaskSubmission 检查是否应该停止任务提交
func (rp *RequestProcessor) shouldStopTaskSubmission(workerPool *WorkerPool) bool {
	select {
	case <-workerPool.ctx.Done():
		return true
	default:
		return false
	}
}

// collectResults 收集处理结果（修复：完善超时和取消机制）
func (rp *RequestProcessor) collectResults(workerPool *WorkerPool, urls []string, responses *[]*interfaces.HTTPResponse, responsesMu *sync.Mutex, stats *ProcessingStats, taskSubmissionDone <-chan struct{}) {
	processedCount := 0
	timeoutDuration := 30 * time.Second

	// 创建结果收集的context，支持提前取消
	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration+10*time.Second)
	defer cancel()

	for processedCount < len(urls) {
		select {
		case result := <-workerPool.GetResult():
			rp.processWorkerResult(result, responses, responsesMu, stats)
			processedCount++

		case <-time.After(timeoutDuration):
			logger.Warnf("Worker Pool处理超时，尝试收集剩余结果...")

			// 修复：尝试收集剩余结果，避免丢失数据
			remainingResults := rp.collectRemainingResults(workerPool, len(urls)-processedCount, responses, responsesMu, stats)
			processedCount += remainingResults

			logger.Warnf("超时处理完成，最终处理: %d/%d", processedCount, len(urls))

			// 等待任务提交完成，但设置超时避免永久阻塞
			select {
			case <-taskSubmissionDone:
			case <-time.After(5 * time.Second):
				logger.Warnf("等待任务提交完成超时，强制退出")
			}
			return

		case <-ctx.Done():
			logger.Warnf("结果收集被取消，已处理: %d/%d", processedCount, len(urls))
			return
		}
	}

	// 确保任务提交完成，但设置超时避免永久阻塞
	select {
	case <-taskSubmissionDone:
	case <-time.After(5 * time.Second):
		logger.Warnf("等待任务提交完成超时")
	}
}

// collectRemainingResults 收集剩余结果（新增：避免结果丢失）
func (rp *RequestProcessor) collectRemainingResults(workerPool *WorkerPool, maxResults int, responses *[]*interfaces.HTTPResponse, responsesMu *sync.Mutex, stats *ProcessingStats) int {
	collected := 0
	timeout := 100 * time.Millisecond

	for i := 0; i < maxResults && i < 50; i++ { // 最多尝试收集50个剩余结果
		select {
		case result := <-workerPool.GetResult():
			rp.processWorkerResult(result, responses, responsesMu, stats)
			collected++
		case <-time.After(timeout):
			// 逐渐增加超时时间，但有上限
			if timeout < 500*time.Millisecond {
				timeout += 50 * time.Millisecond
			}
			break
		}
	}

	logger.Debugf("收集到 %d 个剩余结果", collected)
	return collected
}

// processWorkerResult 处理单个工作结果
func (rp *RequestProcessor) processWorkerResult(result WorkerResult, responses *[]*interfaces.HTTPResponse, responsesMu *sync.Mutex, stats *ProcessingStats) {
	// 应用请求延迟
	if rp.config.Delay > 0 {
		time.Sleep(rp.config.Delay)
	}

	// 更新统计和收集响应
	rp.updateProcessingStats(result.Response, result.URL, responses, responsesMu, stats)
}

// processURLWithStats 处理单个URL并更新统计
func (rp *RequestProcessor) processURLWithStats(targetURL string, responses *[]*interfaces.HTTPResponse, responsesMu *sync.Mutex, stats *ProcessingStats) {
	// 请求延迟
	if rp.config.Delay > 0 {
		time.Sleep(rp.config.Delay)
	}

	// 处理URL（并发控制已在上层处理）
	response := rp.processURL(targetURL)

	// 更新统计和收集响应
	rp.updateProcessingStats(response, targetURL, responses, responsesMu, stats)
}

// requestFetcher 适配器，用于将RequestProcessor适配为redirect.HTTPFetcherFull接口
type requestFetcher struct {
	rp *RequestProcessor
}

func (f *requestFetcher) MakeRequestFull(rawURL string) (string, int, map[string][]string, error) {
	resp, err := f.rp.makeRequest(rawURL)
	if err != nil {
		return "", 0, nil, err
	}
	return resp.Body, resp.StatusCode, resp.ResponseHeaders, nil
}

// processURL 处理单个URL
func (rp *RequestProcessor) processURL(url string) *interfaces.HTTPResponse {
	var response *interfaces.HTTPResponse
	var err error
	sameHostOnly := rp.IsRedirectSameHostOnly()

	// 改进的重试逻辑（指数退避 + 抖动）
	for attempt := 0; attempt <= rp.config.MaxRetries; attempt++ {
		if attempt > 0 {
			logger.Debug(fmt.Sprintf("重试 %d/%d: %s", attempt, rp.config.MaxRetries, url))
		}

		// 构造重定向配置
		redirectConfig := &redirect.Config{
			MaxRedirects:   rp.config.MaxRedirects,
			FollowRedirect: rp.config.FollowRedirect,
			SameHostOnly:   sameHostOnly,
		}

		// 执行请求（包含重定向处理）
		fetcher := &requestFetcher{rp: rp}
		response, err = redirect.Execute(url, fetcher, redirectConfig)

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
			baseDelay := time.Duration(1<<uint(attempt)) * time.Second  // 指数退避: 1s, 2s, 4s, 8s
			jitter := time.Duration(rand.Intn(1000)) * time.Millisecond // 随机抖动: 0-1s
			delay := baseDelay + jitter
			if delay > 10*time.Second {
				delay = 10 * time.Second // 最大延迟10秒
			}
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

// makeRequest 使用fasthttp发起请求
func (rp *RequestProcessor) makeRequest(rawURL string) (*interfaces.HTTPResponse, error) {
	return rp.makeRequestWithHeaders(rawURL, nil)
}

func (rp *RequestProcessor) makeRequestWithHeaders(rawURL string, extraHeaders map[string]string) (*interfaces.HTTPResponse, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	rp.prepareRequest(req, rawURL)
	if len(extraHeaders) > 0 {
		for key, value := range extraHeaders {
			trimmedKey := strings.TrimSpace(key)
			if trimmedKey == "" {
				continue
			}
			req.Header.Set(trimmedKey, value)
		}
	}
	startTime := time.Now()

	err := rp.client.DoTimeout(req, resp, rp.config.Timeout)
	if err != nil {
		rp.logRequestError(rawURL, err)
		return nil, fmt.Errorf("请求失败: %v", err)
	}

	duration := time.Since(startTime)
	logger.Debug(fmt.Sprintf("fasthttp请求完成: %s [%d] 耗时: %v",
		rawURL, resp.StatusCode(), duration))

	return rp.buildHTTPResponse(rawURL, req, resp, startTime)
}

// prepareRequest 准备HTTP请求
func (rp *RequestProcessor) prepareRequest(req *fasthttp.Request, rawURL string) {
	req.SetRequestURI(rawURL)
	req.Header.SetMethod(fasthttp.MethodGet)
	rp.setRequestHeaders(&req.Header)
}

// logRequestError 记录请求错误日志
func (rp *RequestProcessor) logRequestError(rawURL string, err error) {
	if rp.isTimeoutOrCanceledError(err) {
		logger.Debugf("超时丢弃URL: %s, 耗时: >%v, 错误: %v", rawURL, rp.config.Timeout, err)
	} else if rp.isRedirectError(err) {
		logger.Warnf("重定向处理失败: %s, 错误: %v", rawURL, err)
	} else {
		logger.Debugf("请求失败: %s, 错误: %v", rawURL, err)
	}
}

// buildHTTPResponse 构建HTTP响应对象
func (rp *RequestProcessor) buildHTTPResponse(rawURL string, req *fasthttp.Request, resp *fasthttp.Response, startTime time.Time) (*interfaces.HTTPResponse, error) {
	requestHeaders := rp.extractRequestHeaders(&req.Header)
	return rp.processResponse(rawURL, resp, requestHeaders, startTime)
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
	rp.client = createFastHTTPClient(config)

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
	if rp.client != nil {
		rp.client.CloseIdleConnections()
	}
	logger.Info("请求处理器已关闭")
}

// 性能优化：预编译的超时错误正则表达式
var timeoutErrorRegex = regexp.MustCompile(`(?i)(timeout|context canceled|context deadline exceeded|dial timeout|read timeout|write timeout|i/o timeout|deadline exceeded|operation was canceled)`)

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
		"timeout", "connection reset", "connection refused",
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
