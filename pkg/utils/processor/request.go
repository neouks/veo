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
	"veo/pkg/utils/logger"
	"veo/pkg/utils/shared"
	"veo/pkg/utils/useragent"
)

// RequestProcessor 请求处理器
type RequestProcessor struct {
	client         *httpclient.Client
	config         *RequestConfig
	mu             sync.RWMutex
	userAgentPool  []string               // UserAgent池
	titleExtractor *shared.TitleExtractor // 标题提取器
	moduleContext  string                 // 模块上下文标识（用于区分调用来源）
	statsUpdater   StatsUpdater           // 统计更新器
	batchMode      bool                   // 批量扫描模式标志

	// HTTP认证头部管理
	customHeaders        map[string]string // CLI指定的自定义头部
	redirectSameHostOnly bool              // 是否限制重定向在同主机
}

// 构造函数

// NewRequestProcessor 创建新的请求处理器
func NewRequestProcessor(config *RequestConfig) *RequestProcessor {
	if config == nil {
		config = getDefaultConfig()
	}

	// 转换配置到 httpclient.Config
	clientConfig := &httpclient.Config{
		Timeout:            config.Timeout,
		FollowRedirect:     config.FollowRedirect,
		MaxRedirects:       config.MaxRedirects,
		UserAgent:          "", // 动态设置
		SkipTLSVerify:      true,
		ProxyURL:           config.ProxyURL,
		SameHostOnly:       true, // 默认开启同源限制，后续可通过SetRedirectSameHostOnly修改
		MaxConcurrent:      config.MaxConcurrent,
		MaxBodySize:        config.MaxBodySize,
		DecompressResponse: config.DecompressResponse,
	}

	processor := &RequestProcessor{
		client:         httpclient.New(clientConfig),
		config:         config,
		userAgentPool:  initializeUserAgentPool(config),
		titleExtractor: shared.NewTitleExtractor(),

		customHeaders:        make(map[string]string),
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
}

// HasCustomHeaders 检查是否设置了自定义头部
func (rp *RequestProcessor) HasCustomHeaders() bool {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return len(rp.customHeaders) > 0
}

// 请求处理器核心方法
// ProcessURLsWithContext 处理URL列表（可取消）
func (rp *RequestProcessor) ProcessURLsWithContext(ctx context.Context, urls []string) []*interfaces.HTTPResponse {
	if len(urls) == 0 {
		return []*interfaces.HTTPResponse{}
	}
	if ctx == nil {
		ctx = context.Background()
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

	// 并发处理（worker pool）：支持 ctx 取消后停止派发
	rp.processURLsConcurrent(ctx, urls, &responses, &responsesMu, stats, nil)

	// 完成处理
	rp.finalizeProcessing(stats)

	return responses
}

// ProcessURLsWithCallback 处理URL列表，并对每个响应执行回调
func (rp *RequestProcessor) ProcessURLsWithCallback(urls []string, callback func(*interfaces.HTTPResponse)) []*interfaces.HTTPResponse {
	return rp.ProcessURLsWithCallbackWithContext(context.Background(), urls, callback)
}

// ProcessURLsWithCallbackWithContext 处理URL列表（可取消），并对每个响应执行回调
func (rp *RequestProcessor) ProcessURLsWithCallbackWithContext(ctx context.Context, urls []string, callback func(*interfaces.HTTPResponse)) []*interfaces.HTTPResponse {
	if len(urls) == 0 {
		return []*interfaces.HTTPResponse{}
	}
	if ctx == nil {
		ctx = context.Background()
	}

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

	// 并发处理（worker pool）：支持 ctx 取消后停止派发
	rp.processURLsConcurrent(ctx, urls, &responses, &responsesMu, stats, callback)

	// 完成处理
	rp.finalizeProcessing(stats)

	return responses
}

// ProcessURLsWithCallbackOnly 仅通过回调处理响应，不收集/返回结果
func (rp *RequestProcessor) ProcessURLsWithCallbackOnly(urls []string, callback func(*interfaces.HTTPResponse)) {
	rp.ProcessURLsWithCallbackOnlyWithContext(context.Background(), urls, callback)
}

// ProcessURLsWithCallbackOnlyWithContext 仅通过回调处理响应（可取消），不收集/返回结果
func (rp *RequestProcessor) ProcessURLsWithCallbackOnlyWithContext(ctx context.Context, urls []string, callback func(*interfaces.HTTPResponse)) {
	if len(urls) == 0 {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}

	stats := rp.initializeProcessingStats(len(urls), rp.config.MaxConcurrent, rp.config.RandomUserAgent)

	if rp.statsUpdater != nil {
		if rp.IsBatchMode() {
			rp.statsUpdater.AddTotalRequests(int64(len(urls)))
		} else {
			rp.statsUpdater.SetTotalRequests(int64(len(urls)))
		}
	}

	rp.processURLsConcurrent(ctx, urls, nil, nil, stats, callback)
	rp.finalizeProcessing(stats)
}

// processURLsConcurrent 使用 worker pool 并发处理URL列表（支持 ctx 取消）
func (rp *RequestProcessor) processURLsConcurrent(ctx context.Context, urls []string, responses *[]*interfaces.HTTPResponse, responsesMu *sync.Mutex, stats *ProcessingStats, callback func(*interfaces.HTTPResponse)) {
	maxConcurrent := rp.config.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}

	workerCount := maxConcurrent
	if workerCount > len(urls) {
		workerCount = len(urls)
	}
	if workerCount <= 0 {
		workerCount = 1
	}

	jobs := make(chan string)

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case targetURL, ok := <-jobs:
					if !ok {
						return
					}

					// 应用请求延迟（可取消）
					if rp.config.Delay > 0 {
						if !sleepWithContext(ctx, rp.config.Delay) {
							return
						}
					}

					response, reqErr := rp.processURLWithContext(ctx, targetURL)
					rp.updateProcessingStats(response, targetURL, reqErr, responses, responsesMu, stats)

					if callback != nil && response != nil {
						callback(response)
					}
				}
			}
		}()
	}

	// 派发任务：ctx 取消后停止继续投递
	for _, u := range urls {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		case jobs <- u:
		}
	}
	close(jobs)
	wg.Wait()
}

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	if ctx == nil {
		time.Sleep(d)
		return true
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// processURLWithContext 处理单个URL（可取消）
func (rp *RequestProcessor) processURLWithContext(ctx context.Context, url string) (*interfaces.HTTPResponse, error) {
	if ctx != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
	}

	response, err := rp.makeRequest(url)
	if err == nil {
		return response, nil
	}

	if !rp.isRetryableError(err) {
		logger.Debugf("不可重试的错误，停止重试: %s, 错误: %v", url, err)
	}
	return nil, err
}

// HTTP请求相关方法

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

	return rp.processResponse(rawURL, statusCode, body, respHeaders, nil, startTime)
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
		Timeout:            config.Timeout,
		FollowRedirect:     config.FollowRedirect,
		MaxRedirects:       config.MaxRedirects,
		UserAgent:          "", // 动态设置
		SkipTLSVerify:      true,
		ProxyURL:           config.ProxyURL,
		SameHostOnly:       rp.redirectSameHostOnly,
		MaxConcurrent:      config.MaxConcurrent,
		MaxBodySize:        config.MaxBodySize,
		DecompressResponse: config.DecompressResponse,
	}
	rp.client = httpclient.New(clientConfig)

	// 更新UserAgent池
	rp.userAgentPool = initializeUserAgentPool(config)
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

var (
	retryableErrorKeywords = []string{
		"timeout", "timed out", "connection reset", "connection refused",
		"temporary failure", "network unreachable", "host unreachable",
		"dial timeout", "read timeout", "write timeout", "i/o timeout",
		"context deadline exceeded", "server closed idle connection",
		"broken pipe", "connection aborted", "no route to host",
	}
	nonRetryableErrorKeywords = []string{
		"certificate", "tls", "ssl", "x509", "invalid url",
		"malformed", "parse error", "unsupported protocol",
		"no such host", "dns", "name resolution",
	}
	redirectErrorKeywords = []string{
		"missing location header for http redirect",
		"location header",
		"redirect",
	}
)

// isRetryableError 判断错误是否可重试（改进重试策略）
func (rp *RequestProcessor) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())

	for _, retryableErr := range retryableErrorKeywords {
		if strings.Contains(errStr, retryableErr) {
			return true
		}
	}

	for _, nonRetryableErr := range nonRetryableErrorKeywords {
		if strings.Contains(errStr, nonRetryableErr) {
			return false
		}
	}

	// 默认情况下，网络相关错误可重试
	return true
}

// isRedirectError 判断是否为重定向相关的错误
func (rp *RequestProcessor) isRedirectError(err error) bool {
	if err == nil {
		return false
	}

	errStr := strings.ToLower(err.Error())

	for _, keyword := range redirectErrorKeywords {
		if strings.Contains(errStr, keyword) {
			return true
		}
	}

	return false
}

// UserAgent相关方法

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

// MakeRequest 实现 httpclient.HTTPClientInterface 接口
func (rp *RequestProcessor) MakeRequest(rawURL string) (string, int, error) {
	resp, err := rp.makeRequestWithHeadersRetry(context.Background(), rawURL, nil)
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
	resp, err := rp.makeRequestWithHeadersRetry(context.Background(), rawURL, headers)
	if err != nil {
		return "", 0, err
	}
	if resp == nil {
		return "", 0, fmt.Errorf("empty response")
	}
	return resp.ResponseBody, resp.StatusCode, nil
}

func (rp *RequestProcessor) makeRequestWithHeadersRetry(ctx context.Context, rawURL string, headers map[string]string) (*interfaces.HTTPResponse, error) {
	maxRetries := rp.config.MaxRetries
	if maxRetries <= 0 {
		return rp.makeRequestWithHeaders(rawURL, headers)
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if ctx != nil {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
		}

		if attempt > 0 {
			logger.Debug(fmt.Sprintf("重试 %d/%d: %s", attempt, maxRetries, rawURL))
		}

		resp, err := rp.makeRequestWithHeaders(rawURL, headers)
		if err == nil {
			return resp, nil
		}
		lastErr = err

		if !rp.isRetryableError(err) {
			logger.Debugf("不可重试的错误，停止重试: %s, 错误: %v", rawURL, err)
			break
		}

		if attempt < maxRetries {
			baseDelay := time.Duration(100*(1<<uint(attempt))) * time.Millisecond
			if baseDelay > 2*time.Second {
				baseDelay = 2 * time.Second
			}

			jitter := time.Duration(rand.Intn(100)) * time.Millisecond
			delay := baseDelay + jitter
			logger.Debugf("重试延迟: %v (基础: %v, 抖动: %v)", delay, baseDelay, jitter)

			if !sleepWithContext(ctx, delay) {
				if ctx != nil {
					return nil, ctx.Err()
				}
				return nil, context.Canceled
			}
		}
	}

	return nil, lastErr
}
