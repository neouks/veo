package processor

import (
	"context"
	"fmt"
	"math/rand"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"veo/pkg/httpclient"
	"veo/pkg/logger"
	"veo/pkg/shared"
	interfaces "veo/pkg/types"
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
	shiroCookieEnabled   bool              // 是否注入rememberMe Cookie
}

type ProcessingStats struct {
	TotalCount     int64
	SuccessCount   int64
	FailureCount   int64
	SkippedCount   int64
	ProcessedCount int64
	StartTime      time.Time
	TimeoutCount   int64
}

type StatsUpdater interface {
	IncrementCompletedRequests()
	IncrementTimeouts()
	IncrementErrors()
	SetTotalRequests(count int64)
	AddTotalRequests(count int64)
	IncrementCompletedHosts()
}

func buildHTTPClientConfig(config *RequestConfig, sameHostOnly bool) *httpclient.Config {
	return &httpclient.Config{
		Timeout:            config.Timeout,
		FollowRedirect:     config.FollowRedirect,
		MaxRedirects:       config.MaxRedirects,
		UserAgent:          "", // 动态设置
		SkipTLSVerify:      true,
		ProxyURL:           config.ProxyURL,
		SameHostOnly:       sameHostOnly,
		MaxConcurrent:      config.MaxConcurrent,
		MaxBodySize:        config.MaxBodySize,
		DecompressResponse: config.DecompressResponse,
	}
}

func cloneStringMap(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func (rp *RequestProcessor) initializeProcessingStats(totalURLs int, maxConcurrent int, randomUA bool) *ProcessingStats {
	stats := &ProcessingStats{
		TotalCount: int64(totalURLs),
		StartTime:  time.Now(),
	}

	logger.Debug(fmt.Sprintf("开始处理 %d 个URL，并发数: %d，随机UA: %v", stats.TotalCount, maxConcurrent, randomUA))
	return stats
}

func (rp *RequestProcessor) updateProcessingStats(response *interfaces.HTTPResponse, reqErr error,
	responses *[]*interfaces.HTTPResponse, responsesMu *sync.Mutex, stats *ProcessingStats) {

	atomic.AddInt64(&stats.ProcessedCount, 1)

	if response != nil {
		if responses != nil && responsesMu != nil {
			responsesMu.Lock()
			*responses = append(*responses, response)
			responsesMu.Unlock()
		}

		atomic.AddInt64(&stats.SuccessCount, 1)
		if rp.statsUpdater != nil {
			rp.statsUpdater.IncrementCompletedRequests()
		}
		return
	}

	atomic.AddInt64(&stats.FailureCount, 1)
	if rp.statsUpdater != nil {
		rp.statsUpdater.IncrementCompletedRequests()
		rp.statsUpdater.IncrementErrors()
		if reqErr != nil && rp.isTimeoutOrCanceledError(reqErr) {
			atomic.AddInt64(&stats.TimeoutCount, 1)
			rp.statsUpdater.IncrementTimeouts()
		}
	}
}

func (rp *RequestProcessor) finalizeProcessing(stats *ProcessingStats) {
	rp.logProcessingResults(stats)
}

func (rp *RequestProcessor) logProcessingResults(stats *ProcessingStats) {
	logger.Debugf("\r总计: %d, 成功: %d, 失败: %d, 跳过: %d",
		stats.TotalCount, stats.SuccessCount, stats.FailureCount, stats.SkippedCount)
}

// 构造函数

// NewRequestProcessor 创建新的请求处理器
func NewRequestProcessor(config *RequestConfig) *RequestProcessor {
	if config == nil {
		config = getDefaultConfig()
	}

	processor := &RequestProcessor{
		client:         httpclient.New(buildHTTPClientConfig(config, true)), // 默认开启同源限制，后续可通过SetRedirectSameHostOnly修改
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
		customHeaders:        cloneStringMap(rp.customHeaders),
		redirectSameHostOnly: rp.redirectSameHostOnly,
		shiroCookieEnabled:   rp.shiroCookieEnabled,
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

	rp.customHeaders = cloneStringMap(headers)
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
	ctx = normalizeContext(ctx)

	// 初始化处理统计
	stats := rp.initializeProcessingStats(len(urls), rp.config.MaxConcurrent, rp.config.RandomUserAgent)

	// 更新统计显示器的总请求数
	rp.updateTotalRequests(int64(len(urls)))

	// 初始化响应收集
	responses := make([]*interfaces.HTTPResponse, 0, len(urls))
	var responsesMu sync.Mutex

	// 并发处理（worker pool）：支持 ctx 取消后停止派发
	rp.processURLsConcurrent(ctx, urls, &responses, &responsesMu, stats, nil, nil)

	// 完成处理
	rp.finalizeProcessing(stats)

	return responses
}

// ProcessURLsWithCallbackOnlyWithContextAndProgress 仅通过回调处理响应（可取消），支持请求完成回调
func (rp *RequestProcessor) ProcessURLsWithCallbackOnlyWithContextAndProgress(ctx context.Context, urls []string, callback func(*interfaces.HTTPResponse), onProcessed func()) {
	if len(urls) == 0 {
		return
	}
	ctx = normalizeContext(ctx)

	stats := rp.initializeProcessingStats(len(urls), rp.config.MaxConcurrent, rp.config.RandomUserAgent)

	rp.updateTotalRequests(int64(len(urls)))

	rp.processURLsConcurrent(ctx, urls, nil, nil, stats, callback, onProcessed)
	rp.finalizeProcessing(stats)
}

// processURLsConcurrent 使用 worker pool 并发处理URL列表（支持 ctx 取消）
func (rp *RequestProcessor) processURLsConcurrent(ctx context.Context, urls []string, responses *[]*interfaces.HTTPResponse, responsesMu *sync.Mutex, stats *ProcessingStats, callback func(*interfaces.HTTPResponse), onProcessed func()) {
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
					rp.updateProcessingStats(response, reqErr, responses, responsesMu, stats)
					if onProcessed != nil {
						onProcessed()
					}

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

func contextDoneErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// processURLWithContext 处理单个URL（可取消）
func (rp *RequestProcessor) processURLWithContext(ctx context.Context, url string) (*interfaces.HTTPResponse, error) {
	if err := contextDoneErr(ctx); err != nil {
		return nil, err
	}

	return rp.makeRequestWithHeadersRetry(ctx, url, nil)
}

// RequestOnceWithHeaders 执行单次请求，支持自定义头部并更新统计
func (rp *RequestProcessor) RequestOnceWithHeaders(ctx context.Context, rawURL string, headers map[string]string) (*interfaces.HTTPResponse, error) {
	if err := contextDoneErr(ctx); err != nil {
		return nil, err
	}

	rp.updateTotalRequests(1)

	resp, err := rp.makeRequestWithHeadersRetry(ctx, rawURL, headers)

	if rp.statsUpdater != nil {
		rp.statsUpdater.IncrementCompletedRequests()
		if err != nil {
			rp.statsUpdater.IncrementErrors()
			if rp.isTimeoutOrCanceledError(err) {
				rp.statsUpdater.IncrementTimeouts()
			}
		}
	}

	return resp, err
}

// HTTP请求相关方法

func (rp *RequestProcessor) makeRequestWithHeaders(rawURL string, extraHeaders map[string]string) (*interfaces.HTTPResponse, error) {
	// 准备头部
	headers := rp.getDefaultHeaders()
	shouldRemoveCookie := rp.isDirscanModule() && !rp.shouldInjectShiroCookie()
	for k, v := range extraHeaders {
		if strings.EqualFold(k, "Cookie") && strings.TrimSpace(v) == "" {
			shouldRemoveCookie = true
			continue
		}
		headers[k] = v
	}
	if shouldRemoveCookie {
		removeCookieHeader(headers)
	}
	removeConnectionHeader(headers)

	startTime := time.Now()

	// 使用 httpclient 发起请求
	body, statusCode, respHeaders, err := rp.client.MakeRequestFullWithHeaders(rawURL, headers)
	if err != nil {
		rp.logRequestError(rawURL, err)
		return nil, fmt.Errorf("request failed: %v", err)
	}

	return rp.processResponse(rawURL, statusCode, body, respHeaders, nil, startTime)
}

// logRequestError 记录请求错误日志
func (rp *RequestProcessor) logRequestError(rawURL string, err error) {
	if rp.isTimeoutOrCanceledError(err) {
		logger.Debugf("请求超时: %s, 耗时: >%v, 错误: %v", rawURL, rp.config.Timeout, err)
	} else if rp.isRedirectError(err) {
		logger.Warnf("Redirect failed: %s, error: %v", rawURL, err)
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
	rp.client = httpclient.New(buildHTTPClientConfig(config, rp.redirectSameHostOnly))

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

// SetShiroCookieEnabled 控制是否在指纹识别/目录扫描请求中注入rememberMe Cookie
func (rp *RequestProcessor) SetShiroCookieEnabled(enabled bool) {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	rp.shiroCookieEnabled = enabled
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

// IsTimeoutOrCanceledError 判断是否为超时或取消相关的错误（对外提供）
func IsTimeoutOrCanceledError(err error) bool {
	if err == nil {
		return false
	}
	return timeoutErrorRegex.MatchString(err.Error())
}

// isTimeoutOrCanceledError 判断是否为超时或取消相关的错误（性能优化版）
func (rp *RequestProcessor) isTimeoutOrCanceledError(err error) bool {
	return IsTimeoutOrCanceledError(err)
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

	if containsAnyKeyword(errStr, retryableErrorKeywords) {
		return true
	}

	if containsAnyKeyword(errStr, nonRetryableErrorKeywords) {
		return false
	}

	// 默认情况下，网络相关错误可重试
	return true
}

// isRedirectError 判断是否为重定向相关的错误
func (rp *RequestProcessor) isRedirectError(err error) bool {
	if err == nil {
		return false
	}

	return containsAnyKeyword(strings.ToLower(err.Error()), redirectErrorKeywords)
}

func containsAnyKeyword(s string, keywords []string) bool {
	for _, keyword := range keywords {
		if strings.Contains(s, keyword) {
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
		return shared.Primary()
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
	return responseBodyAndStatus(resp, err)
}

// MakeRequestWithHeaders 实现 httpclient.HeaderAwareClient 接口
func (rp *RequestProcessor) MakeRequestWithHeaders(rawURL string, headers map[string]string) (string, int, error) {
	resp, err := rp.makeRequestWithHeadersRetry(context.Background(), rawURL, headers)
	return responseBodyAndStatus(resp, err)
}

func responseBodyAndStatus(resp *interfaces.HTTPResponse, err error) (string, int, error) {
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
		if err := contextDoneErr(ctx); err != nil {
			return nil, err
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
				if err := contextDoneErr(ctx); err != nil {
					return nil, err
				}
				return nil, context.Canceled
			}
		}
	}

	return nil, lastErr
}

func (rp *RequestProcessor) updateTotalRequests(count int64) {
	if rp.statsUpdater == nil || count <= 0 {
		return
	}
	if rp.IsBatchMode() {
		rp.statsUpdater.AddTotalRequests(count)
		return
	}
	rp.statsUpdater.SetTotalRequests(count)
}

type RequestConfig struct {
	Timeout            time.Duration
	MaxRetries         int
	UserAgents         []string
	MaxBodySize        int
	FollowRedirect     bool
	MaxRedirects       int
	MaxConcurrent      int
	ConnectTimeout     time.Duration
	KeepAlive          time.Duration
	RandomUserAgent    bool
	Delay              time.Duration
	ProxyURL           string
	DecompressResponse bool
}

const DefaultMaxRedirects = 3

// ApplyRedirectPolicy 统一重定向策略（指纹识别/目录扫描共用）
func ApplyRedirectPolicy(config *RequestConfig) {
	if config == nil {
		return
	}
	config.FollowRedirect = true
	config.MaxRedirects = DefaultMaxRedirects
}

// GetDefaultConfig 暴露默认配置获取方法（测试用）
func GetDefaultConfig() *RequestConfig {
	return getDefaultConfig()
}

// getDefaultConfig 获取默认配置
func getDefaultConfig() *RequestConfig {
	timeout := 10 * time.Second
	retries := 3
	maxConcurrent := 100
	connectTimeout := 5 * time.Second
	maxRedirects := DefaultMaxRedirects

	randomUserAgent := false

	delay := time.Duration(0)

	userAgents := shared.GetEffectiveList()
	if len(userAgents) == 0 {
		userAgents = shared.DefaultList()
	}

	return &RequestConfig{
		Timeout:            timeout,
		MaxRetries:         retries,
		UserAgents:         userAgents,
		MaxBodySize:        10 * 1024 * 1024,
		FollowRedirect:     false,
		MaxRedirects:       maxRedirects,
		MaxConcurrent:      maxConcurrent,
		ConnectTimeout:     connectTimeout,
		RandomUserAgent:    randomUserAgent,
		Delay:              delay,
		DecompressResponse: true,
	}
}

func initializeUserAgentPool(config *RequestConfig) []string {
	effective := shared.GetEffectiveList()
	if len(effective) == 0 {
		return effective
	}

	if config != nil && !config.RandomUserAgent {
		return []string{effective[0]}
	}

	return effective
}
func (rp *RequestProcessor) getDefaultHeaders() map[string]string {
	acceptEncoding := "gzip, deflate"
	if rp.config != nil && !rp.config.DecompressResponse {
		acceptEncoding = "identity"
	}
	// 获取基础头部
	headers := map[string]string{
		"User-Agent":      rp.getRandomUserAgent(), // 使用随机UserAgent
		"Accept-Encoding": acceptEncoding,
	}

	// 合并认证头部
	authHeaders := rp.getAuthHeaders()
	for key, value := range authHeaders {
		headers[key] = value
	}

	rp.applyShiroCookie(headers)

	return headers
}

func (rp *RequestProcessor) getAuthHeaders() map[string]string {
	rp.mu.RLock()
	defer rp.mu.RUnlock()

	authHeaders := make(map[string]string, len(rp.customHeaders))
	for key, value := range rp.customHeaders {
		authHeaders[key] = value
	}
	return authHeaders
}

func removeConnectionHeader(headers map[string]string) {
	for key := range headers {
		if strings.EqualFold(key, "Connection") {
			delete(headers, key)
		}
	}
}

func removeCookieHeader(headers map[string]string) {
	for key := range headers {
		if strings.EqualFold(key, "Cookie") {
			delete(headers, key)
		}
	}
}

func (rp *RequestProcessor) isDirscanModule() bool {
	context := strings.ToLower(strings.TrimSpace(rp.GetModuleContext()))
	return strings.HasPrefix(context, "dirscan")
}

func (rp *RequestProcessor) shouldInjectShiroCookie() bool {
	rp.mu.RLock()
	enabled := rp.shiroCookieEnabled
	context := rp.moduleContext
	rp.mu.RUnlock()

	if !enabled {
		return false
	}
	context = strings.ToLower(strings.TrimSpace(context))
	return strings.HasPrefix(context, "dirscan") || strings.HasPrefix(context, "finger")
}

func (rp *RequestProcessor) applyShiroCookie(headers map[string]string) {
	if len(headers) == 0 || !rp.shouldInjectShiroCookie() {
		return
	}

	for key, value := range headers {
		if strings.EqualFold(key, "Cookie") {
			trimmed := strings.TrimSpace(value)
			if strings.Contains(strings.ToLower(trimmed), "rememberme=1") {
				return
			}
			if trimmed == "" {
				headers[key] = "rememberMe=1"
			} else {
				headers[key] = trimmed + "; rememberMe=1"
			}
			return
		}
	}

	headers["Cookie"] = "rememberMe=1"
}

// ============================================================================
// Response Processing Helpers
// ============================================================================

// processResponseBody 处理响应体，应用大小限制（内存优化）
func (rp *RequestProcessor) processResponseBody(rawBody string) string {
	// 获取配置的最大响应体大小
	maxSize := rp.config.MaxBodySize
	if maxSize <= 0 {
		maxSize = 10 * 1024 * 1024 // 默认10MB
	}

	// 如果响应体超过限制，进行截断
	if len(rawBody) > maxSize {
		truncatedBody := rawBody[:maxSize]

		// 添加截断标记
		origSize := strconv.Itoa(len(rawBody))
		var builder strings.Builder
		builder.Grow(len(truncatedBody) + len(origSize) + len("\n...[响应体已截断，原始大小:  bytes]"))
		builder.WriteString(truncatedBody)
		builder.WriteString("\n...[响应体已截断，原始大小: ")
		builder.WriteString(origSize)
		builder.WriteString(" bytes]")

		logger.Debugf("响应体已截断: %d bytes -> %d bytes",
			len(rawBody), maxSize)

		return builder.String()
	}

	return rawBody
}

// processResponse 处理响应，构建HTTPResponse结构体
func (rp *RequestProcessor) processResponse(url string, statusCode int, body string, responseHeaders, requestHeaders map[string][]string, startTime time.Time) (*interfaces.HTTPResponse, error) {
	remoteIP := ""
	if responseHeaders != nil {
		if vals, ok := responseHeaders[httpclient.RemoteIPHeaderKey]; ok && len(vals) > 0 {
			remoteIP = strings.TrimSpace(vals[0])
			delete(responseHeaders, httpclient.RemoteIPHeaderKey)
		}
	}

	// 响应体截断处理
	finalBody := rp.processResponseBody(body)

	// 提取 Content-Encoding
	var contentEncoding string
	if enc, ok := responseHeaders["Content-Encoding"]; ok && len(enc) > 0 {
		contentEncoding = strings.ToLower(strings.TrimSpace(enc[0]))
	}

	decodedBody := rp.config.DecompressResponse || contentEncoding == ""
	title := ""
	if decodedBody {
		title = rp.extractTitleSafely(url, finalBody)
	}
	contentLength := int64(len(finalBody))

	// 提取 Content-Type
	contentType := "unknown"
	if ct, ok := responseHeaders["Content-Type"]; ok && len(ct) > 0 {
		contentType = ct[0]
		if v, _, found := strings.Cut(contentType, ";"); found {
			contentType = v
		}
		contentType = strings.TrimSpace(contentType)
	}

	// 提取 Server
	server := "unknown"
	if s, ok := responseHeaders["Server"]; ok && len(s) > 0 {
		server = s[0]
	}

	duration := time.Since(startTime).Milliseconds()

	// 构建响应对象
	response := &interfaces.HTTPResponse{
		URL:             url,
		Method:          "GET",
		StatusCode:      statusCode,
		Title:           title,
		ContentLength:   contentLength,
		ContentType:     contentType,
		Body:            finalBody,
		ResponseHeaders: responseHeaders,
		RequestHeaders:  requestHeaders,
		RemoteIP:        remoteIP,
		BodyDecoded:     decodedBody,
		Server:          server,
		IsDirectory:     rp.isDirectoryURL(url),
		Length:          contentLength,
		Duration:        duration,
		Depth:           0, // 深度信息需要外部设置
		ResponseBody:    finalBody,
		Timestamp:       time.Now(),
	}

	// 记录处理完成日志
	logger.Debug(fmt.Sprintf("响应处理完成: %s [%d] %s, 响应头数量: %d, 耗时: %dms",
		url, statusCode, title, len(responseHeaders), duration))

	return response, nil
}

// extractTitleSafely 安全地提取页面标题
func (rp *RequestProcessor) extractTitleSafely(url, body string) string {
	var title string
	func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Warnf("Title extraction panicked, URL: %s, error: %v", url, r)
				title = "标题提取失败"
			}
		}()
		title = rp.titleExtractor.ExtractTitle(body)
	}()
	return title
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
