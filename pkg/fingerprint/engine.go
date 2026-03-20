package fingerprint

import (
	"context"
	"crypto/md5"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"veo/pkg/httpclient"
	"veo/pkg/logger"
	"veo/pkg/redirect"
	"veo/pkg/shared"
	typespkg "veo/pkg/types"

	"gopkg.in/yaml.v3"
)

type FingerprintRule struct {
	ID        string     `yaml:"-"`
	Name      string     `yaml:"-"`
	DSL       []string   `yaml:"dsl"`
	Condition string     `yaml:"condition,omitempty"`
	Category  string     `yaml:"category,omitempty"`
	Paths     StringList `yaml:"path,omitempty"`
	Headers   StringList `yaml:"header,omitempty"`
}

type FingerprintMatch = typespkg.FingerprintMatch

type HTTPResponse = typespkg.HTTPResponse

type EngineConfig struct {
	RulesPath       string `yaml:"rules_path"`
	MaxConcurrency  int    `yaml:"max_concurrency"`
	EnableFiltering bool   `yaml:"enable_filtering"`
	MaxBodySize     int    `yaml:"max_body_size"`
	LogMatches      bool   `yaml:"log_matches"`

	StaticExtensions         []string        `yaml:"-"`
	StaticContentTypes       []string        `yaml:"-"`
	StaticFileFilterEnabled  bool            `yaml:"-"`
	ContentTypeFilterEnabled bool            `yaml:"-"`
	ShowSnippet              bool            `yaml:"-"`
	OutputFormatter          OutputFormatter `yaml:"-"`
}

type Engine struct {
	config      *EngineConfig
	ruleManager *RuleManager
	matches     []*FingerprintMatch
	dslParser   *DSLParser
	stats       *Statistics
	iconCache   *IconCache
	mu          sync.RWMutex
}

type ProbeResult struct {
	Response *HTTPResponse
	Matches  []*FingerprintMatch
}

type StringList []string

func (sl *StringList) UnmarshalYAML(value *yaml.Node) error {
	if value == nil {
		*sl = nil
		return nil
	}

	switch value.Kind {
	case yaml.ScalarNode:
		trimmed := strings.TrimSpace(value.Value)
		if trimmed == "" {
			*sl = nil
			return nil
		}
		*sl = []string{trimmed}
		return nil
	case yaml.SequenceNode:
		result := make([]string, 0, len(value.Content))
		for _, node := range value.Content {
			if node == nil {
				continue
			}
			if node.Kind == yaml.ScalarNode {
				trimmed := strings.TrimSpace(node.Value)
				if trimmed != "" {
					result = append(result, trimmed)
				}
			}
		}
		if len(result) == 0 {
			*sl = nil
			return nil
		}
		*sl = result
		return nil
	case yaml.AliasNode:
		if value.Alias != nil {
			return sl.UnmarshalYAML(value.Alias)
		}
		return nil
	default:
		return fmt.Errorf("unsupported YAML node for string list: %v", value.Kind)
	}
}

func (r *FingerprintRule) HasPaths() bool {
	return len(r.Paths) > 0
}

func (r *FingerprintRule) HasHeaders() bool {
	return len(r.Headers) > 0
}

func (r *FingerprintRule) GetHeaderMap() map[string]string {
	if len(r.Headers) == 0 {
		return nil
	}
	headers := make(map[string]string)
	for _, line := range r.Headers {
		key, value, ok := parseHeaderLine(line)
		if !ok {
			continue
		}
		headers[key] = value
	}
	if len(headers) == 0 {
		return nil
	}
	return headers
}

func parseHeaderLine(line string) (string, string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", "", false
	}
	parts := strings.SplitN(trimmed, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	if key == "" {
		return "", "", false
	}
	return key, value, true
}

type Statistics struct {
	TotalRequests    int64     `json:"total_requests"`
	MatchedRequests  int64     `json:"matched_requests"`
	FilteredRequests int64     `json:"filtered_requests"`
	RulesLoaded      int       `json:"rules_loaded"`
	StartTime        time.Time `json:"start_time"`
	LastMatchTime    time.Time `json:"last_match_time"`
}

type DSLContext struct {
	Response   *HTTPResponse
	Headers    map[string][]string
	Body       string
	URL        string
	Method     string
	HTTPClient httpclient.HTTPClientInterface
	BaseURL    string
	Engine     *Engine
}

var (
	StaticFileExtensions = []string{
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
		".css", ".woff", ".woff2", ".ttf", ".eot",
		".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".mkv",
	}

	StaticContentTypes = []string{
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
)

// NewEngine 创建新的指纹识别引擎
func NewEngine(config *EngineConfig) *Engine {
	if config == nil {
		config = getDefaultConfig()
	} else {
		// 补充默认配置
		if config.StaticExtensions == nil {
			config.StaticExtensions = append([]string(nil), StaticFileExtensions...)
		}
		if config.StaticContentTypes == nil {
			config.StaticContentTypes = append([]string(nil), StaticContentTypes...)
		}
	}

	engine := &Engine{
		config:      config,
		ruleManager: NewRuleManager(),
		matches:     make([]*FingerprintMatch, 0),
		dslParser:   NewDSLParser(),
		iconCache:   NewIconCache(),
		stats: &Statistics{
			StartTime: time.Now(),
		},
	}

	return engine
}

// GetOutputFormatter 获取输出格式化器
func (e *Engine) GetOutputFormatter() OutputFormatter {
	return e.config.OutputFormatter
}

// LoadRules 加载指纹识别规则
func (e *Engine) LoadRules(rulesPath string) error {
	return e.ruleManager.LoadRules(rulesPath)
}

// GetLoadedSummaryString 返回已加载规则文件的摘要字符串
func (e *Engine) GetLoadedSummaryString() string {
	return e.ruleManager.GetLoadedSummaryString()
}

// AnalyzeResponseWithClient 分析响应包并进行指纹识别（增强版，支持icon()函数主动探测）
func (e *Engine) AnalyzeResponseWithClient(response *HTTPResponse, httpClient httpclient.HTTPClientInterface) []*FingerprintMatch {
	return e.analyzeResponseInternal(response, httpClient, false, true)
}

// AnalyzeResponsePassive 分析响应包并进行指纹识别（仅被动规则匹配）
func (e *Engine) AnalyzeResponsePassive(response *HTTPResponse) []*FingerprintMatch {
	return e.analyzeResponseInternal(response, nil, false, true)
}

// AnalyzeResponseWithClientNoNoMatch 分析响应包并进行指纹识别（不输出无匹配）
func (e *Engine) AnalyzeResponseWithClientNoNoMatch(response *HTTPResponse, httpClient httpclient.HTTPClientInterface) []*FingerprintMatch {
	return e.analyzeResponseInternal(response, httpClient, false, false)
}

// AnalyzeResponseWithClientSilent 分析响应包并进行指纹识别（静默版本，不自动输出结果）
func (e *Engine) AnalyzeResponseWithClientSilent(response *HTTPResponse, httpClient interface{}) []*FingerprintMatch {
	client, _ := httpClient.(httpclient.HTTPClientInterface)
	return e.analyzeResponseInternal(response, client, true, false)
}

// analyzeResponseInternal 内部核心分析逻辑
func (e *Engine) analyzeResponseInternal(response *HTTPResponse, httpClient httpclient.HTTPClientInterface, silent bool, emitNoMatch bool) []*FingerprintMatch {
	// 检查是否应该过滤此响应
	if e.config.EnableFiltering && e.shouldFilterResponse(response) {
		atomic.AddInt64(&e.stats.FilteredRequests, 1)
		if !silent && emitNoMatch && e.config.OutputFormatter != nil {
			e.config.OutputFormatter.FormatNoMatch(response)
		}
		return nil
	}

	// 更新统计
	atomic.AddInt64(&e.stats.TotalRequests, 1)

	// 创建DSL上下文
	var ctx *DSLContext

	if httpClient != nil {
		// baseURL 由 createDSLContextWithClient 内部兜底计算，避免重复解析
		ctx = e.createDSLContextWithClient(response, httpClient, "")
		logger.Debugf("创建增强DSL上下文，支持icon()主动探测: %s (Silent: %v)", ctx.BaseURL, silent)
	} else {
		ctx = e.createDSLContext(response)
		logger.Debugf("创建基础DSL上下文，不支持icon()主动探测 (Silent: %v)", silent)
	}

	var matches []*FingerprintMatch

	// 遍历所有规则进行匹配
	rules := e.ruleManager.GetRulesSnapshot()

	for _, rule := range rules {
		if match := e.matchRule(rule, ctx); match != nil {
			matches = append(matches, match)
		}
	}

	// 更新匹配统计
	if len(matches) > 0 {
		for _, match := range matches {
			if match == nil {
				continue
			}
			if match.Matcher == "" {
				match.Matcher = match.DSLMatched
			}
			if match.DSLMatched == "" {
				match.DSLMatched = match.Matcher
			}
		}
		atomic.AddInt64(&e.stats.MatchedRequests, 1)
		e.mu.Lock()
		e.stats.LastMatchTime = time.Now()
		e.matches = append(e.matches, matches...)
		e.mu.Unlock()

		// 输出逻辑
		if !silent && e.config.OutputFormatter != nil {
			e.config.OutputFormatter.FormatMatch(matches, response)
		} else {
			logger.Debugf("静默模式匹配完成，匹配数量: %d，跳过自动输出", len(matches))
		}
	} else {
		if !silent && emitNoMatch && e.config.OutputFormatter != nil {
			e.config.OutputFormatter.FormatNoMatch(response)
		}
	}

	// 客户端重定向处理
	if httpClient != nil {
		if fetcher, ok := httpClient.(redirect.HTTPFetcher); ok {
			if redirected, err := redirect.FollowClientRedirect(response, fetcher); err == nil && redirected != nil {
				rMatches := e.analyzeResponseInternal(redirected, httpClient, true, emitNoMatch)

				if len(rMatches) > 0 {
					if !silent && e.config.OutputFormatter != nil {
						e.config.OutputFormatter.FormatMatch(rMatches, redirected)
					}
					matches = append(matches, rMatches...)
				}
			} else if err != nil {
				logger.Debugf("客户端重定向抓取失败: %v", err)
			}
		}
	}

	return matches
}

// createDSLContext 创建DSL解析上下文（基础版本，用于被动识别）
func (e *Engine) createDSLContext(response *HTTPResponse) *DSLContext {
	return e.createDSLContextWithClient(response, nil, "")
}

// createDSLContextWithClient 创建DSL解析上下文（增强版，支持主动探测）
func (e *Engine) createDSLContextWithClient(response *HTTPResponse, httpClient httpclient.HTTPClientInterface, baseURL string) *DSLContext {
	headers := make(map[string][]string)
	if response != nil && len(response.ResponseHeaders) > 0 {
		headers = make(map[string][]string, len(response.ResponseHeaders))
		for name, values := range response.ResponseHeaders {
			if len(values) == 0 {
				continue
			}
			dup := make([]string, len(values))
			copy(dup, values)
			headers[name] = dup
		}
	}

	if baseURL == "" && response != nil && response.URL != "" {
		if parsedURL, err := url.Parse(response.URL); err == nil {
			baseURL = fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
		}
	}

	var body, urlStr, method string
	if response != nil {
		body = response.Body
		urlStr = response.URL
		method = response.Method
	}

	return &DSLContext{
		Response:   response,
		Headers:    headers,
		Body:       body,
		URL:        urlStr,
		Method:     method,
		HTTPClient: httpClient,
		BaseURL:    baseURL,
		Engine:     e,
	}
}

// shouldFilterResponse 检查是否应该过滤响应
func (e *Engine) shouldFilterResponse(response *HTTPResponse) bool {
	if e.config.MaxBodySize > 0 && len(response.Body) > e.config.MaxBodySize {
		logger.Debugf("过滤大响应体: %s (大小: %d bytes, 限制: %d bytes)",
			response.URL, len(response.Body), e.config.MaxBodySize)
		return true
	}

	if e.isStaticFile(response.URL) {
		logger.Debugf("过滤静态文件: %s", response.URL)
		return true
	}

	if e.isStaticContentType(response.ContentType) {
		logger.Debugf("过滤静态内容类型: %s (Content-Type: %s)",
			response.URL, response.ContentType)
		return true
	}

	return false
}

func (e *Engine) isStaticFile(rawURL string) bool {
	if !e.config.StaticFileFilterEnabled || len(e.config.StaticExtensions) == 0 {
		return false
	}

	lowerURL := strings.ToLower(rawURL)
	for _, ext := range e.config.StaticExtensions {
		if ext == "" {
			continue
		}
		if strings.HasSuffix(lowerURL, strings.ToLower(ext)) {
			return true
		}
	}

	return false
}

func (e *Engine) isStaticContentType(contentType string) bool {
	if !e.config.ContentTypeFilterEnabled || len(e.config.StaticContentTypes) == 0 {
		return false
	}

	contentType = strings.ToLower(contentType)
	for _, staticType := range e.config.StaticContentTypes {
		if staticType == "" {
			continue
		}
		if strings.HasPrefix(contentType, strings.ToLower(staticType)) {
			return true
		}
	}

	return false
}

// matchRule 匹配单个规则
func (e *Engine) matchRule(rule *FingerprintRule, ctx *DSLContext) *FingerprintMatch {
	if len(rule.DSL) == 0 {
		return nil
	}

	condition := strings.ToLower(strings.TrimSpace(rule.Condition))
	if condition == "" {
		condition = "or"
	}

	matchedDSLs := make([]string, 0)

	switch condition {
	case "and":
		for _, dsl := range rule.DSL {
			if e.dslParser.EvaluateDSL(dsl, ctx) {
				matchedDSLs = append(matchedDSLs, dsl)
				continue
			}
			return nil
		}
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
			matchedExpr := fmt.Sprintf("AND(%s)", strings.Join(matchedDSLs, " && "))
			return &FingerprintMatch{
				URL:        ctx.URL,
				RuleName:   rule.Name,
				Technology: rule.Name,
				Matcher:    matchedExpr,
				DSLMatched: matchedExpr,
				Timestamp:  time.Now(),
				Snippet:    snippet,
			}
		}
	case "or":
	default:
		if condition != "or" {
			logger.Warnf("Unsupported condition type: %s, using default OR condition", condition)
		}
	}

	for _, dsl := range rule.DSL {
		if !e.dslParser.EvaluateDSL(dsl, ctx) {
			continue
		}
		snippet := ""
		if e.shouldCaptureSnippet(rule) {
			snippet = e.extractSnippetForDSL(dsl, ctx)
		}
		return &FingerprintMatch{
			URL:        ctx.URL,
			RuleName:   rule.Name,
			Technology: rule.Name,
			Matcher:    dsl,
			DSLMatched: dsl,
			Timestamp:  time.Now(),
			Snippet:    snippet,
		}
	}

	return nil
}

func (e *Engine) shouldCaptureSnippet(rule *FingerprintRule) bool {
	if rule == nil {
		return false
	}
	return e.config.ShowSnippet
}

func (e *Engine) extractSnippetForDSL(dsl string, ctx *DSLContext) string {
	if ctx == nil || strings.TrimSpace(dsl) == "" {
		return ""
	}
	return e.dslParser.ExtractSnippet(dsl, ctx)
}

// GetConfig 获取引擎配置
func (e *Engine) GetConfig() *EngineConfig {
	return e.config
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
	return e.ruleManager.GetRulesCount()
}

// getDefaultConfig 获取默认配置
func getDefaultConfig() *EngineConfig {
	maxConcurrency := 20

	return &EngineConfig{
		RulesPath:       "config/fingerprint/",
		MaxConcurrency:  maxConcurrency,
		EnableFiltering: true,
		MaxBodySize:     1024 * 1024, // 1MB
		LogMatches:      true,
	}
}

// CheckIconMatch 检查图标哈希是否匹配（委托给IconCache组件）
func (e *Engine) CheckIconMatch(iconURL string, expectedHash string, httpClient httpclient.HTTPClientInterface) (bool, bool) {
	return e.iconCache.CheckMatch(iconURL, expectedHash, httpClient)
}

// HasPathRules 检查是否有包含path字段的规则
func (e *Engine) HasPathRules() bool {
	return e.ruleManager.HasPathRules()
}

// GetPathRulesCount 获取包含path字段的规则数量
func (e *Engine) GetPathRulesCount() int {
	return e.ruleManager.GetPathRulesCount()
}

// GetHeaderRulesCount 获取包含header字段的规则数量
func (e *Engine) GetHeaderRulesCount() int {
	return e.ruleManager.GetHeaderRulesCount()
}

// GetIconRules 获取所有包含icon()函数的规则
func (e *Engine) GetIconRules() []*FingerprintRule {
	return e.ruleManager.GetIconRules()
}

// TriggerActiveProbing 触发主动探测（异步，用于被动模式）
func (e *Engine) TriggerActiveProbing(baseURL string, httpClient httpclient.HTTPClientInterface, timeout time.Duration) {
	if httpClient == nil {
		return
	}
	go func() {
		if timeout <= 0 {
			timeout = 5 * time.Minute
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		_, _ = e.ExecuteActiveProbing(ctx, baseURL, httpClient)
		_, _ = e.Execute404Probing(ctx, baseURL, httpClient)
	}()
}

// ExecuteActiveProbing 执行主动指纹探测（同步返回结果）
func (e *Engine) ExecuteActiveProbing(ctx context.Context, baseURL string, httpClient httpclient.HTTPClientInterface) ([]*ProbeResult, error) {
	logger.Debugf("开始主动探测: %s", baseURL)

	pathRules := e.ruleManager.GetPathRules()
	headerOnlyRules := e.ruleManager.GetHeaderRules()
	if len(pathRules) == 0 && len(headerOnlyRules) == 0 {
		logger.Debug("没有需要主动探测的规则，跳过主动探测")
		return nil, nil
	}

	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}

	var (
		results   []*ProbeResult
		resultsMu sync.Mutex
	)

	type probeTask struct {
		url     string
		headers map[string]string
		rules   []*FingerprintRule
	}
	taskMap := make(map[string]*probeTask)

	addTask := func(probeURL string, headers map[string]string, rule *FingerprintRule) {
		key := buildProbeTaskKey(probeURL, headers)
		task := taskMap[key]
		if task == nil {
			task = &probeTask{url: probeURL, headers: headers}
			taskMap[key] = task
		}
		task.rules = append(task.rules, rule)
	}

	for _, rule := range pathRules {
		seenPaths := make(map[string]struct{}, len(rule.Paths))
		headers := rule.GetHeaderMap()
		for _, p := range rule.Paths {
			path := strings.TrimSpace(p)
			if path == "" {
				continue
			}
			if _, ok := seenPaths[path]; ok {
				continue
			}
			seenPaths[path] = struct{}{}
			addTask(joinURLPath(baseURL, path), headers, rule)
		}
	}
	for _, rule := range headerOnlyRules {
		addTask(joinURLPath(baseURL, "/"), rule.GetHeaderMap(), rule)
	}

	concurrency := e.config.MaxConcurrency
	if concurrency <= 0 {
		concurrency = 20
	}

	tasks := make([]*probeTask, 0, len(taskMap))
	for _, task := range taskMap {
		tasks = append(tasks, task)
	}
	taskChan := make(chan *probeTask, len(tasks))
	for _, t := range tasks {
		taskChan <- t
	}
	close(taskChan)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case tk, ok := <-taskChan:
					if !ok {
						return
					}

					body, statusCode, err := makeRequestWithOptionalHeaders(httpClient, tk.url, tk.headers)
					if err != nil {
						continue
					}

					resp := &HTTPResponse{
						URL:             tk.url,
						Method:          "GET",
						StatusCode:      statusCode,
						ResponseHeaders: make(map[string][]string),
						Body:            body,
						ContentType:     "text/html",
						ContentLength:   int64(len(body)),
						Title:           shared.ExtractTitle(body),
						Timestamp:       time.Now(),
					}

					dslCtx := e.createDSLContextWithClient(resp, httpClient, baseURL)
					var matches []*FingerprintMatch
					for _, rule := range tk.rules {
						if match := e.matchRule(rule, dslCtx); match != nil {
							matches = append(matches, match)
						}
					}
					if len(matches) > 0 {
						resultsMu.Lock()
						results = append(results, &ProbeResult{
							Response: resp,
							Matches:  matches,
						})
						resultsMu.Unlock()
					}
				}
			}
		}()
	}

	wg.Wait()
	return results, nil
}

func buildProbeTaskKey(probeURL string, headers map[string]string) string {
	if len(headers) == 0 {
		return probeURL
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		return strings.ToLower(strings.TrimSpace(keys[i])) < strings.ToLower(strings.TrimSpace(keys[j]))
	})

	var builder strings.Builder
	builder.Grow(len(probeURL) + len(keys)*8)
	builder.WriteString(probeURL)
	for _, key := range keys {
		builder.WriteByte('|')
		builder.WriteString(strings.ToLower(strings.TrimSpace(key)))
		builder.WriteByte(':')
		builder.WriteString(strings.TrimSpace(headers[key]))
	}
	return builder.String()
}

// ExecuteIconProbing 执行Icon主动探测（同步返回结果）
func (e *Engine) ExecuteIconProbing(ctx context.Context, baseURL string, httpClient httpclient.HTTPClientInterface) (*ProbeResult, error) {
	logger.Debugf("开始Icon主动探测: %s", baseURL)

	iconRules := e.ruleManager.GetIconRules()
	if len(iconRules) == 0 {
		return nil, nil
	}

	if _, err := url.Parse(baseURL); err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}

	resp := &HTTPResponse{
		URL:             baseURL,
		Method:          "GET",
		StatusCode:      200,
		ResponseHeaders: make(map[string][]string),
		Body:            "",
		Title:           "",
		Timestamp:       time.Now(),
	}

	dslCtx := e.createDSLContextWithClient(resp, httpClient, baseURL)
	var matches []*FingerprintMatch
	for _, rule := range iconRules {
		if match := e.matchRule(rule, dslCtx); match != nil {
			matches = append(matches, match)
		}
	}

	if len(matches) > 0 {
		return &ProbeResult{
			Response: resp,
			Matches:  matches,
		}, nil
	}
	return nil, nil
}

// Execute404Probing 执行404页面探测（同步返回结果）
func (e *Engine) Execute404Probing(ctx context.Context, baseURL string, httpClient httpclient.HTTPClientInterface) (*ProbeResult, error) {
	logger.Debugf("开始404页面指纹识别: %s", baseURL)

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}
	notFoundURL := fmt.Sprintf("%s://%s/404test", parsedURL.Scheme, parsedURL.Host)

	body, statusCode, err := makeRequestWithOptionalHeaders(httpClient, notFoundURL, nil)
	if err != nil {
		return nil, err
	}

	resp := &HTTPResponse{
		URL:             notFoundURL,
		Method:          "GET",
		StatusCode:      statusCode,
		ResponseHeaders: make(map[string][]string),
		Body:            body,
		ContentType:     "text/html",
		ContentLength:   int64(len(body)),
		Title:           shared.ExtractTitle(body),
		Timestamp:       time.Now(),
	}

	matches := e.match404PageFingerprints(resp, httpClient, baseURL)
	if len(matches) > 0 {
		return &ProbeResult{
			Response: resp,
			Matches:  matches,
		}, nil
	}
	return nil, nil
}

func (e *Engine) match404PageFingerprints(response *HTTPResponse, httpClient httpclient.HTTPClientInterface, baseURL string) []*FingerprintMatch {
	logger.Debugf("开始404页面全量指纹匹配")

	dslCtx := e.createDSLContextWithClient(response, httpClient, baseURL)
	var matches []*FingerprintMatch
	for _, rule := range e.ruleManager.GetRulesSnapshot() {
		if match := e.matchRule(rule, dslCtx); match != nil {
			matches = append(matches, match)
			logger.Debugf("404页面匹配到指纹: %s (规则: %s)", match.Technology, match.RuleName)
		}
	}

	logger.Debugf("404页面全量匹配完成，共匹配到 %d 个指纹", len(matches))
	return matches
}

func makeRequestWithOptionalHeaders(httpClient httpclient.HTTPClientInterface, targetURL string, headers map[string]string) (string, int, error) {
	if len(headers) > 0 {
		if headerClient, ok := httpClient.(httpclient.HeaderAwareClient); ok {
			return headerClient.MakeRequestWithHeaders(targetURL, headers)
		}
		logger.Debugf("HTTP客户端不支持自定义头部，使用默认请求: %s", targetURL)
	}
	return httpClient.MakeRequest(targetURL)
}

func joinURLPath(baseURL, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}

	base := strings.TrimRight(baseURL, "/")
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return base + "/"
	}
	if !strings.HasPrefix(cleanPath, "/") {
		cleanPath = "/" + cleanPath
	}
	return base + cleanPath
}

// IconCache 图标缓存管理组件
// 负责缓存图标哈希值和匹配结果，避免重复请求和计算
type IconCache struct {
	hashCache  map[string]string
	matchCache map[string]bool
	inflight   map[string]chan struct{}
	mu         sync.RWMutex
}

// NewIconCache 创建新的图标缓存实例
func NewIconCache() *IconCache {
	return &IconCache{
		hashCache:  make(map[string]string),
		matchCache: make(map[string]bool),
		inflight:   make(map[string]chan struct{}),
	}
}

// CheckMatch 检查图标哈希是否匹配（包含获取、计算、缓存全流程）
func (c *IconCache) CheckMatch(iconURL string, expectedHash string, client httpclient.HTTPClientInterface) (bool, bool) {
	matchKey := c.buildMatchCacheKey(iconURL, expectedHash)
	c.mu.RLock()
	if match, exists := c.matchCache[matchKey]; exists {
		c.mu.RUnlock()
		return match, true
	}
	c.mu.RUnlock()

	actualHash, err := c.GetHash(iconURL, client)
	if err != nil {
		return false, false
	}

	match := actualHash == expectedHash
	c.mu.Lock()
	c.matchCache[matchKey] = match
	c.mu.Unlock()
	return match, true
}

// GetHash 获取图标哈希值（带缓存和请求合并）
func (c *IconCache) GetHash(iconURL string, client httpclient.HTTPClientInterface) (string, error) {
	c.mu.RLock()
	val, ok := c.hashCache[iconURL]
	c.mu.RUnlock()
	if ok {
		return c.handleCachedHash(val)
	}

	c.mu.Lock()
	if val, ok := c.hashCache[iconURL]; ok {
		c.mu.Unlock()
		return c.handleCachedHash(val)
	}

	if ch, ok := c.inflight[iconURL]; ok {
		c.mu.Unlock()
		<-ch
		return c.GetHash(iconURL, client)
	}

	ch := make(chan struct{})
	c.inflight[iconURL] = ch
	c.mu.Unlock()

	hash, err := c.performRequest(iconURL, client)

	c.mu.Lock()
	if err != nil {
		c.hashCache[iconURL] = "FAILED"
	} else {
		c.hashCache[iconURL] = hash
	}
	delete(c.inflight, iconURL)
	close(ch)
	c.mu.Unlock()

	if err != nil {
		return "", err
	}
	return hash, nil
}

func (c *IconCache) handleCachedHash(val string) (string, error) {
	if val == "FAILED" {
		return "", fmt.Errorf("icon request failed (cached result)")
	}
	return val, nil
}

func (c *IconCache) performRequest(iconURL string, client httpclient.HTTPClientInterface) (string, error) {
	if client == nil {
		return "", fmt.Errorf("HTTP client is nil")
	}

	logger.Debugf("发起图标请求: %s", iconURL)
	body, statusCode, err := client.MakeRequest(iconURL)
	if err != nil {
		logger.Debugf("图标网络请求失败: %s, %v", iconURL, err)
		return "", err
	}
	if statusCode != 200 {
		logger.Debugf("图标请求非200状态: %s, code=%d", iconURL, statusCode)
		return "", fmt.Errorf("status code %d", statusCode)
	}

	hash := fmt.Sprintf("%x", md5.Sum([]byte(body)))
	logger.Debugf("图标哈希计算完成: %s -> %s", iconURL, hash)
	return hash, nil
}

// Clear 清空缓存
func (c *IconCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hashCache = make(map[string]string)
	c.matchCache = make(map[string]bool)
}

// GetMatchResult 获取匹配结果缓存
func (c *IconCache) GetMatchResult(iconURL, expectedHash string) (bool, bool) {
	key := c.buildMatchCacheKey(iconURL, expectedHash)
	c.mu.RLock()
	defer c.mu.RUnlock()
	result, exists := c.matchCache[key]
	return result, exists
}

// SetMatchResult 设置匹配结果缓存
func (c *IconCache) SetMatchResult(iconURL, expectedHash string, match bool) {
	key := c.buildMatchCacheKey(iconURL, expectedHash)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.matchCache[key] = match
}

func (c *IconCache) buildMatchCacheKey(iconURL, expectedHash string) string {
	return iconURL + "||" + expectedHash
}
