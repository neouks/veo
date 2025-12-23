package fingerprint

import (
	"sync/atomic"
	"time"

	"veo/pkg/utils/httpclient"
	"veo/pkg/utils/logger"
	"veo/pkg/utils/redirect"
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

// AnalyzeResponse 分析响应包并进行指纹识别（基础版本）
func (e *Engine) AnalyzeResponse(response *HTTPResponse) []*FingerprintMatch {
	return e.AnalyzeResponseWithClient(response, nil)
}

// AnalyzeResponseWithClient 分析响应包并进行指纹识别（增强版，支持icon()函数主动探测）
func (e *Engine) AnalyzeResponseWithClient(response *HTTPResponse, httpClient httpclient.HTTPClientInterface) []*FingerprintMatch {
	return e.analyzeResponseInternal(response, httpClient, false)
}

// AnalyzeResponseWithClientSilent 分析响应包并进行指纹识别（静默版本，不自动输出结果）
func (e *Engine) AnalyzeResponseWithClientSilent(response *HTTPResponse, httpClient interface{}) []*FingerprintMatch {
	client, _ := httpClient.(httpclient.HTTPClientInterface)
	return e.analyzeResponseInternal(response, client, true)
}

// analyzeResponseInternal 内部核心分析逻辑
func (e *Engine) analyzeResponseInternal(response *HTTPResponse, httpClient httpclient.HTTPClientInterface, silent bool) []*FingerprintMatch {
	// 检查是否应该过滤此响应
	if e.config.EnableFiltering && e.shouldFilterResponse(response) {
		atomic.AddInt64(&e.stats.FilteredRequests, 1)
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
		if !silent && e.config.OutputFormatter != nil {
			e.config.OutputFormatter.FormatNoMatch(response)
		}
	}

	// 客户端重定向处理
	if httpClient != nil {
		if fetcher, ok := httpClient.(redirect.HTTPFetcher); ok {
			if redirected, err := redirect.FollowClientRedirect(response, fetcher); err == nil && redirected != nil {
				rMatches := e.analyzeResponseInternal(redirected, httpClient, true)
				
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

// GetIconRules 获取所有包含icon()函数的规则
func (e *Engine) GetIconRules() []*FingerprintRule {
	return e.ruleManager.GetIconRules()
}
