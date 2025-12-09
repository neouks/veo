package cli

import (
	"context"
	"fmt"
	"net/url"
	"sync"
	"time"

	"veo/pkg/fingerprint"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
)

// FingerprintProgressTracker 指纹识别进度跟踪器
type FingerprintProgressTracker struct {
	totalSteps  int    // 总步骤数（1个基础指纹匹配 + N个path探测）
	currentStep int    // 当前步骤
	baseURL     string // 基础URL
	mu          sync.Mutex
	enabled     bool
}

// NewFingerprintProgressTracker 创建指纹识别进度跟踪器
func NewFingerprintProgressTracker(baseURL string, pathRulesCount int, enabled bool) *FingerprintProgressTracker {
	return &FingerprintProgressTracker{
		totalSteps:  1 + pathRulesCount, // 1个基础指纹匹配 + N个path探测
		currentStep: 0,
		baseURL:     baseURL,
		enabled:     enabled,
	}
}

// UpdateProgress 更新进度并显示
func (fpt *FingerprintProgressTracker) UpdateProgress(stepName string) {
	if !fpt.enabled {
		return
	}
	fpt.mu.Lock()
	defer fpt.mu.Unlock()

	if fpt.currentStep >= fpt.totalSteps {
		return
	}

	fpt.currentStep++

	percentage := float64(fpt.currentStep) / float64(fpt.totalSteps) * 100
	if percentage > 100.0 {
		percentage = 100.0
	}

	fmt.Printf("\rFingerPrint Working %d/%d (%.1f%%)\r",
		fpt.currentStep, fpt.totalSteps, percentage)
}

func (sc *ScanController) runFingerprintModule(targets []string) ([]interfaces.HTTPResponse, error) {
	// 模块启动提示
	// 模块开始前空行，提升可读性
	fmt.Println()
	if sc.fingerprintEngine != nil {
		summary := sc.fingerprintEngine.GetLoadedSummaryString()
		if summary != "" {
			logger.Infof("Start FingerPrint, Loaded FingerPrint Rules: %s", summary)
		} else {
			logger.Infof("Start FingerPrint")
		}
	} else {
		logger.Infof("Start FingerPrint")
	}
	logger.Debugf("开始指纹识别，数量: %d", len(targets))

	// 指纹识别需要解析最终跳转结果，因此临时放宽同主机限制
	if sc.requestProcessor != nil {
		originalRedirectScope := sc.requestProcessor.IsRedirectSameHostOnly()
		sc.requestProcessor.SetRedirectSameHostOnly(false)
		defer sc.requestProcessor.SetRedirectSameHostOnly(originalRedirectScope)
	}

	// 多目标优化：判断是否使用并发扫描（重构：简化判断逻辑）
	if len(targets) > 1 {
		return sc.runConcurrentFingerprint(targets)
	}

	// 单目标或禁用并发时使用原有逻辑
	return sc.runSequentialFingerprint(targets)
}

func (sc *ScanController) runConcurrentFingerprint(targets []string) ([]interfaces.HTTPResponse, error) {
	logger.Debugf("并发指纹识别模式，数量: %d", len(targets))

	originalBatchMode := sc.requestProcessor.IsBatchMode()
	sc.requestProcessor.SetBatchMode(true)
	defer sc.requestProcessor.SetBatchMode(originalBatchMode)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var allResults []interfaces.HTTPResponse
	var resultsMu sync.Mutex
	var wg sync.WaitGroup

	maxTargetConcurrent := sc.requestProcessor.GetConfig().MaxConcurrent
	if maxTargetConcurrent <= 0 {
		maxTargetConcurrent = 20 // 备用默认值
	}
	logger.Debugf("指纹识别目标并发数设置为: %d", maxTargetConcurrent)
	targetSem := make(chan struct{}, maxTargetConcurrent)

	for _, target := range targets {
		wg.Add(1)
		go func(targetURL string) {
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("指纹识别panic恢复: %v, 目标: %s", r, targetURL)
				}
				wg.Done()
			}()

			// 阻塞等待信号量，除非整体上下文被取消
			select {
			case targetSem <- struct{}{}:
				defer func() {
					<-targetSem
				}()
			case <-ctx.Done():
				logger.Debugf("指纹识别取消: %s", targetURL)
				return
			}

			select {
			case <-ctx.Done():
				logger.Debugf("指纹识别处理被取消: %s", targetURL)
				return
			default:
			}

			results := sc.processSingleTargetFingerprintWithTimeout(ctx, targetURL)

			if sc.statsDisplay.IsEnabled() {
				sc.statsDisplay.IncrementCompletedHosts()
				logger.Debugf("指纹识别完成目标 %s，更新已完成主机数", targetURL)
			}

			resultsMu.Lock()
			allResults = append(allResults, results...)
			resultsMu.Unlock()

		}(target)
	}

	// 等待所有目标完成（修复：添加超时保护）
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Debugf("所有指纹识别任务完成")
	case <-ctx.Done():
		logger.Warnf("指纹识别超时或被取消")
		return allResults, ctx.Err()
	case <-time.After(12 * time.Minute):
		logger.Warnf("指纹识别总体超时")
		cancel() // 取消所有正在进行的任务
		return allResults, fmt.Errorf("指纹识别超时")
	}

	// 主动探测path字段指纹（复用被动模式逻辑）
	pathResults := sc.performPathProbing(targets)
	if len(pathResults) > 0 {
		allResults = append(allResults, pathResults...)
	}

	return allResults, nil
}

func (sc *ScanController) runSequentialFingerprint(targets []string) ([]interfaces.HTTPResponse, error) {
	originalContext := sc.requestProcessor.GetModuleContext()
	sc.requestProcessor.SetModuleContext("fingerprint")
	defer sc.requestProcessor.SetModuleContext(originalContext)

	if sc.fingerprintEngine == nil {
		return nil, fmt.Errorf("指纹识别引擎未初始化")
	}

	var allResults []interfaces.HTTPResponse

	pathRulesCount := 0
	if sc.fingerprintEngine.HasPathRules() {
		pathRulesCount = sc.fingerprintEngine.GetPathRulesCount()
	}

	for _, target := range targets {
		sc.progressTracker = NewFingerprintProgressTracker(target, pathRulesCount, !sc.args.JSONOutput)

		responses := sc.requestProcessor.ProcessURLs([]string{target})

		for _, resp := range responses {

			fpResponse := sc.convertToFingerprintResponse(resp)
			if fpResponse == nil {
				logger.Debugf("响应转换失败: %s", resp.URL)
				continue
			}

			matches := sc.fingerprintEngine.AnalyzeResponseWithClient(fpResponse, sc.httpClient)

			sc.progressTracker.UpdateProgress("指纹识别进行中")
			httpResp := interfaces.HTTPResponse{
				URL:             resp.URL,
				StatusCode:      resp.StatusCode,
				ContentLength:   resp.ContentLength,
				ContentType:     resp.ContentType,
				ResponseHeaders: resp.ResponseHeaders,
				RequestHeaders:  resp.RequestHeaders,
				ResponseBody:    resp.ResponseBody,
				Title:           resp.Title,
				Server:          resp.Server,
				Duration:        resp.Duration,
				IsDirectory:     false,
			}
			if converted := convertFingerprintMatches(matches, true); len(converted) > 0 {
				httpResp.Fingerprints = converted
			}
			allResults = append(allResults, httpResp)

			logger.Debugf("%s 指纹识别完成，匹配数量: %d", target, len(matches))
		}

		if sc.statsDisplay.IsEnabled() {
			sc.statsDisplay.IncrementCompletedHosts()
			logger.Debugf("单目标指纹识别完成目标 %s，更新已完成主机数", target)
		}
	}

	// 主动探测path字段指纹（复用被动模式逻辑）
	pathResults := sc.performPathProbing(targets)
	if len(pathResults) > 0 {
		allResults = append(allResults, pathResults...)
	}

	return allResults, nil
}

// processSingleTargetFingerprint 处理单个目标的指纹识别（多目标并发优化）
func (sc *ScanController) processSingleTargetFingerprint(target string) []interfaces.HTTPResponse {
	logger.Debugf("开始处理指纹识别: %s", target)

	// 为目标设置上下文
	targetDomain := extractDomainFromURL(target)
	originalContext := sc.requestProcessor.GetModuleContext()
	sc.requestProcessor.SetModuleContext(fmt.Sprintf("finger-%s", targetDomain))
	defer sc.requestProcessor.SetModuleContext(originalContext)

	var results []interfaces.HTTPResponse

	responses := sc.requestProcessor.ProcessURLs([]string{target})

	for _, resp := range responses {
		fpResponse := sc.convertToFingerprintResponse(resp)
		if fpResponse == nil {
			logger.Debugf("响应转换失败: %s", resp.URL)
			continue
		}

		matches := sc.fingerprintEngine.AnalyzeResponseWithClient(fpResponse, sc.httpClient)

		httpResp := interfaces.HTTPResponse{
			URL:             resp.URL,
			StatusCode:      resp.StatusCode,
			ContentLength:   resp.ContentLength,
			ContentType:     resp.ContentType,
			ResponseHeaders: resp.ResponseHeaders,
			RequestHeaders:  resp.RequestHeaders,
			ResponseBody:    resp.ResponseBody,
			Title:           resp.Title,
			Server:          resp.Server,
			Duration:        resp.Duration,
			IsDirectory:     false,
		}
		if converted := convertFingerprintMatches(matches, true); len(converted) > 0 {
			httpResp.Fingerprints = converted
		}
		results = append(results, httpResp)

		logger.Debugf("%s 识别完成: %d", target, len(matches))
	}

	return results
}

// processSingleTargetFingerprintWithTimeout 处理单个目标的指纹识别（新增：支持超时）
func (sc *ScanController) processSingleTargetFingerprintWithTimeout(ctx context.Context, target string) []interfaces.HTTPResponse {
	// 创建带超时的context
	targetCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	// 使用channel接收结果，支持超时
	resultChan := make(chan []interfaces.HTTPResponse, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Errorf("单目标指纹识别panic: %v, 目标: %s", r, target)
				resultChan <- []interfaces.HTTPResponse{}
			}
		}()

		results := sc.processSingleTargetFingerprint(target)
		resultChan <- results
	}()

	select {
	case results := <-resultChan:
		return results
	case <-targetCtx.Done():
		logger.Warnf("单目标指纹识别超时或被取消: %s", target)
		return []interfaces.HTTPResponse{}
	}
}

// performPathProbing 执行path字段主动探测（复用被动模式逻辑）
func (sc *ScanController) performPathProbing(targets []string) []interfaces.HTTPResponse {
	// 检查指纹引擎是否可用
	if sc.fingerprintEngine == nil {
		logger.Debug("指纹引擎未初始化，跳过path探测")
		return nil
	}

	// 检查是否有包含path字段的规则
	if !sc.fingerprintEngine.HasPathRules() {
		logger.Debug("没有包含path字段的规则，跳过path探测")
		return nil
	}

	var allResults []interfaces.HTTPResponse

	// 为每个目标执行path探测
	for _, target := range targets {
		baseURL := sc.extractBaseURL(target)
		hostKey := sc.extractHostKey(baseURL)

		// 检查是否已经探测过此主机（避免重复探测）
		if sc.shouldTriggerPathProbing(hostKey) {
			logger.Debugf("触发path字段主动探测: %s", hostKey)
			sc.markHostAsProbed(hostKey)

			// 使用Context控制超时
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			
			// 调用指纹引擎的主动探测方法
			results, err := sc.fingerprintEngine.ExecuteActiveProbing(ctx, baseURL, sc.httpClient)
			cancel()

			if err != nil {
				logger.Debugf("Active probing error: %v", err)
				continue
			}

			if len(results) > 0 {
				logger.Debugf("Active probing found %d results for %s", len(results), baseURL)
				for _, res := range results {
					httpResp := sc.convertProbeResult(res)
					allResults = append(allResults, httpResp)
				}
			}
			
			// [新增] 404页面指纹识别
			if res404 := sc.perform404PageProbing(baseURL); res404 != nil {
				allResults = append(allResults, *res404)
			}
		} else {
			logger.Debugf("主机已探测过，跳过path探测: %s", hostKey)
		}
	}
	return allResults
}

// perform404PageProbing 执行404页面指纹识别
func (sc *ScanController) perform404PageProbing(baseURL string) *interfaces.HTTPResponse {
	if sc.fingerprintEngine == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := sc.fingerprintEngine.Execute404Probing(ctx, baseURL, sc.httpClient)
	if err != nil {
		logger.Debugf("404 probing error: %v", err)
		return nil
	}
	
	if result != nil {
		httpResp := sc.convertProbeResult(result)
		return &httpResp
	}
	
	return nil
}

func (sc *ScanController) convertProbeResult(result *fingerprint.ProbeResult) interfaces.HTTPResponse {
	resp := result.Response
	httpResp := interfaces.HTTPResponse{
		URL:             resp.URL,
		StatusCode:      resp.StatusCode,
		ContentLength:   resp.ContentLength,
		ContentType:     resp.ContentType,
		ResponseBody:    resp.Body,
		Title:           resp.Title,
		IsDirectory:     false,
	}
	if len(result.Matches) > 0 {
		httpResp.Fingerprints = convertFingerprintMatches(result.Matches, true)
	}
	return httpResp
}

func extractDomainFromURL(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return u.Host
	}
	if len(rawURL) > 30 {
		return rawURL[:27] + "..."
	}
	return rawURL
}

// shouldTriggerPathProbing 检查是否应该触发path探测
func (sc *ScanController) shouldTriggerPathProbing(hostKey string) bool {
	sc.probedMutex.RLock()
	defer sc.probedMutex.RUnlock()

	// 检查是否已经探测过此主机
	return !sc.probedHosts[hostKey]
}

// markHostAsProbed 标记主机为已探测
func (sc *ScanController) markHostAsProbed(hostKey string) {
	sc.probedMutex.Lock()
	defer sc.probedMutex.Unlock()
	sc.probedHosts[hostKey] = true
}
