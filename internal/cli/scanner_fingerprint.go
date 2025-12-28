package cli

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"veo/pkg/fingerprint"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
)

func (sc *ScanController) runFingerprintModuleWithContext(ctx context.Context, targets []string) ([]interfaces.HTTPResponse, error) {
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

	if sc.requestProcessor != nil {
		originalRedirectScope := sc.requestProcessor.IsRedirectSameHostOnly()
		sc.requestProcessor.SetRedirectSameHostOnly(false)
		defer sc.requestProcessor.SetRedirectSameHostOnly(originalRedirectScope)
	}

	return sc.runConcurrentFingerprintWithContext(ctx, targets)
}

func (sc *ScanController) runConcurrentFingerprintWithContext(parentCtx context.Context, targets []string) ([]interfaces.HTTPResponse, error) {
	logger.Debugf("并发指纹识别模式，数量: %d", len(targets))

	originalBatchMode := sc.requestProcessor.IsBatchMode()
	sc.requestProcessor.SetBatchMode(true)
	defer sc.requestProcessor.SetBatchMode(originalBatchMode)

	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	var allResults []interfaces.HTTPResponse
	var resultsMu sync.Mutex

	maxConcurrent := sc.requestProcessor.GetConfig().MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 20
	}
	logger.Debugf("指纹识别目标并发数设置为: %d", maxConcurrent)

	jobs := make(chan string, len(targets))
	resultsChan := make(chan []interfaces.HTTPResponse, len(targets))

	var wg sync.WaitGroup
	for i := 0; i < maxConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for targetURL := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				taskTimeout := sc.requestProcessor.GetConfig().Timeout
				targetCtx, targetCancel := context.WithTimeout(ctx, taskTimeout)
				results := sc.processSingleTargetFingerprintWithContext(targetCtx, targetURL)
				targetCancel()

				resultsChan <- results

				// 更新统计
				if sc.statsDisplay.IsEnabled() {
					sc.statsDisplay.IncrementCompletedHosts()
				}
			}
		}()
	}

	// 提交任务
	for _, target := range targets {
		jobs <- target
	}
	close(jobs)

	// 结果收集协程
	done := make(chan struct{})
	go func() {
		for resList := range resultsChan {
			if len(resList) > 0 {
				resultsMu.Lock()
				allResults = append(allResults, resList...)
				resultsMu.Unlock()
			}
		}
		close(done)
	}()

	// 等待所有 Worker 完成
	wg.Wait()
	close(resultsChan)

	// 等待结果收集完成
	<-done

	// 主动探测 (Path, Icon, 404)
	activeResults := sc.performActiveProbing(ctx, targets)
	if len(activeResults) > 0 {
		allResults = append(allResults, activeResults...)
	}

	return allResults, nil
}

// processSingleTargetFingerprintWithContext 处理单个目标，支持传入 Context
func (sc *ScanController) processSingleTargetFingerprintWithContext(ctx context.Context, target string) []interfaces.HTTPResponse {
	// 使用channel接收结果以支持select超时
	resultChan := make(chan []interfaces.HTTPResponse, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Errorf("指纹识别panic: %v, 目标: %s", r, target)
				resultChan <- nil
			}
		}()

		resultChan <- sc.processSingleTargetFingerprint(ctx, target)
	}()

	select {
	case res := <-resultChan:
		return res
	case <-ctx.Done():
		logger.Debugf("目标处理超时: %s", target)
		return nil
	}
}

// processSingleTargetFingerprint 处理单个目标的指纹识别（多目标并发优化）
func (sc *ScanController) processSingleTargetFingerprint(ctx context.Context, target string) []interfaces.HTTPResponse {
	if ctx == nil {
		ctx = context.Background()
	}
	logger.Debugf("开始处理指纹识别: %s", target)

	// 为目标设置上下文
	targetDomain := extractDomainFromURL(target)
	originalContext := sc.requestProcessor.GetModuleContext()
	sc.requestProcessor.SetModuleContext(fmt.Sprintf("finger-%s", targetDomain))
	defer sc.requestProcessor.SetModuleContext(originalContext)

	var results []interfaces.HTTPResponse

	responses := sc.requestProcessor.ProcessURLsWithContext(ctx, []string{target})

	for _, resp := range responses {
		fpResponse := sc.convertToFingerprintResponse(resp)
		if fpResponse == nil {
			logger.Debugf("响应转换失败: %s", resp.URL)
			continue
		}

		// Pass client to support icon() probing
		// Note: This does NOT trigger path enumeration, only DSL functions like icon()
		matches := sc.fingerprintEngine.AnalyzeResponseWithClient(fpResponse, sc.requestProcessor)

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

// printFingerprintResultWithProgressClear 输出指纹结果并清除进度条（Helper function for DRY）
func (sc *ScanController) printFingerprintResultWithProgressClear(matches []*fingerprint.FingerprintMatch, response *fingerprint.HTTPResponse, formatter fingerprint.OutputFormatter, tag string) {
	if formatter != nil && len(matches) > 0 {
		// Clear progress bar line if needed
		if !sc.args.JSONOutput && sc.args.Stats {
			fmt.Printf("\r\033[K")
		}
		// Use original formatter
		formatter.FormatMatch(matches, response, tag)
	}
}

// performActiveProbing 执行主动探测（Path, Icon, 404）
func (sc *ScanController) performActiveProbing(ctx context.Context, targets []string) []interfaces.HTTPResponse {
	// 检查指纹引擎是否可用
	if sc.fingerprintEngine == nil {
		logger.Debug("指纹引擎未初始化，跳过主动探测")
		return nil
	}

	// 检查Context是否取消
	select {
	case <-ctx.Done():
		logger.Warn("扫描已取消，跳过主动探测阶段")
		return nil
	default:
	}

	// 检查是否有任何需要主动探测的规则
	hasPathRules := sc.fingerprintEngine.HasPathRules()
	iconRules := sc.fingerprintEngine.GetIconRules() // 需要先在engine暴露，或者直接访问RuleManager
	// 注意：GetIconRules是在RuleManager中，Engine还未暴露。
	// 这里我们需要在Engine中增加GetIconRules或者简单判断。
	// 暂时假设我们总是有可能需要探测Icon（因为Icon规则很常见），或者我们修改Engine暴露此方法。
	// 但为了保持KISS，如果uniqueTargets为空，我们也不做任何事。

	if !hasPathRules && len(iconRules) == 0 {
		logger.Debug("没有Path规则且没有Icon规则，跳过主动探测")
		// 仍然可能需要404探测，但通常404探测是伴随的。
		// 如果完全没有主动规则，是否还要做404？
		// 404探测是全量匹配，理论上总是可以做。但为了性能，我们通常只在有指纹匹配需求时做。
		// 保持现状：如果完全没有任何规则（包括被动），我们根本不会进到这里。
		// 让我们继续，只是记录日志。
	}

	var allResults []interfaces.HTTPResponse

	maxConcurrent := sc.requestProcessor.GetConfig().MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 20
	}

	uniqueTargets := sc.getUniqueProbeTargets(targets)

	if len(uniqueTargets) == 0 {
		logger.Debug("所有目标主机均已探测过或无需探测，跳过主动探测阶段")
		return nil
	}

	outerConcurrent := maxConcurrent

	formatter := sc.fingerprintEngine.GetOutputFormatter()

	jobs := make(chan string, len(uniqueTargets))
	resultsChan := make(chan []interfaces.HTTPResponse, len(uniqueTargets))

	var wg sync.WaitGroup

	var processedCount int32
	totalCount := int32(len(uniqueTargets))

	for i := 0; i < outerConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for baseURL := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				var localResults []interfaces.HTTPResponse
				probeKey := baseURL

				if sc.shouldTriggerPathProbing(probeKey) {
					logger.Debugf("触发主动探测: %s", probeKey)
					sc.markHostAsProbed(probeKey)

					probeTimeout := sc.requestProcessor.GetConfig().Timeout
					probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)

					// 1. Path Probing
					if hasPathRules {
						results, err := sc.fingerprintEngine.ExecuteActiveProbing(probeCtx, baseURL, sc.requestProcessor)
						if err != nil {
							logger.Debugf("Path probing error: %v", err)
						}
						if len(results) > 0 {
							if formatter != nil {
								for _, res := range results {
									sc.printFingerprintResultWithProgressClear(res.Matches, res.Response, formatter, "Path探测")
								}
							}
							for _, res := range results {
								httpResp := sc.convertProbeResult(res)
								localResults = append(localResults, httpResp)
							}
						}
					}

					// 2. Icon Probing (New)
					// Icon指纹识别已经在 processSingleTargetFingerprint (Phase 1) 中通过 AnalyzeResponseWithClient 隐式完成了
					// AnalyzeResponseWithClient 会处理所有规则，包括 icon() 规则，并自动进行 HTTP 请求去重
					// 因此这里不需要再次调用 ExecuteIconProbing，否则会导致重复的指纹结果输出
					// 如果需要单独对非主目标进行 Icon 探测，可以使用 ExecuteIconProbing，但目前 uniqueTargets 主要是主目标
					// 所以这里留空或注释掉，以避免冗余。
					/*
						iconResults, err := sc.fingerprintEngine.ExecuteIconProbing(probeCtx, baseURL, sc.httpClient)
						if err != nil {
							logger.Debugf("Icon probing error: %v", err)
						}
						if iconResults != nil && len(iconResults.Matches) > 0 {
							if formatter != nil {
								sc.printFingerprintResultWithProgressClear(iconResults.Matches, iconResults.Response, formatter, "Icon探测")
							}
							httpResp := sc.convertProbeResult(iconResults)
							localResults = append(localResults, httpResp)
						}
					*/

					// 3. 404 Page Probing
					if res404 := sc.perform404PageProbing(probeCtx, baseURL, formatter); res404 != nil {
						localResults = append(localResults, *res404)
					}

					cancel()
				} else {
					logger.Debugf("目标已探测过，跳过主动探测: %s", probeKey)
				}
				resultsChan <- localResults

				// 更新进度
				curr := atomic.AddInt32(&processedCount, 1)
				if !sc.args.JSONOutput && sc.args.Stats && curr%2 == 0 {
					fmt.Printf("\rActive Probing: %d/%d (%.1f%%)", curr, totalCount, float64(curr)/float64(totalCount)*100)
				}
			}
		}()
	}

	// 提交任务
	for _, baseURL := range uniqueTargets {
		jobs <- baseURL
	}
	close(jobs)

	// 收集结果协程
	resDone := make(chan struct{})
	go func() {
		for res := range resultsChan {
			if len(res) > 0 {
				allResults = append(allResults, res...)
			}
		}
		close(resDone)
	}()

	wg.Wait()
	if !sc.args.JSONOutput && sc.args.Stats {
		fmt.Println() // Newline after progress
	}
	close(resultsChan)
	<-resDone

	return allResults
}

// perform404PageProbing 执行404页面指纹识别
func (sc *ScanController) perform404PageProbing(ctx context.Context, baseURL string, formatter fingerprint.OutputFormatter) *interfaces.HTTPResponse {
	if sc.fingerprintEngine == nil {
		return nil
	}

	// 策略：完全使用全局超时配置
	probeTimeout := sc.requestProcessor.GetConfig().Timeout
	// 使用传入的 ctx 作为父 Context
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	result, err := sc.fingerprintEngine.Execute404Probing(probeCtx, baseURL, sc.requestProcessor)
	if err != nil {
		logger.Debugf("404 probing error: %v", err)
		return nil
	}

	if result != nil {
		// 使用 Helper 输出结果
		sc.printFingerprintResultWithProgressClear(result.Matches, result.Response, formatter, "404探测")

		httpResp := sc.convertProbeResult(result)
		return &httpResp
	}

	return nil
}

func (sc *ScanController) convertProbeResult(result *fingerprint.ProbeResult) interfaces.HTTPResponse {
	resp := result.Response
	httpResp := interfaces.HTTPResponse{
		URL:           resp.URL,
		StatusCode:    resp.StatusCode,
		ContentLength: resp.ContentLength,
		ContentType:   resp.ContentType,
		ResponseBody:  resp.Body,
		Title:         resp.Title,
		IsDirectory:   false,
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

// getUniqueProbeTargets 提取唯一探测目标（Helper method）
func (sc *ScanController) getUniqueProbeTargets(targets []string) map[string]string {
	uniqueTargets := make(map[string]string)
	for _, t := range targets {
		// 策略：对于每个目标，我们总是尝试探测其根目录
		rootURL := sc.extractBaseURL(t)
		if sc.shouldTriggerPathProbing(rootURL) {
			uniqueTargets[rootURL] = rootURL
		}

		// 如果目标包含路径（且不等于根目录），我们也探测该路径
		fullURL := sc.extractBaseURLWithPath(t)
		// 简单比较：移除末尾斜杠后再比较，避免 http://x/ 和 http://x 视为不同
		if strings.TrimRight(fullURL, "/") != strings.TrimRight(rootURL, "/") {
			if sc.shouldTriggerPathProbing(fullURL) {
				uniqueTargets[fullURL] = fullURL
			}
		}
	}
	return uniqueTargets
}

// markHostAsProbed 标记主机为已探测
func (sc *ScanController) markHostAsProbed(hostKey string) {
	sc.probedMutex.Lock()
	defer sc.probedMutex.Unlock()
	sc.probedHosts[hostKey] = true
}
