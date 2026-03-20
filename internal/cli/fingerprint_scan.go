package cli

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"veo/pkg/fingerprint"
	"veo/pkg/httpclient"
	"veo/pkg/logger"
	requests "veo/pkg/processor"
	"veo/pkg/stats"
	interfaces "veo/pkg/types"
)

func (sc *ScanController) extractBaseURL(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err == nil && parsedURL != nil {
		return fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	}
	return rawURL
}

func (sc *ScanController) extractBaseURLWithPath(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err == nil && parsedURL != nil {
		path := strings.TrimRight(parsedURL.Path, "/")
		if path == "" {
			path = "/"
		}
		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, path)
	}
	return rawURL
}

func (sc *ScanController) runFingerprintModuleWithContext(ctx context.Context, targets []string) ([]interfaces.HTTPResponse, error) {
	originalDecompress := true
	originalFollowRedirect := false
	originalMaxRedirects := 0
	if cfg := sc.requestProcessor.GetConfig(); cfg != nil {
		originalDecompress = cfg.DecompressResponse
		originalFollowRedirect = cfg.FollowRedirect
		originalMaxRedirects = cfg.MaxRedirects

		needsUpdate := !cfg.DecompressResponse || !cfg.FollowRedirect || cfg.MaxRedirects != requests.DefaultMaxRedirects
		if needsUpdate {
			updated := *cfg
			updated.DecompressResponse = true
			requests.ApplyRedirectPolicy(&updated)
			sc.requestProcessor.UpdateConfig(&updated)
		}
	}

	defer func() {
		if cfg := sc.requestProcessor.GetConfig(); cfg != nil {
			if cfg.DecompressResponse != originalDecompress || cfg.FollowRedirect != originalFollowRedirect || cfg.MaxRedirects != originalMaxRedirects {
				updated := *cfg
				updated.DecompressResponse = originalDecompress
				updated.FollowRedirect = originalFollowRedirect
				updated.MaxRedirects = originalMaxRedirects
				sc.requestProcessor.UpdateConfig(&updated)
			}
		}
	}()

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

	maxConcurrent := sc.requestProcessor.GetConfig().MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 20
	}
	logger.Debugf("指纹识别目标并发数设置为: %d", maxConcurrent)

	var progressTracker *stats.RequestProgress
	totalRequests := int64(len(targets))
	if sc.fingerprintEngine != nil && sc.args != nil && !sc.args.NoProbe {
		activeTargets := len(sc.getUniqueProbeTargets(targets))
		if activeTargets > 0 {
			activeRequests := activeTargets
			if sc.fingerprintEngine.HasPathRules() {
				pathCount := sc.fingerprintEngine.GetPathRulesCount()
				headerCount := sc.fingerprintEngine.GetHeaderRulesCount()
				activeRequests = activeTargets * (pathCount + headerCount + 1)
			}
			if len(sc.fingerprintEngine.GetIconRules()) > 0 {
				activeRequests += activeTargets
			}
			totalRequests += int64(activeRequests)
		}
	}
	if totalRequests > 0 {
		showProgress := true
		if sc.args != nil && sc.args.JSONOutput {
			showProgress = false
		}
		if updater := sc.requestProcessor.GetStatsUpdater(); updater != nil {
			if enabled, ok := updater.(interface{ IsEnabled() bool }); ok && enabled.IsEnabled() {
				showProgress = false
			}
		}
		if showProgress {
			label := sc.buildFingerprintProgressLabel(targets)
			if label != "" {
				progressTracker = stats.NewRequestProgress(label, totalRequests, true)
			}
		}
	}

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
				results := sc.processSingleTargetFingerprintWithContext(targetCtx, targetURL, progressTracker)
				targetCancel()

				resultsChan <- results

				if sc.statsDisplay.IsEnabled() {
					sc.statsDisplay.IncrementCompletedHosts()
				}
			}
		}()
	}

	for _, target := range targets {
		jobs <- target
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for resList := range resultsChan {
		if len(resList) > 0 {
			allResults = append(allResults, resList...)
		}
	}

	activeResults := sc.performActiveProbing(ctx, targets, progressTracker)
	if len(activeResults) > 0 {
		allResults = append(allResults, activeResults...)
	}

	if progressTracker != nil {
		progressTracker.Stop()
	}

	return allResults, nil
}

func (sc *ScanController) processSingleTargetFingerprintWithContext(ctx context.Context, target string, progressTracker *stats.RequestProgress) []interfaces.HTTPResponse {
	resultChan := make(chan []interfaces.HTTPResponse, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Errorf("Fingerprint panic: %v, target: %s", r, target)
				resultChan <- nil
			}
		}()

		resultChan <- sc.processSingleTargetFingerprint(ctx, target, progressTracker)
	}()

	select {
	case res := <-resultChan:
		return res
	case <-ctx.Done():
		logger.Debugf("目标处理超时: %s", target)
		return nil
	}
}

func (sc *ScanController) processSingleTargetFingerprint(ctx context.Context, target string, progressTracker *stats.RequestProgress) []interfaces.HTTPResponse {
	if ctx == nil {
		ctx = context.Background()
	}
	logger.Debugf("开始处理指纹识别: %s", target)

	var results []interfaces.HTTPResponse
	if sc.requestProcessor == nil || sc.fingerprintEngine == nil {
		return results
	}

	targetDomain := extractDomainFromURL(target)
	originalContext := sc.requestProcessor.GetModuleContext()
	sc.requestProcessor.SetModuleContext(fmt.Sprintf("finger-%s", targetDomain))
	defer sc.requestProcessor.SetModuleContext(originalContext)

	resp, err := sc.requestProcessor.RequestOnceWithHeaders(ctx, target, nil)
	if progressTracker != nil {
		progressTracker.Increment()
	}
	if err != nil || resp == nil {
		return results
	}

	fpResponse := sc.convertToFingerprintResponse(resp)
	if fpResponse == nil {
		logger.Debugf("响应转换失败: %s", resp.URL)
		return results
	}

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
		Timestamp:       responseTimestamp(resp.Timestamp),
	}
	if len(matches) > 0 {
		httpResp.Fingerprints = convertFingerprintMatches(matches, true)
	}
	results = append(results, httpResp)
	logger.Debugf("%s 识别完成: %d", target, len(matches))

	return results
}

func (sc *ScanController) buildFingerprintProgressLabel(targets []string) string {
	if len(targets) == 1 {
		return sc.extractBaseURL(targets[0])
	}
	return "Fingerprint"
}

type progressHTTPClient struct {
	base      httpclient.HTTPClientInterface
	header    httpclient.HeaderAwareClient
	onRequest func()
}

func (c *progressHTTPClient) MakeRequest(rawURL string) (string, int, error) {
	body, statusCode, err := c.base.MakeRequest(rawURL)
	if c.onRequest != nil {
		c.onRequest()
	}
	return body, statusCode, err
}

func (c *progressHTTPClient) MakeRequestWithHeaders(rawURL string, headers map[string]string) (string, int, error) {
	if c.header != nil {
		body, statusCode, err := c.header.MakeRequestWithHeaders(rawURL, headers)
		if c.onRequest != nil {
			c.onRequest()
		}
		return body, statusCode, err
	}

	body, statusCode, err := c.base.MakeRequest(rawURL)
	if c.onRequest != nil {
		c.onRequest()
	}
	return body, statusCode, err
}

func (sc *ScanController) wrapProgressHTTPClient(base httpclient.HTTPClientInterface, progressTracker *stats.RequestProgress) httpclient.HTTPClientInterface {
	if base == nil || progressTracker == nil {
		return base
	}

	client := &progressHTTPClient{
		base:      base,
		onRequest: progressTracker.Increment,
	}
	if header, ok := base.(httpclient.HeaderAwareClient); ok {
		client.header = header
	}
	return client
}

func (sc *ScanController) printFingerprintResultWithProgressClear(matches []*fingerprint.FingerprintMatch, response *fingerprint.HTTPResponse, formatter fingerprint.OutputFormatter, tag string) {
	if formatter != nil && len(matches) > 0 {
		if !sc.args.JSONOutput && sc.args.Stats {
			fmt.Printf("\r\033[K")
		}
		formatter.FormatMatch(matches, response, tag)
	}
}

func (sc *ScanController) appendProbeResult(localResults []interfaces.HTTPResponse, result *fingerprint.ProbeResult, formatter fingerprint.OutputFormatter, tag string) []interfaces.HTTPResponse {
	if result == nil {
		return localResults
	}

	sc.printFingerprintResultWithProgressClear(result.Matches, result.Response, formatter, tag)
	return append(localResults, sc.convertProbeResult(result))
}

func (sc *ScanController) appendProbeResults(localResults []interfaces.HTTPResponse, results []*fingerprint.ProbeResult, formatter fingerprint.OutputFormatter, tag string) []interfaces.HTTPResponse {
	for _, result := range results {
		localResults = sc.appendProbeResult(localResults, result, formatter, tag)
	}
	return localResults
}

func (sc *ScanController) probeTargetActiveFingerprint(ctx context.Context, baseURL string, hasPathRules bool, hasIconRules bool, formatter fingerprint.OutputFormatter, probeClient httpclient.HTTPClientInterface) []interfaces.HTTPResponse {
	if !sc.shouldTriggerPathProbing(baseURL) {
		logger.Debugf("目标已探测过，跳过主动探测: %s", baseURL)
		return nil
	}

	logger.Debugf("触发主动探测: %s", baseURL)
	sc.markHostAsProbed(baseURL)

	probeTimeout := sc.requestProcessor.GetConfig().Timeout
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	var localResults []interfaces.HTTPResponse

	if hasPathRules {
		results, err := sc.fingerprintEngine.ExecuteActiveProbing(probeCtx, baseURL, probeClient)
		if err != nil {
			logger.Debugf("Path probing error: %v", err)
		}
		localResults = sc.appendProbeResults(localResults, results, formatter, "Path探测")
	}

	if hasIconRules {
		iconBaseURL := sc.extractBaseURL(baseURL)
		if iconBaseURL == "" {
			iconBaseURL = baseURL
		}
		if resIcon, err := sc.fingerprintEngine.ExecuteIconProbing(probeCtx, iconBaseURL, probeClient); err != nil {
			logger.Debugf("Icon probing error: %v", err)
		} else if resIcon != nil {
			localResults = sc.appendProbeResult(localResults, resIcon, formatter, "icon探测")
		}
	}

	if res404 := sc.perform404PageProbing(probeCtx, baseURL, formatter, probeClient); res404 != nil {
		localResults = append(localResults, *res404)
	}

	return localResults
}

func (sc *ScanController) performActiveProbing(ctx context.Context, targets []string, progressTracker *stats.RequestProgress) []interfaces.HTTPResponse {
	if sc.fingerprintEngine == nil {
		logger.Debug("指纹引擎未初始化，跳过主动探测")
		return nil
	}

	if sc.args != nil && sc.args.NoProbe {
		logger.Debug("已禁用主动探测 (--no-probe)")
		return nil
	}

	select {
	case <-ctx.Done():
		return nil
	default:
	}

	hasPathRules := sc.fingerprintEngine.HasPathRules()
	hasIconRules := len(sc.fingerprintEngine.GetIconRules()) > 0

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

	formatter := sc.fingerprintEngine.GetOutputFormatter()
	probeClient := sc.wrapProgressHTTPClient(sc.requestProcessor, progressTracker)

	jobs := make(chan string, len(uniqueTargets))
	resultsChan := make(chan []interfaces.HTTPResponse, len(uniqueTargets))

	var wg sync.WaitGroup

	for i := 0; i < maxConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for baseURL := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				localResults := sc.probeTargetActiveFingerprint(ctx, baseURL, hasPathRules, hasIconRules, formatter, probeClient)
				resultsChan <- localResults
			}
		}()
	}

	for _, baseURL := range uniqueTargets {
		jobs <- baseURL
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for res := range resultsChan {
		if len(res) > 0 {
			allResults = append(allResults, res...)
		}
	}

	return allResults
}

func (sc *ScanController) perform404PageProbing(ctx context.Context, baseURL string, formatter fingerprint.OutputFormatter, client httpclient.HTTPClientInterface) *interfaces.HTTPResponse {
	if sc.fingerprintEngine == nil {
		return nil
	}

	probeTimeout := sc.requestProcessor.GetConfig().Timeout
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	if client == nil {
		client = sc.requestProcessor
	}
	result, err := sc.fingerprintEngine.Execute404Probing(probeCtx, baseURL, client)
	if err != nil {
		logger.Debugf("404 probing error: %v", err)
		return nil
	}

	if result != nil {
		sc.printFingerprintResultWithProgressClear(result.Matches, result.Response, formatter, "404探测")

		httpResp := sc.convertProbeResult(result)
		return &httpResp
	}

	return nil
}

func (sc *ScanController) convertProbeResult(result *fingerprint.ProbeResult) interfaces.HTTPResponse {
	resp := result.Response
	ts := resp.Timestamp
	if ts.IsZero() && len(result.Matches) > 0 {
		ts = result.Matches[0].Timestamp
	}
	httpResp := interfaces.HTTPResponse{
		URL:           resp.URL,
		StatusCode:    resp.StatusCode,
		ContentLength: resp.ContentLength,
		ContentType:   resp.ContentType,
		ResponseBody:  resp.Body,
		Title:         resp.Title,
		IsDirectory:   false,
		Timestamp:     responseTimestamp(ts),
	}
	if len(result.Matches) > 0 {
		httpResp.Fingerprints = convertFingerprintMatches(result.Matches, true)
	}
	return httpResp
}

func responseTimestamp(ts time.Time) time.Time {
	if ts.IsZero() {
		return time.Now()
	}
	return ts
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

func (sc *ScanController) shouldTriggerPathProbing(hostKey string) bool {
	sc.probedMutex.RLock()
	defer sc.probedMutex.RUnlock()
	return !sc.probedHosts[hostKey]
}

func (sc *ScanController) getUniqueProbeTargets(targets []string) map[string]string {
	uniqueTargets := make(map[string]string)
	for _, t := range targets {
		rootURL := sc.extractBaseURL(t)
		if sc.shouldTriggerPathProbing(rootURL) {
			uniqueTargets[rootURL] = rootURL
		}

		fullURL := sc.extractBaseURLWithPath(t)
		if strings.TrimRight(fullURL, "/") != strings.TrimRight(rootURL, "/") {
			if sc.shouldTriggerPathProbing(fullURL) {
				uniqueTargets[fullURL] = fullURL
			}
		}
	}
	return uniqueTargets
}

func (sc *ScanController) markHostAsProbed(hostKey string) {
	sc.probedMutex.Lock()
	defer sc.probedMutex.Unlock()
	sc.probedHosts[hostKey] = true
}
