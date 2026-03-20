package cli

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"veo/internal/config"
	"veo/pkg/dirscan"
	"veo/pkg/fingerprint"
	"veo/pkg/formatter"
	"veo/pkg/httpclient"
	"veo/pkg/logger"
	requests "veo/pkg/processor"
	"veo/pkg/redirect"
	reporter "veo/pkg/reporter"
	sharedutils "veo/pkg/shared"
	"veo/pkg/stats"
	interfaces "veo/pkg/types"
)

func isJSONReportPath(path string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(path)), ".json")
}

// toValueSlice 将指针切片转换为值切片
func toValueSlice(pages []*interfaces.HTTPResponse) []interfaces.HTTPResponse {
	result := make([]interfaces.HTTPResponse, 0, len(pages))
	for _, p := range pages {
		if p != nil {
			result = append(result, *p)
		}
	}
	return result
}

// toPointerSlice 将值切片转换为指针切片
func toPointerSlice(pages []interfaces.HTTPResponse) []*interfaces.HTTPResponse {
	result := make([]*interfaces.HTTPResponse, len(pages))
	for i := range pages {
		result[i] = &pages[i]
	}
	return result
}

type fingerprintOutputHookSetter interface {
	SetOutputHook(func(response *fingerprint.HTTPResponse, matches []*fingerprint.FingerprintMatch, tags []string))
}

// ScanController 扫描控制器
type ScanController struct {
	args                   *CLIArgs
	config                 *config.Config
	requestProcessor       *requests.RequestProcessor
	fingerprintEngine      *fingerprint.Engine
	probedHosts            map[string]bool
	probedMutex            sync.RWMutex
	statsDisplay           *stats.StatsDisplay
	showFingerprintSnippet bool
	reportPath             string
	wordlistPath           string
	realtimeReporter       *reporter.RealtimeCSVReporter

	lastDirscanResults     []interfaces.HTTPResponse
	lastFingerprintResults []interfaces.HTTPResponse

	displayedURLs   map[string]bool
	displayedURLsMu sync.Mutex

	collectedPrimaryFiltered []interfaces.HTTPResponse
	collectedStatusFiltered  []interfaces.HTTPResponse
	collectedResultsMu       sync.Mutex
}

func prepareTargetParsingNetworkCheck(args *CLIArgs) func() {
	if args == nil {
		return func() {}
	}

	originalNetworkCheck := args.NetworkCheck
	if args.CheckSimilar && !args.CheckSimilarOnly {
		args.NetworkCheck = false
	}
	return func() {
		args.NetworkCheck = originalNetworkCheck
	}
}

func startSignalCancelWatcher(done <-chan struct{}, cancel context.CancelFunc) func() {
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		interruptCount := 0
		for {
			select {
			case <-sigChan:
				interruptCount++
				if interruptCount == 1 {
					cancel()
					go func() {
						select {
						case <-done:
							return
						case <-time.After(3 * time.Second):
							os.Exit(1)
						}
					}()
					continue
				}
				os.Exit(1)
			case <-done:
				return
			}
		}
	}()

	return func() {
		signal.Stop(sigChan)
	}
}

func runActiveScanMode(args *CLIArgs) error {
	if args == nil || !args.CheckSimilarOnly {
		logger.Debug("启动主动扫描模式")
	}
	cfg := config.GetConfig()
	scanner := NewScanController(args, cfg)
	return scanner.Run()
}

func runCheckSimilarOnlyMode(args *CLIArgs) error {
	if args == nil {
		return fmt.Errorf("arguments are nil")
	}

	cfg := config.GetConfig()
	controller := NewScanController(args, cfg)

	originalNetworkCheck := args.NetworkCheck
	args.NetworkCheck = true
	targets, err := controller.parseTargets(args.Targets)
	args.NetworkCheck = originalNetworkCheck
	if err != nil {
		return fmt.Errorf("Target Parse Error: %v", err)
	}

	targets, report := controller.checkSimilarTargetsWithReport(context.Background(), targets)
	fmt.Printf("原始目标：%d，相似度过滤：%d，超时：%d，最终：%d\n", report.Stats.Total, report.Stats.Deduped, report.Stats.Timeouts, report.Stats.Kept)
	fmt.Println("相似目标：")
	if len(report.SimilarPairs) > 0 {
		for _, pair := range report.SimilarPairs {
			fmt.Printf("%s => %s\n", pair.Target, pair.SimilarTo)
		}
	} else {
		fmt.Println("无")
	}

	fmt.Println("超时目标：")
	if len(report.TimeoutTargets) > 0 {
		for _, target := range report.TimeoutTargets {
			fmt.Println(target)
		}
	} else {
		fmt.Println("无")
	}

	fmt.Println("最终目标：")
	for _, target := range targets {
		fmt.Println(target)
	}

	return nil
}

func displayStartupInfo(args *CLIArgs) {
	fmt.Print(`
		veo@Evilc0de
`)

	if args != nil && args.CheckSimilarOnly {
		return
	}

	logger.Debug("模块状态:")
	logger.Debugf("指纹识别: %s", getModuleStatus(args.HasModule(moduleFinger)))
	logger.Debugf("目录扫描: %s", getModuleStatus(args.HasModule(moduleDirscan)))
}

func getModuleStatus(enabled bool) string {
	if enabled {
		return "[√]"
	}
	return "[X]"
}

func (sc *ScanController) parseTargets(targetStrs []string) ([]string, error) {
	logger.Debugf("开始解析目标")

	var allTargets []string

	if len(targetStrs) > 0 {
		logger.Debugf("处理命令行目标，数量: %d", len(targetStrs))
		for _, targetStr := range targetStrs {
			parts := strings.Split(targetStr, ",")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part != "" {
					allTargets = append(allTargets, part)
				}
			}
		}
	}

	if sc.args.TargetFile != "" {
		logger.Debugf("处理目标文件: %s", sc.args.TargetFile)
		parser := NewTargetParser()
		fileTargets, err := parser.ParseFile(sc.args.TargetFile)
		if err != nil {
			return nil, err
		}
		allTargets = append(allTargets, fileTargets...)
		logger.Debugf("从文件读取到 %d 个目标", len(fileTargets))
	}

	if len(allTargets) == 0 {
		return nil, fmt.Errorf("no valid targets")
	}

	deduplicator := NewDeduplicator()
	uniqueTargets, stats := deduplicator.DeduplicateWithStats(allTargets)

	if stats.DuplicateCount > 0 {
		logger.Debugf("去重完成: 原始 %d 个，去重后 %d 个，重复 %d 个 (%.1f%%)",
			stats.OriginalCount, stats.UniqueCount, stats.DuplicateCount, stats.DuplicateRate)
	}

	checker := NewConnectivityChecker(sc.config)
	var validTargets []string

	if sc.args.NetworkCheck {
		validTargets = checker.BatchCheck(uniqueTargets)
		if len(validTargets) == 0 {
			return nil, fmt.Errorf("no reachable targets")
		}
	} else {
		var err error
		validTargets, err = checker.ValidateAndNormalize(uniqueTargets)
		if err != nil {
			return nil, err
		}
	}

	logger.Debugf("目标解析完成: 最终有效目标 %d 个", len(validTargets))
	return validTargets, nil
}

type ConnectivityChecker struct {
	client *httpclient.Client
	config *config.Config
}

func NewConnectivityChecker(cfg *config.Config) *ConnectivityChecker {
	httpCfg := httpclient.DefaultConfig()
	if cfg != nil && cfg.Addon.Request.Timeout > 0 {
		httpCfg.Timeout = time.Duration(cfg.Addon.Request.Timeout) * time.Second
	} else {
		httpCfg.Timeout = 5 * time.Second
	}
	httpCfg.FollowRedirect = false
	httpCfg.SkipTLSVerify = true

	return &ConnectivityChecker{
		client: httpclient.New(httpCfg),
		config: cfg,
	}
}

func (cc *ConnectivityChecker) BatchCheck(targets []string) []string {
	if len(targets) == 0 {
		return nil
	}

	logger.Debugf("开始目标连通性检测，目标数量: %d", len(targets))
	parser := NewTargetParser()
	var candidates []string
	for _, t := range targets {
		candidates = append(candidates, parser.NormalizeURL(t)...)
	}

	var validTargets []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	concurrency := 20
	if cc.config != nil && cc.config.Module.Dirscan {
		concurrency = 50
	}
	sem := make(chan struct{}, concurrency)

	var processedCount int64
	total := len(candidates)

	logger.Info("Starting target reachability check...")
	for _, targetURL := range candidates {
		wg.Add(1)
		go func(urlStr string) {
			sem <- struct{}{}
			defer func() {
				<-sem
				wg.Done()
			}()

			if cc.isReachable(urlStr) {
				mu.Lock()
				validTargets = append(validTargets, urlStr)
				mu.Unlock()
			}

			current := atomic.AddInt64(&processedCount, 1)
			if total > 0 && (current%5 == 0 || current == int64(total)) {
				fmt.Printf("\r存活性检测: %d/%d (%.1f%%)", current, total, float64(current)/float64(total)*100)
			}
		}(targetURL)
	}

	wg.Wait()
	fmt.Println()

	logger.Debugf("有效目标: %d/%d", len(validTargets), len(candidates))
	if len(validTargets) > 0 {
		logger.Debug("存活目标列表:")
		for _, target := range validTargets {
			logger.Debugf("  %s", target)
		}
	}

	return validTargets
}

func (cc *ConnectivityChecker) isReachable(urlStr string) bool {
	_, statusCode, err := cc.client.MakeRequest(urlStr)
	if err != nil {
		logger.Debugf("目标不可连通: %s (%v)", urlStr, err)
		return false
	}
	logger.Debugf("目标可连通: %s [%d]", urlStr, statusCode)
	return true
}

func (cc *ConnectivityChecker) ValidateAndNormalize(targets []string) ([]string, error) {
	logger.Debugf("开始验证和标准化目标列表")

	parser := NewTargetParser()
	validTargets := make([]string, 0, len(targets))
	for _, target := range targets {
		if err := parser.ValidateURL(target); err != nil {
			logger.Warnf("Skipping invalid target %s: %v", target, err)
			continue
		}
		urls := parser.NormalizeURL(target)
		if len(urls) > 0 {
			validTargets = append(validTargets, urls[0])
		}
	}

	if len(validTargets) == 0 {
		return nil, fmt.Errorf("no valid targets")
	}
	return validTargets, nil
}

type Deduplicator struct {
	seen map[string]bool
}

func NewDeduplicator() *Deduplicator {
	return &Deduplicator{
		seen: make(map[string]bool),
	}
}

func (d *Deduplicator) Deduplicate(targets []string) []string {
	logger.Debugf("开始去重，原始目标数量: %d", len(targets))

	result := make([]string, 0, len(targets))
	for _, target := range targets {
		normalized := d.normalizeForDedup(target)
		if !d.seen[normalized] {
			d.seen[normalized] = true
			result = append(result, target)
			continue
		}
		logger.Debugf("发现重复目标: %s (标准化: %s)", target, normalized)
	}

	logger.Debugf("去重完成，去重后目标数量: %d", len(result))
	return result
}

func (d *Deduplicator) normalizeForDedup(target string) string {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	parsedURL, err := url.Parse(target)
	if err != nil {
		return strings.ToLower(target)
	}

	host := strings.ToLower(parsedURL.Host)
	path := parsedURL.Path
	if path != "/" && strings.HasSuffix(path, "/") {
		path = strings.TrimSuffix(path, "/")
	}
	if path == "" {
		path = "/"
	}

	normalized := parsedURL.Scheme + "://" + host + path
	if parsedURL.RawQuery != "" {
		normalized += "?" + parsedURL.RawQuery
	}
	return normalized
}

type DeduplicationStats struct {
	OriginalCount  int
	UniqueCount    int
	DuplicateCount int
	DuplicateRate  float64
}

func (d *Deduplicator) DeduplicateWithStats(targets []string) ([]string, *DeduplicationStats) {
	originalCount := len(targets)
	result := d.Deduplicate(targets)
	duplicateCount := originalCount - len(result)
	duplicateRate := 0.0
	if originalCount > 0 {
		duplicateRate = float64(duplicateCount) / float64(originalCount) * 100
	}

	return result, &DeduplicationStats{
		OriginalCount:  originalCount,
		UniqueCount:    len(result),
		DuplicateCount: duplicateCount,
		DuplicateRate:  duplicateRate,
	}
}

type TargetParser struct{}

func NewTargetParser() *TargetParser {
	return &TargetParser{}
}

func (tp *TargetParser) ParseFile(filePath string) ([]string, error) {
	logger.Debugf("开始解析目标文件: %s", filePath)

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open target file: %v", err)
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error while reading target file: %v", err)
	}

	logger.Debugf("从文件解析到 %d 个目标", len(targets))
	return targets, nil
}

func (tp *TargetParser) NormalizeURL(target string) []string {
	logger.Debugf("开始标准化目标: %s", target)

	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return []string{target}
	}

	host, port, err := tp.parseHostPort(target)
	if err != nil {
		logger.Debugf("解析主机端口失败: %v，同时尝试HTTP和HTTPS协议", err)
		return []string{"http://" + target, "https://" + target}
	}

	protocols := tp.determineProtocols(port)
	urls := make([]string, 0, len(protocols))
	for _, protocol := range protocols {
		urls = append(urls, formatHostURL(protocol, host, port))
	}

	logger.Debugf("目标 %s 标准化为: %v", target, urls)
	return urls
}

func (tp *TargetParser) parseHostPort(target string) (string, int, error) {
	if strings.Contains(target, ":") {
		host, portStr, err := net.SplitHostPort(target)
		if err != nil {
			return "", 0, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return "", 0, fmt.Errorf("invalid port number: %s", portStr)
		}
		return host, port, nil
	}
	return target, 0, nil
}

func (tp *TargetParser) determineProtocols(port int) []string {
	if port == 80 {
		return []string{"http"}
	}
	if port == 443 {
		return []string{"https"}
	}
	return []string{"http", "https"}
}

func formatHostURL(protocol, host string, port int) string {
	if port == 0 || (port == 80 && protocol == "http") || (port == 443 && protocol == "https") {
		return fmt.Sprintf("%s://%s", protocol, host)
	}
	return fmt.Sprintf("%s://%s:%d", protocol, host, port)
}

func (tp *TargetParser) ValidateURL(target string) error {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	parsedURL, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid URL format: %v", err)
	}
	if parsedURL.Host == "" {
		return fmt.Errorf("URL is missing a hostname")
	}
	return nil
}

func NewScanController(args *CLIArgs, cfg *config.Config) *ScanController {
	threads := args.Threads
	if threads <= 0 {
		threads = 100
	}
	retry := 1
	if args.RetrySet {
		retry = args.Retry
	}
	timeout := args.Timeout
	if timeout <= 0 {
		timeout = 3
	}
	requestConfig := &requests.RequestConfig{
		Timeout:            time.Duration(timeout) * time.Second,
		MaxRetries:         retry,
		MaxConcurrent:      threads,
		RandomUserAgent:    args.RandomUA,
		DecompressResponse: true,
	}
	requests.ApplyRedirectPolicy(requestConfig)

	proxyURL := strings.TrimSpace(args.Proxy)
	if proxyURL == "" {
		if proxyCfg := config.GetProxyConfig(); proxyCfg != nil {
			proxyURL = strings.TrimSpace(proxyCfg.UpstreamProxy)
		}
	}
	if proxyURL != "" {
		requestConfig.ProxyURL = proxyURL
		logger.Debugf("ActiveScan: 设置请求处理器代理: %s", requestConfig.ProxyURL)
	}

	if !args.CheckSimilarOnly {
		logger.Debugf("请求处理器并发数设置为: %d", requestConfig.MaxConcurrent)
		logger.Debugf("请求处理器重试次数设置为: %d", requestConfig.MaxRetries)
		logger.Debugf("请求处理器超时时间设置为: %v", requestConfig.Timeout)
	}

	var fpEngine *fingerprint.Engine
	if !args.CheckSimilarOnly && (args.HasModule(moduleFinger) || args.HasModule(moduleDirscan)) {
		fpEngine = fingerprint.NewEngine(nil)
		if fpEngine != nil {
			if err := fpEngine.LoadRules(fpEngine.GetConfig().RulesPath); err != nil {
				logger.Warnf("Failed to load fingerprint rules, fingerprint detection may return no results: %v", err)
			}
		}
	}

	requestProcessor := requests.NewRequestProcessor(requestConfig)

	if len(args.Modules) == 1 && args.Modules[0] == moduleFinger {
		requestProcessor.SetModuleContext("fingerprint")
	}
	customHeaders := config.GetCustomHeaders()
	if len(customHeaders) > 0 {
		requestProcessor.SetCustomHeaders(customHeaders)
	}
	if args.Shiro {
		requestProcessor.SetShiroCookieEnabled(true)
	}

	statsDisplay := stats.NewStatsDisplay()
	if args.Stats {
		statsDisplay.Enable()
		requestProcessor.SetStatsUpdater(statsDisplay)
	}

	snippetEnabled := args.VeryVerbose
	ruleEnabled := args.Verbose || args.VeryVerbose

	if fpEngine != nil {
		// 启用snippet捕获(用于报告)
		fpEngine.GetConfig().ShowSnippet = true

		// 创建OutputFormatter并注入到Engine
		var outputFormatter fingerprint.OutputFormatter
		if args.JSONOutput {
			jsonFormatter := fingerprint.NewJSONOutputFormatter()
			jsonFormatter.SetSuppressOutput(true)
			outputFormatter = jsonFormatter
		} else {
			consoleFormatter := fingerprint.NewConsoleOutputFormatter(
				true,           // logMatches
				true,           // showSnippet - 始终捕获
				ruleEnabled,    // showRules
				snippetEnabled, // consoleSnippetEnabled
			)
			outputFormatter = consoleFormatter
		}
		fpEngine.GetConfig().OutputFormatter = outputFormatter
		logger.Debugf("指纹引擎 OutputFormatter 已注入: %T", outputFormatter)
	}

	sc := &ScanController{
		args:                   args,
		config:                 cfg,
		requestProcessor:       requestProcessor,
		fingerprintEngine:      fpEngine,
		probedHosts:            make(map[string]bool),
		statsDisplay:           statsDisplay,
		showFingerprintSnippet: snippetEnabled,
		reportPath:             strings.TrimSpace(args.Output),
		wordlistPath:           strings.TrimSpace(args.Wordlist),
		displayedURLs:          make(map[string]bool),
	}

	return sc
}

func (sc *ScanController) Run() error {
	if strings.TrimSpace(sc.reportPath) != "" && !isJSONReportPath(sc.reportPath) {
		realtimeReporter, err := reporter.NewRealtimeCSVReporter(sc.reportPath)
		if err != nil {
			logger.Warnf("Failed to create realtime CSV report: %v", err)
		} else {
			sc.realtimeReporter = realtimeReporter
			sc.attachRealtimeReporter()
			logger.Infof("Realtime CSV Report: %s", realtimeReporter.Path())
			defer func() {
				if err := realtimeReporter.Close(); err != nil {
					logger.Warnf("Failed to close realtime CSV report: %v", err)
				}
			}()
		}
	}

	return sc.runActiveMode()
}

func (sc *ScanController) attachRealtimeReporter() {
	if sc.realtimeReporter == nil || sc.fingerprintEngine == nil {
		return
	}

	hook := func(resp *fingerprint.HTTPResponse, matches []*fingerprint.FingerprintMatch, tags []string) {
		if resp == nil {
			return
		}
		page := *resp
		if len(matches) > 0 {
			page.Fingerprints = convertFingerprintMatches(matches, false)
		} else {
			page.Fingerprints = nil
		}
		_ = sc.realtimeReporter.WriteResponse(&page)
	}

	formatter := sc.fingerprintEngine.GetConfig().OutputFormatter
	if outputHookSetter, ok := formatter.(fingerprintOutputHookSetter); ok {
		outputHookSetter.SetOutputHook(hook)
	}
}

func (sc *ScanController) runActiveMode() error {
	if sc.args == nil || !sc.args.CheckSimilarOnly {
		logger.Debug("启动主动扫描模式")
	}

	restoreNetworkCheck := prepareTargetParsingNetworkCheck(sc.args)
	targets, err := sc.parseTargets(sc.args.Targets)
	restoreNetworkCheck()
	if err != nil {
		return fmt.Errorf("Target Parse Error: %v", err)
	}

	logger.Debugf("解析到 %d 个目标", len(targets))

	orderedModules := sc.getOptimizedModuleOrder()

	// 信号处理：捕获 Ctrl+C / SIGTERM，通过 ctx 取消让各模块尽快收敛
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	defer close(done)

	stopSignalWatcher := startSignalCancelWatcher(done, cancel)
	defer stopSignalWatcher()

	if sc.args.CheckSimilarOnly {
		targets, _ = sc.checkSimilarTargetsWithReport(ctx, targets)
		for _, target := range targets {
			fmt.Println(target)
		}
		return nil
	}

	if sc.args.CheckSimilar {
		targets, _ = sc.checkSimilarTargetsWithReport(ctx, targets)
	}

	// 打印有效性筛选结果
	if !sc.args.JSONOutput {
		logger.Infof("Available Hosts: %d", len(targets))
	}

	if sc.statsDisplay.IsEnabled() {
		sc.statsDisplay.SetTotalHosts(int64(len(targets)))
		logger.Debugf("统计显示器：设置总主机数 = %d", len(targets))
	}

	// 同步执行：避免 goroutine 写结果、主流程读结果带来的数据竞争
	allResults, dirscanResults, fingerprintResults := sc.executeModulesSequenceWithContext(ctx, orderedModules, targets)

	return sc.finalizeScan(allResults, dirscanResults, fingerprintResults)
}

func (sc *ScanController) executeModulesSequenceWithContext(ctx context.Context, modules []string, targets []string) ([]interfaces.HTTPResponse, []interfaces.HTTPResponse, []interfaces.HTTPResponse) {
	var allResults []interfaces.HTTPResponse
	var dirResults []interfaces.HTTPResponse
	var fingerprintResults []interfaces.HTTPResponse

	if len(modules) == 0 || len(targets) == 0 {
		return allResults, dirResults, fingerprintResults
	}

	for i, moduleName := range modules {
		// 检查Context是否取消
		select {
		case <-ctx.Done():
			return allResults, dirResults, fingerprintResults
		default:
		}

		logger.Debugf("开始执行模块: %s (%d/%d)", moduleName, i+1, len(modules))

		moduleResults, err := sc.runModuleForTargetsWithContext(ctx, moduleName, targets)
		if err != nil {
			logger.Errorf("Module %s execution failed: %v", moduleName, err)
			continue
		}

		allResults = append(allResults, moduleResults...)
		switch moduleName {
		case moduleDirscan:
			dirResults = append(dirResults, moduleResults...)
		case moduleFinger:
			fingerprintResults = append(fingerprintResults, moduleResults...)
		}
		logger.Debugf("模块 %s 完成，获得 %d 个结果", moduleName, len(moduleResults))

		if len(modules) > 1 && i < len(modules)-1 && !sc.args.JSONOutput {
			fmt.Println()
		}
	}

	return allResults, dirResults, fingerprintResults
}

func (sc *ScanController) finalizeScan(allResults, dirResults, fingerprintResults []interfaces.HTTPResponse) error {
	logger.Debugf("所有模块执行完成，总结果数: %d", len(allResults))

	filterResult := sc.buildFilterResult(allResults, fingerprintResults)

	sc.lastDirscanResults = dirResults
	sc.lastFingerprintResults = fingerprintResults

	if sc.realtimeReporter != nil {
		logger.Infof("Report Output Success: %s", sc.realtimeReporter.Path())
	}

	if sc.statsDisplay.IsEnabled() {
		sc.statsDisplay.ShowFinalStats()
		sc.statsDisplay.Disable()
	}

	sc.outputConsoleJSON(dirResults, fingerprintResults, filterResult)
	sc.outputJSONReport(dirResults, fingerprintResults, filterResult)

	return nil
}

func (sc *ScanController) buildFilterResult(allResults, fingerprintResults []interfaces.HTTPResponse) *interfaces.FilterResult {
	onlyFingerprint := len(sc.args.Modules) == 1 && sc.args.Modules[0] == moduleFinger
	if onlyFingerprint {
		pages := fingerprintResults
		if len(pages) == 0 {
			pages = allResults
		}
		return &interfaces.FilterResult{
			ValidPages: toPointerSlice(pages),
		}
	}

	filterResult := &interfaces.FilterResult{
		ValidPages:           toPointerSlice(allResults),
		PrimaryFilteredPages: toPointerSlice(sc.collectedPrimaryFiltered),
		StatusFilteredPages:  toPointerSlice(sc.collectedStatusFiltered),
	}
	logger.Debugf("构造FilterResult - ValidPages: %d, PrimaryFiltered: %d, StatusFiltered: %d",
		len(allResults), len(sc.collectedPrimaryFiltered), len(sc.collectedStatusFiltered))
	if len(allResults) > 0 {
		logger.Debugf("所有目标过滤完成，最终有效结果: %d", len(allResults))
	}
	return filterResult
}

func (sc *ScanController) outputConsoleJSON(dirResults, fingerprintResults []interfaces.HTTPResponse, filterResult *interfaces.FilterResult) {
	if !sc.args.JSONOutput {
		return
	}

	jsonStr, err := sc.generateConsoleJSON(dirResults, fingerprintResults, filterResult)
	if err != nil {
		logger.Errorf("Failed to generate JSON output: %v", err)
		return
	}
	fmt.Println(jsonStr)
}

func (sc *ScanController) outputJSONReport(dirResults, fingerprintResults []interfaces.HTTPResponse, filterResult *interfaces.FilterResult) {
	if !isJSONReportPath(sc.reportPath) {
		return
	}

	jsonStr, err := sc.generateJSONReport(dirResults, fingerprintResults, filterResult)
	if err != nil {
		logger.Errorf("Failed to generate JSON report: %v", err)
		return
	}
	if writeErr := os.WriteFile(sc.reportPath, []byte(jsonStr), 0644); writeErr != nil {
		logger.Errorf("Failed to write JSON report: %v", writeErr)
		return
	}
	logger.Infof("Report Output Success: %s", sc.reportPath)
}

func (sc *ScanController) getOptimizedModuleOrder() []string {
	var orderedModules []string

	for _, module := range sc.args.Modules {
		if module == moduleFinger {
			orderedModules = append(orderedModules, module)
			break
		}
	}

	// 然后执行其他模块
	for _, module := range sc.args.Modules {
		if module != moduleFinger {
			orderedModules = append(orderedModules, module)
		}
	}

	return orderedModules
}

func (sc *ScanController) runModuleForTargetsWithContext(ctx context.Context, moduleName string, targets []string) ([]interfaces.HTTPResponse, error) {
	// 简单的包装，未来应该修改 runDirscanModule 和 runFingerprintModule 以接受 Context
	// 目前我们主要关注指纹识别模块的并发控制

	switch moduleName {
	case moduleDirscan:
		// 目录扫描集成 Context
		return sc.runDirscanModule(ctx, targets)
	case moduleFinger:
		return sc.runFingerprintModuleWithContext(ctx, targets)

	default:
		return nil, fmt.Errorf("unsupported module: %s", moduleName)
	}
}
func (sc *ScanController) generateJSONReport(dirPages, fingerprintPages []interfaces.HTTPResponse, filterResult *interfaces.FilterResult) (string, error) {
	return sc.generateJSON(dirPages, fingerprintPages, filterResult, true)
}

func (sc *ScanController) shouldIncludeConsoleSnippet() bool {
	return sc.showFingerprintSnippet || (sc.args != nil && sc.args.JSONOutput)
}

func (sc *ScanController) generateConsoleJSON(dirPages, fingerprintPages []interfaces.HTTPResponse, filterResult *interfaces.FilterResult) (string, error) {
	return sc.generateJSON(dirPages, fingerprintPages, filterResult, sc.shouldIncludeConsoleSnippet())
}

func (sc *ScanController) generateJSON(dirPages, fingerprintPages []interfaces.HTTPResponse, filterResult *interfaces.FilterResult, includeSnippet bool) (string, error) {
	var matches []interfaces.FingerprintMatch
	if sc.fingerprintEngine != nil {
		if raw := sc.fingerprintEngine.GetMatches(); len(raw) > 0 {
			matches = convertFingerprintMatches(raw, includeSnippet)
		}
	}

	if len(fingerprintPages) == 0 && sc.args.HasModule(moduleFinger) {
		fingerprintPages = toValueSlice(filterResult.ValidPages)
	}

	return reporter.GenerateCombinedJSON(dirPages, fingerprintPages, matches)
}

func convertFingerprintMatches(matches []*fingerprint.FingerprintMatch, includeSnippet bool) []interfaces.FingerprintMatch {
	if len(matches) == 0 {
		return nil
	}

	converted := make([]interfaces.FingerprintMatch, 0, len(matches))
	for _, match := range matches {
		if match == nil {
			continue
		}

		matcher := match.Matcher
		if matcher == "" {
			matcher = match.DSLMatched
		}
		dslMatched := match.DSLMatched
		if dslMatched == "" {
			dslMatched = matcher
		}
		convertedMatch := interfaces.FingerprintMatch{
			URL:        match.URL,
			RuleName:   match.RuleName,
			Matcher:    matcher,
			DSLMatched: dslMatched,
			Timestamp:  match.Timestamp,
		}
		if includeSnippet {
			convertedMatch.Snippet = match.Snippet
		}
		converted = append(converted, convertedMatch)
	}

	return converted
}

const urlDisplayLimit = 60

// printHTTPResponseResult 打印单个有效HTTP响应（主动+被动通用）
func printHTTPResponseResult(page *interfaces.HTTPResponse, showSnippet bool, showRule bool) {
	if page == nil {
		return
	}

	matches := page.Fingerprints
	var fingerprintUnion string
	if len(matches) > 0 {
		fingerprintUnion = formatFingerprintMatchesList(matches, showRule)
	}

	fingerprintParts := []string{}
	if strings.TrimSpace(fingerprintUnion) != "" {
		fingerprintParts = append(fingerprintParts, fingerprintUnion)
	}

	displayURL, detailURL := formatter.SplitURLForLog(page.URL, urlDisplayLimit)
	line := formatter.FormatLogLineWithURLSuffix(
		displayURL,
		detailURL,
		page.StatusCode,
		page.Title,
		page.ContentLength,
		page.ContentType,
		fingerprintParts,
		len(matches) > 0,
	)

	var messageBuilder strings.Builder
	messageBuilder.WriteString(line)

	if showSnippet && len(matches) > 0 {
		var snippetLines []string
		for _, m := range matches {
			snippet := strings.TrimSpace(m.Snippet)
			if snippet == "" {
				continue
			}
			highlighted := formatter.HighlightSnippet(snippet, m.Matcher)
			if highlighted == "" {
				continue
			}
			snippetLines = append(snippetLines, highlighted)
		}
		if len(snippetLines) > 0 {
			messageBuilder.WriteString("\n")
			for idx, snippetLine := range snippetLines {
				if idx > 0 {
					messageBuilder.WriteString("\n")
				}
				messageBuilder.WriteString("  ")
				messageBuilder.WriteString(formatter.FormatSnippetArrow())
				messageBuilder.WriteString(snippetLine)
			}
		}
	}

	logger.Info(messageBuilder.String())
}

func formatFingerprintMatchesList(matches []interfaces.FingerprintMatch, showRule bool) string {
	if len(matches) == 0 {
		return ""
	}

	parts := make([]string, 0, len(matches))
	for i := range matches {
		match := matches[i]
		display := formatter.FormatFingerprintDisplay(match.RuleName, match.Matcher, showRule)
		if display != "" {
			parts = append(parts, display)
		}
	}

	return strings.Join(parts, " ")
}

func (sc *ScanController) convertToFingerprintResponse(resp *interfaces.HTTPResponse) *fingerprint.HTTPResponse {
	if resp == nil {
		return nil
	}

	// 转换响应头格式（types.HTTPResponse.ResponseHeaders已经是map[string][]string）
	headers := resp.ResponseHeaders
	if headers == nil {
		headers = make(map[string][]string)
	}

	// 处理响应体解压缩和编码转换
	processedBody := ""
	if resp.ResponseBody != "" {
		if resp.BodyDecoded {
			processedBody = resp.ResponseBody
		} else {
			rawBody := resp.ResponseBody

			// Content-Encoding 解压
			var contentEncoding string
			if headers != nil {
				if encodingHeaders, exists := headers["Content-Encoding"]; exists && len(encodingHeaders) > 0 {
					contentEncoding = encodingHeaders[0]
				}
			}

			decompressed := sharedutils.DecompressByEncoding([]byte(rawBody), contentEncoding)
			processedBody = fingerprint.GetEncodingDetector().DetectAndConvert(string(decompressed), resp.ContentType)
		}
	}

	// 提取处理后的标题
	title := sharedutils.ExtractTitle(processedBody)

	logger.Debugf("响应体处理完成: %s (原始: %d bytes, 处理后: %d bytes)",
		resp.URL, len(resp.ResponseBody), len(processedBody))

	return &fingerprint.HTTPResponse{
		URL:             resp.URL,
		Method:          "GET",
		StatusCode:      resp.StatusCode,
		ResponseHeaders: headers,
		Body:            processedBody,
		ContentType:     resp.ContentType,
		ContentLength:   int64(len(processedBody)),
		Server:          resp.Server,
		Title:           title,
	}
}

// extractBaseURL 从完整URL中提取基础URL（协议+主机）
func (sc *ScanController) extractBaseURL(rawURL string) string {
	parsedURL, err := url.Parse(rawURL)
	if err == nil && parsedURL != nil {
		return fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	}
	return rawURL
}

// extractBaseURLWithPath 从完整URL中提取基础URL（协议+主机+路径），去除查询参数和片段
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

type similarProbe struct {
	idx       int
	target    string
	remoteIP  string
	signature string
	status    int
	isHTTPS   bool
	timeout   bool
	ok        bool
}

type similarStats struct {
	Total    int
	Deduped  int
	Timeouts int
	Failed   int
	Kept     int
}

type similarPair struct {
	Target    string
	SimilarTo string
}

type similarReport struct {
	Stats          similarStats
	SimilarPairs   []similarPair
	TimeoutTargets []string
}

func (sc *ScanController) checkSimilarTargetsWithReport(ctx context.Context, targets []string) ([]string, similarReport) {
	report := similarReport{Stats: similarStats{Total: len(targets)}}
	if len(targets) <= 1 || sc.requestProcessor == nil {
		report.Stats.Kept = len(targets)
		return targets, report
	}

	logSimilarInfo(sc, "Starting similar target check: %d", len(targets))

	reqProcessor := sc.requestProcessor.CloneWithContext("fingerprint-similar", 0)
	reqProcessor.SetStatsUpdater(nil)
	reqProcessor.SetBatchMode(true)
	if cfg := reqProcessor.GetConfig(); cfg != nil {
		if cfg.FollowRedirect || cfg.MaxRedirects != 0 {
			updated := *cfg
			updated.FollowRedirect = false
			updated.MaxRedirects = 0
			reqProcessor.UpdateConfig(&updated)
		}
	}

	iconCache := fingerprint.NewIconCache()

	maxConcurrent := reqProcessor.GetConfig().MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 20
	}
	if maxConcurrent > len(targets) {
		maxConcurrent = len(targets)
	}
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}

	jobs := make(chan int)
	results := make(chan similarProbe, len(targets))

	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for idx := range jobs {
			res := similarProbe{idx: idx, target: targets[idx]}
			if ctx != nil {
				select {
				case <-ctx.Done():
					results <- res
					continue
				default:
				}
			}

			resp, err := reqProcessor.RequestOnceWithHeaders(ctx, targets[idx], nil)
			if err != nil || resp == nil {
				res.timeout = requests.IsTimeoutOrCanceledError(err)
				results <- res
				continue
			}

			iconHash := fetchIconHash(resp.URL, iconCache, reqProcessor)
			signature, signatureInfo := buildSignatureInfo(resp, iconHash)
			res.signature = signature
			if res.signature == "" {
				results <- res
				continue
			}

			res.ok = true
			res.remoteIP = buildRemoteEndpoint(resp)
			res.status = resp.StatusCode
			res.isHTTPS = isHTTPSURL(targets[idx])
			logSimilarSignatureDebug(res.target, res.remoteIP, res.signature, signatureInfo)
			results <- res
		}
	}

	for i := 0; i < maxConcurrent; i++ {
		wg.Add(1)
		go worker()
	}

	for idx := range targets {
		jobs <- idx
	}
	close(jobs)
	wg.Wait()
	close(results)

	ipGroups := make(map[string]map[string][]similarProbe)
	failed := make([]int, 0)
	timeouts := 0
	timeoutTargets := make([]string, 0)
	for res := range results {
		if res.ok {
			ipKey := res.remoteIP
			if ipKey == "" {
				ipKey = fmt.Sprintf("unknown-%d", res.idx)
			}
			if ipGroups[ipKey] == nil {
				ipGroups[ipKey] = make(map[string][]similarProbe)
			}
			ipGroups[ipKey][res.signature] = append(ipGroups[ipKey][res.signature], res)
			continue
		}
		failed = append(failed, res.idx)
		if res.timeout {
			timeouts++
			timeoutTargets = append(timeoutTargets, res.target)
		}
	}

	keep := make([]bool, len(targets))
	if !shouldDropFailedSimilar(sc) {
		for _, idx := range failed {
			if idx >= 0 && idx < len(keep) {
				keep[idx] = true
			}
		}
	}

	deduped := 0
	similarPairs := make([]similarPair, 0)
	for _, groups := range ipGroups {
		for _, group := range groups {
			if len(group) == 0 {
				continue
			}
			best := group[0]
			for i := 1; i < len(group); i++ {
				if preferSimilarCandidate(group[i], best) {
					best = group[i]
				}
			}
			keep[best.idx] = true
			if len(group) > 1 {
				deduped += len(group) - 1
				for _, item := range group {
					if item.idx == best.idx {
						continue
					}
					similarPairs = append(similarPairs, similarPair{
						Target:    item.target,
						SimilarTo: best.target,
					})
				}
			}
		}
	}

	kept := make([]string, 0, len(targets)-deduped)
	for i, target := range targets {
		if keep[i] {
			kept = append(kept, target)
		}
	}

	report.Stats.Deduped = deduped
	report.Stats.Timeouts = timeouts
	report.Stats.Failed = len(failed)
	report.Stats.Kept = len(kept)
	report.SimilarPairs = similarPairs
	report.TimeoutTargets = timeoutTargets

	logSimilarInfo(sc, "Similar target check completed: input %d, kept %d, deduped %d, failed %d", len(targets), len(kept), deduped, len(failed))
	return kept, report
}

func preferSimilarCandidate(a, b similarProbe) bool {
	if a.status == 200 && b.status != 200 {
		return true
	}
	if a.status != 200 && b.status == 200 {
		return false
	}
	if a.isHTTPS && !b.isHTTPS {
		return true
	}
	if !a.isHTTPS && b.isHTTPS {
		return false
	}
	return a.idx < b.idx
}

type signatureInfo struct {
	StatusLine  string
	Server      string
	Title       string
	ContentType string
	IconHash    string
	Location    string
}

func buildSignatureInfo(resp *interfaces.HTTPResponse, iconHash string) (string, signatureInfo) {
	if resp == nil {
		return "", signatureInfo{}
	}

	info := signatureInfo{
		StatusLine:  normalizeStatusLine(resp.StatusCode),
		Server:      normalizeServer(resp.Server),
		Title:       normalizeTitle(resp.Title),
		ContentType: normalizeContentType(resp.ContentType),
		IconHash:    normalizeIconHash(iconHash),
		Location:    normalizeLocation(resp.URL, resp.StatusCode, resp.ResponseHeaders),
	}

	signature := fmt.Sprintf("%s|%s|%s|%s|%s", info.StatusLine, info.Server, info.Title, info.ContentType, info.IconHash)
	if info.Location != "" {
		signature = signature + "|" + info.Location
	}
	return signature, info
}

func normalizeTitle(title string) string {
	title = strings.TrimSpace(strings.ToLower(title))
	if title == "" {
		return "empty"
	}
	return title
}

func normalizeServer(server string) string {
	server = strings.TrimSpace(strings.ToLower(server))
	if server == "" {
		return "unknown"
	}
	return server
}

func normalizeStatusLine(statusCode int) string {
	if statusCode <= 0 {
		return "unknown"
	}
	return strconv.Itoa(statusCode)
}

func normalizeContentType(contentType string) string {
	contentType = strings.TrimSpace(strings.ToLower(contentType))
	if contentType == "" {
		return "unknown"
	}
	if idx := strings.Index(contentType, ";"); idx != -1 {
		contentType = strings.TrimSpace(contentType[:idx])
	}
	return contentType
}

func normalizeIconHash(hash string) string {
	hash = strings.TrimSpace(strings.ToLower(hash))
	if hash == "" {
		return "none"
	}
	return hash
}

func normalizeLocation(rawURL string, statusCode int, headers map[string][]string) string {
	if statusCode != http.StatusMovedPermanently && statusCode != http.StatusFound {
		return ""
	}
	location := strings.TrimSpace(redirect.GetHeaderFirst(headers, "Location"))
	if location == "" {
		return ""
	}
	if resolved := redirect.ResolveRedirectURL(rawURL, location); resolved != "" {
		return resolved
	}
	return location
}

func buildRemoteEndpoint(resp *interfaces.HTTPResponse) string {
	if resp == nil {
		return ""
	}
	ip := strings.TrimSpace(resp.RemoteIP)
	if ip == "" {
		return ""
	}
	port := extractPortFromURL(resp.URL)
	if port == "" {
		return ip
	}
	return net.JoinHostPort(ip, port)
}

func extractPortFromURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" {
		return ""
	}
	if port := strings.TrimSpace(parsed.Port()); port != "" {
		return port
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

func logSimilarSignatureDebug(target, remoteIP, signature string, info signatureInfo) {
	ip := strings.TrimSpace(remoteIP)
	if ip == "" {
		ip = "unknown"
	}
	location := info.Location
	if location == "" {
		location = "none"
	}
	logger.Debugf("相似度要素: %s | IP=%s | 状态=%s | Server=%s | Title=%s | Content-Type=%s | IconMD5=%s | Location=%s | 签名=%s",
		target,
		ip,
		info.StatusLine,
		info.Server,
		info.Title,
		info.ContentType,
		info.IconHash,
		location,
		signature,
	)
}

func fetchIconHash(rawURL string, cache *fingerprint.IconCache, client httpclient.HTTPClientInterface) string {
	if cache == nil || client == nil {
		return ""
	}
	iconURL := buildIconURL(rawURL)
	if iconURL == "" {
		return ""
	}
	hash, err := cache.GetHash(iconURL, client)
	if err != nil {
		return ""
	}
	return hash
}

func buildIconURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return ""
	}
	parsed.Path = "/favicon.ico"
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func shouldDropFailedSimilar(sc *ScanController) bool {
	if sc == nil || sc.args == nil {
		return false
	}
	return sc.args.CheckSimilarOnly
}

func logSimilarInfo(sc *ScanController, format string, args ...interface{}) {
	if sc == nil || sc.args == nil || sc.args.CheckSimilarOnly {
		return
	}
	logger.Infof(format, args...)
}

func isHTTPSURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}
	return strings.HasPrefix(strings.ToLower(raw), "https://")
}

func (sc *ScanController) runDirscanModule(ctx context.Context, targets []string) ([]interfaces.HTTPResponse, error) {
	originalContext := sc.requestProcessor.GetModuleContext()
	sc.requestProcessor.SetModuleContext("dirscan")

	originalBatchMode := sc.requestProcessor.IsBatchMode()
	sc.requestProcessor.SetBatchMode(true)
	originalDecompress := true
	originalFollowRedirect := false
	originalMaxRedirects := 0
	if cfg := sc.requestProcessor.GetConfig(); cfg != nil {
		originalDecompress = cfg.DecompressResponse
		originalFollowRedirect = cfg.FollowRedirect
		originalMaxRedirects = cfg.MaxRedirects
		if originalDecompress || originalFollowRedirect || originalMaxRedirects != 0 {
			updated := *cfg
			updated.DecompressResponse = false
			updated.FollowRedirect = false
			updated.MaxRedirects = 0
			sc.requestProcessor.UpdateConfig(&updated)
		}
	}

	defer func() {
		sc.requestProcessor.SetModuleContext(originalContext)
		sc.requestProcessor.SetBatchMode(originalBatchMode)
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

	// 模块启动提示
	dictInfo := "config/dict/common.txt"
	if strings.TrimSpace(sc.wordlistPath) != "" {
		dictInfo = sc.wordlistPath
	}
	// 模块开始前空行，提升可读性
	logger.Infof("Start Dirscan, Loaded Dict: %s", dictInfo)
	validTargets := make([]string, 0, len(targets))
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		validTargets = append(validTargets, target)
	}

	logger.Debugf("开始目录扫描，目标数量: %d", len(validTargets))

	maxDepth := 0
	if sc.args.DepthSet {
		maxDepth = sc.args.Depth
	}

	if sc.statsDisplay.IsEnabled() {
		if maxDepth <= 0 {
			dictSize := dirscan.GetCommonDictionarySize()
			if dictSize > 0 {
				totalRequests := int64(len(validTargets) * dictSize)
				sc.statsDisplay.EnableManualTotalRequests(totalRequests)
				defer sc.statsDisplay.DisableManualTotalRequests()
			}
		} else {
			sc.statsDisplay.DisableManualTotalRequests()
		}
	}

	reqConfig := sc.requestProcessor.GetConfig()

	var allResults []interfaces.HTTPResponse
	var allResultsMu sync.Mutex
	var firstErr error
	hadSuccess := false

	if len(validTargets) == 0 {
		return allResults, nil
	}

	maxConcurrent := reqConfig.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}

	perTargetConcurrent := maxConcurrent
	if perTargetConcurrent < 1 {
		perTargetConcurrent = 1
	}

	logger.Debugf("目录扫描顺序扫描目标，单目标并发数: %d", perTargetConcurrent)

	for _, target := range validTargets {
		if ctx.Err() != nil {
			break
		}

		currentTarget := target

		workerProcessor := sc.requestProcessor.CloneWithContext("dirscan", 0)
		workerCfg := workerProcessor.GetConfig()
		if workerCfg.MaxConcurrent != perTargetConcurrent {
			workerCfg.MaxConcurrent = perTargetConcurrent
			workerProcessor.UpdateConfig(workerCfg)
		}

		engine := dirscan.NewEngine(&dirscan.EngineConfig{
			MaxConcurrency: perTargetConcurrent,
			RequestTimeout: workerCfg.Timeout,
			ProxyURL:       workerCfg.ProxyURL,
		})
		engine.SetRequestProcessor(workerProcessor)

		runCtx, cancel := context.WithCancel(ctx)

		layerScanner := func(layerTargets []string, filter *dirscan.ResponseFilter, depth int) ([]interfaces.HTTPResponse, error) {
			tempCollector := dirscan.NewRecursionCollector(layerTargets)

			recursive := depth > 0
			scanResult, err := engine.PerformScanWithFilter(runCtx, tempCollector, recursive, filter)
			if err != nil {
				return nil, err
			}
			if scanResult == nil || scanResult.FilterResult == nil {
				return nil, nil
			}

			validPages := scanResult.FilterResult.ValidPages

			sc.collectedResultsMu.Lock()
			if len(scanResult.FilterResult.PrimaryFilteredPages) > 0 {
				sc.collectedPrimaryFiltered = append(sc.collectedPrimaryFiltered, toValueSlice(scanResult.FilterResult.PrimaryFilteredPages)...)
			}
			if len(scanResult.FilterResult.StatusFilteredPages) > 0 {
				sc.collectedStatusFiltered = append(sc.collectedStatusFiltered, toValueSlice(scanResult.FilterResult.StatusFilteredPages)...)
			}
			sc.collectedResultsMu.Unlock()

			if sc.statsDisplay.IsEnabled() {
				for range layerTargets {
					sc.statsDisplay.IncrementCompletedHosts()
				}
			}

			result := make([]interfaces.HTTPResponse, 0, len(validPages))
			for _, page := range validPages {
				if page != nil {
					result = append(result, *page)
				}
			}

			return result, nil
		}

		targetFilter := dirscan.CreateResponseFilterFromExternal()
		if sc.fingerprintEngine != nil {
			targetFilter.SetFingerprintEngine(sc.fingerprintEngine)
		}
		targetFilter.SetOnValid(func(page *interfaces.HTTPResponse) {
			if page == nil {
				return
			}
			sc.displayedURLsMu.Lock()
			if sc.displayedURLs[page.URL] {
				sc.displayedURLsMu.Unlock()
				return
			}
			sc.displayedURLs[page.URL] = true
			sc.displayedURLsMu.Unlock()

			allResultsMu.Lock()
			allResults = append(allResults, *page)
			allResultsMu.Unlock()

			if sc.realtimeReporter != nil {
				_ = sc.realtimeReporter.WriteResponse(page)
			}
			printHTTPResponseResult(page, sc.showFingerprintSnippet, sc.args.Verbose || sc.args.VeryVerbose)
		})

		_, err := dirscan.RunRecursiveScan(
			runCtx,
			[]string{currentTarget},
			maxDepth,
			layerScanner,
			targetFilter,
		)
		if cancel != nil {
			cancel()
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			logger.Warnf("Dirscan failed for target %s: %v", currentTarget, err)
			continue
		}

		hadSuccess = true
	}

	if !hadSuccess && firstErr != nil {
		return nil, firstErr
	}

	return allResults, nil
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

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	for resList := range resultsChan {
		if len(resList) > 0 {
			allResults = append(allResults, resList...)
		}
	}

	// 主动探测 (Path, Icon, 404)
	activeResults := sc.performActiveProbing(ctx, targets, progressTracker)
	if len(activeResults) > 0 {
		allResults = append(allResults, activeResults...)
	}

	if progressTracker != nil {
		progressTracker.Stop()
	}

	return allResults, nil
}

// processSingleTargetFingerprintWithContext 处理单个目标，支持传入 Context
func (sc *ScanController) processSingleTargetFingerprintWithContext(ctx context.Context, target string, progressTracker *stats.RequestProgress) []interfaces.HTTPResponse {
	// 使用channel接收结果以支持select超时
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

// processSingleTargetFingerprint 处理单个目标的指纹识别（多目标并发优化）
func (sc *ScanController) processSingleTargetFingerprint(ctx context.Context, target string, progressTracker *stats.RequestProgress) []interfaces.HTTPResponse {
	if ctx == nil {
		ctx = context.Background()
	}
	logger.Debugf("开始处理指纹识别: %s", target)

	var results []interfaces.HTTPResponse
	if sc.requestProcessor == nil || sc.fingerprintEngine == nil {
		return results
	}

	// 为目标设置上下文
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

// printFingerprintResultWithProgressClear 输出指纹结果并清除进度条
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

	// 1. Path Probing
	if hasPathRules {
		results, err := sc.fingerprintEngine.ExecuteActiveProbing(probeCtx, baseURL, probeClient)
		if err != nil {
			logger.Debugf("Path probing error: %v", err)
		}
		localResults = sc.appendProbeResults(localResults, results, formatter, "Path探测")
	}

	// 2. Icon Probing
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

	// 3. 404 Page Probing
	if res404 := sc.perform404PageProbing(probeCtx, baseURL, formatter, probeClient); res404 != nil {
		localResults = append(localResults, *res404)
	}

	return localResults
}

// performActiveProbing 执行主动探测（Path, Icon, 404）
func (sc *ScanController) performActiveProbing(ctx context.Context, targets []string, progressTracker *stats.RequestProgress) []interfaces.HTTPResponse {
	// 检查指纹引擎是否可用
	if sc.fingerprintEngine == nil {
		logger.Debug("指纹引擎未初始化，跳过主动探测")
		return nil
	}

	if sc.args != nil && sc.args.NoProbe {
		logger.Debug("已禁用主动探测 (--no-probe)")
		return nil
	}

	// 检查Context是否取消
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	// 检查是否有任何需要主动探测的规则
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

	// 提交任务
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

// perform404PageProbing 执行404页面指纹识别
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

// shouldTriggerPathProbing 检查是否应该触发path探测
func (sc *ScanController) shouldTriggerPathProbing(hostKey string) bool {
	sc.probedMutex.RLock()
	defer sc.probedMutex.RUnlock()

	// 检查是否已经探测过此主机
	return !sc.probedHosts[hostKey]
}

// getUniqueProbeTargets 提取唯一探测目标
func (sc *ScanController) getUniqueProbeTargets(targets []string) map[string]string {
	uniqueTargets := make(map[string]string)
	for _, t := range targets {
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
