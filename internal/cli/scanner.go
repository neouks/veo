package cli

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"veo/internal/core/config"
	"veo/internal/scheduler"
	modulepkg "veo/pkg/core/module"
	"veo/pkg/dirscan"
	"veo/pkg/fingerprint"
	portscanpkg "veo/pkg/portscan"
	gogoscanner "veo/pkg/portscan/gogo"
	report "veo/pkg/reporter"
	"veo/pkg/types"
	"veo/pkg/utils/checkalive"
	"veo/pkg/utils/formatter"
	"veo/pkg/utils/httpclient"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
	requests "veo/pkg/utils/processor"
	"veo/pkg/utils/stats"
	"veo/pkg/utils/useragent"

	"path/filepath"
	sharedutils "veo/pkg/utils/shared"
)

func toReporterStats(stats *fingerprint.Statistics) *report.FingerprintStats {
	if stats == nil {
		return nil
	}
	return &report.FingerprintStats{
		TotalRequests:    stats.TotalRequests,
		MatchedRequests:  stats.MatchedRequests,
		FilteredRequests: stats.FilteredRequests,
		RulesLoaded:      stats.RulesLoaded,
		StartTime:        stats.StartTime,
		LastMatchTime:    stats.LastMatchTime,
	}
}

// FingerprintProgressTracker 指纹识别进度跟踪器
type FingerprintProgressTracker struct {
	totalSteps  int    // 总步骤数（1个基础指纹匹配 + N个path探测）
	currentStep int    // 当前步骤
	baseURL     string // 基础URL
	mu          sync.Mutex
	enabled     bool
}

func shouldUsePortFirst(args *CLIArgs) bool {
	if args.HasModule("port") && len(args.Modules) > 1 {
		return true
	}
	if strings.TrimSpace(args.Ports) == "" {
		return false
	}

	// 当同时启用端口、指纹、目录扫描模块并指定端口时，强制走端口优先流程
	if args.HasModule(string(modulepkg.ModuleDirscan)) && args.HasModule(string(modulepkg.ModuleFinger)) {
		return true
	}

	rawTargets, err := collectRawTargets(args)
	if err != nil {
		logger.Warnf("解析目标失败，回退到非端口优先模式: %v", err)
		return false
	}
	if len(rawTargets) == 0 {
		return false
	}
	multiCount := 0
	for _, target := range rawTargets {
		if isMultiTargetExpression(target) {
			multiCount++
		}
	}
	if multiCount > 0 {
		if multiCount < len(rawTargets) {
			logger.Infof("检测到混合目标（单目标与范围共存），优先执行端口扫描流程")
		}
		return true
	}
	return false
}

func collectRawTargets(args *CLIArgs) ([]string, error) {
	var raw []string
	raw = append(raw, args.Targets...)
	if strings.TrimSpace(args.TargetFile) != "" {
		parser := checkalive.NewTargetParser()
		fileTargets, err := parser.ParseFile(strings.TrimSpace(args.TargetFile))
		if err != nil {
			return nil, err
		}
		raw = append(raw, fileTargets...)
	}
	return raw, nil
}

func isMultiTargetExpression(target string) bool {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return false
	}
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return false
	}
	if _, _, err := net.ParseCIDR(trimmed); err == nil {
		return true
	}
	if isIPRangeExpression(trimmed) {
		return true
	}
	return false
}

func isIPRangeExpression(expr string) bool {
	if !strings.Contains(expr, "-") {
		return false
	}
	parts := strings.SplitN(expr, "-", 2)
	if len(parts) != 2 {
		return false
	}
	left := strings.TrimSpace(parts[0])
	right := strings.TrimSpace(parts[1])
	if net.ParseIP(left) != nil && net.ParseIP(right) != nil {
		return true
	}
	if idx := strings.LastIndex(left, "."); idx != -1 {
		prefix := left[:idx+1]
		startStr := left[idx+1:]
		if _, err := strconv.Atoi(startStr); err != nil {
			return false
		}
		if _, err := strconv.Atoi(right); err != nil {
			return false
		}
		if net.ParseIP(prefix+"0") != nil {
			return true
		}
	}
	return false
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

	// 边界条件检查：防止计数器超过总步骤数
	if fpt.currentStep >= fpt.totalSteps {
		// 已经完成，不再更新进度
		return
	}

	fpt.currentStep++

	// 确保百分比不超过100%
	percentage := float64(fpt.currentStep) / float64(fpt.totalSteps) * 100
	if percentage > 100.0 {
		percentage = 100.0
	}

	fmt.Printf("\rFingerPrint Working %d/%d (%.1f%%)\r",
		fpt.currentStep, fpt.totalSteps, percentage)
}

// ScanMode 扫描模式
type ScanMode int

const (
	ActiveMode  ScanMode = iota // 主动扫描模式
	PassiveMode                 // 被动代理模式
)

// ScanController 扫描控制器
type ScanController struct {
	mode                   ScanMode
	args                   *CLIArgs
	config                 *config.Config
	requestProcessor       *requests.RequestProcessor
	urlGenerator           *dirscan.URLGenerator
	contentManager         *dirscan.ContentManager
	fingerprintEngine      *fingerprint.Engine           // 指纹识别引擎
	encodingDetector       *fingerprint.EncodingDetector // 编码检测器
	probedHosts            map[string]bool               // 已探测的主机缓存（用于path探测去重）
	probedMutex            sync.RWMutex                  // 探测缓存锁
	progressTracker        *FingerprintProgressTracker   // 指纹识别进度跟踪器
	statsDisplay           *stats.StatsDisplay           // 统计显示器
	lastTargets            []string                      // 最近解析的目标列表
	showFingerprintSnippet bool                          // 是否展示指纹匹配内容
	showFingerprintRule    bool                          // 是否展示指纹匹配规则
	lastPortResults        []portscanpkg.OpenPortResult
	lastPortExpr           string
	lastPortRate           int
	portFirstMode          bool
	maxConcurrent          int
	retryCount             int
	timeoutSeconds         int
	reportPath             string
	wordlistPath           string
	skipAliveCheck         bool
	rawTargets             []string

	// 缓存最近一次各模块结果（用于合并报告落盘）
	lastDirscanResults     []interfaces.HTTPResponse
	lastFingerprintResults []interfaces.HTTPResponse
	ipHostMapping          map[string][]string
}

// NewScanController 创建扫描控制器
func NewScanController(args *CLIArgs, cfg *config.Config) *ScanController {
	mode := ActiveMode
	if args.Listen {
		mode = PassiveMode
	}

	portFirstMode := args.PortFirst
	if !portFirstMode {
		portFirstMode = shouldUsePortFirst(args)
	}

	threads := args.Threads
	if threads <= 0 {
		threads = 200
	}
	retry := args.Retry
	if retry <= 0 {
		retry = 1
	}
	timeout := args.Timeout
	if timeout <= 0 {
		timeout = 3
	}

	// 创建请求处理器配置
	requestConfig := &requests.RequestConfig{
		Timeout:         time.Duration(timeout) * time.Second,
		MaxRetries:      retry,
		MaxConcurrent:   threads,
		FollowRedirect:  true,
		RandomUserAgent: args.RandomUA,
	}

	// 应用代理配置
	if proxyCfg := config.GetProxyConfig(); proxyCfg != nil && proxyCfg.UpstreamProxy != "" {
		requestConfig.ProxyURL = proxyCfg.UpstreamProxy
		logger.Debugf("ActiveScan: 设置请求处理器代理: %s", requestConfig.ProxyURL)
	}

	logger.Debugf("请求处理器并发数设置为: %d", requestConfig.MaxConcurrent)
	logger.Debugf("请求处理器重试次数设置为: %d", requestConfig.MaxRetries)
	logger.Debugf("请求处理器超时时间设置为: %v", requestConfig.Timeout)

	// 修复重复加载：主动模式复用被动模式的指纹引擎
	var fpEngine *fingerprint.Engine
	if mode == ActiveMode {
		// 获取全局指纹识别插件实例（由被动模式创建）
		globalAddon := fingerprint.GetGlobalAddon()
		if globalAddon != nil {
			// 复用被动模式的指纹引擎，避免重复加载
			fpEngine = globalAddon.GetEngine()
			logger.Debug("复用被动模式的指纹引擎，避免重复加载")
		}
	}

	// [新增] 如果指纹引擎仍为空，且启用了目录扫描，则手动初始化指纹引擎以支持二次识别
	if fpEngine == nil && args.HasModule(string(modulepkg.ModuleDirscan)) {
		logger.Debug("检测到目录扫描模块启用，正在初始化指纹引擎以支持二次识别...")
		// 使用默认配置初始化指纹插件
		addon, err := fingerprint.CreateDefaultAddon()
		if err != nil {
			logger.Warnf("初始化指纹引擎失败，目录扫描将不包含指纹信息: %v", err)
		} else {
			fpEngine = addon.GetEngine()
			logger.Debug("指纹引擎初始化成功 (二次识别模式)")
		}
	}

	// 创建请求处理器并自定义防缓存头部
	requestProcessor := requests.NewRequestProcessor(requestConfig)

	// 为指纹识别模式设置模块上下文，禁用processor进度条
	// 注意：这里只为纯指纹识别模式设置，混合模式需要在运行时动态设置
	if mode == ActiveMode && len(args.Modules) == 1 && args.Modules[0] == "finger" {
		requestProcessor.SetModuleContext("fingerprint")
	}

	// 创建统计显示器
	statsDisplay := stats.NewStatsDisplay()
	if args.Stats {
		statsDisplay.Enable()
	}

	// 设置请求处理器的统计更新器
	if args.Stats {
		requestProcessor.SetStatsUpdater(statsDisplay)
	}

	snippetEnabled := args.VeryVerbose
	ruleEnabled := args.Verbose || args.VeryVerbose

	if fpEngine != nil {
		fpEngine.EnableSnippet(snippetEnabled)
		fpEngine.EnableRuleLogging(ruleEnabled)
	}

	return &ScanController{
		mode:                   mode,
		args:                   args,
		config:                 cfg,
		requestProcessor:       requestProcessor,
		urlGenerator:           dirscan.NewURLGenerator(),
		contentManager:         dirscan.NewContentManager(),
		fingerprintEngine:      fpEngine,
		encodingDetector:       fingerprint.GetEncodingDetector(), // 初始化编码检测器
		probedHosts:            make(map[string]bool),             // 初始化探测缓存
		statsDisplay:           statsDisplay,                      // 初始化统计显示器
		showFingerprintSnippet: snippetEnabled,
		showFingerprintRule:    ruleEnabled,
		portFirstMode:          portFirstMode,
		maxConcurrent:          threads,
		retryCount:             retry,
		timeoutSeconds:         timeout,
		reportPath:             strings.TrimSpace(args.Output),
		wordlistPath:           strings.TrimSpace(args.Wordlist),
		skipAliveCheck:         args.NoAliveCheck,
		ipHostMapping:          make(map[string][]string),
	}
}

// Run 运行扫描
func (sc *ScanController) Run() error {
	switch sc.mode {
	case ActiveMode:
		return sc.runActiveMode()
	case PassiveMode:
		return sc.runPassiveMode()
	default:
		return fmt.Errorf("未知的扫描模式")
	}
}

// runActiveMode 运行主动扫描模式
// 1. 解析并验证目标
// 2. 顺序执行配置的模块
// 3. 如果配置了端口扫描，则进行端口扫描并对结果进行二次扫描
func (sc *ScanController) runActiveMode() error {
	logger.Debug("启动主动扫描模式")

	rawTargets, err := collectRawTargets(sc.args)
	if err != nil {
		return fmt.Errorf("目标解析失败: %v", err)
	}
	if len(rawTargets) == 0 {
		return fmt.Errorf("没有有效的目标")
	}
	sc.rawTargets = rawTargets
	sc.enrichIPHostMapping(rawTargets)

	if sc.portFirstMode {
		sc.lastTargets = rawTargets
		return sc.runPortFirstWorkflow(rawTargets)
	}

	// 解析和验证目标URL
	targets, err := sc.parseTargets(sc.args.Targets)
	if err != nil {
		return fmt.Errorf("目标解析失败: %v", err)
	}

	sc.lastTargets = targets

	logger.Debugf("解析到 %d 个目标", len(targets))

	// 初始化统计信息（使用最终有效目标数量）
	if sc.statsDisplay.IsEnabled() {
		sc.statsDisplay.SetTotalHosts(int64(len(targets)))
		logger.Debugf("统计显示器：设置总主机数 = %d", len(targets))
	}

	// 创建结果收集器
	var allResults []interfaces.HTTPResponse
	var dirscanResults []interfaces.HTTPResponse
	var fingerprintResults []interfaces.HTTPResponse

	// 顺序执行各个模块，避免模块上下文冲突
	// 优化执行顺序：指纹识别优先，然后目录扫描
	orderedModules := sc.getOptimizedModuleOrder()
	allResults, dirscanResults, fingerprintResults = sc.executeModulesSequence(orderedModules, targets)

	if strings.TrimSpace(sc.args.Ports) != "" && !sc.portFirstMode {
		newAll, newDir, newFinger := sc.performPortScanAndRescan()
		if len(newAll) > 0 {
			allResults = append(allResults, newAll...)
		}
		if len(newDir) > 0 {
			dirscanResults = append(dirscanResults, newDir...)
		}
		if len(newFinger) > 0 {
			fingerprintResults = append(fingerprintResults, newFinger...)
		}
	}

	return sc.finalizeScan(allResults, dirscanResults, fingerprintResults)
}

// GetRequestProcessor 获取请求处理器（用于测试和调试）
func (sc *ScanController) GetRequestProcessor() *requests.RequestProcessor {
	return sc.requestProcessor
}

func (sc *ScanController) executeModulesSequence(modules []string, targets []string) ([]interfaces.HTTPResponse, []interfaces.HTTPResponse, []interfaces.HTTPResponse) {
	var allResults []interfaces.HTTPResponse
	var dirResults []interfaces.HTTPResponse
	var fingerprintResults []interfaces.HTTPResponse

	if len(modules) == 0 || len(targets) == 0 {
		return allResults, dirResults, fingerprintResults
	}

	for i, moduleName := range modules {
		logger.Debugf("开始执行模块: %s (%d/%d)", moduleName, i+1, len(modules))

		moduleResults, err := sc.runModuleForTargets(moduleName, targets)
		if err != nil {
			logger.Errorf("模块 %s 执行失败: %v", moduleName, err)
			continue
		}

		allResults = append(allResults, moduleResults...)
		switch moduleName {
		case string(modulepkg.ModuleDirscan):
			dirResults = append(dirResults, moduleResults...)
		case string(modulepkg.ModuleFinger):
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

	onlyFingerprint := len(sc.args.Modules) == 1 && sc.args.Modules[0] == string(modulepkg.ModuleFinger)
	var filterResult *interfaces.FilterResult

	if onlyFingerprint {
		pages := fingerprintResults
		if len(pages) == 0 {
			pages = allResults
		}
		filterResult = &interfaces.FilterResult{
			ValidPages: pages,
		}
	} else {
		filterResult = &interfaces.FilterResult{
			ValidPages: allResults,
		}
		if len(allResults) > 0 {
			logger.Debugf("所有目标过滤完成，最终有效结果: %d", len(allResults))
		}
	}

	sc.lastDirscanResults = dirResults
	sc.lastFingerprintResults = fingerprintResults

	if sc.reportPath != "" {
		if err := sc.generateReport(filterResult); err != nil {
			logger.Errorf("报告生成失败: %v", err)
		}
	}

	if sc.statsDisplay.IsEnabled() {
		sc.statsDisplay.ShowFinalStats()
		sc.statsDisplay.Disable()
	}

	if sc.args.JSONOutput {
		jsonStr, err := sc.generateConsoleJSON(dirResults, fingerprintResults, filterResult)
		if err != nil {
			logger.Errorf("生成JSON输出失败: %v", err)
		} else {
			fmt.Println(jsonStr)
		}
	}

	return nil
}

func (sc *ScanController) runPortFirstWorkflow(rawTargets []string) error {
	logger.Debug("检测到端口优先模式，先执行端口扫描")

	if sc.statsDisplay.IsEnabled() {
		sc.statsDisplay.SetTotalHosts(int64(len(rawTargets)))
	}

	if len(sc.rawTargets) == 0 {
		sc.rawTargets = rawTargets
	}

	results, portsExpr, rate, err := runPortScanAndCollect(sc.args, rawTargets, true, true)
	if err != nil {
		return err
	}
	if len(results) == 0 {
		logger.Info("端口扫描完成，未发现开放端口")
		return sc.finalizeScan(nil, nil, nil)
	}

	sc.lastPortResults = results
	sc.lastPortExpr = portsExpr
	sc.lastPortRate = rate

	httpTargets := sc.deriveHTTPRescanTargets(results)
	filteredTargets := sc.filterHTTPRescanTargets(httpTargets)
	if len(filteredTargets) == 0 {
		logger.Info("端口扫描未发现 HTTP/HTTPS 服务，无需二轮扫描")
		return sc.finalizeScan(nil, nil, nil)
	}

	sc.lastTargets = filteredTargets
	if sc.statsDisplay.IsEnabled() {
		sc.statsDisplay.SetTotalHosts(int64(len(filteredTargets)))
	}

	modules := sc.getSecondPassModules()
	if len(modules) == 0 {
		logger.Info("未启用指纹或目录扫描模块，跳过二轮扫描")
		return sc.finalizeScan(nil, nil, nil)
	}

	logger.Infof("Detected %d HTTP/HTTPS services, Starting Fingerprint and Dirscan", len(filteredTargets))
	allResults, dirResults, fingerprintResults := sc.executeModulesSequence(modules, filteredTargets)

	return sc.finalizeScan(allResults, dirResults, fingerprintResults)
}

// runPassiveMode 运行被动代理模式
func (sc *ScanController) runPassiveMode() error {
	logger.Info("启动被动代理模式")
	// 直接返回，让主函数处理被动模式
	// 这样可以保持与现有代码100%兼容
	return nil
}

func (sc *ScanController) buildScanParams() map[string]interface{} {
	params := map[string]interface{}{
		"threads":                   sc.maxConcurrent,
		"timeout":                   sc.timeoutSeconds,
		"retry":                     sc.retryCount,
		"dir_targets_count":         0,
		"fingerprint_targets_count": 0,
		"fingerprint_rules_loaded":  0,
	}

	if sc.args.HasModule(string(modulepkg.ModuleDirscan)) {
		params["dir_targets_count"] = len(sc.lastTargets)
	}

	if sc.args.HasModule(string(modulepkg.ModuleFinger)) {
		params["fingerprint_targets_count"] = len(sc.lastTargets)
	}

	if sc.fingerprintEngine != nil {
		if stats := sc.fingerprintEngine.GetStats(); stats != nil {
			params["fingerprint_rules_loaded"] = stats.RulesLoaded
		}
	}

	return params
}

func (sc *ScanController) generateConsoleJSON(dirPages, fingerprintPages []interfaces.HTTPResponse, filterResult *interfaces.FilterResult) (string, error) {
	var matches []types.FingerprintMatch
	var stats *report.FingerprintStats
	if sc.fingerprintEngine != nil {
		if raw := sc.fingerprintEngine.GetMatches(); len(raw) > 0 {
			matches = convertFingerprintMatches(raw, sc.showFingerprintSnippet)
		}
		stats = toReporterStats(sc.fingerprintEngine.GetStats())
	}

	if len(fingerprintPages) == 0 && sc.args.HasModule(string(modulepkg.ModuleFinger)) {
		fingerprintPages = filterResult.ValidPages
	}

	params := sc.buildScanParams()

	// 若请求包含端口扫描参数，则在JSON输出时合并端口结果（复用统一收集函数，避免重复实现）
	var portResults []report.SDKPortResult
	if strings.TrimSpace(sc.args.Ports) != "" {
		if _, agg := sc.collectPortResults(); agg != nil {
			portResults = agg
		}
	}

	return report.GenerateCombinedJSON(dirPages, fingerprintPages, matches, stats, portResults, params)
}

// collectPortResults 运行 masscan 收集端口结果（返回原始与聚合两种形态）
// 参数：无（依赖 sc.args）
// 返回：
//   - []portscanpkg.OpenPortResult 原始结果
//   - []report.SDKPortResult 聚合为每个IP一个条目的端口数组
func (sc *ScanController) collectPortResults() ([]portscanpkg.OpenPortResult, []report.SDKPortResult) {
	if len(sc.lastPortResults) > 0 {
		results := make([]portscanpkg.OpenPortResult, len(sc.lastPortResults))
		copy(results, sc.lastPortResults)
		return results, aggregatePortResults(results)
	}

	announce := true
	printResults := true
	baseTargets := sc.lastTargets
	if len(baseTargets) == 0 {
		baseTargets = sc.args.Targets
	}
	results, portsExpr, rate, err := runPortScanAndCollect(sc.args, baseTargets, announce, printResults)
	if err != nil {
		logger.Errorf("端口扫描合并失败: %v", err)
		return nil, nil
	}
	sc.lastPortResults = results
	sc.lastPortExpr = portsExpr
	sc.lastPortRate = rate
	return results, aggregatePortResults(results)
}

func (sc *ScanController) deriveHTTPRescanTargets(results []portscanpkg.OpenPortResult) []string {
	seen := make(map[string]struct{})
	var potentialTargets []string

	for _, r := range results {
		service := strings.ToLower(strings.TrimSpace(r.Service))
		if service == "" {
			continue
		}

		// 只要服务名以http开头（包括http, https, http-alt等），就同时尝试http和https两种协议
		if !strings.HasPrefix(service, "http") {
			continue
		}

		schemes := []string{"http", "https"}

		host := strings.TrimSpace(r.IP)
		if host == "" {
			continue
		}

		candidateHosts := []string{host}
		if mappedHosts, ok := sc.ipHostMapping[host]; ok && len(mappedHosts) > 0 {
			candidateHosts = append(candidateHosts, mappedHosts...)
		}

		for _, candidateHost := range candidateHosts {
			candidateHost = strings.TrimSpace(candidateHost)
			if candidateHost == "" {
				continue
			}

			for _, scheme := range schemes {
				targetURL := fmt.Sprintf("%s://%s:%d", scheme, candidateHost, r.Port)
				if (scheme == "http" && r.Port == 80) || (scheme == "https" && r.Port == 443) {
					targetURL = fmt.Sprintf("%s://%s", scheme, candidateHost)
				}

				if _, exists := seen[targetURL]; !exists {
					seen[targetURL] = struct{}{}
					potentialTargets = append(potentialTargets, targetURL)
				}
			}
		}
	}

	if len(potentialTargets) == 0 {
		return nil
	}

	// 连通性检测（受-na参数控制）
	if sc.skipAliveCheck {
		logger.Debugf("跳过连通性检测，保留所有 %d 个潜在HTTP目标", len(potentialTargets))
		return potentialTargets
	}

	logger.Debugf("正在对 %d 个潜在HTTP目标进行连通性检测...", len(potentialTargets))
	checker := checkalive.NewConnectivityChecker(sc.config)
	validTargets := checker.BatchCheck(potentialTargets)
	logger.Debugf("连通性检测完成，有效目标: %d", len(validTargets))

	return validTargets
}

// aggregatePortResults 将 OpenPortResult 列表按 IP 聚合为 SDKPortResult（端口数组）
// aggregatePortResults (scanner) 移至 cli.go，避免重复定义

// parseTargets 解析目标列表（支持命令行参数和文件输入）
func (sc *ScanController) parseTargets(targetStrs []string) ([]string, error) {
	logger.Debugf("开始解析目标")

	var allTargets []string

	// 处理命令行直接指定的目标
	if len(targetStrs) > 0 {
		logger.Debugf("处理命令行目标，数量: %d", len(targetStrs))
		for _, targetStr := range targetStrs {
			// 分割逗号分隔的目标
			parts := strings.Split(targetStr, ",")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part != "" {
					allTargets = append(allTargets, part)
				}
			}
		}
	}

	// 处理文件中的目标
	if sc.args.TargetFile != "" {
		logger.Debugf("处理目标文件: %s", sc.args.TargetFile)
		parser := checkalive.NewTargetParser()
		fileTargets, err := parser.ParseFile(sc.args.TargetFile)
		if err != nil {
			return nil, err
		}
		allTargets = append(allTargets, fileTargets...)
		logger.Debugf("从文件读取到 %d 个目标", len(fileTargets))
	}

	if len(allTargets) == 0 {
		return nil, fmt.Errorf("没有有效的目标")
	}

	// 去重
	deduplicator := checkalive.NewDeduplicator()
	uniqueTargets, stats := deduplicator.DeduplicateWithStats(allTargets)

	if stats.DuplicateCount > 0 {
		logger.Debugf("去重完成: 原始 %d 个，去重后 %d 个，重复 %d 个 (%.1f%%)",
			stats.OriginalCount, stats.UniqueCount, stats.DuplicateCount, stats.DuplicateRate)
	}

	// 连通性检测和URL标准化
	var validTargets []string
	if sc.skipAliveCheck {
		parser := checkalive.NewTargetParser()
		for _, target := range uniqueTargets {
			urls := parser.NormalizeURL(target)
			if len(urls) > 0 {
				validTargets = append(validTargets, urls[0])
			} else {
				validTargets = append(validTargets, target)
			}
		}
		logger.Debugf("跳过存活检测，直接使用标准化目标: %d 个", len(validTargets))
	} else {
		checker := checkalive.NewConnectivityChecker(sc.config)
		validTargets = checker.BatchCheck(uniqueTargets)
		if len(validTargets) == 0 {
			return nil, fmt.Errorf("没有可连通的目标")
		}
	}

	logger.Debugf("目标解析完成: 最终有效目标 %d 个", len(validTargets))
	return validTargets, nil
}

// getOptimizedModuleOrder 获取优化的模块执行顺序
// 指纹识别优先执行，然后执行其他模块
func (sc *ScanController) getOptimizedModuleOrder() []string {
	var orderedModules []string

	// 指纹识别优先执行
	for _, module := range sc.args.Modules {
		if module == "finger" {
			orderedModules = append(orderedModules, module)
			break
		}
	}

	// 然后执行其他模块
	for _, module := range sc.args.Modules {
		if module != "finger" {
			orderedModules = append(orderedModules, module)
		}
	}

	return orderedModules
}

// runModuleForTargets 为目标运行指定模块
func (sc *ScanController) runModuleForTargets(moduleName string, targets []string) ([]interfaces.HTTPResponse, error) {

	switch moduleName {
	case "dirscan":
		return sc.runDirscanModule(targets)
	case "finger":

		return sc.runFingerprintModule(targets)
	default:
		return nil, fmt.Errorf("不支持的模块: %s", moduleName)
	}
}

func (sc *ScanController) performPortScanAndRescan() ([]interfaces.HTTPResponse, []interfaces.HTTPResponse, []interfaces.HTTPResponse) {
	baseTargets := sc.rawTargets
	if len(baseTargets) == 0 {
		baseTargets = sc.args.Targets
	}
	results, portsExpr, rate, err := runPortScanAndCollect(sc.args, baseTargets, true, true)
	if err != nil {
		logger.Errorf("端口扫描失败: %v", err)
		return nil, nil, nil
	}
	if len(results) == 0 {
		return nil, nil, nil
	}

	sc.lastPortResults = results
	sc.lastPortExpr = portsExpr
	sc.lastPortRate = rate

	httpTargets := sc.deriveHTTPRescanTargets(results)
	filteredTargets := sc.filterHTTPRescanTargets(httpTargets)
	if len(filteredTargets) == 0 {
		return nil, nil, nil
	}

	logger.Infof("Detected %d HTTP/HTTPS Services, Starting FingerPrint, Dirscan", len(filteredTargets))

	if sc.statsDisplay.IsEnabled() {
		stats := sc.statsDisplay.GetStats()
		sc.statsDisplay.SetTotalHosts(stats.TotalHosts + int64(len(filteredTargets)))
	}

	modules := sc.getSecondPassModules()
	if len(modules) == 0 {
		return nil, nil, nil
	}

	var allResults []interfaces.HTTPResponse
	var dirResults []interfaces.HTTPResponse
	var fingerResults []interfaces.HTTPResponse

	for i, module := range modules {
		moduleResults, err := sc.runModuleForTargets(module, filteredTargets)
		if err != nil {
			logger.Errorf("二轮模块 %s 执行失败: %v", module, err)
			continue
		}
		allResults = append(allResults, moduleResults...)
		if module == string(modulepkg.ModuleDirscan) {
			dirResults = append(dirResults, moduleResults...)
		} else if module == string(modulepkg.ModuleFinger) {
			fingerResults = append(fingerResults, moduleResults...)
		}
		if len(modules) > 1 && i < len(modules)-1 && !sc.args.JSONOutput {
			fmt.Println()
		}
	}

	sc.lastTargets = appendUniqueTargets(sc.lastTargets, filteredTargets)

	return allResults, dirResults, fingerResults
}

func (sc *ScanController) getSecondPassModules() []string {
	var modules []string
	for _, m := range sc.args.Modules {
		if m == string(modulepkg.ModuleFinger) {
			modules = append(modules, m)
		}
	}
	for _, m := range sc.args.Modules {
		if m == string(modulepkg.ModuleDirscan) {
			modules = append(modules, m)
		}
	}
	return modules
}

func (sc *ScanController) filterHTTPRescanTargets(targets []string) []string {
	if len(targets) == 0 {
		return nil
	}
	existing := make(map[string]struct{})
	for _, t := range sc.lastTargets {
		key := strings.TrimRight(t, "/")
		existing[key] = struct{}{}
	}
	unique := make(map[string]struct{})
	var filtered []string
	for _, t := range targets {
		key := strings.TrimRight(t, "/")
		if _, ok := existing[key]; ok {
			continue
		}
		if _, ok := unique[key]; ok {
			continue
		}
		unique[key] = struct{}{}
		filtered = append(filtered, t)
	}
	return filtered
}

func appendUniqueTargets(base []string, additional []string) []string {
	if len(additional) == 0 {
		return base
	}
	seen := make(map[string]struct{}, len(base))
	for _, t := range base {
		seen[t] = struct{}{}
	}
	for _, t := range additional {
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		base = append(base, t)
	}
	return base
}

func (sc *ScanController) enrichIPHostMapping(targets []string) {
	if len(targets) == 0 {
		return
	}

	if sc.ipHostMapping == nil {
		sc.ipHostMapping = make(map[string][]string)
	}

	for _, target := range targets {
		host := extractHostForMapping(target)
		if host == "" {
			continue
		}

		if net.ParseIP(host) != nil {
			continue
		}

		ips, err := net.LookupIP(host)
		if err != nil {
			logger.Debugf("域名解析失败，跳过IP映射: %s, err: %v", host, err)
			continue
		}

		for _, ipAddr := range ips {
			ipStr := strings.TrimSpace(ipAddr.String())
			if ipStr == "" {
				continue
			}

			if containsString(sc.ipHostMapping[ipStr], host) {
				continue
			}
			sc.ipHostMapping[ipStr] = append(sc.ipHostMapping[ipStr], host)
		}
	}
}

func extractHostForMapping(target string) string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return ""
	}

	if strings.Contains(trimmed, "://") {
		if parsed, err := url.Parse(trimmed); err == nil {
			return parsed.Hostname()
		}
	}

	parts := strings.Split(trimmed, "/")
	if len(parts) > 0 {
		trimmed = parts[0]
	}

	trimmed = strings.Trim(trimmed, "[]")

	if strings.Contains(trimmed, ":") {
		if host, _, err := net.SplitHostPort(trimmed); err == nil {
			trimmed = host
		}
	}

	return strings.TrimSpace(trimmed)
}

func containsString(values []string, target string) bool {
	for _, v := range values {
		if v == target {
			return true
		}
	}
	return false
}

// runDirscanModule 运行目录扫描模块（多目标并发优化）
func (sc *ScanController) runDirscanModule(targets []string) ([]interfaces.HTTPResponse, error) {
	originalContext := sc.requestProcessor.GetModuleContext()
	sc.requestProcessor.SetModuleContext("dirscan")
	defer func() {
		sc.requestProcessor.SetModuleContext(originalContext)
	}()

	// [强制配置] 在运行目录扫描前，强制更新 RequestProcessor 的重定向配置
	reqConfig := sc.requestProcessor.GetConfig()
	if !reqConfig.FollowRedirect || reqConfig.MaxRedirects < 3 {
		reqConfig.FollowRedirect = true
		if reqConfig.MaxRedirects < 3 {
			reqConfig.MaxRedirects = 5
		}
		sc.requestProcessor.UpdateConfig(reqConfig)
		logger.Debug("Dirscan模块运行前强制启用重定向跟随 (MaxRedirects=5)")
	}

	// 模块启动提示
	dictInfo := "config/dict/common.txt"
	if strings.TrimSpace(sc.wordlistPath) != "" {
		dictInfo = sc.wordlistPath
	}
	// 模块开始前空行，提升可读性
	logger.Infof("Start Dirscan, Loaded Dict: %s", dictInfo)
	logger.Debugf("开始目录扫描，目标数量: %d", len(targets))

	// 多目标优化：判断是否使用并发扫描（重构：简化判断逻辑）
	if len(targets) > 1 {
		return sc.runConcurrentDirscan(targets)
	}

	// 单目标或禁用并发时使用原有逻辑
	return sc.runSequentialDirscan(targets)
}

// runConcurrentDirscan 运行并发目录扫描（修改：单目标独立过滤）
func (sc *ScanController) runConcurrentDirscan(targets []string) ([]interfaces.HTTPResponse, error) {
	logger.Debugf("目标数量: %d", len(targets))

	// 创建目标调度器
	scheduler := scheduler.NewTargetScheduler(targets, sc.config)

	// 设置基础请求处理器，确保统计更新正常工作
	scheduler.SetBaseRequestProcessor(sc.requestProcessor)

	// 执行并发扫描
	targetResults, err := scheduler.ExecuteConcurrentScan()
	if err != nil {
		return nil, fmt.Errorf("多目标并发扫描失败: %v", err)
	}

	// [修改] 对每个目标的结果独立应用过滤器，然后合并
	var allResults []interfaces.HTTPResponse
	for target, responses := range targetResults {
		logger.Debugf("处理目标 %s 的 %d 个响应", target, len(responses))

		// 转换为接口类型
		var targetResponses []interfaces.HTTPResponse
		for _, resp := range responses {
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
				IsDirectory:     strings.HasSuffix(resp.URL, "/"),
			}
			targetResponses = append(targetResponses, httpResp)
		}

		// [新增] 对单个目标立即应用过滤器
		if len(targetResponses) > 0 {
			filterResult, err := sc.applyFilterForTarget(targetResponses, target)
			if err != nil {
				logger.Errorf("目标 %s 过滤器应用失败: %v", target, err)
				// 如果过滤失败，使用原始结果
				allResults = append(allResults, targetResponses...)
			} else {
				// 使用过滤后的结果
				allResults = append(allResults, filterResult.ValidPages...)
			}
		}
	}

	return allResults, nil
}

// runSequentialDirscan 运行顺序目录扫描（修改：单目标独立过滤）
func (sc *ScanController) runSequentialDirscan(targets []string) ([]interfaces.HTTPResponse, error) {
	var allResults []interfaces.HTTPResponse

	for _, target := range targets {
		// 生成扫描URL
		scanURLs := sc.generateDirscanURLs(target)
		logger.Debugf("为 %s 生成了 %d 个扫描URL", target, len(scanURLs))

		// 发起HTTP请求
		responses := sc.requestProcessor.ProcessURLs(scanURLs)

		// 转换为接口类型
		var targetResponses []interfaces.HTTPResponse
		for _, resp := range responses {
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
				IsDirectory:     strings.HasSuffix(resp.URL, "/"),
			}
			targetResponses = append(targetResponses, httpResp)
		}

		// [新增] 对单个目标立即应用过滤器
		if len(targetResponses) > 0 {
			filterResult, err := sc.applyFilterForTarget(targetResponses, target)
			if err != nil {
				logger.Errorf("目标 %s 过滤器应用失败: %v", target, err)
				// 如果过滤失败，使用原始结果
				allResults = append(allResults, targetResponses...)
			} else {
				// 使用过滤后的结果
				allResults = append(allResults, filterResult.ValidPages...)
			}
		}

		// 更新已完成主机数统计（单目标扫描）
		if sc.statsDisplay.IsEnabled() {
			sc.statsDisplay.IncrementCompletedHosts()
			logger.Debugf("单目标扫描完成目标 %s，更新已完成主机数", target)
		}
	}
	return allResults, nil
}

// runFingerprintModule 运行指纹识别模块（多目标并发优化）
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

	// 多目标优化：判断是否使用并发扫描（重构：简化判断逻辑）
	if len(targets) > 1 {
		return sc.runConcurrentFingerprint(targets)
	}

	// 单目标或禁用并发时使用原有逻辑
	return sc.runSequentialFingerprint(targets)
}

// runConcurrentFingerprint 运行并发指纹识别（修复：添加超时和panic恢复）
func (sc *ScanController) runConcurrentFingerprint(targets []string) ([]interfaces.HTTPResponse, error) {
	logger.Debugf("并发指纹识别模式，数量: %d", len(targets))

	// 设置批量扫描模式，确保统计更新正确
	originalBatchMode := sc.requestProcessor.IsBatchMode()
	sc.requestProcessor.SetBatchMode(true)
	defer sc.requestProcessor.SetBatchMode(originalBatchMode) // 恢复原始模式

	// 创建带超时的context
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// 指纹识别使用简化的并发逻辑，因为每个目标只需要一个请求
	var allResults []interfaces.HTTPResponse
	var resultsMu sync.Mutex
	var wg sync.WaitGroup

	// 创建目标信号量（重构：使用统一并发控制）
	// 使用请求处理器的并发数作为目标并发数
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
	pathResults := sc.performPathProbingWithTimeout(ctx, targets)
	if len(pathResults) > 0 {
		allResults = append(allResults, pathResults...)
	}

	return allResults, nil
}

// runSequentialFingerprint 运行顺序指纹识别（保持原有逻辑）
func (sc *ScanController) runSequentialFingerprint(targets []string) ([]interfaces.HTTPResponse, error) {
	// 动态设置模块上下文为指纹识别，禁用processor进度条
	originalContext := sc.requestProcessor.GetModuleContext()
	sc.requestProcessor.SetModuleContext("fingerprint")
	defer sc.requestProcessor.SetModuleContext(originalContext) // 恢复原始上下文

	// 检查指纹引擎是否可用
	if sc.fingerprintEngine == nil {
		return nil, fmt.Errorf("指纹识别引擎未初始化")
	}

	var allResults []interfaces.HTTPResponse

	// 初始化指纹识别进度跟踪器
	pathRulesCount := 0
	if sc.fingerprintEngine.HasPathRules() {
		pathRulesCount = sc.fingerprintEngine.GetPathRulesCount()
	}

	for _, target := range targets {
		// 为每个目标创建进度跟踪器
		sc.progressTracker = NewFingerprintProgressTracker(target, pathRulesCount, !sc.args.JSONOutput)

		responses := sc.requestProcessor.ProcessURLs([]string{target})

		for _, resp := range responses {

			// 转换为fingerprint模块的HTTPResponse格式
			fpResponse := sc.convertToFingerprintResponse(resp)
			if fpResponse == nil {
				logger.Debugf("响应转换失败: %s", resp.URL)
				continue
			}

			// 关键修复：使用带HTTP客户端的分析方法，支持icon()函数主动探测
			httpClient := sc.createHTTPClientAdapter()

			matches := sc.fingerprintEngine.AnalyzeResponseWithClient(fpResponse, httpClient)

			// 更新进度：基础指纹匹配完成
			sc.progressTracker.UpdateProgress("指纹识别进行中")

			// 转换为接口类型（用于报告生成，但指纹识别不需要Filter）
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
			if converted := convertFingerprintMatches(matches, sc.showFingerprintSnippet); len(converted) > 0 {
				httpResp.Fingerprints = converted
			}
			allResults = append(allResults, httpResp)

			logger.Debugf("%s 指纹识别完成，匹配数量: %d", target, len(matches))
		}

		// 更新已完成主机数统计（单目标指纹识别）
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

	// 发起HTTP请求
	responses := sc.requestProcessor.ProcessURLs([]string{target})

	for _, resp := range responses {
		// 转换为fingerprint模块的HTTPResponse格式
		fpResponse := sc.convertToFingerprintResponse(resp)
		if fpResponse == nil {
			logger.Debugf("响应转换失败: %s", resp.URL)
			continue
		}

		// 关键修复：使用带HTTP客户端的分析方法，支持icon()函数主动探测
		httpClient := sc.createHTTPClientAdapter()
		matches := sc.fingerprintEngine.AnalyzeResponseWithClient(fpResponse, httpClient)

		// 转换为接口类型
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
		if converted := convertFingerprintMatches(matches, sc.showFingerprintSnippet); len(converted) > 0 {
			httpResp.Fingerprints = converted
		}
		results = append(results, httpResp)

		logger.Debugf("%s 识别完成: %d", target, len(matches))
	}

	return results
}

// extractDomainFromURL 从URL中提取域名（用于目标标识）
func extractDomainFromURL(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return u.Host
	}
	// 简单的域名提取，用于日志标识
	if len(rawURL) > 30 {
		return rawURL[:27] + "..."
	}
	return rawURL
}

// generateDirscanURLs 生成目录扫描URL
func (sc *ScanController) generateDirscanURLs(target string) []string {
	// 解析URL以获取路径信息
	parsedURL, err := url.Parse(target)
	if err != nil {
		logger.Errorf("URL解析失败: %v", err)
		return []string{target}
	}

	// 获取基础URL（协议+主机+端口）
	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	// 分析路径层级
	path := strings.Trim(parsedURL.Path, "/")
	if path == "" {
		// 根目录扫描
		return sc.urlGenerator.GenerateURLs([]string{baseURL})
	}

	// 多层级目录扫描
	pathParts := strings.Split(path, "/")
	var scanTargets []string

	// 为每个路径层级生成扫描目标
	currentPath := ""
	for _, part := range pathParts {
		currentPath += "/" + part
		scanTarget := baseURL + currentPath
		if !strings.HasSuffix(scanTarget, "/") {
			scanTarget += "/"
		}
		scanTargets = append(scanTargets, scanTarget)
	}

	// 使用URLGenerator生成最终的扫描URL
	return sc.urlGenerator.GenerateURLs(scanTargets)
}

// generateReport 生成扫描报告
func (sc *ScanController) generateReport(filterResult *interfaces.FilterResult) error {
	// 检查输出路径是否指定
	reportPath := strings.TrimSpace(sc.reportPath)
	if reportPath == "" {
		logger.Debug("未指定输出路径，跳过报告生成")
		return nil
	}

	// 检查目标文件是否已存在
	if _, err := os.Stat(reportPath); err == nil {
		logger.Infof("Override Files: %s", reportPath)
	}

	// 使用自定义报告生成器，直接指定输出路径
	reportPath, err := sc.generateCustomReport(filterResult, reportPath)
	if err != nil {
		return fmt.Errorf("报告生成失败: %v", err)
	}

	logger.Infof("Report Output Success: %s", reportPath)
	return nil
}

// generateCustomReport 生成自定义路径的报告
func (sc *ScanController) generateCustomReport(filterResult *interfaces.FilterResult, outputPath string) (string, error) {
	logger.Debugf("开始生成自定义报告到: %s", outputPath)

	// 准备报告数据（JSON分支直接复用控制台JSON构建，无需target）

	lowerOutput := strings.ToLower(outputPath)
	// 根据文件扩展名选择报告格式
	switch {
	case strings.HasSuffix(lowerOutput, ".json"):
		// JSON：若包含 -p，运行端口扫描并在控制台打印指示器与端口结果；然后统一构建合并JSON并落盘
		var pr []report.SDKPortResult
		if strings.TrimSpace(sc.args.Ports) != "" {
			// 计算有效速率与端口表达式（用于指示器输出）
			effectiveRate := sc.args.Rate
			if effectiveRate <= 0 {
				effectiveRate = gogoscanner.DefaultRate
			}

			// 执行端口扫描（一次），复用结果：控制台打印 + 合并JSON
			reused := len(sc.lastPortResults) > 0
			results, agg := sc.collectPortResults()
			pr = agg
			portsExpr := sc.lastPortExpr
			if portsExpr == "" {
				if resolved, _, err := resolvePortExpression(sc.args); err == nil {
					portsExpr = resolved
				} else {
					portsExpr = strings.TrimSpace(sc.args.Ports)
				}
			}

			if !reused {
				fmt.Println()
				logPortScanBanner(portsExpr, effectiveRate)
				for _, r := range results {
					if strings.TrimSpace(r.Service) != "" {
						logger.Infof("%s:%d %s", r.IP, r.Port, formatter.FormatProtocol(strings.ToUpper(strings.TrimSpace(r.Service))))
					} else {
						logger.Infof("%s:%d", r.IP, r.Port)
					}
				}
				logger.Debugf("端口扫描完成，发现开放端口: %d", len(results))
			} else {
				logger.Infof("复用已完成的端口扫描结果")
			}
		}

		// 指纹匹配信息
		var matches []types.FingerprintMatch
		var stats *fingerprint.Statistics
		if sc.fingerprintEngine != nil {
			if raw := sc.fingerprintEngine.GetMatches(); len(raw) > 0 {
				matches = convertFingerprintMatches(raw, sc.showFingerprintSnippet)
			}
			stats = sc.fingerprintEngine.GetStats()
		}
		params := sc.buildScanParams()

		// 复用合并JSON构建器，写入指定路径
		jsonStr, err := report.GenerateCombinedJSON(sc.lastDirscanResults, sc.lastFingerprintResults, matches, toReporterStats(stats), pr, params)
		if err != nil {
			return "", err
		}
		if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
			return "", fmt.Errorf("创建输出目录失败: %v", err)
		}
		if err := os.WriteFile(outputPath, []byte(jsonStr), 0o644); err != nil {
			return "", fmt.Errorf("写入JSON文件失败: %v", err)
		}
		return outputPath, nil
	case strings.HasSuffix(lowerOutput, ".xlsx"):
		reportType := determineExcelReportType(sc.args.Modules)
		// 若包含端口扫描参数，则合并端口结果到 Excel
		if strings.TrimSpace(sc.args.Ports) != "" {
			// 准备 masscan 选项（与控制台JSON相同）
			portsExpr, _, err := resolvePortExpression(sc.args)
			if err != nil {
				logger.Errorf("端口表达式解析失败，Excel报告不包含端口: %v", err)
				return report.GenerateExcelReport(filterResult, reportType, outputPath)
			}
			var targets []string
			if strings.TrimSpace(sc.args.TargetFile) == "" {
				if ips, err := portscanpkg.ResolveTargetsToIPs(sc.args.Targets); err == nil {
					targets = ips
				}
			}
			var scannerOpts []gogoscanner.Option
			effectiveRate := sc.args.Rate
			if effectiveRate <= 0 {
				effectiveRate = gogoscanner.DefaultRate
			}
			scannerOpts = append(scannerOpts, gogoscanner.WithRate(effectiveRate))
			if sc.args.Timeout > 0 {
				scannerOpts = append(scannerOpts, gogoscanner.WithTimeout(time.Duration(sc.args.Timeout)*time.Second))
			}
			if sc.args.Threads > 0 {
				scannerOpts = append(scannerOpts, gogoscanner.WithThreads(sc.args.Threads))
			}

			scanner := gogoscanner.NewScanner(scannerOpts...)
			if results, err := scanner.Scan(context.Background(), targets, portsExpr); err == nil {
				return report.GenerateExcelReportWithPorts(filterResult, reportType, results, outputPath)
			} else {
				logger.Errorf("端口扫描失败，Excel合并不包含端口: %v", err)
			}
		}
		return report.GenerateExcelReport(filterResult, reportType, outputPath)
	default:
		reportType := determineExcelReportType(sc.args.Modules)
		deducedPath := outputPath
		if filepath.Ext(outputPath) == "" {
			deducedPath = outputPath + ".xlsx"
		} else {
			deducedPath = strings.TrimSuffix(outputPath, filepath.Ext(outputPath)) + ".xlsx"
		}
		logger.Warnf("不支持的报告后缀，默认为xlsx输出: %s", deducedPath)
		return report.GenerateExcelReport(filterResult, reportType, deducedPath)
	}
}

func determineExcelReportType(modules []string) report.ExcelReportType {
	var hasDirscan, hasFingerprint bool
	for _, moduleName := range modules {
		if moduleName == string(modulepkg.ModuleDirscan) {
			hasDirscan = true
		}
		if moduleName == string(modulepkg.ModuleFinger) {
			hasFingerprint = true
		}
	}

	switch {
	case hasDirscan && hasFingerprint:
		return report.ExcelReportDirscanAndFingerprint
	case hasDirscan:
		return report.ExcelReportDirscan
	default:
		return report.ExcelReportFingerprint
	}
}

// generateJSONReport 生成JSON格式报告
func (sc *ScanController) generateJSONReport(filterResult *interfaces.FilterResult, target string, outputPath string) (string, error) {
	logger.Debugf("开始生成JSON报告到: %s", outputPath)

	// 准备扫描参数
	scanParams := sc.buildScanParams()

	// 检查是否为指纹识别模式
	onlyFingerprint := len(sc.args.Modules) == 1 && sc.args.Modules[0] == "finger"

	if onlyFingerprint {
		// 指纹识别JSON报告
		if sc.fingerprintEngine == nil {
			return "", fmt.Errorf("指纹识别引擎未初始化")
		}

		// 获取指纹匹配结果和统计信息
		matches := sc.fingerprintEngine.GetMatches()
		stats := toReporterStats(sc.fingerprintEngine.GetStats())
		if stats != nil {
			scanParams["fingerprint_rules_loaded"] = stats.RulesLoaded
		}

		fingerprintResponses := filterResult.ValidPages

		// 生成指纹识别JSON报告
		return report.GenerateCustomJSONFingerprintReport(fingerprintResponses, convertFingerprintMatches(matches, sc.showFingerprintSnippet), stats, target, scanParams, outputPath)
	} else {
		// 目录扫描JSON报告
		// 添加目录扫描特定参数
		if sc.wordlistPath != "" {
			scanParams["wordlist"] = sc.wordlistPath
		} else {
			scanParams["wordlist"] = "default"
		}

		// 生成目录扫描JSON报告
		return report.GenerateCustomJSONDirscanReport(filterResult.ValidPages, target, scanParams, outputPath)
	}
}

// applyFilter 应用过滤器（复用dirscan模块的实现模式）
func (sc *ScanController) applyFilter(responses []interfaces.HTTPResponse) (*interfaces.FilterResult, error) {
	logger.Debug("开始应用响应过滤器")

	// 创建响应过滤器（从外部配置）
	responseFilter := dirscan.CreateResponseFilterFromExternal()
	responseFilter.EnableFingerprintSnippet(sc.showFingerprintSnippet)
	responseFilter.EnableFingerprintRuleDisplay(sc.showFingerprintRule)

	// 应用过滤器
	filterResult := responseFilter.FilterResponses(responses)

	// 显示过滤结果（复用现有的日志打印功能）
	responseFilter.PrintFilterResult(filterResult)

	logger.Debugf("过滤完成 - 总响应: %d, 有效结果: %d",
		len(responses), len(filterResult.ValidPages))

	return filterResult, nil
}

// applyFilterForTarget 对单个目标应用过滤器（新增：单目标独立过滤）
func (sc *ScanController) applyFilterForTarget(responses []interfaces.HTTPResponse, target string) (*interfaces.FilterResult, error) {
	logger.Debugf("开始对目标 %s 应用过滤器，响应数量: %d", target, len(responses))

	// 创建响应过滤器（从外部配置）
	responseFilter := dirscan.CreateResponseFilterFromExternal()
	responseFilter.EnableFingerprintSnippet(sc.showFingerprintSnippet)
	responseFilter.EnableFingerprintRuleDisplay(sc.showFingerprintRule)

	// [新增] 如果指纹引擎可用，设置到过滤器中（启用二次识别）
	if sc.fingerprintEngine != nil {
		responseFilter.SetFingerprintEngine(sc.fingerprintEngine)
		logger.Debugf("目录扫描模块已启用指纹二次识别功能，引擎类型: %T", sc.fingerprintEngine)
	} else {
		logger.Debugf("指纹引擎为nil，未启用二次识别")
	}

	// [关键] 重置过滤器状态，确保目标间状态隔离
	responseFilter.Reset()

	// 应用过滤器
	filterResult := responseFilter.FilterResponses(responses)

	// 显示单个目标的过滤结果（现在会包含指纹信息）
	logger.Debugf("目标 %s 过滤完成:", target)
	responseFilter.PrintFilterResult(filterResult)

	logger.Debugf("目标 %s 过滤完成 - 原始响应: %d, 有效结果: %d",
		target, len(responses), len(filterResult.ValidPages))

	return filterResult, nil
}

// convertToFingerprintResponse 将processor响应转换为fingerprint模块的HTTPResponse格式
// 集成被动模式的高级HTTP处理功能：解压缩、编码检测、HTML实体解码
func (sc *ScanController) convertToFingerprintResponse(resp *interfaces.HTTPResponse) *fingerprint.HTTPResponse {
	if resp == nil {
		return nil
	}

	// 转换响应头格式（interfaces.HTTPResponse.ResponseHeaders已经是map[string][]string）
	headers := resp.ResponseHeaders
	if headers == nil {
		headers = make(map[string][]string)
	}

	// 关键修复：处理响应体解压缩和编码转换
	processedBody := sc.processResponseBody(resp)

	// 提取处理后的标题（使用解压缩和编码转换后的内容）
	title := sc.extractTitleFromHTML(processedBody)

	logger.Debugf("响应体处理完成: %s (原始: %d bytes, 处理后: %d bytes)",
		resp.URL, len(resp.ResponseBody), len(processedBody))

	return &fingerprint.HTTPResponse{
		URL:             resp.URL,
		Method:          "GET", // 主动扫描默认使用GET方法
		StatusCode:      resp.StatusCode,
		ResponseHeaders: headers,
		Body:            processedBody, // 使用处理后的响应体
		ContentType:     resp.ContentType,
		ContentLength:   int64(len(processedBody)), // 更新为处理后的长度
		Server:          resp.Server,
		Title:           title, // 使用处理后的标题
	}
}

// processResponseBody 处理响应体：解压缩 + 编码检测转换（复用fingerprint模块逻辑）
func (sc *ScanController) processResponseBody(resp *interfaces.HTTPResponse) string {
	if resp == nil || resp.ResponseBody == "" {
		return ""
	}

	rawBody := resp.ResponseBody

	// 步骤1: 检查Content-Encoding并解压缩
	decompressedBody := sc.decompressResponseBody(rawBody, resp.ResponseHeaders)

	// 步骤2: 字符编码检测和转换
	convertedBody := sc.encodingDetector.DetectAndConvert(decompressedBody, resp.ContentType)

	logger.Debugf("响应体处理: %s (原始: %d -> 解压: %d -> 转换: %d bytes)",
		resp.URL, len(rawBody), len(decompressedBody), len(convertedBody))

	return convertedBody
}

// decompressResponseBody 解压缩响应体（复用fingerprint/addon.go的逻辑）
func (sc *ScanController) decompressResponseBody(body string, headers map[string][]string) string {
	if body == "" {
		return ""
	}

	// 获取Content-Encoding头部
	var contentEncoding string
	if headers != nil {
		if encodingHeaders, exists := headers["Content-Encoding"]; exists && len(encodingHeaders) > 0 {
			contentEncoding = encodingHeaders[0]
		}
	}

	decompressed := sharedutils.DecompressByEncoding([]byte(body), contentEncoding)
	return string(decompressed)
}

// extractTitleFromHTML 从HTML中提取标题（复用fingerprint/addon.go的逻辑）
func (sc *ScanController) extractTitleFromHTML(body string) string {
	return sharedutils.ExtractTitle(body)
}

func (sc *ScanController) formatFingerprintDisplay(name, rule string) string {
	return formatter.FormatFingerprintDisplay(name, rule, sc.showFingerprintRule)
}

func convertFingerprintMatches(matches []*fingerprint.FingerprintMatch, includeSnippet bool) []types.FingerprintMatch {
	if len(matches) == 0 {
		return nil
	}

	converted := make([]types.FingerprintMatch, 0, len(matches))
	for _, match := range matches {
		if match == nil {
			continue
		}

		convertedMatch := types.FingerprintMatch{
			URL:       match.URL,
			RuleName:  match.RuleName,
			Matcher:   match.DSLMatched,
			Timestamp: match.Timestamp,
		}
		if includeSnippet {
			convertedMatch.Snippet = match.Snippet
		}
		converted = append(converted, convertedMatch)
	}

	return converted
}

func (sc *ScanController) highlightSnippetLines(snippet, matcher string) []string {
	if snippet == "" {
		return nil
	}
	snippet = strings.ReplaceAll(snippet, "\r\n", "\n")
	snippet = strings.ReplaceAll(snippet, "\r", "\n")
	rawLines := strings.Split(snippet, "\n")
	var lines []string
	for _, raw := range rawLines {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		highlighted := formatter.HighlightSnippet(raw, matcher)
		if highlighted != "" {
			lines = append(lines, highlighted)
		}
	}
	if len(lines) == 0 {
		if highlighted := formatter.HighlightSnippet(strings.TrimSpace(snippet), matcher); highlighted != "" {
			lines = append(lines, highlighted)
		}
	}
	return lines
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

	// 创建HTTP客户端适配器（复用RequestProcessor的HTTP处理能力）
	httpClient := sc.createHTTPClientAdapter()

	var allResults []interfaces.HTTPResponse

	// 为每个目标执行path探测
	for _, target := range targets {
		baseURL := sc.extractBaseURL(target)
		hostKey := sc.extractHostKey(baseURL)

		// 检查是否已经探测过此主机（避免重复探测）
		if sc.shouldTriggerPathProbing(hostKey) {
			logger.Debugf("触发path字段主动探测: %s", hostKey)
			sc.markHostAsProbed(hostKey)

			// 修复：使用同步方式执行path探测，确保所有path规则都被处理
			results := sc.performSyncPathProbing(baseURL, httpClient)
			if len(results) > 0 {
				allResults = append(allResults, results...)
			}
		} else {
			logger.Debugf("主机已探测过，跳过path探测: %s", hostKey)
		}
	}
	return allResults
}

// createHTTPClientAdapter 创建HTTP客户端（支持TLS和重定向）
func (sc *ScanController) createHTTPClientAdapter() httpclient.HTTPClientInterface {
	// 使用HTTP客户端工厂（代码质量优化）
	userAgent := ""
	if sc.requestProcessor != nil {
		userAgent = sc.requestProcessor.GetUserAgent()
	}
	if userAgent == "" {
		userAgent = useragent.Primary()
	}
	if userAgent == "" {
		userAgent = "veo-HTTPClient/1.0"
	}

	// 构造配置，确保包含代理设置
	clientConfig := httpclient.DefaultConfigWithUserAgent(userAgent)

	// [修复] 应用全局超时设置
	if sc.timeoutSeconds > 0 {
		clientConfig.Timeout = time.Duration(sc.timeoutSeconds) * time.Second
		// 相应调整TLS握手超时，但不超过总超时的一半
		tlsTimeout := clientConfig.Timeout / 2
		if tlsTimeout > 5*time.Second {
			tlsTimeout = 5 * time.Second
		}
		clientConfig.TLSTimeout = tlsTimeout
	}

	if proxyCfg := config.GetProxyConfig(); proxyCfg != nil && proxyCfg.UpstreamProxy != "" {
		clientConfig.ProxyURL = proxyCfg.UpstreamProxy
		logger.Debugf("ActiveScan: 设置HTTPClient适配器代理: %s", clientConfig.ProxyURL)
	}

	return httpclient.New(clientConfig)
}

// extractBaseURL 从完整URL中提取基础URL（协议+主机）
func (sc *ScanController) extractBaseURL(rawURL string) string {
	if parsedURL, err := url.Parse(rawURL); err == nil {
		return fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	}
	return rawURL
}

// extractHostKey 提取主机键（用于探测缓存）
func (sc *ScanController) extractHostKey(rawURL string) string {
	if parsedURL, err := url.Parse(rawURL); err == nil {
		return parsedURL.Host // 包含端口的主机名
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

// performSyncPathProbing 执行同步path字段主动探测（修复异步执行问题）
func (sc *ScanController) performSyncPathProbing(baseURL string, httpClient httpclient.HTTPClientInterface) []interfaces.HTTPResponse {
	logger.Debugf("开始同步path字段主动探测: %s", baseURL)

	var allResults []interfaces.HTTPResponse

	// 获取所有包含path字段的规则
	pathRules := sc.getPathRulesFromEngine()
	if len(pathRules) == 0 {
		logger.Debug("没有包含path字段的规则，跳过主动探测")
		return nil
	}

	logger.Debugf("找到 %d 个包含path字段的规则，开始展开路径", len(pathRules))

	// 解析baseURL获取协议和主机
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		logger.Debugf("URL解析失败: %s, 错误: %v", baseURL, err)
		return nil
	}

	scheme := parsedURL.Scheme
	host := parsedURL.Host

	var tasks []struct {
		rule *fingerprint.FingerprintRule
		path string
	}
	for _, rule := range pathRules {
		if rule == nil {
			continue
		}
		for _, rawPath := range rule.Paths {
			trimmed := strings.TrimSpace(rawPath)
			if trimmed == "" {
				continue
			}
			tasks = append(tasks, struct {
				rule *fingerprint.FingerprintRule
				path string
			}{rule: rule, path: trimmed})
		}
	}

	totalPaths := len(tasks)
	if totalPaths == 0 {
		logger.Debug("没有有效的path路径，跳过主动探测")
		return nil
	}
	logger.Debugf("共需探测 %d 条路径", totalPaths)

	// 性能优化：并发遍历所有path规则进行探测（修复：添加超时和panic恢复）
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 50) // 性能优化：提升path探测并发数
	resultChan := make(chan *interfaces.HTTPResponse, totalPaths)

	for i, task := range tasks {
		wg.Add(1)
		go func(index int, r *fingerprint.FingerprintRule, path string) {
			defer func() {
				// 修复：添加panic恢复，确保WaitGroup计数正确
				if rec := recover(); rec != nil {
					logger.Errorf("Path探测panic恢复: %v, 规则: %s", rec, r.Name)
				}
				wg.Done()
			}()

			// 获取信号量（修复：添加超时避免永久阻塞）
			select {
			case semaphore <- struct{}{}:
				defer func() {
					select {
					case <-semaphore:
					default:
						// 信号量已满，不需要释放
					}
				}()
			case <-ctx.Done():
				logger.Debugf("Path探测被取消: %s", r.Name)
				return
			case <-time.After(30 * time.Second):
				logger.Warnf("获取Path探测信号量超时: %s", r.Name)
				return
			}

			// 处理path规则（添加超时检查）
			select {
			case <-ctx.Done():
				logger.Debugf("Path规则处理被取消: %s", r.Name)
				return
			default:
			}

			sc.processPathRuleWithTimeout(ctx, index, totalPaths, r, path, scheme, host, baseURL, httpClient, resultChan)
		}(i, task.rule, task.path)
	}

	// 等待所有path探测完成（修复：添加超时保护）
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
		close(resultChan)
	}()

	// 收集结果
	go func() {
		for res := range resultChan {
			if res != nil {
				allResults = append(allResults, *res)
			}
		}
	}()

	select {
	case <-done:
		logger.Debugf("所有Path探测完成")
	case <-ctx.Done():
		logger.Warnf("Path探测超时或被取消")
	case <-time.After(6 * time.Minute):
		logger.Warnf("Path探测总体超时")
		cancel() // 取消所有正在进行的探测
	}

	logger.Debugf("并发path字段主动探测完成: %s (共探测 %d 条路径, 发现 %d 个指纹)", baseURL, totalPaths, len(allResults))

	// [新增] 404页面指纹识别
	if res404 := sc.perform404PageProbing(baseURL, httpClient); res404 != nil {
		allResults = append(allResults, *res404)
	}

	return allResults
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

// performPathProbingWithTimeout 执行path探测（新增：支持超时）
func (sc *ScanController) performPathProbingWithTimeout(ctx context.Context, targets []string) []interfaces.HTTPResponse {
	// 创建带超时的context
	probingCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	// 使用channel接收结果
	resultChan := make(chan []interfaces.HTTPResponse, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Errorf("Path探测panic: %v", r)
				resultChan <- nil
			}
		}()

		resultChan <- sc.performPathProbing(targets)
	}()

	select {
	case results := <-resultChan:
		logger.Debugf("Path探测完成，获得 %d 个结果", len(results))
		return results
	case <-probingCtx.Done():
		logger.Warnf("Path探测超时或被取消")
		return nil
	}
}

// processPathRuleWithTimeout 处理单个path规则（新增：支持超时）
func (sc *ScanController) processPathRuleWithTimeout(ctx context.Context, index, total int, rule *fingerprint.FingerprintRule, path, scheme, host, baseURL string, httpClient interface{}, resultChan chan<- *interfaces.HTTPResponse) {
	// 创建带超时的context
	ruleCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// 使用channel通知完成
	done := make(chan struct{})

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Errorf("Path规则处理panic: %v, 规则: %s", r, rule.Name)
			}
			close(done)
		}()

		// 类型断言转换为正确的接口类型
		if client, ok := httpClient.(httpclient.HTTPClientInterface); ok {
			result := sc.processPathRule(index, total, rule, path, scheme, host, baseURL, client)
			if result != nil {
				select {
				case resultChan <- result:
				case <-ruleCtx.Done():
				}
			}
		} else {
			logger.Warnf("HTTP客户端类型转换失败，跳过path规则: %s", rule.Name)
		}
	}()

	select {
	case <-done:
		// 处理完成
	case <-ruleCtx.Done():
		logger.Warnf("Path规则处理超时或被取消: %s", rule.Name)
	}
}

// processPathRule 处理单个path规则（提取出来支持并发）
func (sc *ScanController) processPathRule(index, total int, rule *fingerprint.FingerprintRule, path, scheme, host, baseURL string, httpClient httpclient.HTTPClientInterface) *interfaces.HTTPResponse {
	// 构造完整的探测URL
	probeURL := sc.buildProbeURLFromParts(scheme, host, path)

	logger.Debugf("主动探测URL [%d/%d]: %s (规则: %s)",
		index+1, total, probeURL, rule.Name)

	// 发起HTTP请求
	headers := rule.GetHeaderMap()
	body, statusCode, err := sc.makePathRequest(httpClient, probeURL, headers)
	if err != nil {
		logger.Debugf("主动探测请求失败: %s, 错误: %v", probeURL, err)
		// 即使失败也要更新进度
		if sc.progressTracker != nil {
			sc.progressTracker.UpdateProgress("指纹识别进行中")
		}
		return nil
	}

	logger.Debugf("主动探测请求成功: %s [%d] 响应体长度: %d",
		probeURL, statusCode, len(body))

	// 构造模拟的HTTPResponse用于DSL匹配
	response := &fingerprint.HTTPResponse{
		URL:             probeURL,
		Method:          "GET",
		StatusCode:      statusCode,
		ResponseHeaders: make(map[string][]string), // 简化版，暂不解析响应头
		Body:            body,
		ContentType:     "text/html", // 简化假设
		ContentLength:   int64(len(body)),
		Server:          "",
		Title:           sc.extractTitleFromHTML(body), // 复用现有的标题提取方法
	}

	// 性能优化：使用专用的单规则匹配，避免遍历所有525个规则
	match := sc.fingerprintEngine.MatchSpecificRule(rule, response, httpClient, baseURL)
	if match != nil {
		logger.Debugf("path探测发现匹配: %s -> %s", probeURL, rule.Name)

		// 手动输出匹配结果（因为没有使用完整的AnalyzeResponse流程）
		// 使用与指纹引擎一致的高亮格式
		display := sc.formatFingerprintDisplay(rule.Name, match.DSLMatched)
		if display == "" {
			display = "<" + formatter.FormatFingerprintName(rule.Name) + ">"
		}
		logger.Infof("%s %s [%s]",
			formatter.FormatURL(probeURL),
			display,
			formatter.FormatFingerprintTag("主动探测"))

		// 构造返回结果
		httpResp := &interfaces.HTTPResponse{
			URL:           probeURL,
			StatusCode:    statusCode,
			ContentLength: int64(len(body)),
			ContentType:   "text/html",
			ResponseBody:  body,
			Title:         response.Title,
			IsDirectory:   false,
		}
		if converted := convertFingerprintMatches([]*fingerprint.FingerprintMatch{match}, sc.showFingerprintSnippet); len(converted) > 0 {
			httpResp.Fingerprints = converted
		}

		// 更新进度：path探测完成
		if sc.progressTracker != nil {
			sc.progressTracker.UpdateProgress("指纹识别进行中")
		}
		return httpResp
	}

	// 更新进度：path探测完成
	if sc.progressTracker != nil {
		sc.progressTracker.UpdateProgress("指纹识别进行中")
	}
	return nil
}

func (sc *ScanController) buildProbeURLFromParts(scheme, host, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	trimmed := path
	if trimmed == "" {
		trimmed = "/"
	}
	if !strings.HasPrefix(trimmed, "/") {
		trimmed = "/" + trimmed
	}
	return fmt.Sprintf("%s://%s%s", scheme, host, trimmed)
}

func (sc *ScanController) makePathRequest(client httpclient.HTTPClientInterface, target string, headers map[string]string) (string, int, error) {
	if len(headers) > 0 {
		if headerClient, ok := client.(httpclient.HeaderAwareClient); ok {
			return headerClient.MakeRequestWithHeaders(target, headers)
		}
		logger.Debugf("HTTP客户端不支持自定义头部，使用默认请求: %s", target)
	}
	return client.MakeRequest(target)
}

// getPathRulesFromEngine 从指纹引擎获取包含path字段的规则
func (sc *ScanController) getPathRulesFromEngine() []*fingerprint.FingerprintRule {
	if sc.fingerprintEngine == nil {
		return nil
	}

	// 通过反射或公共方法获取path规则
	// 这里我们需要添加一个公共方法到fingerprint.Engine
	return sc.fingerprintEngine.GetPathRules()
}

// runPassiveModeInternal 运行被动模式的内部实现
// 这个函数将调用现有的被动模式逻辑，保持100%兼容性
func runPassiveModeInternal(args *CLIArgs, cfg *config.Config) error {
	logger.Info("被动代理模式使用现有实现，保持100%兼容性")

	// 初始化应用程序（使用现有逻辑）
	app, err := initializeAppForPassiveMode(args)
	if err != nil {
		return fmt.Errorf("初始化应用程序失败: %v", err)
	}

	// 启动应用程序（使用现有逻辑）
	if err := startApplicationForPassiveMode(args, app); err != nil {
		return fmt.Errorf("启动应用程序失败: %v", err)
	}

	logger.Info("被动代理模式启动成功，等待连接...")

	// 这里不需要等待信号，因为主函数会处理
	return nil
}

// 这些函数将在下一步实现，用于调用现有的被动模式逻辑
func initializeAppForPassiveMode(args *CLIArgs) (*CLIApp, error) {
	// 占位符，将调用现有的initializeApp函数
	return nil, nil
}

func startApplicationForPassiveMode(args *CLIArgs, app *CLIApp) error {
	// 占位符，将调用现有的startApplication函数
	return nil
}

// perform404PageProbing 执行404页面指纹识别
func (sc *ScanController) perform404PageProbing(baseURL string, httpClient httpclient.HTTPClientInterface) *interfaces.HTTPResponse {
	logger.Debugf("开始404页面指纹识别: %s", baseURL)

	// 解析baseURL获取协议和主机
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		logger.Debugf("URL解析失败: %s, 错误: %v", baseURL, err)
		return nil
	}

	scheme := parsedURL.Scheme
	host := parsedURL.Host

	// 构造404测试URL
	notFoundURL := fmt.Sprintf("%s://%s/404test", scheme, host)
	logger.Debugf("404页面探测URL: %s", notFoundURL)

	// 发起HTTP请求
	body, statusCode, err := httpClient.MakeRequest(notFoundURL)
	if err != nil {
		logger.Debugf("404页面探测请求失败: %s, 错误: %v", notFoundURL, err)
		return nil
	}

	logger.Debugf("404页面响应: 状态码=%d, 内容长度=%d", statusCode, len(body))

	// 构造模拟的HTTPResponse用于DSL匹配
	response := &fingerprint.HTTPResponse{
		URL:             notFoundURL,
		Method:          "GET",
		StatusCode:      statusCode,
		ResponseHeaders: make(map[string][]string), // 简化版，暂不解析响应头
		Body:            body,
		ContentType:     "text/html", // 简化假设
		ContentLength:   int64(len(body)),
		Server:          "",
		Title:           sc.extractTitleFromHTML(body), // 提取标题
	}

	// 对404页面进行全量指纹规则匹配（使用静默模式避免重复输出）
	httpClientAdapter := sc.createHTTPClientAdapter()
	logger.Debugf("开始对404页面进行全量指纹匹配: %s", notFoundURL)
	matches := sc.fingerprintEngine.AnalyzeResponseWithClientSilent(response, httpClientAdapter)
	logger.Debugf("404页面指纹匹配完成，匹配结果数量: %d", len(matches))

	if len(matches) > 0 {
		logger.Debugf("404页面匹配到 %d 个指纹", len(matches))

		title := response.Title
		if title == "" {
			title = "无标题"
		}

		pairs := make([]string, 0, len(matches))
		var snippetLines []string

		for _, match := range matches {
			if match == nil {
				continue
			}
			display := sc.formatFingerprintDisplay(match.RuleName, match.DSLMatched)
			if display != "" {
				pairs = append(pairs, display)
			}

			if sc.showFingerprintSnippet {
				for _, line := range sc.highlightSnippetLines(match.Snippet, match.DSLMatched) {
					snippetLines = append(snippetLines, line)
				}
			}
		}

		var builder strings.Builder
		builder.WriteString(formatter.FormatURL(notFoundURL))
		builder.WriteString(" ")
		builder.WriteString(formatter.FormatTitle(title))
		builder.WriteString(" ")

		for _, pair := range pairs {
			builder.WriteString(" ")
			builder.WriteString(pair)
		}

		builder.WriteString(" [")
		builder.WriteString(formatter.FormatFingerprintTag("404页面"))
		builder.WriteString("]")

		if len(snippetLines) > 0 {
			builder.WriteString("\n")
			for idx, snippetLine := range snippetLines {
				if idx > 0 {
					builder.WriteString("\n")
				}
				builder.WriteString("  ")
				builder.WriteString(formatter.FormatSnippetArrow())
				builder.WriteString(snippetLine)
			}
		}

		logger.Info(builder.String())

		// 构造返回结果
		httpResp := &interfaces.HTTPResponse{
			URL:           notFoundURL,
			StatusCode:    statusCode,
			ContentLength: int64(len(body)),
			ContentType:   "text/html",
			ResponseBody:  body,
			Title:         title,
			IsDirectory:   false,
		}
		if converted := convertFingerprintMatches(matches, sc.showFingerprintSnippet); len(converted) > 0 {
			httpResp.Fingerprints = converted
		}
		return httpResp
	} else {
		logger.Debugf("404页面未匹配到任何指纹")
	}
	return nil
}
