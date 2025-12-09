package cli

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"veo/internal/core/config"
	modulepkg "veo/pkg/core/module"
	"veo/pkg/dirscan"
	"veo/pkg/fingerprint"
	"veo/pkg/utils/httpclient"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
	requests "veo/pkg/utils/processor"
	"veo/pkg/utils/stats"
)

// toReporterStats 和 convertFingerprintMatches 已移动到 report.go 以实现共享

// ScanMode 扫描模式
type ScanMode int

const (
	ActiveMode ScanMode = iota
	PassiveMode
)

// ScanController 扫描控制器
type ScanController struct {
	mode                   ScanMode
	args                   *CLIArgs
	config                 *config.Config
	requestProcessor       *requests.RequestProcessor
	urlGenerator           *dirscan.URLGenerator
	fingerprintEngine      *fingerprint.Engine           // 指纹识别引擎
	encodingDetector       *fingerprint.EncodingDetector // 编码检测器
	probedHosts            map[string]bool               // 已探测的主机缓存（用于path探测去重）
	probedMutex            sync.RWMutex                  // 探测缓存锁
	progressTracker        *FingerprintProgressTracker   // 指纹识别进度跟踪器
	statsDisplay           *stats.StatsDisplay           // 统计显示器
	lastTargets            []string                      // 最近解析的目标列表
	showFingerprintSnippet bool                          // 是否展示指纹匹配内容
	showFingerprintRule    bool                          // 是否展示指纹匹配规则
	maxConcurrent          int
	retryCount             int
	timeoutSeconds         int
	reportPath             string
	wordlistPath           string

	lastDirscanResults     []interfaces.HTTPResponse
	lastFingerprintResults []interfaces.HTTPResponse
	httpClient             httpclient.HTTPClientInterface // 共享的HTTP客户端

	// 全局去重，防止递归扫描中出现重复的结果
	displayedURLs   map[string]bool
	displayedURLsMu sync.Mutex

	// 站点过滤器缓存，确保同一站点的过滤器状态（Hash记录）跨递归层级共享
	siteFilters   map[string]*dirscan.ResponseFilter
	siteFiltersMu sync.Mutex

	// 收集被过滤的结果（用于报告生成）
	collectedPrimaryFiltered []interfaces.HTTPResponse
	collectedStatusFiltered  []interfaces.HTTPResponse
	collectedResultsMu       sync.Mutex
}

func NewScanController(args *CLIArgs, cfg *config.Config) *ScanController {
	mode := ActiveMode
	if args.Listen {
		mode = PassiveMode
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
	requestConfig := &requests.RequestConfig{
		Timeout:         time.Duration(timeout) * time.Second,
		MaxRetries:      retry,
		MaxConcurrent:   threads,
		MaxRedirects:    3,
		FollowRedirect:  true,
		RandomUserAgent: args.RandomUA,
	}

	if proxyCfg := config.GetProxyConfig(); proxyCfg != nil && proxyCfg.UpstreamProxy != "" {
		requestConfig.ProxyURL = proxyCfg.UpstreamProxy
		logger.Debugf("ActiveScan: 设置请求处理器代理: %s", requestConfig.ProxyURL)
	}

	logger.Debugf("请求处理器并发数设置为: %d", requestConfig.MaxConcurrent)
	logger.Debugf("请求处理器重试次数设置为: %d", requestConfig.MaxRetries)
	logger.Debugf("请求处理器超时时间设置为: %v", requestConfig.Timeout)

	var fpEngine *fingerprint.Engine
	if mode == ActiveMode {
		globalAddon := fingerprint.GetGlobalAddon()
		if globalAddon != nil {
			fpEngine = globalAddon.GetEngine()
			logger.Debug("复用被动模式的指纹引擎，避免重复加载")
		}
	}

	if fpEngine == nil && args.HasModule(string(modulepkg.ModuleDirscan)) {
		logger.Debug("检测到目录扫描模块启用，正在初始化指纹引擎以支持二次识别...")
		addon, err := fingerprint.CreateDefaultAddon()
		if err != nil {
			logger.Warnf("初始化指纹引擎失败，目录扫描将不包含指纹信息: %v", err)
		} else {
			fpEngine = addon.GetEngine()
			logger.Debug("指纹引擎初始化成功 (二次识别模式)")
		}
	}

	requestProcessor := requests.NewRequestProcessor(requestConfig)

	if mode == ActiveMode && len(args.Modules) == 1 && args.Modules[0] == "finger" {
		requestProcessor.SetModuleContext("fingerprint")
	}

	statsDisplay := stats.NewStatsDisplay()
	if args.Stats {
		statsDisplay.Enable()
	}

	if args.Stats {
		requestProcessor.SetStatsUpdater(statsDisplay)
	}

	snippetEnabled := args.VeryVerbose
	ruleEnabled := args.Verbose || args.VeryVerbose

	if fpEngine != nil {
		fpEngine.EnableSnippet(true) // 始终启用片段捕获，以便报告中使用
		fpEngine.EnableConsoleSnippet(snippetEnabled)
		fpEngine.EnableRuleLogging(ruleEnabled)
	}

	sc := &ScanController{
		mode:                   mode,
		args:                   args,
		config:                 cfg,
		requestProcessor:       requestProcessor,
		urlGenerator:           dirscan.NewURLGenerator(),
		fingerprintEngine:      fpEngine,
		encodingDetector:       fingerprint.GetEncodingDetector(), // 初始化编码检测器
		probedHosts:            make(map[string]bool),             // 初始化探测缓存
		statsDisplay:           statsDisplay,                      // 初始化统计显示器
		showFingerprintSnippet: snippetEnabled,
		showFingerprintRule:    ruleEnabled,
		maxConcurrent:          threads,
		retryCount:             retry,
		timeoutSeconds:         timeout,
		reportPath:             strings.TrimSpace(args.Output),
		wordlistPath:           strings.TrimSpace(args.Wordlist),
		displayedURLs:          make(map[string]bool),
		siteFilters:            make(map[string]*dirscan.ResponseFilter),
	}

	sc.httpClient = sc.createHTTPClientAdapter()
	return sc
}

func (sc *ScanController) Run() error {
	switch sc.mode {
	case ActiveMode:
		return sc.runActiveMode()
	case PassiveMode:
		logger.Info("启动被动代理模式")
		return nil
	default:
		return fmt.Errorf("未知的扫描模式")
	}
}

func (sc *ScanController) runActiveMode() error {
	logger.Debug("启动主动扫描模式")
	targets, err := sc.parseTargets(sc.args.Targets)
	if err != nil {
		return fmt.Errorf("目标解析失败: %v", err)
	}

	sc.lastTargets = targets

	logger.Debugf("解析到 %d 个目标", len(targets))

	if sc.statsDisplay.IsEnabled() {
		sc.statsDisplay.SetTotalHosts(int64(len(targets)))
		logger.Debugf("统计显示器：设置总主机数 = %d", len(targets))
	}

	var allResults []interfaces.HTTPResponse
	var dirscanResults []interfaces.HTTPResponse
	var fingerprintResults []interfaces.HTTPResponse

	orderedModules := sc.getOptimizedModuleOrder()
	allResults, dirscanResults, fingerprintResults = sc.executeModulesSequence(orderedModules, targets)

	return sc.finalizeScan(allResults, dirscanResults, fingerprintResults)
}

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
			ValidPages:           allResults,
			PrimaryFilteredPages: sc.collectedPrimaryFiltered,
			StatusFilteredPages:  sc.collectedStatusFiltered,
		}
		logger.Debugf("构造FilterResult - ValidPages: %d, PrimaryFiltered: %d, StatusFiltered: %d",
			len(allResults), len(sc.collectedPrimaryFiltered), len(sc.collectedStatusFiltered))
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

func (sc *ScanController) getOptimizedModuleOrder() []string {
	var orderedModules []string

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

// createHTTPClientAdapter 创建HTTP客户端（支持TLS和重定向）
func (sc *ScanController) createHTTPClientAdapter() httpclient.HTTPClientInterface {
	if sc.requestProcessor == nil {
		logger.Warn("RequestProcessor 未初始化，无法复用连接池，回退到独立HTTP客户端")
		return httpclient.New(httpclient.DefaultConfig())
	}
	return newRequestProcessorHTTPClient(sc.requestProcessor)
}
