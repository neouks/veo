//go:build passive

package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"veo/internal/config"
	"veo/pkg/dirscan"
	"veo/pkg/fingerprint"
	"veo/pkg/logger"
	requests "veo/pkg/processor"
	reporter "veo/pkg/reporter"
	"veo/proxy"
)

const passiveBuild = true

// Execute 执行CLI命令
func Execute() {
	args := bootstrapCLI()
	if handlePreScanShortCircuit(args) {
		return
	}

	displayStartupInfo(args)

	app, err := initializeApp(args)
	if err != nil {
		logger.Fatalf("初始化应用程序失败: %v", err)
	}

	if args.Listen {
		if err := app.startApplication(); err != nil {
			logger.Fatalf("启动应用程序失败: %v", err)
		}
		waitForSignal(app)
	} else {
		if err := runActiveScanMode(args); err != nil {
			logger.Fatalf("主动扫描失败: %v", err)
		}
	}
}

type CLIApp struct {
	proxy             *proxy.Proxy
	collector         *dirscan.Collector
	fingerprintAddon  *fingerprint.FingerprintAddon
	authLearningAddon *AuthLearningAddon
	proxyStarted      bool
	args              *CLIArgs
}

// initializeApp 初始化应用程序（被动代理模式/通用初始化）
func initializeApp(args *CLIArgs) (*CLIApp, error) {
	// 创建代理服务器
	logger.Debug("创建代理服务器...")
	proxyServer, err := createProxy()
	if err != nil {
		return nil, fmt.Errorf("创建代理服务器失败: %v", err)
	}

	// 只在启用dirscan模块时创建collector和相关组件
	var collectorInstance *dirscan.Collector
	if args.HasModule(moduleDirscan) {
		logger.Debug("启用目录扫描模块，创建相关组件...")
		collectorInstance = dirscan.NewCollector()
	} else {
		logger.Debug("未启用目录扫描模块，跳过collector和consoleManager创建")
	}

	// 创建指纹识别插件（如果启用）
	var fingerprintAddon *fingerprint.FingerprintAddon
	if args.HasModule(moduleFinger) {
		logger.Debug("创建指纹识别插件...")
		fingerprintAddon, err = createFingerprintAddon()
		if err != nil {
			logger.Warnf("Failed to initialize fingerprint addon: %v", err)
		}
	}

	// 创建认证学习插件（总是创建，用于被动代理模式下的认证学习）
	logger.Debug("创建认证学习插件...")
	authLearningAddon := createAuthLearningAddon()

	app := &CLIApp{
		proxy:             proxyServer,
		collector:         collectorInstance,
		fingerprintAddon:  fingerprintAddon,
		authLearningAddon: authLearningAddon,
		proxyStarted:      false,
		args:              args,
	}

	logger.Debug("应用程序初始化完成")
	return app, nil
}

func createProxy() (*proxy.Proxy, error) {
	serverConfig := config.GetServerConfig()
	proxyConfig := config.GetProxyConfig()

	opts := &proxy.Options{
		Addr:              serverConfig.Listen,
		StreamLargeBodies: proxyConfig.StreamLargebody,
		SslInsecure:       proxyConfig.SSLInsecure,
		Upstream:          proxyConfig.UpstreamProxy,
	}
	return proxy.NewProxy(opts)
}

func createFingerprintAddon() (*fingerprint.FingerprintAddon, error) {
	return fingerprint.CreateDefaultAddon()
}

func createAuthLearningAddon() *AuthLearningAddon {
	addon := NewAuthLearningAddon()

	addon.SetCallbacks(
		func(headers map[string]string) {
			currentHeaders := config.GetCustomHeaders()
			mergedHeaders := make(map[string]string)
			for key, value := range currentHeaders {
				mergedHeaders[key] = value
			}

			newHeadersCount := 0
			for key, value := range headers {
				if _, exists := mergedHeaders[key]; !exists {
					mergedHeaders[key] = value
					newHeadersCount++
				}
			}

			if newHeadersCount > 0 {
				config.SetCustomHeaders(mergedHeaders)
				logger.Debugf("应用了 %d 个新的Authorization头部到全局配置", newHeadersCount)
			}
		},
		func() bool {
			return config.HasCustomHeaders()
		},
	)

	logger.Debug("认证学习插件创建成功")
	return addon
}

// StartProxy 启动代理服务器
func (app *CLIApp) StartProxy() error {
	if app.proxyStarted {
		return nil
	}

	// 总是添加认证学习插件
	if app.authLearningAddon != nil {
		app.proxy.AddAddon(app.authLearningAddon)
		logger.Debug("认证学习插件已添加到代理服务器")
	}

	// 只在启用目录扫描模块时添加collector
	if app.args.HasModule(moduleDirscan) && app.collector != nil {
		app.proxy.AddAddon(app.collector)
	}

	// 根据启用的模块添加插件
	if app.args.HasModule(moduleFinger) && app.fingerprintAddon != nil {
		app.proxy.AddAddon(app.fingerprintAddon)
	}

	go func() {
		if err := app.proxy.Start(); err != nil {
			logger.Error(err)
		}
	}()

	app.proxyStarted = true
	return nil
}

// StopProxy 停止代理服务器
func (app *CLIApp) StopProxy() error {
	if !app.proxyStarted {
		return nil
	}

	if err := app.proxy.Close(); err != nil {
		return err
	}

	app.proxyStarted = false
	return nil
}

// startApplication 启动被动代理模式应用
func (app *CLIApp) startApplication() error {
	// 启动代理服务器（并添加Addon）
	if err := app.StartProxy(); err != nil {
		return fmt.Errorf("启动代理服务器失败: %v", err)
	}

	// 启动指纹识别模块
	if app.args.HasModule(moduleFinger) && app.fingerprintAddon != nil {
		app.fingerprintAddon.Enable()

		engine := app.fingerprintAddon.GetEngine()
		if engine != nil {
			engine.GetConfig().ShowSnippet = true

			snippetEnabled := app.args.VeryVerbose
			ruleEnabled := app.args.Verbose || app.args.VeryVerbose

			var outputFormatter fingerprint.OutputFormatter
			if app.args.JSONOutput {
				outputFormatter = fingerprint.NewJSONOutputFormatter()
			} else {
				outputFormatter = fingerprint.NewConsoleOutputFormatter(
					true,
					true,
					ruleEnabled,
					snippetEnabled,
				)
			}
			engine.GetConfig().OutputFormatter = outputFormatter
			logger.Debugf("被动代理模式 OutputFormatter 已注入: %T", outputFormatter)
		}

		logger.Debug("指纹识别模块启动成功")
	}

	if app.args.HasModule(moduleDirscan) && app.collector != nil {
		app.collector.EnableCollection()
		logger.Debug("目录扫描采集器已启用")
	}

	// 模块间依赖注入：为指纹主动探测注入统一HTTP客户端
	if app.fingerprintAddon != nil {
		injectFingerprintHTTPClient(app.fingerprintAddon, app.args.Shiro)
	}

	logger.Debug("模块启动和依赖注入完成")
	return nil
}

func injectFingerprintHTTPClient(addon *fingerprint.FingerprintAddon, shiro bool) {
	if addon == nil {
		return
	}

	globalReqConfig := config.GetRequestConfig()
	procConfig := requests.GetDefaultConfig()

	if globalReqConfig != nil {
		if globalReqConfig.Timeout > 0 {
			procConfig.Timeout = time.Duration(globalReqConfig.Timeout) * time.Second
		}
		if globalReqConfig.Retry > 0 {
			procConfig.MaxRetries = globalReqConfig.Retry
		}
		if globalReqConfig.Threads > 0 {
			procConfig.MaxConcurrent = globalReqConfig.Threads
		}
		if globalReqConfig.RandomUA != nil {
			procConfig.RandomUserAgent = *globalReqConfig.RandomUA
		}
	}

	if proxyCfg := config.GetProxyConfig(); proxyCfg.UpstreamProxy != "" {
		procConfig.ProxyURL = proxyCfg.UpstreamProxy
	}

	requestProcessor := requests.NewRequestProcessor(procConfig)
	requestProcessor.SetModuleContext("fingerprint-passive")
	if shiro {
		requestProcessor.SetShiroCookieEnabled(true)
	}

	addon.SetHTTPClient(requestProcessor)
	addon.SetTimeout(procConfig.Timeout)
	logger.Debugf("指纹插件主动探测超时已设置为: %v", procConfig.Timeout)
	logger.Debug("统一的RequestProcessor客户端已注入到指纹识别模块")
}

func (app *CLIApp) newPassiveScanController() *ScanController {
	controller := NewScanController(app.args, config.GetConfig())
	if app.fingerprintAddon != nil {
		if engine := app.fingerprintAddon.GetEngine(); engine != nil {
			controller.fingerprintEngine = engine
		}
	}
	if strings.TrimSpace(app.args.Output) == "" {
		return controller
	}

	realtimeReporter, err := reporter.NewRealtimeCSVReporter(app.args.Output)
	if err != nil {
		logger.Errorf("Failed to create realtime CSV report: %v", err)
		return controller
	}

	controller.realtimeReporter = realtimeReporter
	return controller
}

func closePassiveRealtimeReporter(realtimeReporter *reporter.RealtimeCSVReporter) {
	if realtimeReporter == nil {
		return
	}
	if err := realtimeReporter.Close(); err != nil {
		logger.Errorf("Failed to close realtime CSV report: %v", err)
		return
	}
	logger.Infof("Report Output Success: %s", realtimeReporter.Path())
}

// waitForSignal 等待中断信号或用户输入
func waitForSignal(app *CLIApp) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	inputChan := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				return
			}
			if buf[0] == '\n' {
				inputChan <- struct{}{}
			}
		}
	}()

	logger.Info("Press [Enter] to scan collected targets...")

	for {
		select {
		case sig := <-sigChan:
			fmt.Println()
			logger.Info(sig)
			cleanup(app)
			return
		case <-inputChan:
			app.triggerScan()
		}
	}
}

// triggerScan 触发被动模式下的目录扫描
func (app *CLIApp) triggerScan() {
	logger.Info("Scan triggered by user...")

	if app.collector == nil {
		logger.Warn("Dirscan module is not enabled, scan cannot be started")
		return
	}

	targets := app.collector.GetURLMap()
	if len(targets) == 0 {
		logger.Warn("No URLs collected for scanning, please browse the target site first")
		return
	}

	depth := 0
	if app.args.DepthSet {
		depth = app.args.Depth
	}
	if depth > 0 {
		logger.Infof("Passive scan recursion depth set to: %d", depth)
	}

	// 暂停指纹识别插件，避免扫描流量干扰
	if app.fingerprintAddon != nil {
		app.fingerprintAddon.Disable()
		logger.Debug("指纹识别插件已暂停")
	}

	controller := app.newPassiveScanController()
	defer closePassiveRealtimeReporter(controller.realtimeReporter)

	collectedURLs := make([]string, 0, len(targets))
	for target := range targets {
		collectedURLs = append(collectedURLs, target)
	}

	logger.Info("Starting dirscan...")
	result, err := controller.runDirscanModule(context.Background(), collectedURLs)
	if err != nil {
		logger.Errorf("Scan execution failed: %v", err)
	} else {
		app.collector.ClearURLMap()
		logger.Infof("Scan completed, found %d valid results", len(result))
	}

	if app.fingerprintAddon != nil {
		app.fingerprintAddon.Enable()
		logger.Debug("指纹识别插件已恢复")
	}

	logger.Info("Waiting for the next collection round, press [Enter] to scan again...")
}

// cleanup 清理资源
func cleanup(app *CLIApp) {
	if app != nil && app.proxyStarted {
		if err := app.StopProxy(); err != nil {
			logger.Errorf("Failed to stop proxy server: %v", err)
		}
	}

	time.Sleep(500 * time.Millisecond)
	os.Exit(0)
}

var customAuthHeaderNames = map[string]struct{}{
	"x-access-token":  {},
	"x-api-key":       {},
	"x-auth-token":    {},
	"x-csrf-token":    {},
	"x-xsrf-token":    {},
	"x-session-token": {},
	"x-user-token":    {},
	"api-key":         {},
	"apikey":          {},
	"access-token":    {},
	"auth-token":      {},
	"session-token":   {},
	"user-token":      {},
}

type AuthDetector struct {
	detectedSchemes map[string]string
	mu              sync.RWMutex
	onAuthFound     func(map[string]string)
}

func NewAuthDetector() *AuthDetector {
	return &AuthDetector{
		detectedSchemes: make(map[string]string),
	}
}

func (ad *AuthDetector) SetCallbacks(onAuthFound func(map[string]string)) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	ad.onAuthFound = onAuthFound
}

func (ad *AuthDetector) LearnFromRequest(req *http.Request) map[string]string {
	authHeaders := make(map[string]string)

	if authHeader := req.Header.Get("Authorization"); authHeader != "" {
		authHeaders["Authorization"] = authHeader
		logger.Debugf("学习到Authorization头部: %s", ad.maskSensitiveValue(authHeader))

		authType := ad.parseAuthorizationType(authHeader)
		if authType != "" {
			logger.Debugf("识别认证类型: %s", authType)
		}
	}

	for headerName, headerValue := range ad.detectCustomAuthHeaders(req) {
		authHeaders[headerName] = headerValue
		logger.Debugf("学习到自定义认证头部: %s = %s", headerName, ad.maskSensitiveValue(headerValue))
	}

	if len(authHeaders) > 0 {
		ad.updateDetectedSchemes(authHeaders)
	}
	return authHeaders
}

func (ad *AuthDetector) updateDetectedSchemes(newHeaders map[string]string) {
	ad.mu.Lock()
	updated := false
	for key, value := range newHeaders {
		if oldVal, exists := ad.detectedSchemes[key]; !exists || (value != "" && oldVal != value) {
			ad.detectedSchemes[key] = value
			updated = true
		}
	}
	callback := ad.onAuthFound
	ad.mu.Unlock()

	if updated && callback != nil {
		callback(newHeaders)
	}
}

func (ad *AuthDetector) detectCustomAuthHeaders(req *http.Request) map[string]string {
	customHeaders := make(map[string]string)
	for headerName, headerValues := range req.Header {
		if len(headerValues) == 0 {
			continue
		}
		if ad.isCustomAuthHeader(headerName) {
			customHeaders[headerName] = headerValues[0]
		}
	}
	return customHeaders
}

func (ad *AuthDetector) isCustomAuthHeader(headerName string) bool {
	_, ok := customAuthHeaderNames[strings.ToLower(headerName)]
	return ok
}

func (ad *AuthDetector) parseAuthorizationType(authHeader string) string {
	parts := strings.Fields(strings.TrimSpace(authHeader))
	if len(parts) == 0 {
		return ""
	}

	switch strings.ToLower(parts[0]) {
	case "bearer":
		return "Bearer Token"
	case "basic":
		return "Basic Authentication"
	case "digest":
		return "Digest Authentication"
	case "jwt":
		return "JWT Token"
	case "oauth":
		return "OAuth Token"
	default:
		word := strings.ToLower(parts[0])
		if len(word) == 0 {
			return ""
		}
		return strings.ToUpper(word[:1]) + word[1:]
	}
}

func (ad *AuthDetector) maskSensitiveValue(value string) string {
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}
	return value[:4] + strings.Repeat("*", len(value)-8) + value[len(value)-4:]
}

type AuthLearningAddon struct {
	proxy.BaseAddon
	detector  *AuthDetector
	isAuthSet func() bool
}

func NewAuthLearningAddon() *AuthLearningAddon {
	return &AuthLearningAddon{
		detector: NewAuthDetector(),
	}
}

func (ala *AuthLearningAddon) SetCallbacks(onAuthLearned func(map[string]string), isAuthSet func() bool) {
	ala.detector.SetCallbacks(onAuthLearned)
	ala.isAuthSet = isAuthSet
}

func (ala *AuthLearningAddon) Requestheaders(f *proxy.Flow) {
	if ala.detector == nil {
		return
	}
	if ala.isAuthSet != nil && ala.isAuthSet() {
		return
	}
	ala.detector.LearnFromRequest(f.Request.Raw())
}
