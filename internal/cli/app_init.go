package cli

import (
	"fmt"
	"time"

	"veo/internal/core/config"
	"veo/pkg/core/console"
	modulepkg "veo/pkg/core/module"
	"veo/pkg/dirscan"
	"veo/pkg/fingerprint"
	"veo/pkg/utils/logger"
	requests "veo/pkg/utils/processor"
	"veo/pkg/utils/processor/auth"
	"veo/proxy"
)

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
	var consoleManager *console.ConsoleManager
	var dirscanModule *dirscan.DirscanModule

	if args.HasModule(string(modulepkg.ModuleDirscan)) {
		logger.Debug("启用目录扫描模块，创建相关组件...")

		collectorInstance = dirscan.NewCollector()
		consoleManager = console.NewConsoleManager(collectorInstance)

		dirscanModule, err = dirscan.NewDirscanModule(collectorInstance)
		if err != nil {
			return nil, fmt.Errorf("创建目录扫描模块失败: %v", err)
		}

		// 应用全局代理设置到目录扫描模块
		if proxyCfg := config.GetProxyConfig(); proxyCfg.UpstreamProxy != "" {
			dirscanModule.SetProxy(proxyCfg.UpstreamProxy)
		}
	} else {
		logger.Debug("未启用目录扫描模块，跳过collector和consoleManager创建")
	}

	// 创建指纹识别插件（如果启用）
	var fingerprintAddon *fingerprint.FingerprintAddon
	if args.HasModule(string(modulepkg.ModuleFinger)) {
		logger.Debug("创建指纹识别插件...")
		fingerprintAddon, err = createFingerprintAddon()
		if err != nil {
			logger.Warnf("指纹识别插件初始化失败: %v", err)
		}
	}

	// 创建认证学习插件（总是创建，用于被动代理模式下的认证学习）
	logger.Debug("创建认证学习插件...")
	authLearningAddon := createAuthLearningAddon()

	app := &CLIApp{
		proxy:             proxyServer,
		collector:         collectorInstance,
		consoleManager:    consoleManager,
		dirscanModule:     dirscanModule,
		fingerprintAddon:  fingerprintAddon,
		authLearningAddon: authLearningAddon,
		proxyStarted:      false,
		args:              args,
	}

	if consoleManager != nil {
		consoleManager.SetProxyController(app)
		if fingerprintAddon != nil {
			consoleManager.SetFingerprintAddon(fingerprintAddon)
		}
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
	addon, err := fingerprint.CreateDefaultAddon()
	if err != nil {
		return nil, err
	}
	fingerprint.SetGlobalAddon(addon)
	return addon, nil
}

func createAuthLearningAddon() *auth.AuthLearningAddon {
	addon := auth.NewAuthLearningAddon()

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

// startApplication 启动被动代理模式应用
func startApplication(args *CLIArgs) error {
	// 启动代理服务器（并添加Addon）
	if err := app.StartProxy(); err != nil {
		return fmt.Errorf("启动代理服务器失败: %v", err)
	}

	// 启动指纹识别模块
	if args.HasModule(string(modulepkg.ModuleFinger)) && app.fingerprintAddon != nil {
		fingerprint.SetGlobalAddon(app.fingerprintAddon)
		app.fingerprintAddon.Enable()

		engine := app.fingerprintAddon.GetEngine()
		if engine != nil {
			engine.GetConfig().ShowSnippet = true

			snippetEnabled := args.VeryVerbose
			ruleEnabled := args.Verbose || args.VeryVerbose

			var outputFormatter fingerprint.OutputFormatter
			if args.JSONOutput {
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

	// 启动目录扫描模块
	if args.HasModule(string(modulepkg.ModuleDirscan)) && app.dirscanModule != nil {
		if err := app.dirscanModule.Start(); err != nil {
			logger.Errorf("启动目录扫描模块失败: %v", err)
		} else {
			logger.Debug("目录扫描模块启动成功")
		}
	}

	// 模块间依赖注入：为指纹主动探测注入统一HTTP客户端
	if app.fingerprintAddon != nil {
		injectFingerprintHTTPClient(app.fingerprintAddon)
	}

	logger.Debug("模块启动和依赖注入完成")
	return nil
}

func injectFingerprintHTTPClient(addon *fingerprint.FingerprintAddon) {
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

	addon.SetHTTPClient(requestProcessor)
	addon.SetTimeout(procConfig.Timeout)
	logger.Debugf("指纹插件主动探测超时已设置为: %v", procConfig.Timeout)
	logger.Debug("统一的RequestProcessor客户端已注入到指纹识别模块")
}
