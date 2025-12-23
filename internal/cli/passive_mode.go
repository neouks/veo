package cli

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"veo/pkg/fingerprint"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
)

// waitForSignal 等待中断信号或用户输入
func waitForSignal() {
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

	logger.Info("按 [Enter] 键开始扫描收集到的目标...")

	for {
		select {
		case sig := <-sigChan:
			fmt.Println()
			logger.Info(sig)
			cleanup()
			return
		case <-inputChan:
			if app != nil {
				app.triggerScan()
			}
		}
	}
}

// triggerScan 触发被动模式下的目录扫描
func (app *CLIApp) triggerScan() {
	logger.Info("用户触发扫描...")

	if app.dirscanModule == nil {
		logger.Warn("目录扫描模块未启用，无法执行扫描")
		return
	}

	addon := app.dirscanModule.GetAddon()
	if addon == nil {
		logger.Error("目录扫描Addon未初始化")
		return
	}

	if len(addon.GetCollectedURLs()) == 0 {
		logger.Warn("没有收集到待扫描的URL，请先浏览目标网站")
		return
	}

	// 暂停指纹识别插件，避免扫描流量干扰
	if app.fingerprintAddon != nil {
		app.fingerprintAddon.Disable()
		logger.Debug("指纹识别插件已暂停")
	}

	logger.Info("开始执行目录扫描...")
	result, err := addon.TriggerScan()
	if err != nil {
		logger.Errorf("扫描执行失败: %v", err)
	} else {
		logger.Infof("扫描完成，发现 %d 个有效结果", len(result.FilterResult.ValidPages))
	}

	if app.fingerprintAddon != nil {
		app.fingerprintAddon.Enable()
		logger.Debug("指纹识别插件已恢复")
	}

	// 如果指定了 -o 输出路径，则在扫描结束后生成报告
	if app.args.Output != "" {
		scanParams := map[string]interface{}{
			"threads":                   0,
			"timeout":                   0,
			"retry":                     0,
			"dir_targets_count":         len(result.ScanURLs),
			"fingerprint_targets_count": 0,
			"fingerprint_rules_loaded":  0,
		}

		var fpEngine *fingerprint.Engine
		if app.fingerprintAddon != nil {
			fpEngine = app.fingerprintAddon.GetEngine()
			if fpEngine != nil {
				stats := fpEngine.GetStats()
				scanParams["fingerprint_rules_loaded"] = stats.RulesLoaded
			}
		}

		reportConfig := &ReportConfig{
			Modules:                app.args.Modules,
			OutputPath:             app.args.Output,
			ShowFingerprintSnippet: app.args.VeryVerbose,
			ScanParams:             scanParams,
		}

		var dirResults, fingerResults []interfaces.HTTPResponse
		for _, p := range result.FilterResult.ValidPages {
			if p != nil {
				dirResults = append(dirResults, *p)
			}
		}

		err := GenerateReport(reportConfig, dirResults, fingerResults, result.FilterResult, fpEngine)
		if err != nil {
			logger.Errorf("报告生成失败: %v", err)
		}
	}

	logger.Info("等待下一轮收集，按 [Enter] 键再次扫描...")
}

// cleanup 清理资源
func cleanup() {
	if app != nil {
		if app.dirscanModule != nil {
			if err := app.dirscanModule.Stop(); err != nil {
				logger.Errorf("停止目录扫描模块失败: %v", err)
			}
		}

		if err := app.StopProxy(); err != nil {
			logger.Errorf("停止代理服务器失败: %v", err)
		}
	}

	time.Sleep(500 * time.Millisecond)
	os.Exit(0)
}
