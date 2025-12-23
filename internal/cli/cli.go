package cli

import (
	"fmt"
	"runtime"

	"veo/internal/core/config"
	"veo/pkg/utils/formatter"
	"veo/pkg/utils/logger"
)

// Execute 执行CLI命令
func Execute() {
	// 优先初始化配置系统
	if err := config.InitConfig(); err != nil {
		// 如果配置加载失败，使用默认配置
		fmt.Printf("配置文件加载失败，使用默认配置: %v\n", err)
	}

	// 初始化日志系统
	loggerConfig := &logger.LogConfig{
		Level:       "info",
		ColorOutput: true,
	}
	if err := logger.InitializeLogger(loggerConfig); err != nil {
		// 如果初始化失败，使用默认配置
		logger.InitializeLogger(nil)
	}
	logger.Debug("日志系统初始化完成")

	// 初始化formatter包的Windows ANSI支持
	// Windows 10+默认支持ANSI颜色
	if runtime.GOOS == "windows" {
		formatter.SetWindowsANSISupported(true)
		logger.Debug("Windows ANSI颜色支持已启用")
	}

	// 解析命令行参数
	args := ParseCLIArgs()

	// 应用CLI参数到配置（包括--debug标志）
	applyArgsToConfig(args)

	// 处理指纹库更新逻辑 (前置处理，如果是更新操作则直接退出)
	handleRuleUpdates(args)

	//  提前显示启动信息，确保banner在所有日志输出之前显示
	displayStartupInfo(args)

	// 初始化应用程序
	var err error
	app, err = initializeApp(args)
	if err != nil {
		logger.Fatalf("初始化应用程序失败: %v", err)
	}

	// 根据模式启动应用程序
	if args.Listen {
		// 被动代理模式
		if err := startApplication(args); err != nil {
			logger.Fatalf("启动应用程序失败: %v", err)
		}
		// 等待中断信号或用户输入
		waitForSignal()
	} else {
		// 主动扫描模式
		if err := runActiveScanMode(args); err != nil {
			logger.Fatalf("主动扫描失败: %v", err)
		}
	}
}

