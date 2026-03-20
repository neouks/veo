package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"veo/internal/config"
	"veo/pkg/logger"
)

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
