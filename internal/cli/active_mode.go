package cli

import (
	"veo/internal/core/config"
	"veo/pkg/utils/logger"
)

func runActiveScanMode(args *CLIArgs) error {
	logger.Debug("启动主动扫描模式")
	cfg := config.GetConfig()
	scanner := NewScanController(args, cfg)
	return scanner.Run()
}
