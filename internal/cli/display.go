package cli

import (
	"fmt"

	modulepkg "veo/pkg/core/module"
	"veo/pkg/utils/logger"
)

func displayStartupInfo(args *CLIArgs) {
	fmt.Print(`
		veo@Evilc0de
`)

	logger.Debug("模块状态:")
	logger.Debugf("指纹识别: %s", getModuleStatus(args.HasModule(string(modulepkg.ModuleFinger))))
	logger.Debugf("目录扫描: %s", getModuleStatus(args.HasModule(string(modulepkg.ModuleDirscan))))
}

func getModuleStatus(enabled bool) string {
	if enabled {
		return "[√]"
	}
	return "[X]"
}
