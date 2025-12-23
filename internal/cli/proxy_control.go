package cli

import (
	modulepkg "veo/pkg/core/module"
	"veo/pkg/fingerprint"
	"veo/pkg/utils/logger"
)

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
	if app.args.HasModule(string(modulepkg.ModuleDirscan)) && app.collector != nil {
		app.proxy.AddAddon(app.collector)
	}

	// 根据启用的模块添加插件
	if app.args.HasModule(string(modulepkg.ModuleFinger)) && app.fingerprintAddon != nil {
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

// IsProxyStarted 检查代理是否已启动
func (app *CLIApp) IsProxyStarted() bool {
	return app.proxyStarted
}

// GetFingerprintAddon 获取指纹识别插件
func (app *CLIApp) GetFingerprintAddon() *fingerprint.FingerprintAddon {
	return app.fingerprintAddon
}
