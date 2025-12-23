package cli

import (
	"veo/pkg/core/console"
	"veo/pkg/dirscan"
	"veo/pkg/fingerprint"
	"veo/pkg/utils/processor/auth"
	"veo/proxy"
)

// CLIApp CLI应用程序
// 职责：聚合被动代理模式下的各组件实例与启动/停止状态
// KISS：不在此处放置业务逻辑，仅做依赖持有

type CLIApp struct {
	proxy             *proxy.Proxy
	collector         *dirscan.Collector
	consoleManager    *console.ConsoleManager
	dirscanModule     *dirscan.DirscanModule
	fingerprintAddon  *fingerprint.FingerprintAddon
	authLearningAddon *auth.AuthLearningAddon
	proxyStarted      bool
	args              *CLIArgs
}

var app *CLIApp
