package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"veo/internal/core/config"
	modulepkg "veo/pkg/core/module"
	"veo/pkg/dirscan"
	"veo/pkg/utils/formatter"
	"veo/pkg/utils/logger"
	"veo/pkg/utils/shared"
)

// CLIArgs CLI参数结构体
type CLIArgs struct {
	Targets    []string // 目标主机/URL (-u)
	TargetFile string   // 目标文件路径 (-l)
	Modules    []string // 启用的模块 (-m)
	Port       int      // 监听端口 (--lp)
	Listen     bool     // 被动代理模式 (--listen)
	Wordlist   string   // 自定义字典路径 (-w)
	Proxy      string   // 上游代理地址 (--proxy)
	Debug      bool     // 调试模式 (--debug)

	Threads int // 统一线程并发数量 (-t, --threads)
	Retry   int // 重试次数 (--retry)
	Timeout int // 全局超时时间 (--timeout)

	Output string // 报告文件输出路径 (-o, --output)
	Stats  bool   // 启用实时扫描进度统计显示 (--stats)

	NoColor      bool // 禁用彩色输出 (-no-color)
	NetworkCheck bool // 启用存活性检测 (--check-alive)
	JSONOutput   bool // 控制台输出JSON结果 (--json)

	Verbose     bool // 指纹匹配规则展示开关 (-v)
	VeryVerbose bool // 指纹匹配内容展示开关 (-vv)

	Headers []string // 自定义HTTP认证头部 (--header "Header-Name: Header-Value")

	StatusCodes string // 自定义过滤HTTP状态码 (-s "200,301,302")

	DisableHashFilter bool // 禁用哈希过滤 (--no-filter)

	RandomUA bool // 是否启用随机User-Agent (-ua, 默认启用)

	Depth int // 递归目录扫描层级 (--depth)
	// DepthSet 仅当用户通过CLI传入 --depth 时为 true
	DepthSet bool

	UpdateRules bool // 更新指纹识别规则库 (--update-rules)
}

// ParseCLIArgs 解析命令行参数
func ParseCLIArgs() *CLIArgs {
	var (
		targetsStr = flag.String("u", "", "目标主机/URL，多个目标用逗号分隔 (例如: -u www.baidu.com,api.baidu.com)")
		targetFile = flag.String("l", "", "目标文件路径，每行一个目标 (例如: -l targets.txt)")
		modulesStr = flag.String("m", "", "启用的模块，多个模块用逗号分隔 (例如: -m finger,dirscan)")
		localPort  = flag.Int("lp", 9080, "本地代理监听端口，仅在被动模式下使用 (默认: 9080)")
		wordlist   = flag.String("w", "", "自定义字典文件路径 (例如: -w /path/to/custom.txt)")
		listen     = flag.Bool("listen", false, "启用被动代理模式 (默认: 主动扫描模式)")
		proxy      = flag.String("proxy", "", "设置上游代理 (例如: http://127.0.0.1:8080 或 socks5://127.0.0.1:1080)")
		debug      = flag.Bool("debug", false, "启用调试模式，显示详细日志 (默认: 仅显示INFO及以上级别)")

		threads     = flag.Int("t", 0, "统一线程并发数量，对所有模块生效 (默认: 200)")
		threadsLong = flag.Int("threads", 0, "统一线程并发数量，对所有模块生效 (默认: 200)")
		retry       = flag.Int("retry", 0, "扫描失败目标的重试次数 (默认: 1)")
		timeout     = flag.Int("timeout", 0, "全局连接超时时间(秒)，对所有模块生效 (默认: 3)")

		output     = flag.String("o", "", "输出报告文件路径 (默认不输出文件)")
		outputLong = flag.String("output", "", "输出报告文件路径 (默认不输出文件)")

		stats        = flag.Bool("stats", false, "启用实时扫描进度统计显示")
		verbose      = flag.Bool("v", false, "显示指纹匹配规则内容 (默认关闭，可使用 -v 开启)")
		veryVerbose  = flag.Bool("vv", false, "显示指纹匹配规则与内容片段 (默认关闭，可使用 -vv 开启)")
		noColor      = flag.Bool("no-color", false, "禁用彩色输出，适用于控制台不支持ANSI的环境")
		networkCheck = flag.Bool("check-alive", false, "启用存活性检测 (默认关闭)")
		jsonOutput   = flag.Bool("json", false, "使用JSON格式输出扫描结果，便于与其他工具集成")

		statusCodes = flag.String("s", "", "指定需要保留的HTTP状态码，逗号分隔 (例如: -s 200,301,302)")

		noFilter = flag.Bool("no-filter", false, "完全禁用目录扫描哈希过滤（默认开启）")

		randomUAFlag = flag.Bool("ua", true, "是否启用随机User-Agent池 (默认: true，可通过 -ua=false 关闭)")
		depth        = flag.Int("depth", 0, "递归目录扫描深度 (0 表示关闭递归，默认: 0)")
		updateRules  = flag.Bool("update-rules", false, "从云端更新指纹识别规则库")

		help     = flag.Bool("h", false, "显示帮助信息")
		helpLong = flag.Bool("help", false, "显示帮助信息")
	)

	var headers arrayFlags
	flag.Var(&headers, "header", "自定义HTTP认证头部，格式: \"Header-Name: Header-Value\" (可重复使用)")

	flag.Usage = showCustomHelp
	flag.Parse()

	if *help || *helpLong {
		flag.Usage()
		os.Exit(0)
	}

	args := &CLIArgs{
		TargetFile: *targetFile,
		Port:       *localPort,
		Wordlist:   *wordlist,
		Listen:     *listen,
		Proxy:      *proxy,
		Debug:      *debug,

		Threads:      getMaxInt(*threads, *threadsLong),
		Retry:        *retry,
		Timeout:      *timeout,
		Output:       getStringValue(*output, *outputLong),
		Stats:        *stats,
		Verbose:      *verbose,
		VeryVerbose:  *veryVerbose,
		NoColor:      *noColor,
		NetworkCheck: *networkCheck,
		JSONOutput:   *jsonOutput,

		Headers: []string(headers),

		StatusCodes:       *statusCodes,
		DisableHashFilter: *noFilter,

		RandomUA: *randomUAFlag,
		Depth:    *depth,
		DepthSet: flagProvided("depth"),

		UpdateRules: *updateRules,
	}

	if *targetsStr != "" {
		args.Targets = parseTargets(*targetsStr)
	}

	if *modulesStr != "" {
		args.Modules = parseModules(*modulesStr)
	}

	if len(args.Modules) == 0 {
		args.Modules = []string{string(modulepkg.ModuleFinger), string(modulepkg.ModuleDirscan)}
		logger.Debugf("未指定模块，使用默认模块: %s, %s", modulepkg.ModuleFinger, modulepkg.ModuleDirscan)
	}

	if args.JSONOutput {
		args.Stats = false
	}

	if err := validateArgs(args); err != nil {
		logger.Error(fmt.Sprintf("参数验证失败: %v", err))
		os.Exit(1)
	}

	return args
}

func flagProvided(name string) bool {
	if name == "" {
		return false
	}
	prefix := "-" + name
	doublePrefix := "--" + name
	for _, arg := range os.Args[1:] {
		if arg == prefix || arg == doublePrefix {
			return true
		}
		if strings.HasPrefix(arg, prefix+"=") || strings.HasPrefix(arg, doublePrefix+"=") {
			return true
		}
	}
	return false
}

// showCustomHelp 显示自定义帮助信息
func showCustomHelp() {
	prog := filepath.Base(os.Args[0])
	listenHelp := ""
	listenExample := ""
	if passiveBuild {
		listenHelp = "  --listen          启用被动代理模式\n  -lp int           被动代理监听端口 (默认: 9080)\n"
		listenExample = fmt.Sprintf("  %s -u target.com --listen --lp 8080\n", prog)
	}

	fmt.Printf(`
veo - 指纹识别/目录扫描

用法:
  %[1]s -u <targets> [options]
  %[1]s -l <file> [options]
%s
目标与模块:
  -u string          目标列表，逗号分隔；支持 URL / 域名 / host:port / CIDR / IP 范围
  -l string          目标文件，每行一个目标；支持空行和 # 注释
  -m string          启用模块，默认 finger,dirscan。可选 finger / dirscan

扫描控制:
  --debug            输出调试日志
  --stats            显示实时统计信息
  -v                 显示指纹匹配规则内容
  -vv                显示指纹匹配规则及匹配片段
  --check-alive      启用存活性检测 (默认关闭)
  --no-color         禁用彩色输出
  --json             控制台输出 JSON
  -ua bool           是否启用随机User-Agent 池 (默认 true，使用 -ua=false 关闭)

性能调优:
  -t, --threads int  全局并发线程数（默认 200）
  --retry int        失败重试次数（默认 1）
  --timeout int      全局超时时间（秒，默认 3）

目录扫描:
  -w string          指定自定义目录字典，可用逗号添加多个
  --depth int        递归目录扫描深度 (0 表示关闭递归，默认: 0)
  --no-filter        完全禁用目录扫描哈希过滤（默认开启）

输出与过滤:
  -o, --output string  写入实时CSV报告（输出为 <path>_realtime.csv）
  --header string      自定义 HTTP 头部，可重复指定
  -s string            保留的 HTTP 状态码列表
  --update-rules       从云端更新指纹识别规则库

帮助:
  -h, --help         显示本帮助信息

示例:
  %[1]s -u https://target.com -m finger,dirscan
  %[1]s -l targets.txt -m finger,dirscan --stats
%s
`, prog, listenHelp, listenExample)
}

// validateArgs 验证CLI参数
func validateArgs(args *CLIArgs) error {
	if args.Listen && !passiveBuild {
		return fmt.Errorf("当前构建不支持被动代理模式 (--listen)")
	}

	if args.Listen {
		if args.Port <= 0 || args.Port > 65535 {
			return fmt.Errorf("端口必须在1-65535范围内，当前值: %d", args.Port)
		}
	}

	if args.Threads < 0 || args.Threads > 1000 {
		return fmt.Errorf("线程并发数量必须在0-1000范围内，当前值: %d", args.Threads)
	}

	if args.Retry < 0 || args.Retry > 10 {
		return fmt.Errorf("重试次数必须在0-10范围内，当前值: %d", args.Retry)
	}

	if args.Timeout < 0 || args.Timeout > 300 {
		return fmt.Errorf("超时时间必须在0-300秒范围内，当前值: %d", args.Timeout)
	}

	if args.Listen {
		if len(args.Targets) == 0 {
			args.Targets = []string{"*"}
		}
	} else if !args.UpdateRules && len(args.Targets) == 0 && args.TargetFile == "" {
		return fmt.Errorf("必须指定目标主机/URL (-u) 或目标文件 (-l)")
	}

	if !args.Listen {
		for _, target := range args.Targets {
			if target == "*" {
				return fmt.Errorf("主动扫描模式不支持通配符目标，请指定具体的URL")
			}
		}
	}

	if !args.UpdateRules {
		if err := validateTargets(args.Targets); err != nil {
			return fmt.Errorf("目标参数无效: %v", err)
		}
	}

	if args.Wordlist != "" {
		if err := validateWordlistFile(args.Wordlist); err != nil {
			return fmt.Errorf("字典文件无效: %v", err)
		}
	}

	if args.Output != "" {
		if err := validateOutputPath(args.Output); err != nil {
			return fmt.Errorf("输出路径无效: %v", err)
		}
	}

	if err := validateModules(args.Modules); err != nil {
		return fmt.Errorf("模块参数无效: %v", err)
	}

	if len(args.Modules) == 0 {
		return fmt.Errorf("内部错误: 模块列表为空（应该已设置默认模块）")
	}

	return nil
}

// validateTargets 验证目标列表
func validateTargets(targets []string) error {
	for _, target := range targets {
		if strings.Contains(target, " ") {
			return fmt.Errorf("目标不能包含空格: '%s'", target)
		}
		if len(target) == 0 {
			return fmt.Errorf("目标不能为空")
		}

		if target == "*" {
			if passiveBuild {
				continue
			}
			return fmt.Errorf("主动扫描模式不支持通配符目标，请指定具体的URL")
		}

		if strings.HasPrefix(target, ".") || strings.HasSuffix(target, ".") {
			return fmt.Errorf("无效的目标格式: '%s'", target)
		}
	}
	return nil
}

// applyArgsToConfig 将CLI参数应用到配置系统
func applyArgsToConfig(args *CLIArgs) {
	if passiveBuild {
		serverConfig := config.GetServerConfig()
		if args.Port > 0 {
			serverConfig.Listen = fmt.Sprintf(":%d", args.Port)
		}
	}

	if args.Debug {
		logger.SetLogLevel("debug")
		logger.Debug("调试模式已启用，显示所有级别日志")
	} else {
		logger.SetLogLevel("info")
	}

	if args.NoColor {
		formatter.SetColorEnabled(false)
		logger.SetColorOutput(false)
		os.Setenv("NO_COLOR", "1")
	}

	if args.JSONOutput && !args.Debug {
		logger.SetLogLevel("error")
	}

	requestConfig := config.GetRequestConfig()
	if requestConfig == nil {
		logger.Warn("请求配置未初始化，跳过线程/超时设置")
	} else {
		if args.Threads > 0 {
			requestConfig.Threads = args.Threads
			logger.Debugf("全局配置：线程并发数量设置为 %d", requestConfig.Threads)
		} else if requestConfig.Threads <= 0 {
			requestConfig.Threads = 200
		}

		if args.Retry > 0 {
			requestConfig.Retry = args.Retry
			logger.Debugf("全局配置：重试次数设置为 %d", requestConfig.Retry)
		} else if requestConfig.Retry <= 0 {
			requestConfig.Retry = 1
		}

		if args.Timeout > 0 {
			requestConfig.Timeout = args.Timeout
			logger.Debugf("全局配置：超时时间设置为 %d 秒", requestConfig.Timeout)
		} else if requestConfig.Timeout <= 0 {
			requestConfig.Timeout = 3
		}

		randomUA := args.RandomUA
		requestConfig.RandomUA = &randomUA

		requestConfig.Depth = args.Depth
		logger.Debugf("全局配置：递归目录扫描深度设置为 %d", requestConfig.Depth)
	}

	if len(args.Headers) > 0 {
		if parsed, err := parseHeaderFlags(args.Headers); err != nil {
			logger.Errorf("HTTP头部参数处理失败: %v", err)
		} else if len(parsed) > 0 {
			config.SetCustomHeaders(parsed)
		}
	}

	var customFilterConfig *dirscan.FilterConfig
	if args.StatusCodes != "" {
		statusCodes, err := parseStatusCodes(args.StatusCodes)
		if err != nil {
			logger.Errorf("状态码过滤参数处理失败: %v", err)
		} else if len(statusCodes) > 0 {
			customFilterConfig = dirscan.DefaultFilterConfig()
			customFilterConfig.ValidStatusCodes = statusCodes
			logger.Infof("状态码过滤设置为 %v", statusCodes)
		}
	}

	if args.DisableHashFilter {
		if customFilterConfig == nil {
			customFilterConfig = dirscan.DefaultFilterConfig()
		}
		customFilterConfig.DisableHashFilter = true
		logger.Warn("CLI参数：已禁用目录扫描哈希过滤 (--no-filter)")
	}

	if customFilterConfig != nil {
		dirscan.SetGlobalFilterConfig(customFilterConfig)
	}

	if len(args.Targets) > 0 {
		hostConfig := config.GetHostsConfig()
		allowList := buildHostAllowList(args.Targets)
		hostConfig.Allow = allowList
		if len(allowList) > 0 {
			logger.Debugf("主机白名单已设置: %v", allowList)
		}
	}

	if args.Wordlist != "" {
		wordlists := parseWordlistPaths(args.Wordlist)
		dirscan.SetWordlistPaths(wordlists)
		logger.Infof("Use Dicts: %s", strings.Join(wordlists, ","))
	} else {
		dirscan.SetWordlistPaths(nil)
	}

	if args.Proxy != "" {
		proxyConfig := config.GetProxyConfig()
		proxyConfig.UpstreamProxy = args.Proxy
		logger.Infof("UpstreamProxy: %s", args.Proxy)
	}

	if collectorCfg := config.GetCollectorConfig(); collectorCfg != nil {
		if len(collectorCfg.Static.Extensions) > 0 {
			shared.SetGlobalStaticExtensions(collectorCfg.Static.Extensions)
			logger.Debugf("已应用 %d 个静态资源扩展名黑名单到全局配置", len(collectorCfg.Static.Extensions))
		}
		if len(collectorCfg.Static.Path) > 0 {
			shared.SetGlobalStaticPaths(collectorCfg.Static.Path)
			logger.Debugf("已应用 %d 个静态路径黑名单到全局配置", len(collectorCfg.Static.Path))
		}
	}
}
