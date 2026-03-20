package cli

import (
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"veo/internal/config"
	"veo/pkg/dirscan"
	fpaddon "veo/pkg/fingerprint"
	"veo/pkg/formatter"
	"veo/pkg/logger"
	"veo/pkg/shared"
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
	// RetrySet 仅当用户通过CLI传入 --retry 时为 true
	RetrySet bool
	Timeout  int // 全局超时时间 (--timeout)

	Output string // 报告文件输出路径 (-o, --output)
	Stats  bool   // 启用实时扫描进度统计显示 (--stats)

	NoColor          bool // 禁用彩色输出 (-no-color)
	NetworkCheck     bool // 启用存活性检测 (--check-alive)
	CheckSimilar     bool // 扫描前进行目标相似性检查 (--check-similar)
	CheckSimilarOnly bool // 仅执行相似性检查 (--check-similar-only)
	JSONOutput       bool // 控制台输出JSON结果 (--json)
	Shiro            bool // Shiro rememberMe测试 (--shiro)

	Verbose     bool // 指纹匹配规则展示开关 (-v)
	VeryVerbose bool // 指纹匹配内容展示开关 (-vv)
	NoProbe     bool // 禁用主动目录指纹识别与404探测 (-np, --no-probe)

	Headers []string // 自定义HTTP认证头部 (--header "Header-Name: Header-Value")

	StatusCodes string // 自定义过滤HTTP状态码 (-s "200,301,302")

	DisableHashFilter bool // 禁用哈希过滤 (--no-filter)

	RandomUA bool // 是否启用随机User-Agent (-ua, 默认关闭)

	Depth int // 递归目录扫描层级 (--depth)
	// DepthSet 仅当用户通过CLI传入 --depth 时为 true
	DepthSet bool

	UpdateRules bool // 更新指纹识别规则库 (--update-rules)
}

func bootstrapCLI() *CLIArgs {
	if err := config.InitConfig(); err != nil {
		fmt.Printf("配置文件加载失败，使用默认配置: %v\n", err)
	}

	loggerConfig := &logger.LogConfig{
		Level:       "info",
		ColorOutput: true,
	}
	if err := logger.InitializeLogger(loggerConfig); err != nil {
		logger.InitializeLogger(nil)
	}
	logger.Debug("日志系统初始化完成")

	args := ParseCLIArgs()
	applyArgsToConfig(args)
	handleRuleUpdates(args)
	return args
}

func handlePreScanShortCircuit(args *CLIArgs) bool {
	if !args.CheckSimilarOnly {
		return false
	}
	if err := runCheckSimilarOnlyMode(args); err != nil {
		logger.Fatalf("相似度检查失败: %v", err)
	}
	return true
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

		threads     = flag.Int("t", 0, "统一线程并发数量，对所有模块生效 (默认: 100)")
		threadsLong = flag.Int("threads", 0, "统一线程并发数量，对所有模块生效 (默认: 100)")
		retry       = flag.Int("retry", 0, "扫描失败目标的重试次数 (默认: 1)")
		timeout     = flag.Int("timeout", 0, "全局连接超时时间(秒)，对所有模块生效 (默认: 3)")

		output     = flag.String("o", "", "输出报告文件路径 (默认不输出文件)")
		outputLong = flag.String("output", "", "输出报告文件路径 (默认不输出文件)")

		stats            = flag.Bool("stats", false, "启用实时扫描进度统计显示")
		verbose          = flag.Bool("v", false, "显示指纹匹配规则内容 (默认关闭，可使用 -v 开启)")
		veryVerbose      = flag.Bool("vv", false, "显示指纹匹配规则与内容片段 (默认关闭，可使用 -vv 开启)")
		noProbe          = flag.Bool("np", false, "禁用主动目录指纹识别与404探测 (默认开启)")
		noProbeLong      = flag.Bool("no-probe", false, "禁用主动目录指纹识别与404探测 (默认开启)")
		noColor          = flag.Bool("no-color", false, "禁用彩色输出，适用于控制台不支持ANSI的环境")
		networkCheck     = flag.Bool("check-alive", false, "启用存活性检测 (默认关闭)")
		checkSimilar     = flag.Bool("check-similar", false, "扫描前进行目标相似性检查并去重 (默认关闭)")
		checkSimilarOnly = flag.Bool("check-similar-only", false, "仅执行相似性检查，不进行指纹识别和目录扫描 (默认关闭)")
		jsonOutput       = flag.Bool("json", false, "使用JSON格式输出扫描结果，便于与其他工具集成")
		shiro            = flag.Bool("shiro", false, "在指纹识别/目录扫描请求头中添加 Cookie: rememberMe=1 (默认关闭)")

		statusCodes = flag.String("s", "", "指定需要保留的HTTP状态码，逗号分隔 (例如: -s 200,301,302)")

		noFilter = flag.Bool("no-filter", false, "完全禁用目录扫描哈希过滤（默认开启）")

		randomUAFlag = flag.Bool("ua", false, "是否启用随机User-Agent池 (默认: false，可通过 -ua=true 开启)")
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

		Threads:          getMaxInt(*threads, *threadsLong),
		Retry:            *retry,
		Timeout:          *timeout,
		Output:           getStringValue(*output, *outputLong),
		Stats:            *stats,
		Verbose:          *verbose,
		VeryVerbose:      *veryVerbose,
		NoProbe:          *noProbe || *noProbeLong,
		NoColor:          *noColor,
		NetworkCheck:     *networkCheck,
		CheckSimilar:     *checkSimilar,
		CheckSimilarOnly: *checkSimilarOnly,
		JSONOutput:       *jsonOutput,
		Shiro:            *shiro,

		Headers: []string(headers),

		StatusCodes:       *statusCodes,
		DisableHashFilter: *noFilter,

		RandomUA: *randomUAFlag,
		Depth:    *depth,
		DepthSet: flagProvided("depth"),
		RetrySet: flagProvided("retry"),

		UpdateRules: *updateRules,
	}

	if *targetsStr != "" {
		args.Targets = parseTargets(*targetsStr)
	}

	if *modulesStr != "" {
		args.Modules = parseModules(*modulesStr)
	}

	if len(args.Modules) == 0 {
		args.Modules = []string{moduleFinger, moduleDirscan}
		logger.Debugf("未指定模块，使用默认模块: %s, %s", moduleFinger, moduleDirscan)
	}

	if args.JSONOutput {
		args.Stats = false
	}

	if err := validateArgs(args); err != nil {
		logger.Error(fmt.Sprintf("Argument validation failed: %v", err))
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
		listenExample = fmt.Sprintf(
			"  %s -u target.com --listen --lp 8080\n  %s -u *.baidu.com --listen --lp 8080\n  %s -u 10.0.0.* --listen --lp 8080\n",
			prog,
			prog,
			prog,
		)
	}

	fmt.Printf(`
veo - 指纹识别/目录扫描

用法:
  %[1]s -u <targets> [options]
  %[1]s -l <file> [options]
%s
目标与模块:
  -u string          目标列表，逗号分隔；支持 URL / 域名 / host:port / CIDR / IP 范围；被动模式额外支持通配主机，如 *.baidu.com、10.0.0.*
  -l string          目标文件，每行一个目标；支持空行和 # 注释
  -m string          启用模块，默认 finger,dirscan。可选 finger / dirscan

扫描控制:
  --debug            输出调试日志
  --stats            显示实时统计信息
  -v                 显示指纹匹配规则内容
  -vv                显示指纹匹配规则及匹配片段
  -np, --no-probe    禁用主动目录指纹识别与404探测
  --check-alive      启用存活性检测 (默认关闭)
  --check-similar    扫描前进行目标相似性检查并去重 (默认关闭)
  --check-similar-only 仅执行相似性检查，不进行指纹识别和目录扫描 (默认关闭)
  --shiro            在指纹识别/目录扫描请求头中添加 Cookie: rememberMe=1 (默认关闭)
  --no-color         禁用彩色输出
  --json             控制台输出 JSON
  --proxy string     上游代理地址（HTTP/SOCKS5），例如 http://127.0.0.1:8080 或 socks5://127.0.0.1:1080
  -ua bool           是否启用随机User-Agent 池 (默认 false，使用 -ua=true 开启)

性能调优:
  -t, --threads int  全局并发线程数（默认 100）
  --retry int        失败重试次数（默认 1）
  --timeout int      全局超时时间（秒，默认 3）

目录扫描:
  -w string          指定自定义目录字典，可用逗号添加多个
  --depth int        递归目录扫描深度 (0 表示关闭递归，默认: 0)
  --no-filter        完全禁用目录扫描哈希过滤（默认开启）

输出与过滤:
  -o, --output string  写入实时CSV报告（输出为 <path>）
  --header string      自定义 HTTP 头部，可重复指定
  -s string            保留的 HTTP 状态码列表
  --update-rules       从云端更新指纹识别规则库

帮助:
  -h, --help         显示本帮助信息

示例:
  %[1]s -u https://target.com -m finger,dirscan
  %[1]s -u https://target.com --proxy http://127.0.0.1:8080
  %[1]s -l targets.txt -m finger,dirscan --stats
%s
`, prog, listenHelp, listenExample)
}

// validateArgs 验证CLI参数
func validateArgs(args *CLIArgs) error {
	if args.Listen && !passiveBuild {
		return fmt.Errorf("the current build does not support passive proxy mode (--listen)")
	}

	if args.Listen {
		if args.CheckSimilarOnly {
			return fmt.Errorf("similarity-check mode does not support passive proxy (--check-similar-only)")
		}
		if args.Port <= 0 || args.Port > 65535 {
			return fmt.Errorf("port must be in the range 1-65535, got: %d", args.Port)
		}
	}

	if args.Threads < 0 || args.Threads > 1000 {
		return fmt.Errorf("thread count must be in the range 0-1000, got: %d", args.Threads)
	}

	if args.Retry < 0 || args.Retry > 10 {
		return fmt.Errorf("retry count must be in the range 0-10, got: %d", args.Retry)
	}

	if args.Timeout < 0 || args.Timeout > 300 {
		return fmt.Errorf("timeout must be in the range 0-300 seconds, got: %d", args.Timeout)
	}

	if args.Listen {
		if len(args.Targets) == 0 {
			args.Targets = []string{"*"}
		}
	} else if !args.UpdateRules && len(args.Targets) == 0 && args.TargetFile == "" {
		return fmt.Errorf("either target hosts/URLs (-u) or a target file (-l) must be provided")
	}

	if !args.Listen {
		for _, target := range args.Targets {
			if strings.Contains(target, "*") {
				return fmt.Errorf("active scan mode does not support wildcard targets, please specify a concrete URL")
			}
		}
	}

	if !args.UpdateRules {
		if err := validateTargets(args.Targets); err != nil {
			return fmt.Errorf("invalid target arguments: %v", err)
		}
	}

	if args.Wordlist != "" {
		if err := validateWordlistFile(args.Wordlist); err != nil {
			return fmt.Errorf("invalid wordlist file: %v", err)
		}
	}

	if args.Output != "" {
		if err := validateOutputPath(args.Output); err != nil {
			return fmt.Errorf("invalid output path: %v", err)
		}
	}

	if err := validateModules(args.Modules); err != nil {
		return fmt.Errorf("invalid module arguments: %v", err)
	}

	if len(args.Modules) == 0 {
		return fmt.Errorf("internal error: module list is empty (default modules should already be set)")
	}

	return nil
}

// validateTargets 验证目标列表
func validateTargets(targets []string) error {
	for _, target := range targets {
		if strings.Contains(target, " ") {
			return fmt.Errorf("target must not contain spaces: '%s'", target)
		}
		if len(target) == 0 {
			return fmt.Errorf("target must not be empty")
		}

		if target == "*" {
			if passiveBuild {
				continue
			}
			return fmt.Errorf("active scan mode does not support wildcard targets, please specify a concrete URL")
		}
		if !passiveBuild && strings.Contains(target, "*") {
			return fmt.Errorf("active scan mode does not support wildcard targets, please specify a concrete URL")
		}

		if strings.HasPrefix(target, ".") || strings.HasSuffix(target, ".") {
			return fmt.Errorf("invalid target format: '%s'", target)
		}
	}
	return nil
}

func applyLogLevel(args *CLIArgs) {
	if args.Debug {
		logger.SetLogLevel("debug")
		logger.Debug("调试模式已启用，显示所有级别日志")
	} else {
		logger.SetLogLevel("info")
	}

	if args.JSONOutput && !args.Debug {
		logger.SetLogLevel("error")
	}
}

func applyRequestArgsToConfig(requestConfig *config.RequestConfig, args *CLIArgs) {
	if args.Threads > 0 {
		requestConfig.Threads = args.Threads
		logger.Debugf("全局配置：线程并发数量设置为 %d", requestConfig.Threads)
	} else if requestConfig.Threads <= 0 {
		requestConfig.Threads = 100
	}

	if args.RetrySet {
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

func ensureFilterConfig(cfg *dirscan.FilterConfig) *dirscan.FilterConfig {
	if cfg != nil {
		return cfg
	}
	return dirscan.DefaultFilterConfig()
}

// applyArgsToConfig 将CLI参数应用到配置系统
func applyArgsToConfig(args *CLIArgs) {
	if passiveBuild {
		serverConfig := config.GetServerConfig()
		if args.Port > 0 {
			serverConfig.Listen = fmt.Sprintf(":%d", args.Port)
		}
	}

	applyLogLevel(args)

	if args.NoColor {
		formatter.SetColorEnabled(false)
		logger.SetColorOutput(false)
		os.Setenv("NO_COLOR", "1")
	}

	requestConfig := config.GetRequestConfig()
	if requestConfig == nil {
		logger.Warn("Request config is not initialized, skipping thread/timeout settings")
	} else {
		applyRequestArgsToConfig(requestConfig, args)
	}

	if len(args.Headers) > 0 {
		if parsed, err := parseHeaderFlags(args.Headers); err != nil {
			logger.Errorf("Failed to parse HTTP header arguments: %v", err)
		} else if len(parsed) > 0 {
			config.SetCustomHeaders(parsed)
		}
	}

	var customFilterConfig *dirscan.FilterConfig
	if args.StatusCodes != "" {
		statusCodes, err := parseStatusCodes(args.StatusCodes)
		if err != nil {
			logger.Errorf("Failed to parse status code filter arguments: %v", err)
		} else if len(statusCodes) > 0 {
			customFilterConfig = ensureFilterConfig(customFilterConfig)
			customFilterConfig.ValidStatusCodes = statusCodes
			logger.Infof("Status code filter set to %v", statusCodes)
		}
	}

	if args.DisableHashFilter {
		customFilterConfig = ensureFilterConfig(customFilterConfig)
		customFilterConfig.DisableHashFilter = true
		logger.Warn("CLI option: dirscan hash filtering disabled (--no-filter)")
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

type arrayFlags []string

const (
	moduleFinger  = "finger"
	moduleDirscan = "dirscan"
)

func (af *arrayFlags) String() string {
	return strings.Join(*af, ", ")
}

func (af *arrayFlags) Set(value string) error {
	*af = append(*af, value)
	return nil
}

// ValidModules 有效的模块列表
var ValidModules = []string{moduleFinger, moduleDirscan}

// HasModule 检查是否包含指定模块
func (args *CLIArgs) HasModule(module string) bool {
	for _, m := range args.Modules {
		if m == module {
			return true
		}
	}
	return false
}

// getMaxInt 获取两个整数中的最大值，用于处理短参数和长参数
func getMaxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// getStringValue 获取字符串参数值，优先使用非空值，用于处理短参数和长参数
func getStringValue(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// parseCommaSeparatedString 解析逗号分隔的字符串
func parseCommaSeparatedString(input string) []string {
	if input == "" {
		return []string{}
	}

	items := strings.Split(input, ",")
	var cleanItems []string

	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			cleanItems = append(cleanItems, item)
		}
	}
	return cleanItems
}

func parseTargets(targetsStr string) []string {
	return parseCommaSeparatedString(targetsStr)
}

func parseModules(modulesStr string) []string {
	return parseCommaSeparatedString(modulesStr)
}

// validateWordlistFile 验证字典文件
func validateWordlistFile(wordlistPath string) error {
	if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
		return fmt.Errorf("wordlist file does not exist: %s", wordlistPath)
	}

	// 检查文件是否可读
	file, err := os.Open(wordlistPath)
	if err != nil {
		return fmt.Errorf("unable to read wordlist file: %v", err)
	}
	file.Close()

	return nil
}

// validateOutputPath 验证输出路径
func validateOutputPath(outputPath string) error {
	outputPath = strings.TrimSpace(outputPath)
	if outputPath == "" {
		return fmt.Errorf("output path must not be empty")
	}
	dir := filepath.Dir(outputPath)

	// 如果目录不存在，尝试创建
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("unable to create output directory %s: %v", dir, err)
		}
	}

	// 检查目录是否可写
	testFile := filepath.Join(dir, ".veo_write_test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("output directory is not writable %s: %v", dir, err)
	}
	os.Remove(testFile) // 清理测试文件

	return nil
}

func validateModules(modules []string) error {
	for _, module := range modules {
		if !isValidModule(module) {
			return fmt.Errorf("invalid module: '%s', supported modules: %s", module, strings.Join(ValidModules, ", "))
		}
	}
	return nil
}

// isValidModule 检查模块是否有效
func isValidModule(module string) bool {
	for _, validModule := range ValidModules {
		if module == validModule {
			return true
		}
	}
	return false
}

func parseHeaderFlags(headers []string) (map[string]string, error) {
	parsed := make(map[string]string)
	for _, header := range headers {
		h := strings.TrimSpace(header)
		if h == "" {
			continue
		}
		if strings.ContainsAny(h, "\r\n") {
			return nil, fmt.Errorf("header must not contain newlines: %q", h)
		}
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid header format: %s (expected Header: Value)", h)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			return nil, fmt.Errorf("header name must not be empty: %s", h)
		}
		if value == "" {
			return nil, fmt.Errorf("header value must not be empty: %s", h)
		}
		parsed[key] = value
	}
	return parsed, nil
}

// parseStatusCodes 解析CLI参数中的状态码字符串
func parseStatusCodes(statusCodesStr string) ([]int, error) {
	if statusCodesStr == "" {
		return nil, fmt.Errorf("status code string must not be empty")
	}

	// 分割逗号分隔的状态码
	codeStrings := strings.Split(statusCodesStr, ",")
	statusCodes := make([]int, 0, len(codeStrings))

	for _, codeStr := range codeStrings {
		codeStr = strings.TrimSpace(codeStr)
		if codeStr == "" {
			continue // 跳过空字符串
		}

		// 转换为整数
		code, err := strconv.Atoi(codeStr)
		if err != nil {
			return nil, fmt.Errorf("invalid status code '%s': must be an integer", codeStr)
		}

		// 验证状态码范围
		if err := validateStatusCode(code); err != nil {
			return nil, fmt.Errorf("invalid status code %d: %v", code, err)
		}

		statusCodes = append(statusCodes, code)
		logger.Debugf("解析状态码: %d", code)
	}

	if len(statusCodes) == 0 {
		return nil, fmt.Errorf("no valid status codes were parsed")
	}

	return statusCodes, nil
}

// validateStatusCode 验证单个状态码的有效性
func validateStatusCode(code int) error {
	// HTTP状态码范围: 100-599
	if code < 100 || code > 599 {
		return fmt.Errorf("status code must be between 100 and 599")
	}
	return nil
}

func parseWordlistPaths(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	seen := make(map[string]struct{})
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func buildHostAllowList(targets []string) []string {
	allow := make([]string, 0, len(targets))
	seen := make(map[string]struct{})
	for _, raw := range targets {
		host, _, _ := normalizeTargetHost(raw)
		if host == "" {
			continue
		}
		host = strings.TrimSpace(strings.ToLower(host))
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		allow = append(allow, host)
		seen[host] = struct{}{}
	}
	return allow
}

func normalizeTargetHost(raw string) (host string, port string, wildcard bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", false
	}
	candidate := s
	if strings.Contains(s, "://") {
		if parsed, err := url.Parse(s); err == nil {
			candidate = parsed.Host
		}
	}
	if idx := strings.Index(candidate, "/"); idx != -1 {
		candidate = candidate[:idx]
	}
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return "", "", false
	}
	if at := strings.LastIndex(candidate, "@"); at != -1 {
		candidate = candidate[at+1:]
	}
	port = ""
	hostPart := candidate
	if strings.HasPrefix(hostPart, "[") {
		if h, p, err := net.SplitHostPort(hostPart); err == nil {
			hostPart, port = h, p
		} else {
			hostPart = strings.Trim(hostPart, "[]")
		}
	} else {
		if h, p, err := net.SplitHostPort(hostPart); err == nil {
			hostPart, port = h, p
		}
	}
	hostPart = strings.TrimSpace(hostPart)
	if hostPart == "" {
		return "", "", false
	}
	lower := strings.ToLower(hostPart)
	return lower, port, strings.HasPrefix(lower, "*.")
}

// handleRuleUpdates 处理指纹库更新逻辑
func handleRuleUpdates(args *CLIArgs) {
	updater := fpaddon.NewUpdater("config/fingerprint/finger.yaml")

	if args.UpdateRules {
		logger.Info("Checking for fingerprint rule updates...")
		if err := updater.UpdateRules(); err != nil {
			logger.Fatalf("指纹库更新失败: %v", err)
		}
		logger.Info("Fingerprint rules updated")
		os.Exit(0)
	}

	// 检查更新 (同步执行，确保在扫描前提示)
	// 使用短超时 (1s) 避免阻塞过久
	hasUpdate, localVer, remoteVer, err := updater.CheckForUpdates()
	if err != nil {
		logger.Debugf("检查指纹库更新失败: %v", err)
		return
	}

	if hasUpdate {
		msg := fmt.Sprintf("New fingerprint rules version available: %s (current: %s), run --update-rules to update", remoteVer, localVer)
		logger.Info(msg)
	} else {
		logger.Debugf("指纹库已是最新版本: %s", localVer)
	}
}
