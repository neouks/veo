package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"veo/internal/core/config"
	"veo/pkg/core/console"
	modulepkg "veo/pkg/core/module"
	"veo/pkg/dirscan"
	fpaddon "veo/pkg/fingerprint"
	portconfig "veo/pkg/portscan"
	"veo/pkg/utils/formatter"
	"veo/pkg/utils/httpclient"
	"veo/pkg/utils/logger"
	"veo/pkg/utils/processor/auth"
	"veo/proxy"

	// "os/exec" // removed: masscan执行迁移至模块
	portscanpkg "veo/pkg/portscan"
	gogoscanner "veo/pkg/portscan/gogo"
	portservice "veo/pkg/portscan/service"
	report "veo/pkg/reporter"
)

// arrayFlags 实现flag.Value接口，支持多个相同参数
type arrayFlags []string

func (af *arrayFlags) String() string {
	return strings.Join(*af, ", ")
}

func (af *arrayFlags) Set(value string) error {
	*af = append(*af, value)
	return nil
}

// CLIArgs CLI参数结构体
type CLIArgs struct {
	Targets    []string // 目标主机/URL (-u)
	TargetFile string   // 新增：目标文件路径 (-l)
	Modules    []string // 启用的模块 (-m)
	Port       int      // 监听端口 (--lp)
	// 端口扫描（masscan）相关
	Ports    string // 扫描端口表达式 (-p 例如: 80,443,8000-8100 或 1-65535)
	Rate     int    // 扫描速率 (--rate，包/秒)
	Wordlist string // 自定义字典路径 (-w)
	Listen   bool   // 被动代理模式 (--listen)
	Proxy    string // 上游代理地址 (--proxy)
	Debug    bool   // 调试模式 (--debug)

	// 新增：线程并发控制和全局配置参数
	Threads int // 统一线程并发数量 (-t, --threads)
	Retry   int // 重试次数 (--retry)
	Timeout int // 全局超时时间 (--timeout)

	// 新增：报告输出控制参数
	Output string // 报告文件输出路径 (-o, --output)

	// 新增：实时统计显示参数
	Stats bool // 启用实时扫描进度统计显示 (--stats)

	// 输出控制
	NoColor    bool // 禁用彩色输出 (-nc)
	JSONOutput bool // 控制台输出JSON结果 (--json)

	// 指纹细节输出开关
	Verbose            bool // 指纹匹配规则展示开关 (-v)
	VeryVerbose        bool // 指纹匹配内容展示开关 (-vv)
	NoAliveCheck       bool // 跳过存活检测 (-na)
	EnableServiceProbe bool // 启用端口服务识别 (默认开启，-sV 关闭)

	// 新增：HTTP认证头部参数
	Headers []string // 自定义HTTP认证头部 (--header "Header-Name: Header-Value")

	// 新增：状态码过滤参数
	StatusCodes string // 自定义过滤HTTP状态码 (-s "200,301,302")

	// 新增：相似页面过滤容错阈值参数
	FilterTolerance int // 相似页面过滤容错阈值 (--filter-tolerance)

	// 新增：随机User-Agent控制
	RandomUA bool // 是否启用随机User-Agent (-ua, 默认启用)

	// 内部：端口优先模式标记
	PortFirst bool
}

// ValidModules 有效的模块列表（使用module包的类型定义）
var ValidModules = []string{string(modulepkg.ModuleFinger), string(modulepkg.ModuleDirscan), "port"}

// CLIApp CLI应用程序
type CLIApp struct {
	proxy             *proxy.Proxy
	collector         *dirscan.Collector
	consoleManager    *console.ConsoleManager
	dirscanModule     *dirscan.DirscanModule
	fingerprintAddon  *fpaddon.FingerprintAddon
	authLearningAddon *auth.AuthLearningAddon
	proxyStarted      bool
	args              *CLIArgs
}

var app *CLIApp

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
	args.PortFirst = shouldUsePortFirst(args)

	// 应用CLI参数到配置（包括--debug标志）
	applyArgsToConfig(args)

	//  提前显示启动信息，确保banner在所有日志输出之前显示
	displayStartupInfo(args)

	// 仅端口扫描模式：-m port
	if !args.Listen && args.HasModule("port") && len(args.Modules) == 1 {
		if _, _, err := resolvePortExpression(args); err != nil {
			logger.Fatalf("端口扫描参数错误: %v", err)
		}
		if err := runMasscanPortScan(args); err != nil {
			logger.Fatalf("端口扫描失败: %v", err)
		}
		return
	}

	// 保持既有逻辑：不携带 -p 时，按原有模块执行（目录扫描+指纹识别）。
	// 若携带 -p，则先执行正常扫描（目录扫描+指纹识别），结束后再执行端口扫描。

	// 初始化应用程序（仅当非端口扫描场景）
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
		reportPath := strings.TrimSpace(args.Output)
		// 若启用端口模块，则在正常扫描完成后执行端口扫描（仅当未输出合并JSON文件时）
		if args.HasModule("port") && !args.PortFirst && !args.JSONOutput && !strings.HasSuffix(strings.ToLower(reportPath), ".json") {
			if _, _, err := resolvePortExpression(args); err != nil {
				logger.Fatalf("端口扫描参数错误: %v", err)
			}
			if err := runMasscanPortScan(args); err != nil {
				logger.Fatalf("端口扫描失败: %v", err)
			}
		}
	}
}

// ParseCLIArgs 解析命令行参数
func ParseCLIArgs() *CLIArgs {
	var (
		targetsStr = flag.String("u", "", "目标主机/URL，多个目标用逗号分隔 (例如: -u www.baidu.com,api.baidu.com)")
		targetFile = flag.String("l", "", "目标文件路径，每行一个目标 (例如: -l targets.txt)")
		modulesStr = flag.String("m", "", "启用的模块，多个模块用逗号分隔 (例如: -m finger,dirscan)")
		localPort  = flag.Int("lp", 9080, "本地代理监听端口，仅在被动模式下使用 (默认: 9080)")
		portsArg   = flag.String("p", "", "端口范围或字典名称，如 80,443,8000-8100 / web / service / top1000 / all")
		rateArg    = flag.Int("rate", 0, "端口扫描速率(包/秒)，仅在启用端口扫描时使用 (例如: --rate 10000)")
		wordlist   = flag.String("w", "", "自定义字典文件路径 (例如: -w /path/to/custom.txt)")
		listen     = flag.Bool("listen", false, "启用被动代理模式 (默认: 主动扫描模式)")
		proxy      = flag.String("proxy", "", "设置上游代理 (例如: http://127.0.0.1:8080 或 socks5://127.0.0.1:1080)")
		debug      = flag.Bool("debug", false, "启用调试模式，显示详细日志 (默认: 仅显示INFO及以上级别)")

		// 新增：线程并发控制和全局配置参数
		threads     = flag.Int("t", 0, "统一线程并发数量，对所有模块生效 (默认: 200)")
		threadsLong = flag.Int("threads", 0, "统一线程并发数量，对所有模块生效 (默认: 200)")
		retry       = flag.Int("retry", 0, "扫描失败目标的重试次数 (默认: 1)")
		timeout     = flag.Int("timeout", 0, "全局连接超时时间(秒)，对所有模块生效 (默认: 3)")

		// 新增：报告输出控制参数
		output     = flag.String("o", "", "输出报告文件路径 (默认不输出文件)")
		outputLong = flag.String("output", "", "输出报告文件路径 (默认不输出文件)")

		// 新增：实时统计显示参数
		stats        = flag.Bool("stats", false, "启用实时扫描进度统计显示")
		verbose      = flag.Bool("v", false, "显示指纹匹配规则内容 (默认关闭，可使用 -v 开启)")
		veryVerbose  = flag.Bool("vv", false, "显示指纹匹配规则与内容片段 (默认关闭，可使用 -vv 开启)")
		noColor      = flag.Bool("nc", false, "禁用彩色输出，适用于控制台不支持ANSI的环境")
		jsonOutput   = flag.Bool("json", false, "使用JSON格式输出扫描结果，便于与其他工具集成")
		noAlive      = flag.Bool("na", false, "跳过扫描前的存活检测 (默认进行存活检测)")
		serviceProbe = flag.Bool("sV", false, "禁用端口服务识别 (默认开启)")

		// 新增：状态码过滤参数
		statusCodes = flag.String("s", "", "指定需要保留的HTTP状态码，逗号分隔 (例如: -s 200,301,302)")

		// 新增：相似页面过滤容错阈值参数（-1表示使用默认值）
		filterTolerance = flag.Int("filter", -1, "相似页面过滤容错阈值(字节)，值越大过滤越严格 (默认: 50, 范围: 0-500, 0表示禁用过滤)")

		// 新增：随机User-Agent控制
		randomUAFlag = flag.Bool("ua", true, "是否启用随机User-Agent池 (默认: true，可通过 -ua=false 关闭)")

		help     = flag.Bool("h", false, "显示帮助信息")
		helpLong = flag.Bool("help", false, "显示帮助信息")
	)

	// 新增：自定义HTTP头部参数（支持多个）
	var headers arrayFlags
	flag.Var(&headers, "header", "自定义HTTP认证头部，格式: \"Header-Name: Header-Value\" (可重复使用)")

	// 设置自定义帮助信息
	flag.Usage = showCustomHelp

	flag.Parse()

	// 显示帮助信息
	if *help || *helpLong {
		flag.Usage()
		os.Exit(0)
	}

	// 创建CLIArgs实例
	args := &CLIArgs{
		TargetFile: *targetFile,
		Port:       *localPort,
		Ports:      *portsArg,
		Rate:       *rateArg,
		Wordlist:   *wordlist,
		Listen:     *listen,
		Proxy:      *proxy,
		Debug:      *debug,

		// 新增参数处理：支持短参数和长参数
		Threads:            getMaxInt(*threads, *threadsLong),
		Retry:              *retry,
		Timeout:            *timeout,
		Output:             getStringValue(*output, *outputLong),
		Stats:              *stats,
		Verbose:            *verbose,
		VeryVerbose:        *veryVerbose,
		NoColor:            *noColor,
		JSONOutput:         *jsonOutput,
		NoAliveCheck:       *noAlive,
		EnableServiceProbe: !*serviceProbe,

		// 新增：HTTP认证头部参数
		Headers: []string(headers),

		// 新增：状态码过滤参数
		StatusCodes: *statusCodes,

		// 新增：相似页面过滤容错阈值参数
		FilterTolerance: *filterTolerance,

		// 新增：随机User-Agent控制
		RandomUA: *randomUAFlag,
	}

	if *targetsStr != "" {
		args.Targets = parseTargets(*targetsStr)
	}

	if *modulesStr != "" {
		args.Modules = parseModules(*modulesStr)
	}

	// [新增] 如果未指定模块，使用默认模块
	if len(args.Modules) == 0 {
		args.Modules = []string{string(modulepkg.ModuleFinger), string(modulepkg.ModuleDirscan)}
		logger.Debugf("未指定模块，使用默认模块: %s, %s", modulepkg.ModuleFinger, modulepkg.ModuleDirscan)
	}

	if args.JSONOutput {
		args.Stats = false
	}

	// 验证参数
	if err := validateArgs(args); err != nil {
		logger.Error(fmt.Sprintf("参数验证失败: %v", err))
		os.Exit(1)
	}

	return args
}

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

// showCustomHelp 显示自定义帮助信息
func showCustomHelp() {
	prog := filepath.Base(os.Args[0])
	fmt.Printf(`
veo - 端口扫描/指纹识别/目录扫描

用法:
  %[1]s -u <targets> [options]           # 主动扫描（默认）
  %[1]s -l <file> [options]              # 文件批量扫描
  %[1]s -u <targets> --listen [options]  # 被动代理模式

目标与模块:
  -u string            目标列表，逗号分隔；支持 URL / 域名 / host:port / CIDR / IP 范围
  -l string            目标文件，每行一个目标；支持空行和 # 注释
  -m string            启用模块，默认 finger,dirscan。可选 finger / dirscan / port
  --listen             被动代理模式；配合 --lp 指定监听端口（默认 9080）

端口扫描:
  -p string            端口表达式，例如 80,443,8000-8100
  -pw string           端口字典文件或预设(top/web/service)，未指定 -p 时使用
  --rate int           探测速率，默认 2048；大于 2048 时按 2048 为一批运行
  -sV                  禁用服务识别（默认开启，可省略该参数）

扫描控制:
  --debug              输出调试日志
  --stats              显示实时统计信息
  -v                   显示指纹匹配规则内容
  -na                  跳过存活检测
  -vv                  显示指纹匹配规则及匹配片段
  -nc                  禁用彩色输出
  --json               控制台输出 JSON
  -ua bool             是否启用随机User-Agent 池 (默认 true，使用 -ua=false 关闭)

性能调优:
  -t, --threads int    全局并发线程数（默认 200）
  --retry int          失败重试次数（默认 1）
  --timeout int        全局超时时间（秒，默认 3）

目录扫描:
  -w string            指定自定义目录字典，可用逗号添加多个

输出与过滤:
  -o, --output string  写入报告文件 (.json / .xlsx)
  --header string      自定义 HTTP 头部，可重复指定
  -s string            保留的 HTTP 状态码列表
  --filter int         相似页面过滤阈值（字节，0 表示关闭）

帮助:
  -h, --help           显示本帮助信息

示例:
  %[1]s -u https://target.com -m finger,dirscan
  %[1]s -u 1.1.1.1 -m port -p 1-65535 -sV --rate 10000
  %[1]s -l targets.txt -m finger,dirscan --stats
  %[1]s -u target.com --listen --lp 8080

`, prog)
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

// validateArgs 验证CLI参数
func validateArgs(args *CLIArgs) error {
	// 验证端口范围（仅在被动模式下需要）
	if args.Listen && (args.Port <= 0 || args.Port > 65535) {
		return fmt.Errorf("端口必须在1-65535范围内，当前值: %d", args.Port)
	}

	// 当指定端口扫描时进行基础校验
	if strings.TrimSpace(args.Ports) != "" {
		if len(args.Targets) == 0 && strings.TrimSpace(args.TargetFile) == "" {
			return fmt.Errorf("端口扫描需要通过 -u 或 -l 指定目标")
		}
	}

	// 验证线程并发数量
	if args.Threads < 0 || args.Threads > 1000 {
		return fmt.Errorf("线程并发数量必须在0-1000范围内，当前值: %d", args.Threads)
	}

	// 验证重试次数
	if args.Retry < 0 || args.Retry > 10 {
		return fmt.Errorf("重试次数必须在0-10范围内，当前值: %d", args.Retry)
	}

	// 验证超时时间
	if args.Timeout < 0 || args.Timeout > 300 {
		return fmt.Errorf("超时时间必须在0-300秒范围内，当前值: %d", args.Timeout)
	}

	// 验证相似页面过滤容错阈值（-1表示使用默认值，不需要验证）
	if args.FilterTolerance != -1 && (args.FilterTolerance < 0 || args.FilterTolerance > 500) {
		return fmt.Errorf("相似页面过滤容错阈值必须在0-500范围内，当前值: %d", args.FilterTolerance)
	}

	// 端口扫描模块需要指定端口范围
	if args.HasModule("port") && !args.Listen {
		if len(args.Targets) == 0 && strings.TrimSpace(args.TargetFile) == "" {
			return fmt.Errorf("端口扫描需要通过 -u 或 -l 指定目标")
		}
	}

	// 根据模式验证参数
	if args.Listen {
		// 被动代理模式：如果没有指定目标，设置默认值为 * (全部抓取)
		if len(args.Targets) == 0 {
			args.Targets = []string{"*"}
		}
	} else {
		// 主动扫描模式：必须指定具体目标或目标文件
		if len(args.Targets) == 0 && args.TargetFile == "" {
			return fmt.Errorf("主动扫描模式必须指定目标主机/URL (-u) 或目标文件 (-l)")
		}
		// 主动模式不允许使用通配符
		for _, target := range args.Targets {
			if target == "*" {
				return fmt.Errorf("主动扫描模式不支持通配符目标，请指定具体的URL")
			}
		}
	}

	// 验证目标格式
	if err := validateTargets(args.Targets); err != nil {
		return fmt.Errorf("目标参数无效: %v", err)
	}

	// 验证自定义字典文件（如果指定）
	if args.Wordlist != "" {
		if err := validateWordlistFile(args.Wordlist); err != nil {
			return fmt.Errorf("字典文件无效: %v", err)
		}
	}

	// 验证输出路径（如果指定）
	if args.Output != "" {
		if err := validateOutputPath(args.Output); err != nil {
			return fmt.Errorf("输出路径无效: %v", err)
		}
	}

	// 验证模块
	if err := validateModules(args.Modules); err != nil {
		return fmt.Errorf("模块参数无效: %v", err)
	}

	// [修改] 移除"必须指定模块"的检查，因为现在有默认模块
	// 注意：ParseCLIArgs() 已经在未指定模块时自动设置默认模块
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

		// 允许通配符 "*" 表示全部抓取
		if target == "*" {
			continue
		}

		// 基本的目标格式检查
		if strings.HasPrefix(target, ".") || strings.HasSuffix(target, ".") {
			return fmt.Errorf("无效的目标格式: '%s'", target)
		}
	}
	return nil
}

// validateWordlistFile 验证字典文件
func validateWordlistFile(wordlistPath string) error {
	if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
		return fmt.Errorf("字典文件不存在: %s", wordlistPath)
	}

	// 检查文件是否可读
	file, err := os.Open(wordlistPath)
	if err != nil {
		return fmt.Errorf("无法读取字典文件: %v", err)
	}
	file.Close()

	return nil
}

// validateOutputPath 验证输出路径
func validateOutputPath(outputPath string) error {
	// 支持 .json 和 .xlsx 扩展名
	lowerPath := strings.ToLower(outputPath)
	if !strings.HasSuffix(lowerPath, ".json") && !strings.HasSuffix(lowerPath, ".xlsx") {
		return fmt.Errorf("输出文件必须以.json或.xlsx结尾，当前: %s", outputPath)
	}

	// 获取目录路径
	dir := filepath.Dir(outputPath)

	// 如果目录不存在，尝试创建
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("无法创建输出目录 %s: %v", dir, err)
		}
	}

	// 检查目录是否可写
	testFile := filepath.Join(dir, ".veo_write_test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("输出目录不可写 %s: %v", dir, err)
	}
	os.Remove(testFile) // 清理测试文件

	return nil
}

// validateModules 验证模块列表
func validateModules(modules []string) error {
	for _, module := range modules {
		if !isValidModule(module) {
			return fmt.Errorf("无效的模块: '%s'，支持的模块: %s", module, strings.Join(ValidModules, ", "))
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

// GetTargetsString 获取目标列表字符串
func (args *CLIArgs) GetTargetsString() string {
	return strings.Join(args.Targets, ",")
}

// GetModulesString 获取模块列表字符串
func (args *CLIArgs) GetModulesString() string {
	return strings.Join(args.Modules, ",")
}

// initializeReportGenerator 初始化报告生成器（已优化为无操作）
func initializeReportGenerator() {
	// 新架构中过滤器已经独立化，不再需要全局设置
	logger.Debug("报告生成器已独立化，无需全局设置")
}

// initializeApp 初始化应用程序
func initializeApp(args *CLIArgs) (*CLIApp, error) {
	// 配置系统和日志系统已在Execute()函数开始时初始化，这里无需重复

	// 初始化报告生成器
	initializeReportGenerator()

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

		// 创建collector
		logger.Debug("创建URL采集器...")
		collectorInstance = dirscan.NewCollector()

		// 创建控制台管理器
		logger.Debug("创建控制台管理器...")
		consoleManager = console.NewConsoleManager(collectorInstance)

		// 创建目录扫描模块
		logger.Debug("创建目录扫描模块...")
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
	var fingerprintAddon *fpaddon.FingerprintAddon
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

	// 创建应用程序实例
	app := &CLIApp{
		proxy:             proxyServer,
		collector:         collectorInstance, // 可能为nil
		consoleManager:    consoleManager,    // 可能为nil
		dirscanModule:     dirscanModule,     // 可能为nil
		fingerprintAddon:  fingerprintAddon,  // 可能为nil
		authLearningAddon: authLearningAddon, // 总是存在
		proxyStarted:      false,
		args:              args,
	}

	// 只在有控制台管理器时设置回调
	if consoleManager != nil {
		consoleManager.SetProxyController(app)
		if fingerprintAddon != nil {
			consoleManager.SetFingerprintAddon(fingerprintAddon)
		}
	}

	logger.Debug("应用程序初始化完成")
	return app, nil
}

// ApplyArgsToConfig 将CLI参数应用到配置系统（导出用于测试）
func ApplyArgsToConfig(args *CLIArgs) {
	applyArgsToConfig(args)
}

// applyArgsToConfig 将CLI参数应用到配置系统
func applyArgsToConfig(args *CLIArgs) {
	// 设置监听端口
	serverConfig := config.GetServerConfig()
	serverConfig.Listen = fmt.Sprintf(":%d", args.Port)

	// 应用调试模式设置
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
	}

	// 处理HTTP认证头部参数
	if len(args.Headers) > 0 {
		if parsed, err := parseHeaderFlags(args.Headers); err != nil {
			logger.Errorf("HTTP头部参数处理失败: %v", err)
		} else if len(parsed) > 0 {
			config.SetCustomHeaders(parsed)
		}
	}

	// 新增：处理状态码过滤参数
	// 目标：统一主动/被动两种模式对状态码来源的处理逻辑
	// 1) 设置全局 ResponseFilter 的有效状态码（影响目录扫描结果过滤）
	// 2) 同步覆盖被动模式 URL 采集器（Collector）的状态码白名单
	var customFilterConfig *dirscan.FilterConfig

	if args.StatusCodes != "" {
		statusCodes, err := parseStatusCodes(args.StatusCodes)
		if err != nil {
			logger.Errorf("状态码过滤参数处理失败: %v", err)
		} else if len(statusCodes) > 0 {
			logger.Debugf("成功解析 %d 个状态码: %v", len(statusCodes), statusCodes)

			// 1) 覆盖全局过滤配置（供 ResponseFilter 使用）
			customFilterConfig = dirscan.DefaultFilterConfig()
			customFilterConfig.ValidStatusCodes = statusCodes
			logger.Infof("状态码过滤设置为 %v", statusCodes)

			// 2) 覆盖被动模式 Collector 的采集状态码白名单
			collectorCfg := config.GetCollectorConfig()
			if collectorCfg != nil {
				collectorCfg.GenerationStatusCodes = statusCodes
				logger.Infof("被动采集状态码白名单设置为 %v", statusCodes)
			}
		}
	}

	if args.FilterTolerance != -1 {
		if customFilterConfig == nil {
			customFilterConfig = dirscan.DefaultFilterConfig()
		}
		customFilterConfig.FilterTolerance = int64(args.FilterTolerance)
		logger.Debugf("CLI参数覆盖：相似页面过滤容错阈值设置为 %d 字节", args.FilterTolerance)
	}

	if customFilterConfig != nil {
		dirscan.SetGlobalFilterConfig(customFilterConfig)
	}

	// 设置目标白名单
	if len(args.Targets) > 0 {
		hostConfig := config.GetHostsConfig()
		allowList := buildHostAllowList(args.Targets)
		hostConfig.Allow = allowList
		if len(allowList) > 0 {
			logger.Debugf("主机白名单已设置: %v", allowList)
		}
	}

	// 应用自定义字典路径
	if args.Wordlist != "" {
		wordlists := parseWordlistPaths(args.Wordlist)
		dirscan.SetWordlistPaths(wordlists)
		logger.Infof("Use Dicts: %s", strings.Join(wordlists, ","))
	} else {
		dirscan.SetWordlistPaths(nil)
	}

	// 设置上游代理
	if args.Proxy != "" {
		proxyConfig := config.GetProxyConfig()
		proxyConfig.UpstreamProxy = args.Proxy
		logger.Infof("上游代理已设置: %s", args.Proxy)
	}

	// 应用输出文件路径
}

// createProxy 创建代理服务器
func createProxy() (*proxy.Proxy, error) {
	serverConfig := config.GetServerConfig()
	proxyConfig := config.GetProxyConfig()

	opts := &proxy.Options{
		Addr:              serverConfig.Listen,
		StreamLargeBodies: proxyConfig.StreamLargebody,
		SslInsecure:       proxyConfig.SSLInsecure, // 添加缺失的SSL配置
		Upstream:          proxyConfig.UpstreamProxy,
	}
	return proxy.NewProxy(opts)
}

// runMasscanPortScan 调用 masscan 扫描（模块化实现）
func runMasscanPortScan(args *CLIArgs) error {
	reportPath := strings.TrimSpace(args.Output)
	results, portsExpr, effectiveRate, err := runPortScanAndCollect(args, args.Targets, true, false)
	if err != nil {
		return err
	}
	// --json 模式：输出合并JSON（仅包含 portscan_results）到控制台；如指定 --output .json，则写入相同内容
	if args.JSONOutput {
		pr := aggregatePortResults(results)
		params := map[string]interface{}{
			"ports": portsExpr,
			"rate":  effectiveRate,
		}
		jsonStr, jerr := report.GenerateCombinedJSON(nil, nil, nil, nil, pr, params)
		if jerr != nil {
			return jerr
		}
		fmt.Println(jsonStr)
		if reportPath != "" && strings.HasSuffix(strings.ToLower(reportPath), ".json") {
			if err := os.MkdirAll(filepath.Dir(reportPath), 0o755); err != nil {
				logger.Errorf("创建输出目录失败: %v", err)
			} else if werr := os.WriteFile(reportPath, []byte(jsonStr), 0o644); werr != nil {
				logger.Errorf("写入合并JSON失败: %v", werr)
			}
		}
		return nil
	}
	for _, r := range results {
		if r.Service != "" {
			logger.Infof("%s:%d %s", r.IP, r.Port, formatter.FormatProtocol(strings.ToUpper(strings.TrimSpace(r.Service))))
		} else {
			logger.Infof("%s:%d", r.IP, r.Port)
		}
	}
	logger.Debugf("端口扫描完成，发现开放端口: %d", len(results))

	// 若指定输出路径，则根据扩展名导出 JSON 或 Excel
	if reportPath != "" {
		out := reportPath
		lower := strings.ToLower(out)
		if strings.HasSuffix(lower, ".json") {
			// 落盘合并JSON（仅包含 portscan_results），与 --json 控制台一致
			pr := aggregatePortResults(results)
			params := map[string]interface{}{"ports": portsExpr, "rate": effectiveRate}
			if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
				logger.Errorf("创建输出目录失败: %v", err)
			} else {
				if jsonStr, jerr := report.GenerateCombinedJSON(nil, nil, nil, nil, pr, params); jerr != nil {
					logger.Errorf("生成合并JSON失败: %v", jerr)
				} else if werr := os.WriteFile(out, []byte(jsonStr), 0o644); werr != nil {
					logger.Errorf("端口扫描合并JSON报告写入失败: %v", werr)
				}
			}
		} else if strings.HasSuffix(lower, ".xlsx") {
			if _, err := report.GeneratePortscanExcel(results, out); err != nil {
				logger.Errorf("端口扫描Excel报告生成失败: %v", err)
			}
		} else {
			logger.Warnf("未知的输出文件类型: %s (支持 .json/.xlsx)", out)
		}
	}
	return nil
}

func parseHeaderFlags(headers []string) (map[string]string, error) {
	parsed := make(map[string]string)
	for _, header := range headers {
		h := strings.TrimSpace(header)
		if h == "" {
			continue
		}
		if strings.ContainsAny(h, "\r\n") {
			return nil, fmt.Errorf("头部不能包含换行符: %q", h)
		}
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("无效的头部格式: %s (需要 Header: Value)", h)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			return nil, fmt.Errorf("头部名称不能为空: %s", h)
		}
		if value == "" {
			return nil, fmt.Errorf("头部值不能为空: %s", h)
		}
		parsed[key] = value
	}
	return parsed, nil
}

// aggregatePortResults 将 OpenPortResult 列表按 IP 聚合为 SDKPortResult（端口字符串数组）
func aggregatePortResults(results []portscanpkg.OpenPortResult) []report.SDKPortResult {
	if len(results) == 0 {
		return nil
	}
	m := make(map[string]map[int]string)
	for _, r := range results {
		if _, ok := m[r.IP]; !ok {
			m[r.IP] = make(map[int]string)
		}
		if _, exists := m[r.IP][r.Port]; !exists || m[r.IP][r.Port] == "" {
			m[r.IP][r.Port] = strings.TrimSpace(r.Service)
		}
	}
	out := make([]report.SDKPortResult, 0, len(m))
	for ip, portsSet := range m {
		ports := make([]int, 0, len(portsSet))
		for p := range portsSet {
			ports = append(ports, p)
		}
		for i := 0; i < len(ports); i++ {
			for j := i + 1; j < len(ports); j++ {
				if ports[j] < ports[i] {
					ports[i], ports[j] = ports[j], ports[i]
				}
			}
		}
		entries := make([]report.SDKPortEntry, 0, len(ports))
		for _, p := range ports {
			entry := report.SDKPortEntry{
				Port:    p,
				Service: strings.TrimSpace(portsSet[p]),
			}
			if entry.Service == "" {
				entry.Service = ""
			}
			entries = append(entries, entry)
		}
		out = append(out, report.SDKPortResult{IP: ip, Ports: entries})
	}
	return out
}

// createFingerprintAddon 创建指纹识别插件
func createFingerprintAddon() (*fpaddon.FingerprintAddon, error) {
	addon, err := fpaddon.CreateDefaultAddon()
	if err != nil {
		return nil, err
	}

	fpaddon.SetGlobalAddon(addon)
	return addon, nil
}

// createAuthLearningAddon 创建认证学习插件
func createAuthLearningAddon() *auth.AuthLearningAddon {
	addon := auth.NewAuthLearningAddon()

	// 设置回调：与全局配置交互
	addon.SetCallbacks(
		// OnAuthLearned: 更新全局配置
		func(headers map[string]string) {
			// 获取当前的全局自定义头部
			currentHeaders := config.GetCustomHeaders()
			mergedHeaders := make(map[string]string)

			// 先复制现有的头部
			for key, value := range currentHeaders {
				mergedHeaders[key] = value
			}

			// 添加新学习到的Authorization头部（如果不存在的话）
			newHeadersCount := 0
			for key, value := range headers {
				if _, exists := mergedHeaders[key]; !exists {
					mergedHeaders[key] = value
					newHeadersCount++
				}
			}

			// 更新全局配置
			if newHeadersCount > 0 {
				config.SetCustomHeaders(mergedHeaders)
				logger.Debugf("应用了 %d 个新的Authorization头部到全局配置", newHeadersCount)
			}
		},
		// IsAuthSet: 检查是否已设置认证头部
		func() bool {
			return config.HasCustomHeaders()
		},
	)

	logger.Debug("认证学习插件创建成功")
	return addon
}

// startApplication 启动应用程序
func startApplication(args *CLIArgs) error {
	// 启动代理服务器
	if err := app.StartProxy(); err != nil {
		return fmt.Errorf("启动代理服务器失败: %v", err)
	}

	// 启动指定的模块
	logger.Debug("开始启动指定的模块...")

	// 启动指纹识别模块
	if args.HasModule(string(modulepkg.ModuleFinger)) && app.fingerprintAddon != nil {
		// 注意：fingerprintAddon是直接的addon，不是模块，需要设置为全局实例
		fpaddon.SetGlobalAddon(app.fingerprintAddon)
		app.fingerprintAddon.Enable()

		// 控制匹配输出粒度
		app.fingerprintAddon.EnableSnippet(args.VeryVerbose)
		app.fingerprintAddon.EnableRuleLogging(args.Verbose || args.VeryVerbose)

		// 将指纹识别addon添加到代理服务器
		app.proxy.AddAddon(app.fingerprintAddon)
		logger.Debug("指纹识别addon已添加到代理服务器")
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

	// 执行模块间依赖注入
	if app.fingerprintAddon != nil {
		// 使用HTTP客户端工厂创建客户端（代码质量优化）
		userAgent := "Moziilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0"

		// 获取并更新客户端配置
		clientConfig := httpclient.DefaultConfigWithUserAgent(userAgent)
		if proxyCfg := config.GetProxyConfig(); proxyCfg.UpstreamProxy != "" {
			clientConfig.ProxyURL = proxyCfg.UpstreamProxy
		}

		httpClient := httpclient.New(clientConfig)

		// 注入到指纹识别模块
		app.fingerprintAddon.SetHTTPClient(httpClient)
		logger.Debug("HTTP客户端已注入到指纹识别模块")
	}

	logger.Debug("模块启动和依赖注入完成")
	return nil
}

func displayStartupInfo(args *CLIArgs) {
	// 显示模块状态
	fmt.Print(`
		veo@Evilc0de

`)
	logger.Debugf("模块状态:")
	logger.Debugf("指纹识别: %s\n", getModuleStatus(args.HasModule(string(modulepkg.ModuleFinger))))
	logger.Debugf("目录扫描: %s\n", getModuleStatus(args.HasModule(string(modulepkg.ModuleDirscan))))
}

// StartProxy 启动代理服务器
func (app *CLIApp) StartProxy() error {
	if app.proxyStarted {
		return nil
	}

	// 总是添加认证学习插件（用于被动代理模式下的认证学习）
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

	// 启动代理服务器
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
func (app *CLIApp) GetFingerprintAddon() *fpaddon.FingerprintAddon {
	return app.fingerprintAddon
}

// getModuleStatus 获取模块状态文本
func getModuleStatus(enabled bool) string {
	if enabled {
		return "[√]"
	}
	return "[X]"
}

// waitForSignal 等待中断信号或用户输入
func waitForSignal() {
	// 创建信号通道
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 键盘输入通道 (支持按回车触发扫描)
	inputChan := make(chan struct{})
	go func() {
		// 读取标准输入
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				// 如果stdin关闭或出错，退出输入监听
				return
			}
			// 只有按回车才触发
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

	// 检查是否有收集到URL
	if len(addon.GetCollectedURLs()) == 0 {
		logger.Warn("没有收集到待扫描的URL，请先浏览目标网站")
		return
	}

	// 暂停指纹识别插件（如果存在），避免扫描流量干扰指纹识别
	if app.fingerprintAddon != nil {
		app.fingerprintAddon.Disable()
		logger.Debug("指纹识别插件已暂停")
	}

	// 执行扫描
	// TriggerScan 会自动暂停收集，扫描完成后恢复收集
	logger.Info("开始执行目录扫描...")
	result, err := addon.TriggerScan()
	if err != nil {
		logger.Errorf("扫描执行失败: %v", err)
	} else {
		logger.Infof("扫描完成，发现 %d 个有效结果", len(result.FilterResult.ValidPages))
	}

	// 恢复指纹识别插件
	if app.fingerprintAddon != nil {
		app.fingerprintAddon.Enable()
		logger.Debug("指纹识别插件已恢复")
	}

	logger.Info("等待下一轮收集，按 [Enter] 键再次扫描...")
}

// cleanup 清理资源
func cleanup() {

	if app != nil {
		// 停止目录扫描模块
		if app.dirscanModule != nil {
			if err := app.dirscanModule.Stop(); err != nil {
				logger.Errorf("停止目录扫描模块失败: %v", err)
			}
		}

		// 停止代理服务器
		if err := app.StopProxy(); err != nil {
			logger.Errorf("停止代理服务器失败: %v", err)
		}
	}

	// 等待清理完成
	time.Sleep(500 * time.Millisecond)
	os.Exit(0)
}

// runActiveScanMode 运行主动扫描模式
func runActiveScanMode(args *CLIArgs) error {
	logger.Debug("启动主动扫描模式")

	// [修复] 使用已经应用了CLI参数的全局配置，而不是重新加载配置文件
	// 这样可以确保CLI参数（如-t线程数）能够正确生效
	cfg := config.GetConfig()

	// 创建扫描控制器并运行
	scanner := NewScanController(args, cfg)
	return scanner.Run()
}

// ===========================================
// 状态码过滤解析和验证函数
// ===========================================

// parseStatusCodes 解析CLI参数中的状态码字符串
func parseStatusCodes(statusCodesStr string) ([]int, error) {
	if statusCodesStr == "" {
		return nil, fmt.Errorf("状态码字符串不能为空")
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
			return nil, fmt.Errorf("无效的状态码 '%s': 必须是整数", codeStr)
		}

		// 验证状态码范围
		if err := validateStatusCode(code); err != nil {
			return nil, fmt.Errorf("无效的状态码 %d: %v", code, err)
		}

		statusCodes = append(statusCodes, code)
		logger.Debugf("解析状态码: %d", code)
	}

	if len(statusCodes) == 0 {
		return nil, fmt.Errorf("未解析到有效的状态码")
	}

	return statusCodes, nil
}

// validateStatusCode 验证单个状态码的有效性
func validateStatusCode(code int) error {
	// HTTP状态码范围: 100-599
	if code < 100 || code > 599 {
		return fmt.Errorf("状态码必须在100-599之间")
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
	allow := make([]string, 0, len(targets)*2)
	seen := make(map[string]struct{})
	for _, raw := range targets {
		host, port, wildcard := normalizeTargetHost(raw)
		if host == "" {
			continue
		}
		add := func(value string) {
			value = strings.TrimSpace(strings.ToLower(value))
			if value == "" {
				return
			}
			if _, ok := seen[value]; ok {
				return
			}
			allow = append(allow, value)
			seen[value] = struct{}{}
		}
		add(host)
		if port != "" {
			add(host + ":" + port)
		}
		if wildcard {
			continue
		}
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

func resolvePortExpression(args *CLIArgs) (string, string, error) {
	expr, source, err := portconfig.ResolveExpression(args.Ports)
	if err != nil {
		if errors.Is(err, portconfig.ErrEmptyExpression) {
			return "", "", fmt.Errorf("端口扫描需要指定 -p 参数，例如: -p web / -p service / -p top1000 / -p all / -p 80,443,8000-8100")
		}
		return "", "", err
	}
	return expr, source, nil
}

func logPortScanBanner(ports string, rate int) {
	logger.Infof("%s", formatter.FormatBold(fmt.Sprintf("Start Port Scan, Ports: %s rate: %d", ports, rate)))
}

func runPortScanAndCollect(args *CLIArgs, baseTargets []string, announce bool, printResults bool) ([]portscanpkg.OpenPortResult, string, int, error) {
	effectiveRate := args.Rate
	if effectiveRate <= 0 {
		effectiveRate = gogoscanner.DefaultRate
	}
	portsExpr, portSource, err := resolvePortExpression(args)
	if err != nil {
		fallback := portscanpkg.DerivePortsFromTargets(baseTargets)
		if strings.TrimSpace(fallback) == "" {
			return nil, "", effectiveRate, err
		}
		portsExpr = fallback
		logger.Warnf("加载端口字典失败: %v，改用目标推导端口: %s", err, portsExpr)
	} else if portSource != "" {
		logger.Infof("Use Port Dict: %s", portSource)
	}

	var msTargets []string
	if strings.TrimSpace(args.TargetFile) == "" {
		targetList := baseTargets
		if len(targetList) == 0 {
			targetList = args.Targets
		}
		var resolveErr error
		msTargets, resolveErr = portscanpkg.ResolveTargetsToIPs(targetList)
		if resolveErr != nil {
			return nil, portsExpr, effectiveRate, fmt.Errorf("目标解析失败: %v", resolveErr)
		}
	}

	if announce {
		fmt.Println()
		logPortScanBanner(portsExpr, effectiveRate)
	}

	var scannerOpts []gogoscanner.Option
	if effectiveRate > 0 {
		scannerOpts = append(scannerOpts, gogoscanner.WithRate(effectiveRate))
	}
	if args.Timeout > 0 {
		scannerOpts = append(scannerOpts, gogoscanner.WithTimeout(time.Duration(args.Timeout)*time.Second))
	}
	if args.Threads > 0 {
		scannerOpts = append(scannerOpts, gogoscanner.WithThreads(args.Threads))
	}

	scanner := gogoscanner.NewScanner(scannerOpts...)
	results, err := scanner.Scan(context.Background(), msTargets, portsExpr)
	if err != nil {
		return nil, portsExpr, effectiveRate, err
	}

	results = deduplicateOpenPorts(results)

	// 准备服务识别选项
	identifyOpts := portservice.Options{}
	if args.Timeout > 0 {
		identifyOpts.Timeout = time.Duration(args.Timeout) * time.Second
	}
	if args.Threads > 0 {
		identifyOpts.Concurrency = args.Threads
	}

	if args.EnableServiceProbe {
		results = portservice.IdentifyServices(context.Background(), results, identifyOpts)
	}

	if printResults {
		for _, r := range results {
			if strings.TrimSpace(r.Service) != "" {
				logger.Infof("%s:%d %s", r.IP, r.Port, formatter.FormatProtocol(strings.ToUpper(strings.TrimSpace(r.Service))))
			} else {
				logger.Infof("%s:%d", r.IP, r.Port)
			}
		}
		logger.Debugf("端口扫描完成，发现开放端口: %d", len(results))
	}

	return results, portsExpr, effectiveRate, nil
}

func deduplicateOpenPorts(results []portscanpkg.OpenPortResult) []portscanpkg.OpenPortResult {
	if len(results) <= 1 {
		return results
	}
	seen := make(map[string]portscanpkg.OpenPortResult, len(results))
	for _, r := range results {
		key := fmt.Sprintf("%s:%d", r.IP, r.Port)
		if existing, ok := seen[key]; ok {
			if strings.TrimSpace(existing.Service) == "" && strings.TrimSpace(r.Service) != "" {
				seen[key] = r
			}
			continue
		}
		seen[key] = r
	}
	deduped := make([]portscanpkg.OpenPortResult, 0, len(seen))
	for _, r := range seen {
		deduped = append(deduped, r)
	}
	sort.Slice(deduped, func(i, j int) bool {
		if deduped[i].IP == deduped[j].IP {
			return deduped[i].Port < deduped[j].Port
		}
		return deduped[i].IP < deduped[j].IP
	})
	return deduped
}
