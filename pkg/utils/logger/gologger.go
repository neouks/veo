package logger

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"veo/pkg/utils/formatter"
)

// veo 日志系统（轻量实现）
// 目标：
// 1) 保留现有对外 API（Info/Debug/Warn/Error/Fatal/InitializeLogging/SetLogLevel 等）
// 2) 移除 projectdiscovery/gologger 依赖，减少二进制体积

// StandardLogFilter 用于过滤标准库 log 输出的特定噪声消息
// 目前主要用于抑制 "Deprecated newline only separator found in header" 之类的告警。
type StandardLogFilter struct{}

func (f *StandardLogFilter) Write(p []byte) (n int, err error) {
	msg := string(p)
	if strings.Contains(msg, "Deprecated newline only separator found in header") {
		return len(p), nil
	}
	return os.Stderr.Write(p)
}

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

type LogConfig struct {
	Level       string `yaml:"level"`
	ColorOutput bool   `yaml:"color_output"`
}

var (
	globalMu     sync.RWMutex
	globalConfig = getDefaultLogConfig()
	globalLevel  = parseLogLevel(globalConfig.Level)
	outputMu     sync.Mutex
	lineCleaner  func()
)

// InitializeLogger 初始化日志系统
func InitializeLogger(config *LogConfig) error {
	if config == nil {
		config = getDefaultLogConfig()
	}

	globalMu.Lock()
	globalConfig = config
	globalLevel = parseLogLevel(config.Level)
	globalMu.Unlock()

	// 通过拦截标准库 log 输出进行过滤
	log.SetOutput(&StandardLogFilter{})
	return nil
}

func getDefaultLogConfig() *LogConfig {
	return &LogConfig{Level: "info", ColorOutput: true}
}

func parseLogLevel(levelStr string) Level {
	switch strings.ToLower(strings.TrimSpace(levelStr)) {
	case "debug":
		return LevelDebug
	case "info", "":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	case "fatal", "panic":
		return LevelFatal
	default:
		return LevelInfo
	}
}

func shouldUseColors() bool {
	return formatter.ColorsEnabled()
}

func levelLabel(level Level) string {
	switch level {
	case LevelDebug:
		return "DBG"
	case LevelInfo:
		return "INF"
	case LevelWarn:
		return "WRN"
	case LevelError:
		return "ERR"
	case LevelFatal:
		return "FTL"
	default:
		return "INF"
	}
}

func levelColor(level Level) string {
	switch level {
	case LevelDebug:
		return "\033[36m" // cyan
	case LevelInfo:
		return "\033[34m" // blue
	case LevelWarn:
		return "\033[33m" // yellow
	case LevelError:
		return "\033[31m" // red
	case LevelFatal:
		return "\033[35m" // magenta
	default:
		return ""
	}
}

func shouldLog(level Level) bool {
	globalMu.RLock()
	minLevel := globalLevel
	globalMu.RUnlock()
	return level >= minLevel
}

func logf(level Level, format string, args ...interface{}) {
	if !shouldLog(level) {
		return
	}
	msg := fmt.Sprintf(format, args...)
	logMessage(level, msg)
}

func logMessage(level Level, message string) {
	if !shouldLog(level) {
		return
	}

	globalMu.RLock()
	cfg := globalConfig
	globalMu.RUnlock()

	enableColors := cfg != nil && cfg.ColorOutput && shouldUseColors()
	label := levelLabel(level)

	var line string
	if enableColors {
		line = fmt.Sprintf("%s[%s]\033[0m %s", levelColor(level), label, message)
	} else {
		line = fmt.Sprintf("[%s] %s", label, message)
	}

	// 避免多 goroutine 输出交错
	outputMu.Lock()
	defer outputMu.Unlock()

	if lineCleaner != nil {
		lineCleaner()
	}

	if level >= LevelError {
		fmt.Fprintln(os.Stderr, line)
	} else {
		fmt.Fprintln(os.Stdout, line)
	}

	if level == LevelFatal {
		os.Exit(1)
	}
}

// SetLogLevel 设置日志级别
func SetLogLevel(levelStr string) {
	globalMu.Lock()
	globalLevel = parseLogLevel(levelStr)
	if globalConfig == nil {
		globalConfig = getDefaultLogConfig()
	}
	globalConfig.Level = strings.ToLower(strings.TrimSpace(levelStr))
	globalMu.Unlock()
}

// SetColorOutput 设置日志颜色输出开关
func SetColorOutput(enabled bool) {
	globalMu.Lock()
	if globalConfig == nil {
		globalConfig = getDefaultLogConfig()
	}
	globalConfig.ColorOutput = enabled
	globalMu.Unlock()
}

// SetLineCleaner 设置日志输出前的行清理回调
func SetLineCleaner(cleaner func()) {
	outputMu.Lock()
	defer outputMu.Unlock()
	lineCleaner = cleaner
}

// WithOutputLock 在日志输出锁内执行函数
func WithOutputLock(fn func()) {
	outputMu.Lock()
	defer outputMu.Unlock()
	fn()
}

// 全局日志函数
func Debug(args ...interface{})                 { logMessage(LevelDebug, fmt.Sprint(args...)) }
func Debugf(format string, args ...interface{}) { logf(LevelDebug, format, args...) }
func Info(args ...interface{})                  { logMessage(LevelInfo, fmt.Sprint(args...)) }
func Infof(format string, args ...interface{})  { logf(LevelInfo, format, args...) }
func Warn(args ...interface{})                  { logMessage(LevelWarn, fmt.Sprint(args...)) }
func Warnf(format string, args ...interface{})  { logf(LevelWarn, format, args...) }
func Error(args ...interface{})                 { logMessage(LevelError, fmt.Sprint(args...)) }
func Errorf(format string, args ...interface{}) { logf(LevelError, format, args...) }
func Fatal(args ...interface{})                 { logMessage(LevelFatal, fmt.Sprint(args...)) }
func Fatalf(format string, args ...interface{}) { logf(LevelFatal, format, args...) }
