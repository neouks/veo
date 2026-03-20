package config

import (
	"fmt"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"veo/pkg/logger"

	"gopkg.in/yaml.v3"
)

// Config 全局配置结构体
type Config struct {
	Server ServerConfig `yaml:"server"`
	Module ModuleConfig `yaml:"module"` // 修正拼写错误: modle -> module
	Hosts  HostsConfig  `yaml:"hosts"`
	Addon  AddonConfig  `yaml:"addon"`
}

// ModuleConfig 模块配置
type ModuleConfig struct {
	Dirscan     bool `yaml:"dirscan"`
	Fingerprint bool `yaml:"fingerprint"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Listen string `yaml:"listen"`
}

// HostsConfig 主机过滤配置
type HostsConfig struct {
	Allow  []string `yaml:"allow"`
	Reject []string `yaml:"reject"`
}

// AddonConfig 插件配置
type AddonConfig struct {
	Collector CollectorConfig `yaml:"collector"`
	Request   RequestConfig   `yaml:"request"`
	Proxy     ProxyConfig     `yaml:"proxy"`
}

// CollectorConfig 收集器配置
type CollectorConfig struct {
	Static StaticConfig `yaml:"static"`
}

// StaticConfig 静态资源配置
type StaticConfig struct {
	Path       []string `yaml:"path"`
	Extensions []string `yaml:"extensions"`
}

// RequestConfig 请求配置
type RequestConfig struct {
	Timeout             int      `yaml:"timeout"` // 统一超时配置，对所有模块生效
	Retry               int      `yaml:"retry"`   // 重试次数
	UserAgents          []string `yaml:"user_agents"`
	Depth               int      `yaml:"depth"`   // 递归扫描深度
	Threads             int      `yaml:"threads"` // 统一并发控制，对所有模块生效
	KeepAliveSeconds    int      `yaml:"keep_alive_seconds"`
	RandomUA            *bool    `yaml:"randomUA"`               // 保留，processor包中被使用
	MaxResponseBodySize int      `yaml:"max_response_body_size"` // 内存优化：响应体大小限制
}

// ProxyConfig 代理配置
type ProxyConfig struct {
	UpstreamProxy   string `yaml:"upstream_proxy"`
	StreamLargebody int64  `yaml:"stream_largebody"`
	SSLInsecure     bool   `yaml:"ssl_insecure"`
	ConnectTimeout  int    `yaml:"connect_timeout"`
	ReadTimeout     int    `yaml:"read_timeout"`
}

// 全局配置实例
var GlobalConfig *Config

// LoadConfig 加载配置文件
func LoadConfig(configPath string) (*Config, error) {
	logger.Debug("开始加载配置文件: ", configPath)

	// 检查配置文件是否存在
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("配置文件不存在: %s", configPath)
	}

	// 读取配置文件
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	// 解析YAML配置
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %v", err)
	}

	// 验证配置
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("配置验证失败: %v", err)
	}

	// 设置全局配置
	GlobalConfig = &config

	logger.Debug("配置文件加载成功")

	return &config, nil
}

// validateConfig 验证配置文件
func validateConfig(config *Config) error {
	// 验证服务器配置
	if config.Server.Listen == "" {
		return fmt.Errorf("服务器监听地址不能为空")
	}

	// 验证代理配置
	if config.Addon.Proxy.ConnectTimeout <= 0 {
		return fmt.Errorf("代理连接超时时间必须大于0")
	}

	if config.Addon.Proxy.ReadTimeout <= 0 {
		return fmt.Errorf("代理读取超时时间必须大于0")
	}

	return nil
}

// InitConfig 初始化配置（自动查找配置文件）
func InitConfig() error {
	if customPath := os.Getenv("VEO_CONFIG_PATH"); customPath != "" {
		if _, err := os.Stat(customPath); err == nil {
			if _, err := LoadConfig(customPath); err != nil {
				return fmt.Errorf("加载配置文件 %s 失败: %v", customPath, err)
			}
			return nil
		}
	}
	// 尝试多个可能的配置文件路径
	configPaths := []string{
		"config.yaml",
		"./config/config.yaml",
		"./config.yaml",
	}

	for _, configPath := range configPaths {
		if _, err := os.Stat(configPath); err == nil {
			_, err := LoadConfig(configPath)
			if err != nil {
				return fmt.Errorf("加载配置文件 %s 失败: %v", configPath, err)
			}
			return nil
		}
	}

	return fmt.Errorf("未找到配置文件，请确保存在以下文件之一: %v", configPaths)
}

// GetConfig 获取全局配置
func GetConfig() *Config {
	if GlobalConfig == nil {
		// 尝试自动初始化配置
		if err := InitConfig(); err != nil {
			logger.Fatal("配置未初始化且自动初始化失败: ", err)
		}
	}
	return GlobalConfig
}

// GetServerConfig 获取服务器配置
func GetServerConfig() *ServerConfig {
	return &GetConfig().Server
}

// GetHostsConfig 获取主机配置
func GetHostsConfig() *HostsConfig {
	return &GetConfig().Hosts
}

// GetCollectorConfig 获取收集器配置（保留，collector包中被使用）
func GetCollectorConfig() *CollectorConfig {
	return &GetConfig().Addon.Collector
}

// GetRequestConfig 获取请求配置（保留，processor包中被使用）
func GetRequestConfig() *RequestConfig {
	return &GetConfig().Addon.Request
}

// GetProxyConfig 获取代理配置（保留，CLI中被使用）
func GetProxyConfig() *ProxyConfig {
	return &GetConfig().Addon.Proxy
}

// IsHostAllowed 检查主机是否被允许
func IsHostAllowed(host string) bool {
	config := GetHostsConfig()
	hostLower, hostWithoutPort := normalizeHostKey(host)

	// 检查拒绝列表
	for _, reject := range config.Reject {
		pattern := strings.ToLower(strings.TrimSpace(reject))
		if pattern == "" {
			continue
		}
		if matchPattern(hostLower, pattern) || (hostWithoutPort != hostLower && matchPattern(hostWithoutPort, pattern)) {
			return false
		}
	}

	// 检查允许列表
	if len(config.Allow) == 0 {
		return true
	}

	for _, allow := range config.Allow {
		pattern := strings.ToLower(strings.TrimSpace(allow))
		if pattern == "" {
			continue
		}
		if matchPattern(hostLower, pattern) || (hostWithoutPort != hostLower && matchPattern(hostWithoutPort, pattern)) {
			return true
		}
	}

	return false
}

func normalizeHostKey(host string) (string, string) {
	hostLower := strings.ToLower(strings.TrimSpace(host))
	if hostLower == "" {
		return "", ""
	}
	hostWithoutPort := hostLower

	if strings.HasPrefix(hostLower, "[") {
		if h, _, err := net.SplitHostPort(hostLower); err == nil {
			hostWithoutPort = strings.ToLower(strings.TrimSpace(h))
		} else if strings.HasSuffix(hostLower, "]") {
			hostWithoutPort = strings.TrimSpace(hostLower[1 : len(hostLower)-1])
		}
	} else {
		if h, _, err := net.SplitHostPort(hostLower); err == nil {
			hostWithoutPort = strings.ToLower(strings.TrimSpace(h))
		} else {
			if idx := strings.LastIndex(hostLower, ":"); idx > -1 && idx < len(hostLower)-1 {
				if _, err := strconv.Atoi(hostLower[idx+1:]); err == nil {
					hostWithoutPort = strings.TrimSpace(hostLower[:idx])
				}
			}
		}
	}

	if hostWithoutPort == "" {
		hostWithoutPort = hostLower
	}
	return hostLower, hostWithoutPort
}

// matchPattern 简单的模式匹配（支持通配符*）
func matchPattern(text, pattern string) bool {
	text = strings.ToLower(strings.TrimSpace(text))
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	if text == "" || pattern == "" {
		return false
	}

	if pattern == "*" {
		return true
	}

	if !strings.ContainsAny(pattern, "*?[") {
		return text == pattern
	}

	matched, err := path.Match(pattern, text)
	if err != nil {
		logger.Debugf("主机模式匹配失败: pattern=%s text=%s err=%v", pattern, text, err)
		return text == pattern
	}
	return matched
}

// HTTP认证头部全局管理

// 全局变量存储自定义HTTP头部
var (
	globalCustomHeaders map[string]string
	customHeadersMutex  sync.RWMutex
)

// SetCustomHeaders 设置全局自定义HTTP头部
func SetCustomHeaders(headers map[string]string) {
	customHeadersMutex.Lock()
	defer customHeadersMutex.Unlock()

	globalCustomHeaders = make(map[string]string)
	for key, value := range headers {
		globalCustomHeaders[key] = value
	}

	logger.Debugf("设置全局自定义HTTP头部: %d 个", len(globalCustomHeaders))
}

// GetCustomHeaders 获取全局自定义HTTP头部
func GetCustomHeaders() map[string]string {
	customHeadersMutex.RLock()
	defer customHeadersMutex.RUnlock()

	if globalCustomHeaders == nil {
		return make(map[string]string)
	}

	headers := make(map[string]string)
	for key, value := range globalCustomHeaders {
		headers[key] = value
	}

	return headers
}

// HasCustomHeaders 检查是否设置了自定义HTTP头部
func HasCustomHeaders() bool {
	customHeadersMutex.RLock()
	defer customHeadersMutex.RUnlock()
	return len(globalCustomHeaders) > 0
}
