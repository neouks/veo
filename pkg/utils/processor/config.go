package processor

import (
	"time"

	"veo/pkg/utils/useragent"
)

// RequestConfig 请求配置
type RequestConfig struct {
	Timeout         time.Duration // 请求超时时间
	MaxRetries      int           // 最大重试次数
	UserAgents      []string      // User-Agent列表（支持随机选择）
	MaxBodySize     int           // 最大响应体大小
	FollowRedirect  bool          // 是否跟随重定向
	MaxRedirects    int           // 最大重定向次数
	MaxConcurrent   int           // 最大并发数
	ConnectTimeout  time.Duration // 连接超时时间
	KeepAlive       time.Duration // 保持连接时间
	RandomUserAgent bool          // 是否随机使用UserAgent
	Delay           time.Duration // 请求延迟时间
	ProxyURL        string        // 上游代理URL
}

const DefaultMaxRedirects = 3

// ApplyRedirectPolicy 统一重定向策略（指纹识别/目录扫描共用）
func ApplyRedirectPolicy(config *RequestConfig) {
	if config == nil {
		return
	}
	config.FollowRedirect = true
	config.MaxRedirects = DefaultMaxRedirects
}

// ============================================================================
// 配置相关功能
// ============================================================================

// GetDefaultConfig 暴露默认配置获取方法（测试用）
func GetDefaultConfig() *RequestConfig {
	return getDefaultConfig()
}

// getDefaultConfig 获取默认配置
func getDefaultConfig() *RequestConfig {
	timeout := 10 * time.Second // 默认超时时间

	retries := 3 // 默认重试次数

	maxConcurrent := 50 // 默认并发数

	connectTimeout := 5 * time.Second // 默认连接超时时间
	maxRedirects := DefaultMaxRedirects

	randomUserAgent := true

	delay := time.Duration(0) // 移除延迟配置，统一为0

	userAgents := useragent.GetEffectiveList()
	if len(userAgents) == 0 {
		userAgents = useragent.DefaultList()
	}

	return &RequestConfig{
		Timeout:         timeout,
		MaxRetries:      retries,
		UserAgents:      userAgents,
		MaxBodySize:     10 * 1024 * 1024, // 10MB
		FollowRedirect:  false,            // 默认不跟随重定向
		MaxRedirects:    maxRedirects,
		MaxConcurrent:   maxConcurrent,
		ConnectTimeout:  connectTimeout,
		RandomUserAgent: randomUserAgent,
		Delay:           delay,
	}
}

// initializeUserAgentPool 初始化UserAgent池
func initializeUserAgentPool(config *RequestConfig) []string {
	effective := useragent.GetEffectiveList()
	if len(effective) == 0 {
		return effective
	}

	if config != nil && !config.RandomUserAgent {
		return []string{effective[0]}
	}

	return effective
}
