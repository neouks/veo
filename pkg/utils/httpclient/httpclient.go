package httpclient

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"veo/pkg/utils/logger"
	"veo/pkg/utils/redirect"
	"veo/pkg/utils/useragent"
)

// 接口定义

// HTTPClientInterface HTTP客户端接口（通用HTTP客户端抽象）
type HTTPClientInterface interface {
	// MakeRequest 发起HTTP请求
	// 参数: rawURL - 目标URL
	// 返回: 响应体内容, 状态码, 错误信息
	MakeRequest(rawURL string) (body string, statusCode int, err error)
}

// HeaderAwareClient 支持自定义请求头的HTTP客户端
type HeaderAwareClient interface {
	MakeRequestWithHeaders(rawURL string, headers map[string]string) (body string, statusCode int, err error)
}

// 配置结构

// Config HTTP客户端配置结构
type Config struct {
	Timeout        time.Duration     // 请求超时时间
	FollowRedirect bool              // 是否跟随重定向
	MaxRedirects   int               // 最大重定向次数
	UserAgent      string            // User-Agent
	SkipTLSVerify  bool              // 跳过TLS证书验证
	TLSTimeout     time.Duration     // TLS握手超时
	ProxyURL       string            // 上游代理URL
	CustomHeaders  map[string]string // 自定义HTTP头部
}

// DefaultConfig 获取默认HTTP客户端配置（安全扫描优化版）
func DefaultConfig() *Config {
	ua := useragent.Pick()
	if ua == "" {
		ua = "veo-HTTPClient/1.0"
	}

	return &Config{
		Timeout:        10 * time.Second,
		FollowRedirect: true, // 默认跟随重定向
		MaxRedirects:   5,    // 最大5次重定向
		UserAgent:      ua,
		SkipTLSVerify:  true,            // 网络安全扫描工具常用设置
		TLSTimeout:     5 * time.Second, // TLS握手超时
	}
}

// DefaultConfigWithUserAgent 获取带自定义UserAgent的默认HTTP客户端配置
func DefaultConfigWithUserAgent(userAgent string) *Config {
	config := DefaultConfig()
	if userAgent != "" {
		config.UserAgent = userAgent
	}
	return config
}

// 通用HTTP客户端实现（支持TLS配置和重定向）

// Client 通用HTTP客户端实现
// 支持配置化的重定向跟随和TLS配置功能
type Client struct {
	client         *http.Client
	followRedirect bool              // 是否跟随重定向
	maxRedirects   int               // 最大重定向次数
	userAgent      string            // User-Agent
	customHeaders  map[string]string // 自定义HTTP头部
}

// New 创建配置化的HTTP客户端（支持TLS）
func New(config *Config) *Client {
	if config == nil {
		config = DefaultConfig()
	}

	// 创建TLS配置
	tlsConfig := &tls.Config{
		InsecureSkipVerify: config.SkipTLSVerify,
		ServerName:         "", // 允许IP地址连接
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
	}

	transport := &http.Transport{
		MaxIdleConns:        1000,             // 性能优化：增加最大空闲连接数
		IdleConnTimeout:     90 * time.Second, // 性能优化：延长空闲连接超时时间
		DisableCompression:  false,
		MaxIdleConnsPerHost: 200, // 性能优化：增加每个Host的最大空闲连接数
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: config.TLSTimeout,
		ForceAttemptHTTP2:   true, // 性能优化：强制尝试HTTP/2
	}

	// 配置代理
	if config.ProxyURL != "" {
		if proxyURL, err := url.Parse(config.ProxyURL); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
			logger.Debugf("HTTPClient使用代理: %s", config.ProxyURL)
		} else {
			logger.Warnf("无效的代理URL: %s, 错误: %v", config.ProxyURL, err)
		}
	}

	client := &http.Client{
		Timeout:   config.Timeout,
		Transport: transport,
	}

	// 配置重定向策略
	// 统一禁用net/http的自动重定向，交由redirect.Execute统一管理
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &Client{
		client:         client,
		followRedirect: config.FollowRedirect,
		maxRedirects:   config.MaxRedirects,
		userAgent:      config.UserAgent,
		customHeaders:  config.CustomHeaders,
	}
}

// httpClientFetcher 适配器，用于将Client适配为redirect.HTTPFetcherFull接口
type httpClientFetcher struct {
	client        *Client
	customHeaders map[string]string
}

func (f *httpClientFetcher) MakeRequestFull(rawURL string) (string, int, map[string][]string, error) {
	return f.client.doRequestInternal(rawURL, f.customHeaders)
}

// MakeRequest 实现HTTPClientInterface接口，支持TLS和重定向
func (c *Client) MakeRequest(rawURL string) (body string, statusCode int, err error) {
	return c.executeRequest(rawURL, nil)
}

// MakeRequestWithHeaders 支持附加自定义请求头
func (c *Client) MakeRequestWithHeaders(rawURL string, headers map[string]string) (body string, statusCode int, err error) {
	return c.executeRequest(rawURL, headers)
}

// MakeRequestFull 实现扩展的HTTP请求接口，返回响应头
func (c *Client) MakeRequestFull(rawURL string) (body string, statusCode int, headers map[string][]string, err error) {
	return c.executeRequestFull(rawURL, nil)
}

func (c *Client) executeRequest(rawURL string, customHeaders map[string]string) (body string, statusCode int, err error) {
	body, statusCode, _, err = c.executeRequestFull(rawURL, customHeaders)
	return
}

func (c *Client) executeRequestFull(rawURL string, customHeaders map[string]string) (body string, statusCode int, headers map[string][]string, err error) {
	// 构造重定向配置
	redirectConfig := &redirect.Config{
		MaxRedirects:   c.maxRedirects,
		FollowRedirect: c.followRedirect,
		SameHostOnly:   false, // 指纹识别默认不限制跨域跳转
	}

	// 构造Fetcher适配器
	fetcher := &httpClientFetcher{
		client:        c,
		customHeaders: customHeaders,
	}

	// 执行请求（包含重定向处理）
	resp, err := redirect.Execute(rawURL, fetcher, redirectConfig)
	if err != nil {
		return "", 0, nil, err
	}

	return resp.Body, resp.StatusCode, resp.ResponseHeaders, nil
}

func (c *Client) doRequestInternal(rawURL string, customHeaders map[string]string) (body string, statusCode int, headers map[string][]string, err error) {
	logger.Debugf("发起请求: %s (跟随重定向: %v)", rawURL, c.followRedirect)

	// 创建请求
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return "", 0, nil, fmt.Errorf("创建请求失败: %v", err)
	}

	// 设置请求头
	c.setRequestHeaders(req)
	if len(customHeaders) > 0 {
		for key, value := range customHeaders {
			trimmedKey := strings.TrimSpace(key)
			if trimmedKey == "" {
				continue
			}
			req.Header.Set(trimmedKey, value)
		}
	}

	// 发起请求
	resp, err := c.client.Do(req)
	if err != nil {
		return "", 0, nil, c.handleRequestError(err)
	}
	defer resp.Body.Close()

	// 处理重定向响应
	if c.isRedirectResponse(resp.StatusCode) && !c.followRedirect {
		logger.Debugf("检测到重定向响应 %d，但未启用跟随: %s", resp.StatusCode, rawURL)
	}

	// 提取响应头
	headers = make(map[string][]string)
	for k, v := range resp.Header {
		headers[k] = v
	}

	// 读取响应体
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", resp.StatusCode, headers, fmt.Errorf("读取响应体失败: %v", err)
	}

	logger.Debugf("请求完成: %s [%d] 响应体: %d bytes", rawURL, resp.StatusCode, len(respBody))
	return string(respBody), resp.StatusCode, headers, nil
}

// 辅助方法

// setRequestHeaders 设置标准请求头（包括全局自定义头部）
func (c *Client) setRequestHeaders(req *http.Request) {
	// 设置标准请求头
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")

	// [新增] 为指纹识别添加自定义Cookie头
	req.Header.Set("Cookie", "rememberMe=1")

	// 应用配置中的自定义头部（如学习到的认证头部）
	c.applyCustomHeaders(req)
}

// applyCustomHeaders 应用配置中的自定义HTTP头部
func (c *Client) applyCustomHeaders(req *http.Request) {
	if len(c.customHeaders) > 0 {
		// 应用自定义头部到请求
		for key, value := range c.customHeaders {
			req.Header.Set(key, value)
		}

		logger.Debugf("应用了 %d 个自定义HTTP头部: %s", len(c.customHeaders), req.URL.String())

		// 记录应用的头部（调试用）
		for key, value := range c.customHeaders {
			// 对敏感信息进行遮蔽显示
			maskedValue := c.maskSensitiveValue(value)
			logger.Debugf("自定义头部: %s = %s", key, maskedValue)
		}
	}
}

// maskSensitiveValue 遮蔽敏感值用于日志输出
func (c *Client) maskSensitiveValue(value string) string {
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}

	// 显示前4个和后4个字符，中间用*代替
	prefix := value[:4]
	suffix := value[len(value)-4:]
	middle := strings.Repeat("*", len(value)-8)

	return prefix + middle + suffix
}

// handleRequestError 处理请求错误（统一TLS错误处理）
func (c *Client) handleRequestError(err error) error {
	errStr := err.Error()
	if strings.Contains(errStr, "tls:") || strings.Contains(errStr, "x509:") {
		return fmt.Errorf("TLS连接失败 (可能需要跳过证书验证): %v", err)
	}
	if strings.Contains(errStr, "Unsolicited response received on idle HTTP channel") {
		logger.Debugf("忽略远端推送的空闲连接响应: %v", err)
		return nil
	}
	return fmt.Errorf("请求失败: %v", err)
}

// isRedirectResponse 检查是否为重定向响应
func (c *Client) isRedirectResponse(statusCode int) bool {
	return statusCode >= 300 && statusCode < 400
}
