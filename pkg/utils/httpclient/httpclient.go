package httpclient

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"veo/pkg/utils/logger"
	"veo/pkg/utils/redirect"
	"veo/pkg/utils/shared"
	"veo/pkg/utils/useragent"

	"github.com/valyala/fasthttp"
	"golang.org/x/net/html/charset"
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

// Config HTTP客户端配置结构
type Config struct {
	Timeout            time.Duration     // 请求超时时间
	FollowRedirect     bool              // 是否跟随重定向
	MaxRedirects       int               // 最大重定向次数
	UserAgent          string            // User-Agent
	SkipTLSVerify      bool              // 跳过TLS证书验证
	TLSTimeout         time.Duration     // TLS握手超时
	ProxyURL           string            // 上游代理URL
	CustomHeaders      map[string]string // 自定义HTTP头部
	SameHostOnly       bool              // 重定向仅限同主机
	MaxBodySize        int               // 最大响应体大小(字节)
	MaxConcurrent      int               // 最大并发连接数
	DecompressResponse bool              // 是否解压/解码响应体
}

// DefaultConfig 获取默认HTTP客户端配置（安全扫描优化版）
func DefaultConfig() *Config {
	ua := useragent.Pick()
	if ua == "" {
		ua = "veo-HTTPClient/1.0"
	}

	return &Config{
		Timeout:            10 * time.Second,
		FollowRedirect:     true, // 默认跟随重定向
		MaxRedirects:       5,    // 最大5次重定向
		UserAgent:          ua,
		SkipTLSVerify:      true,             // 网络安全扫描工具常用设置
		TLSTimeout:         5 * time.Second,  // TLS握手超时
		MaxBodySize:        10 * 1024 * 1024, // 10MB
		MaxConcurrent:      1000,
		DecompressResponse: true,
	}
}

// 通用HTTP客户端实现（基于 fasthttp）

// Client 通用HTTP客户端实现
type Client struct {
	client             *fasthttp.Client
	timeout            time.Duration     // 单次请求超时
	followRedirect     bool              // 是否跟随重定向
	maxRedirects       int               // 最大重定向次数
	userAgent          string            // User-Agent
	customHeaders      map[string]string // 自定义HTTP头部
	sameHostOnly       bool              // 重定向仅限同主机
	decompressResponse bool
}

// New 创建配置化的HTTP客户端（支持TLS）
func New(config *Config) *Client {
	if config == nil {
		config = DefaultConfig()
	}

	// 创建 fasthttp 客户端
	waitTimeout := config.Timeout
	if waitTimeout <= 0 {
		waitTimeout = 3 * time.Second
	}
	fastClient := &fasthttp.Client{
		Name:                config.UserAgent,
		ReadTimeout:         config.Timeout,
		WriteTimeout:        config.Timeout,
		MaxConnsPerHost:     config.MaxConcurrent,
		MaxConnWaitTimeout:  waitTimeout,
		MaxIdleConnDuration: 30 * time.Second,
		MaxResponseBodySize: config.MaxBodySize,
		ReadBufferSize:      16384, // 16KB
		TLSConfig: &tls.Config{
			InsecureSkipVerify: config.SkipTLSVerify,
			Renegotiation:      tls.RenegotiateOnceAsClient,
			MinVersion:         tls.VersionTLS10,
		},
		DisablePathNormalizing:        true,
		DisableHeaderNamesNormalizing: true,
		NoDefaultUserAgentHeader:      true, // 我们自己控制 UA
	}

	// 配置代理 Dial
	if config.ProxyURL != "" {
		dialFunc := FasthttpDialerFactory(config.ProxyURL, 5*time.Second)
		if dialFunc != nil {
			fastClient.Dial = dialFunc
		}
	} else {
		dialer := &fasthttp.TCPDialer{
			Concurrency:      config.MaxConcurrent,
			DNSCacheDuration: time.Minute,
		}
		fastClient.DialTimeout = dialer.DialTimeout
	}

	return &Client{
		client:             fastClient,
		timeout:            config.Timeout,
		followRedirect:     config.FollowRedirect,
		maxRedirects:       config.MaxRedirects,
		userAgent:          config.UserAgent,
		customHeaders:      config.CustomHeaders,
		sameHostOnly:       config.SameHostOnly,
		decompressResponse: config.DecompressResponse,
	}
}

// SetSameHostOnly 设置是否仅限同主机重定向
func (c *Client) SetSameHostOnly(enabled bool) {
	c.sameHostOnly = enabled
}

// httpClientFetcher 适配器，用于将Client适配为redirect.HTTPFetcherFull接口
type httpClientFetcher struct {
	client        *Client
	customHeaders map[string]string
}

func (f *httpClientFetcher) MakeRequestFull(rawURL string) (string, int, map[string][]string, error) {
	// 调用底层单次请求
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

// MakeRequestFullWithHeaders 支持自定义请求头的扩展HTTP请求接口，返回响应头
func (c *Client) MakeRequestFullWithHeaders(rawURL string, customHeaders map[string]string) (body string, statusCode int, headers map[string][]string, err error) {
	return c.executeRequestFull(rawURL, customHeaders)
}

func (c *Client) executeRequest(rawURL string, customHeaders map[string]string) (body string, statusCode int, err error) {
	body, statusCode, _, err = c.executeRequestFull(rawURL, customHeaders)
	return
}

func (c *Client) executeRequestFull(rawURL string, customHeaders map[string]string) (body string, statusCode int, headers map[string][]string, err error) {
	if !c.followRedirect {
		return c.doRequestInternal(rawURL, customHeaders)
	}
	// 构造重定向配置
	redirectConfig := &redirect.Config{
		MaxRedirects:   c.maxRedirects,
		FollowRedirect: c.followRedirect,
		SameHostOnly:   c.sameHostOnly,
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

// doRequestInternal 执行单次请求（fasthttp implementation）
func (c *Client) doRequestInternal(rawURL string, customHeaders map[string]string) (body string, statusCode int, headers map[string][]string, err error) {
	requestURL := encodeHashInURL(rawURL)
	if requestURL == "" {
		return "", 0, nil, fmt.Errorf("empty url")
	}

	// Acquire objects
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	// Prepare Request
	req.SetRequestURI(requestURL)
	req.Header.SetMethod(fasthttp.MethodGet)

	// Default Headers
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Cache-Control", "no-cache")

	// Apply Global Custom Headers
	if len(c.customHeaders) > 0 {
		for k, v := range c.customHeaders {
			req.Header.Set(k, v)
		}
	}

	// Apply Per-Request Custom Headers
	if len(customHeaders) > 0 {
		for k, v := range customHeaders {
			trimmedKey := strings.TrimSpace(k)
			if trimmedKey != "" {
				req.Header.Set(trimmedKey, v)
			}
		}
	}

	// Execute
	if err := c.client.DoTimeout(req, resp, c.timeout); err != nil {
		return "", 0, nil, c.handleRequestError(err)
	}

	// Extract Info
	statusCode = resp.StatusCode()

	// Headers Map
	headers = make(map[string][]string)
	resp.Header.VisitAll(func(key, value []byte) {
		k := string(key)
		v := string(value)
		headers[k] = append(headers[k], v)
	})

	// Body Decompression (if needed) & Charset Decoding
	contentEncoding := string(resp.Header.Peek("Content-Encoding"))
	var respBody []byte
	respBody = resp.Body()
	if c.decompressResponse && contentEncoding != "" {
		respBody = shared.DecompressByEncoding(respBody, contentEncoding)
	}

	contentType := string(resp.Header.Peek("Content-Type"))
	if (c.decompressResponse || contentEncoding == "") && shouldDecodeBody(contentType, respBody) {
		if decoded, ok := decodeToUTF8(respBody, contentType); ok {
			respBody = decoded
		}
	}

	// Convert to string (Copy happens here, safe to release Response after)
	body = string(respBody)

	logger.Debugf("Fasthttp请求完成: %s [%d] Size: %d", rawURL, statusCode, len(body))
	return body, statusCode, headers, nil
}

// handleRequestError 处理请求错误（统一TLS错误处理）
func (c *Client) handleRequestError(err error) error {
	errStr := err.Error()
	if strings.Contains(errStr, "tls:") || strings.Contains(errStr, "x509:") {
		return fmt.Errorf("TLS握手失败: %v", err)
	}
	return fmt.Errorf("请求失败: %v", err)
}

func encodeHashInURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	if !strings.Contains(rawURL, "#") {
		return rawURL
	}
	// 将 '#' 视为路径字符：编码为 %23，避免被当作 fragment 丢弃
	return strings.ReplaceAll(rawURL, "#", "%23")
}

func shouldDecodeBody(contentType string, body []byte) bool {
	if len(body) == 0 {
		return false
	}
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if strings.HasPrefix(ct, "text/") || strings.Contains(ct, "application/json") || strings.Contains(ct, "application/xml") || strings.Contains(ct, "application/xhtml+xml") {
		return strings.Contains(ct, "charset=") || !utf8.Valid(body)
	}
	// HTML 场景：部分站点会漏写/写错 Content-Type，但 body 不是 UTF-8
	if strings.Contains(ct, "html") {
		return strings.Contains(ct, "charset=") || !utf8.Valid(body)
	}
	return false
}

func decodeToUTF8(body []byte, contentType string) ([]byte, bool) {
	r, err := charset.NewReader(bytes.NewReader(body), contentType)
	if err != nil {
		return nil, false
	}
	decoded, err := io.ReadAll(r)
	if err != nil {
		return nil, false
	}
	if len(decoded) == 0 {
		return nil, false
	}
	return decoded, true
}
