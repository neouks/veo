package httpclient

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"veo/pkg/logger"
	"veo/pkg/redirect"
	"veo/pkg/shared"

	"github.com/valyala/fasthttp"
	"golang.org/x/net/html/charset"
	xproxy "golang.org/x/net/proxy"
)

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
	Timeout            time.Duration
	FollowRedirect     bool
	MaxRedirects       int
	UserAgent          string
	SkipTLSVerify      bool
	TLSTimeout         time.Duration
	ProxyURL           string
	CustomHeaders      map[string]string
	SameHostOnly       bool
	MaxBodySize        int
	MaxConcurrent      int
	DecompressResponse bool
}

// RemoteIPHeaderKey 内部传递远端IP，不参与规则匹配
const RemoteIPHeaderKey = "X-VEO-Remote-IP"

// DefaultConfig 获取默认HTTP客户端配置（安全扫描优化版）
func DefaultConfig() *Config {
	ua := shared.Primary()
	if ua == "" {
		ua = "CNVD TEST"
	}

	return &Config{
		Timeout:            10 * time.Second,
		FollowRedirect:     true,
		MaxRedirects:       5,
		UserAgent:          ua,
		SkipTLSVerify:      true,
		TLSTimeout:         5 * time.Second,
		MaxBodySize:        10 * 1024 * 1024,
		MaxConcurrent:      1000,
		DecompressResponse: true,
	}
}

// Client 通用HTTP客户端实现
type Client struct {
	client             *fasthttp.Client
	timeout            time.Duration
	followRedirect     bool
	maxRedirects       int
	userAgent          string
	customHeaders      map[string]string
	sameHostOnly       bool
	decompressResponse bool
}

// New 创建配置化的HTTP客户端（支持TLS）
func New(config *Config) *Client {
	if config == nil {
		config = DefaultConfig()
	}

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
		ReadBufferSize:      16384,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: config.SkipTLSVerify,
			Renegotiation:      tls.RenegotiateOnceAsClient,
			MinVersion:         tls.VersionTLS10,
		},
		DisablePathNormalizing:        true,
		DisableHeaderNamesNormalizing: true,
		NoDefaultUserAgentHeader:      true,
	}

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
	redirectConfig := &redirect.Config{
		MaxRedirects:   c.maxRedirects,
		FollowRedirect: c.followRedirect,
		SameHostOnly:   c.sameHostOnly,
	}

	fetcher := &httpClientFetcher{
		client:        c,
		customHeaders: customHeaders,
	}

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

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(requestURL)
	req.Header.SetMethod(fasthttp.MethodGet)

	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Cache-Control", "no-cache")

	if len(c.customHeaders) > 0 {
		for k, v := range c.customHeaders {
			req.Header.Set(k, v)
		}
	}

	if len(customHeaders) > 0 {
		for k, v := range customHeaders {
			trimmedKey := strings.TrimSpace(k)
			if trimmedKey != "" {
				req.Header.Set(trimmedKey, v)
			}
		}
	}

	if err := c.client.DoTimeout(req, resp, c.timeout); err != nil {
		return "", 0, nil, c.handleRequestError(err)
	}

	remoteIP := remoteIPFromAddr(resp.RemoteAddr())

	statusCode = resp.StatusCode()

	headers = make(map[string][]string)
	resp.Header.VisitAll(func(key, value []byte) {
		k := string(key)
		v := string(value)
		headers[k] = append(headers[k], v)
	})
	if remoteIP != "" {
		headers[RemoteIPHeaderKey] = []string{remoteIP}
	}

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

	body = string(respBody)

	logger.Debugf("Fasthttp请求完成: %s [%d] Size: %d", rawURL, statusCode, len(body))
	return body, statusCode, headers, nil
}

func remoteIPFromAddr(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	if tcpAddr, ok := addr.(*net.TCPAddr); ok && tcpAddr.IP != nil {
		return tcpAddr.IP.String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil && host != "" {
		return host
	}
	return addr.String()
}

// handleRequestError 处理请求错误（统一TLS错误处理）
func (c *Client) handleRequestError(err error) error {
	errStr := err.Error()
	if strings.Contains(errStr, "tls:") || strings.Contains(errStr, "x509:") {
		return fmt.Errorf("TLS handshake failed: %v", err)
	}
	return fmt.Errorf("request failed: %v", err)
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

func FasthttpDialerFactory(proxyURL string, connectTimeout time.Duration) fasthttp.DialFunc {
	if proxyURL == "" {
		return nil
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		logger.Warnf("Invalid proxy URL: %s, error: %v", proxyURL, err)
		return nil
	}

	if strings.HasPrefix(proxyURL, "socks5") {
		dialer, err := xproxy.FromURL(u, xproxy.Direct)
		if err != nil {
			logger.Warnf("Failed to initialize SOCKS5 proxy: %v", err)
			return nil
		}

		logger.Debugf("Fasthttp使用SOCKS5代理: %s", proxyURL)
		return func(addr string) (net.Conn, error) {
			return dialer.Dial("tcp", addr)
		}
	}

	if strings.HasPrefix(proxyURL, "http") {
		proxyAddr := u.Host
		if !strings.Contains(proxyAddr, ":") {
			proxyAddr += ":80"
		}

		var authHeader string
		if u.User != nil {
			username := u.User.Username()
			password, _ := u.User.Password()
			auth := username + ":" + password
			authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
		}

		logger.Debugf("Fasthttp使用HTTP代理(CONNECT模式): %s", proxyURL)

		return func(addr string) (net.Conn, error) {
			conn, err := net.DialTimeout("tcp", proxyAddr, connectTimeout)
			if err != nil {
				return nil, err
			}

			req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n"
			if authHeader != "" {
				req += "Proxy-Authorization: " + authHeader + "\r\n"
			}
			req += "\r\n"

			if _, err := conn.Write([]byte(req)); err != nil {
				conn.Close()
				return nil, err
			}

			reader := bufio.NewReader(conn)
			statusLine, err := reader.ReadString('\n')
			if err != nil {
				conn.Close()
				return nil, err
			}

			if !strings.Contains(statusLine, "200") {
				conn.Close()
				return nil, fmt.Errorf("proxy connection failed: %s", strings.TrimSpace(statusLine))
			}

			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					conn.Close()
					return nil, err
				}
				if line == "\r\n" || line == "\n" {
					break
				}
			}

			if reader.Buffered() > 0 {
				logger.Debugf("警告: 代理握手后缓冲区有残留数据 %d 字节", reader.Buffered())
			}

			return conn, nil
		}
	}

	return nil
}
