package formatter

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// ANSI颜色代码常量
const (
	ColorReset  = "\033[0m"  // 重置
	ColorGreen  = "\033[32m" // 绿色
	ColorLightRed   = "\033[91m" // 浅红色
	ColorRed    = "\033[31m" // 红色
	ColorYellow = "\033[33m" // 黄色
	ColorBlue   = "\033[34m" // 蓝色
	ColorBold   = "\033[1m"  // 加粗
	ColorUnder  = "\033[4m"  // 下划线

	// 保留的颜色常量（用于其他功能）
	ColorMagenta = "\033[35m" // 紫色（保留用于其他功能）
	ColorGray    = "\033[90m" // 灰色（保留用于其他功能）
	ColorDim     = "\033[2m"  // 暗淡（用于DSL规则显示）

	// URL专用颜色常量
	ColorDarkGreen         = "\033[38;2;46;125;50m" // 深绿色 (#2e7d32) - 24位真彩色
	ColorDarkGreenFallback = "\033[32m"             // 深绿色降级方案 - 标准绿色（16色兼容）
)

// FormatProtocol 格式化协议显示（加粗绿色）
func FormatProtocol(proto string) string {
	if !shouldUseColors() {
		return fmt.Sprintf("[%s]", proto)
	}
	// 对方括号和内容都应用加粗绿色，保持风格一致
	return fmt.Sprintf("%s%s[%s]%s", ColorBold, ColorGreen, proto, ColorReset)
}

// FormatURL 格式化URL显示（使用深绿色）
func FormatURL(url string) string {
	if !shouldUseColors() {
		return url // 如果禁用彩色输出，直接返回URL
	}
	// 使用深绿色显示URL
	return getDarkGreenColor() + url + ColorReset
}

// FormatFingerprintName 格式化指纹名称显示（统一蓝色显示，无加粗）
func FormatFingerprintName(name string) string {
	if !shouldUseColors() {
		return name // 如果禁用彩色输出，直接返回指纹名称
	}

	// 统一使用蓝色显示所有指纹信息，不使用加粗格式
	return ColorBlue + name + ColorReset
}

// FormatStatusCode 格式化状态码显示（根据状态码类别使用不同颜色）
func FormatStatusCode(statusCode int) string {
	if !shouldUseColors() {
		return fmt.Sprintf("[%d]", statusCode) // 如果禁用彩色输出，直接返回状态码
	}

	// 根据状态码范围选择对应颜色（恢复：重新添加加粗格式）
	var color string
	switch {
	case statusCode >= 200 && statusCode < 300:
		// 2XX状态码（成功）：加粗绿色
		color = ColorBold + ColorGreen
	case statusCode >= 300 && statusCode < 400:
		// 3XX状态码（重定向）：加粗黄色
		color = ColorBold + ColorYellow
	case statusCode >= 400 && statusCode < 500:
		// 4XX状态码（客户端错误）：加粗红色
		color = ColorBold + ColorRed
	case statusCode >= 500 && statusCode < 600:
		// 5XX状态码（服务器错误）：加粗紫色
		color = ColorBold + ColorMagenta
	default:
		// 其他状态码：加粗默认颜色
		color = ColorBold
	}

	return color + fmt.Sprintf("[%d]", statusCode) + ColorReset
}

// FormatTitle 格式化标题显示
func FormatTitle(title string) string {
	// [修复] 检查标题是否已经包含方括号，避免双重方括号问题
	if strings.HasPrefix(title, "[") && strings.HasSuffix(title, "]") {
		// 标题已经包含方括号，直接返回
		if !shouldUseColors() {
			return title
		}
		return title + ColorReset
	}

	// 标题不包含方括号，添加方括号格式化
	if !shouldUseColors() {
		return fmt.Sprintf("[%s]", title)
	}
	return fmt.Sprintf("[%s]", title) + ColorReset
}

// FormatFingerprintTitle 格式化指纹匹配后的标题显示（浅红色，不加粗）
func FormatFingerprintTitle(title string) string {
	// 检查标题是否已经包含方括号
	if strings.HasPrefix(title, "[") && strings.HasSuffix(title, "]") {
		if !shouldUseColors() {
			return title
		}
		// 使用浅红色显示
		return ColorLightRed + title + ColorReset
	}

	if !shouldUseColors() {
		return fmt.Sprintf("[%s]", title)
	}
	// 添加方括号并使用浅红色显示
	return ColorLightRed + fmt.Sprintf("[%s]", title) + ColorReset
}

// FormatNumber 格式化数字显示（移除颜色，使用默认颜色）
func FormatNumber(num int) string {
	// 修改：数字使用默认颜色，不添加任何颜色
	return fmt.Sprintf("%d", num)
}

// FormatPercentage 格式化百分比显示（移除颜色，使用默认颜色）
func FormatPercentage(percentage float64) string {
	// 修改：百分比使用默认颜色，不添加任何颜色
	return fmt.Sprintf("%.1f%%", percentage)
}

// FormatResultNumber 格式化结果编号显示（已废弃：不再使用序号显示）
// Deprecated: 根据新的日志输出要求，不再显示序号
func FormatResultNumber(number int) string {
	// 返回空字符串，因为不再使用序号显示
	return ""
}

// FormatContentLength 格式化内容长度显示
func FormatContentLength(length int) string {
	if !shouldUseColors() {
		return fmt.Sprintf("[%d]", length) // 如果禁用彩色输出，直接返回内容长度
	}
	// 修改：内容长度使用加粗默认颜色显示
	return fmt.Sprintf("[%d]", length) + ColorReset
}

// FormatContentType 格式化内容类型显示（简化格式，只保留主要类型）
func FormatContentType(contentType string) string {
	// 简化Content-Type：只保留分号前的主要类型
	simplifiedType := simplifyContentType(contentType)

	if !shouldUseColors() {
		return fmt.Sprintf("[%s]", simplifiedType) // 如果禁用彩色输出，直接返回简化的内容类型
	}
	return fmt.Sprintf("[%s]", simplifiedType) + ColorReset
}

// simplifyContentType 简化Content-Type，只保留分号前的主要类型
// 例如：application/json;charset=utf-8 -> application/json
func simplifyContentType(contentType string) string {
	if contentType == "" {
		return contentType
	}

	// 查找第一个分号的位置
	if semicolonIndex := strings.Index(contentType, ";"); semicolonIndex != -1 {
		// 返回分号前的内容，并去除前后空格
		return strings.TrimSpace(contentType[:semicolonIndex])
	}

	// 如果没有分号，返回原始内容（去除前后空格）
	return strings.TrimSpace(contentType)
}

// FormatDSLRule 格式化DSL规则显示（指纹识别专用）
func FormatDSLRule(dslRule string) string {
	if !shouldUseColors() {
		return dslRule // 如果禁用彩色输出，直接返回DSL规则
	}
	// DSL规则使用灰色显示，不过于突出
	return ColorDim + dslRule + ColorReset
}

// FormatFingerprintPair 将指纹名称与匹配规则格式化为 "<名称> <规则>" 的统一输出
func FormatFingerprintPair(name, rule string) string {
	name = strings.TrimSpace(name)
	rule = strings.TrimSpace(rule)
	if name == "" || rule == "" {
		return ""
	}
	return "<" + FormatFingerprintName(name) + "> <" + FormatDSLRule(rule) + ">"
}

// FormatFingerprintDisplay 根据开关决定是否携带规则内容
func FormatFingerprintDisplay(name, rule string, showRule bool) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if showRule {
		if formatted := FormatFingerprintPair(name, rule); formatted != "" {
			return formatted
		}
	}
	return "<" + FormatFingerprintName(name) + ">"
}

// FormatFingerprintTag 格式化指纹标签显示（指纹识别专用）
func FormatFingerprintTag(tag string) string {
	if !shouldUseColors() {
		return tag // 如果禁用彩色输出，直接返回标签
	}

	// 根据标签类型选择颜色
	var color string
	switch tag {
	case "主动探测":
		// 主动探测：加粗红色
		color = ColorBold + ColorRed
	case "被动识别":
		// 被动识别：加粗绿色
		color = ColorBold + ColorGreen
	default:
		// 其他标签：加粗默认颜色
		color = ColorBold
	}

	return color + tag + ColorReset
}

// FormatBold 将文本加粗显示（若启用颜色）
// 参数：
//   - s: 原始文本
//
// 返回：
//   - string: 加粗后的文本（或原文本，当颜色禁用时）
func FormatBold(s string) string {
	if !shouldUseColors() {
		return s
	}
	return ColorBold + s + ColorReset
}

// FormatSnippetArrow 返回用于指纹匹配片段前缀的箭头（加粗绿色高亮）
// 示例："➜ "（带尾随空格）
// 参数：无
// 返回：带颜色（或不带颜色）的箭头字符串
func FormatSnippetArrow() string {
	arrow := "➜ "
	if !shouldUseColors() {
		return arrow
	}
	return ColorBold + ColorGreen + arrow + ColorReset
}

// FormatFingerprintMatch 已废弃：统一使用FormatFingerprintName函数
// Deprecated: 为了保持主动扫描和被动扫描的输出格式一致，
// 现在统一使用FormatFingerprintName函数，该函数提供加粗显示效果
// 此函数保留仅为向后兼容，实际调用FormatFingerprintName
// shouldUseColors 检查是否应该使用颜色
// 返回: 布尔值表示是否使用颜色（配置允许且平台支持）
func shouldUseColors() bool {
	if atomic.LoadInt32(&globalColorEnabled) == 0 {
		return false
	}
	// Windows系统检查ANSI支持状态
	if runtime.GOOS == "windows" {
		return isWindowsANSISupported()
	}

	// 其他系统直接使用
	return true
}

// isWindowsANSISupported 检查Windows是否支持ANSI颜色
// 这个函数通过反射的方式避免导入循环依赖
// 返回: 布尔值表示Windows ANSI支持状态
func isWindowsANSISupported() bool {
	// 为了避免循环导入，我们使用一个全局变量来获取状态
	// 这个变量将在console包初始化时设置
	return getWindowsANSIStatus()
}

// Windows ANSI状态变量，由console包设置
var (
	windowsANSISupported bool
	globalColorEnabled   int32 = 1
)

// SetWindowsANSISupported 设置Windows ANSI支持状态
// 此函数由console包调用，用于通知formatter包Windows ANSI支持状态
// 参数 supported: Windows ANSI支持状态
func SetWindowsANSISupported(supported bool) {
	windowsANSISupported = supported
}

// getWindowsANSIStatus 获取Windows ANSI支持状态
// 内部函数，返回由console包设置的ANSI支持状态
// 返回: Windows ANSI支持状态
func getWindowsANSIStatus() bool {
	return windowsANSISupported
}

// SetColorEnabled 控制全局颜色输出
func SetColorEnabled(enabled bool) {
	if enabled {
		atomic.StoreInt32(&globalColorEnabled, 1)
	} else {
		atomic.StoreInt32(&globalColorEnabled, 0)
	}
}

// ColorsEnabled 返回当前颜色输出状态
func ColorsEnabled() bool {
	return atomic.LoadInt32(&globalColorEnabled) == 1
}

// getDarkGreenColor 获取深绿色颜色代码（支持降级）
// 返回适合当前终端环境的深绿色ANSI代码
func getDarkGreenColor() string {
	if !shouldUseColors() {
		return "" // 如果禁用彩色输出，返回空字符串
	}

	// 临时修复：强制使用16色降级方案，绕过24位真彩色问题
	// TODO: 调试完成后恢复24位真彩色检测逻辑
	return ColorDarkGreenFallback

	// 原始逻辑（临时注释）：
	// // 检查是否支持24位真彩色
	// if supportsTrueColor() {
	// 	return ColorDarkGreen // 使用24位真彩色
	// }
	//
	// // 降级到16色方案
	// return ColorDarkGreenFallback
}

// ============================================================================
// 目录扫描指纹识别专用格式化函数
// ============================================================================

// FormatDSL 格式化DSL表达式（用于目录扫描结果的DSL显示）
// 使用灰色显示DSL表达式，并截断过长的内容
func FormatDSL(dsl string) string {
	// 截断过长的DSL表达式
	maxLen := 80
	if len(dsl) > maxLen {
		dsl = dsl[:maxLen] + "..."
	}

	if !shouldUseColors() {
		return dsl // 如果禁用彩色输出，直接返回DSL表达式
	}
	// 使用灰色显示DSL表达式
	return ColorGray + dsl + ColorReset
}

var quotedValueRegexp = regexp.MustCompile(`['"]([^'"` + "`" + `]+)['"]`)

// HighlightSnippet 根据匹配DSL中的字符串常量，对片段中的关键字进行高亮显示
func HighlightSnippet(snippet, matcher string) string {
	snippet = strings.TrimSpace(snippet)
	if snippet == "" {
		return ""
	}

	if !shouldUseColors() {
		return snippet
	}

	values := quotedValueRegexp.FindAllStringSubmatch(matcher, -1)
	if len(values) == 0 {
		return snippet
	}

	highlighted := snippet
	seen := make(map[string]struct{})
	for _, match := range values {
		if len(match) < 2 {
			continue
		}
		value := strings.TrimSpace(match[1])
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		highlight := ColorYellow + value + ColorReset
		highlighted = strings.ReplaceAll(highlighted, value, highlight)
	}
	return highlighted
}

// ============================================================================
// 网络工具函数 (从helper包合并)
// ============================================================================

// ReaderToBuffer 尝试将 Reader 读取至 buffer 中
// 如果未达到 limit，则成功读取进入 buffer
// 否则 buffer 返回 nil，且返回新 Reader，状态为未读取前
func ReaderToBuffer(r io.Reader, limit int64) ([]byte, io.Reader, error) {
	buf := bytes.NewBuffer(make([]byte, 0))
	lr := io.LimitReader(r, limit)

	_, err := io.Copy(buf, lr)
	if err != nil {
		return nil, nil, err
	}

	// 达到上限
	if int64(buf.Len()) == limit {
		// 返回新的 Reader
		return nil, io.MultiReader(bytes.NewBuffer(buf.Bytes()), r), nil
	}

	// 返回 buffer
	return buf.Bytes(), nil, nil
}

// CanonicalAddr returns url.Host but always with a ":port" suffix.
func CanonicalAddr(url *url.URL) string {
	port := url.Port()
	if port == "" {
		port = getDefaultPort(url.Scheme)
	}
	return net.JoinHostPort(url.Hostname(), port)
}

// getDefaultPort 获取协议的默认端口
func getDefaultPort(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	case "socks5":
		return "1080"
	default:
		return ""
	}
}

// GetProxyConn connect proxy
// ref: http/transport.go dialConn func
func GetProxyConn(ctx context.Context, proxyUrl *url.URL, address string, sslInsecure bool) (net.Conn, error) {
	var conn net.Conn
	if proxyUrl.Scheme == "socks5" {
		//检测socks5认证信息
		proxyAuth := &proxy.Auth{}
		if proxyUrl.User != nil {
			user := proxyUrl.User.Username()
			pass, _ := proxyUrl.User.Password()
			proxyAuth.User = user
			proxyAuth.Password = pass
		}
		dialer, err := proxy.SOCKS5("tcp", proxyUrl.Host, proxyAuth, proxy.Direct)
		if err != nil {
			return nil, err
		}
		dc := dialer.(interface {
			DialContext(ctx context.Context, network, addr string) (net.Conn, error)
		})
		conn, err = dc.DialContext(ctx, "tcp", address)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return conn, err
	} else {
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyUrl.Host)
		if err != nil {
			return nil, err
		}
		// 如果代理URL是HTTPS，则进行TLS握手
		if proxyUrl.Scheme == "https" {
			tlsConfig := &tls.Config{
				ServerName:         proxyUrl.Hostname(), // 设置TLS握手的服务器名称
				InsecureSkipVerify: sslInsecure,
				// 可以在这里添加其他TLS配置
			}
			// 包装原始连接为TLS连接
			tlsConn := tls.Client(conn, tlsConfig)
			// 执行TLS握手
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close() // 握手失败，关闭连接
				return nil, err
			}
			conn = tlsConn // 使用TLS连接替换原始连接
		}
		connectReq := &http.Request{
			Method: "CONNECT",
			URL:    &url.URL{Opaque: address},
			Host:   address,
			Header: http.Header{},
		}
		if proxyUrl.User != nil {
			connectReq.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(proxyUrl.User.String())))
		}
		connectCtx, cancel := context.WithTimeout(ctx, 1*time.Minute)
		defer cancel()
		didReadResponse := make(chan struct{}) // closed after CONNECT write+read is done or fails
		var resp *http.Response
		// Write the CONNECT request & read the response.
		go func() {
			defer close(didReadResponse)
			err = connectReq.Write(conn)
			if err != nil {
				return
			}
			// Okay to use and discard buffered reader here, because
			// TLS server will not speak until spoken to.
			br := bufio.NewReader(conn)
			resp, err = http.ReadResponse(br, connectReq)
		}()
		select {
		case <-connectCtx.Done():
			conn.Close()
			<-didReadResponse
			return nil, connectCtx.Err()
		case <-didReadResponse:
			// resp or err now set
		}
		if err != nil {
			conn.Close()
			return nil, err
		}
		if resp.StatusCode != 200 {
			_, text, ok := strings.Cut(resp.Status, " ")
			conn.Close()
			if !ok {
				return nil, errors.New("unknown status code")
			}
			return nil, errors.New(text)
		}
		return conn, nil
	}
}
