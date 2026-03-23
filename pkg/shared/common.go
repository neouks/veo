package shared

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"math/rand"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"veo/pkg/logger"

	"github.com/andybalholm/brotli"
)

// URLValidator URL验证工具
type URLValidator struct{}

// NewURLValidator 创建URL验证器
func NewURLValidator() *URLValidator {
	return &URLValidator{}
}

// IsValidURL 检查URL是否合法（增强版，合并了collector中的验证逻辑）
func (v *URLValidator) IsValidURL(rawURL string) bool {
	// 1. 基本格式检查
	if rawURL == "" {
		return false
	}

	// 2. 检查是否是协议相对URL（如 //example.com）
	if strings.HasPrefix(rawURL, "//") {
		return false
	}

	// 3. 检查是否包含协议
	if !v.hasValidScheme(rawURL) {
		return false
	}

	// 4. 基本字符检查
	if strings.Contains(rawURL, " ") ||
		strings.Contains(rawURL, "\n") ||
		strings.Contains(rawURL, "\t") {
		return false
	}

	// 5. 尝试解析URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// 6. 检查是否有有效的主机名
	if parsedURL.Host == "" {
		return false
	}

	// 7. 检查协议是否为HTTP或HTTPS
	return v.isSupportedScheme(parsedURL.Scheme)
}

// hasValidScheme 检查URL是否包含有效的协议
func (v *URLValidator) hasValidScheme(rawURL string) bool {
	lowerURL := strings.ToLower(rawURL)
	return strings.HasPrefix(lowerURL, "http://") ||
		strings.HasPrefix(lowerURL, "https://")
}

// isSupportedScheme 检查协议是否被支持
func (v *URLValidator) isSupportedScheme(scheme string) bool {
	switch strings.ToLower(scheme) {
	case "http", "https":
		return true
	default:
		return false
	}
}

// TitleExtractor 标题提取工具
type TitleExtractor struct{}

var (
	titleRegex         = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
	whitespaceRegex    = regexp.MustCompile(`\s+`)
	htmlEntityReplacer = strings.NewReplacer(
		"&amp;", "&",
		"&lt;", "<",
		"&gt;", ">",
		"&quot;", "\"",
		"&apos;", "'",
		"&nbsp;", " ",
		"&#39;", "'",
		"&#34;", "\"",
		"&copy;", "©",
		"&reg;", "®",
		"&trade;", "™",
	)
)

// NewTitleExtractor 创建标题提取器
func NewTitleExtractor() *TitleExtractor {
	return &TitleExtractor{}
}

// ExtractTitle 从HTML内容中提取标题（便捷函数）
func ExtractTitle(body string) string {
	return NewTitleExtractor().ExtractTitle(body)
}

// ExtractTitle 从HTML内容中提取标题
func (e *TitleExtractor) ExtractTitle(body string) string {
	if body == "" {
		return "空标题"
	}

	matches := titleRegex.FindStringSubmatch(body)
	if len(matches) < 2 || matches[1] == "" {
		return "无标题"
	}

	title := strings.TrimSpace(matches[1])
	if title == "" {
		return "空标题"
	}

	title = e.CleanTitle(title)
	if len(title) > 100 {
		title = title[:100] + "..."
	}

	return title
}

// CleanTitle 清理标题内容
func (e *TitleExtractor) CleanTitle(title string) string {
	title = htmlEntityReplacer.Replace(title)
	title = whitespaceRegex.ReplaceAllString(title, " ")
	return strings.TrimSpace(title)
}

// DecompressByEncoding 根据 Content-Encoding 对响应体进行解压缩。
// 若解压失败或不支持该编码，返回原始数据。
func DecompressByEncoding(data []byte, contentEncoding string) []byte {
	if len(data) == 0 {
		return data
	}

	enc := strings.ToLower(contentEncoding)
	if enc == "" {
		return data
	}

	if strings.Contains(enc, "gzip") {
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			logger.Debugf("gzip解压失败: %v, 返回原始内容", err)
			return data
		}
		defer r.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			logger.Debugf("gzip读取失败: %v, 返回原始内容", err)
			return data
		}
		logger.Debugf("gzip解压成功: %d -> %d bytes", len(data), len(out))
		return out
	}

	if strings.Contains(enc, "deflate") {
		r := flate.NewReader(bytes.NewReader(data))
		defer r.Close()
		out, err := io.ReadAll(r)
		if err != nil {
			logger.Debugf("deflate读取失败: %v, 返回原始内容", err)
			return data
		}
		logger.Debugf("deflate解压成功: %d -> %d bytes", len(data), len(out))
		return out
	}

	if strings.Contains(enc, "br") {
		r := brotli.NewReader(bytes.NewReader(data))
		out, err := io.ReadAll(r)
		if err != nil {
			logger.Debugf("brotli读取失败: %v, 返回原始内容", err)
			return data
		}
		logger.Debugf("brotli解压成功: %d -> %d bytes", len(data), len(out))
		return out
	}

	logger.Debugf("不支持的压缩格式: %s", enc)
	return data
}

// FileExtensionChecker 文件扩展名检查工具
type FileExtensionChecker struct {
	extensions []string
}

var (
	defaultStaticExtensions = []string{
		".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
		".woff", ".woff2", ".ttf", ".eot", ".map", ".pdf", ".zip",
		".rar", ".tar", ".gz", ".doc", ".docx", ".xls", ".xlsx",
	}
	globalStaticExtensions []string
	staticExtensionsMu     sync.RWMutex

	defaultStaticPaths = []string{
		"/assets/", "/css/", "/js/", "/images/", "/fonts/", "/media/", "/static/", "/public/",
	}
	globalStaticPaths []string
	staticPathsMu     sync.RWMutex
)

// SetGlobalStaticExtensions 设置全局静态文件扩展名列表
func SetGlobalStaticExtensions(extensions []string) {
	staticExtensionsMu.Lock()
	defer staticExtensionsMu.Unlock()

	// 深拷贝并过滤空值和修正格式（确保以.开头）
	globalStaticExtensions = make([]string, 0, len(extensions))
	for _, ext := range extensions {
		ext = strings.TrimSpace(ext)
		if ext == "" {
			continue
		}
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		globalStaticExtensions = append(globalStaticExtensions, ext)
	}
}

// SetGlobalStaticPaths 设置全局静态路径列表
func SetGlobalStaticPaths(paths []string) {
	staticPathsMu.Lock()
	defer staticPathsMu.Unlock()

	globalStaticPaths = make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		// 统一格式：确保以/开头
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		// 确保以/结尾（因为是目录）
		if !strings.HasSuffix(p, "/") {
			p = p + "/"
		}
		globalStaticPaths = append(globalStaticPaths, p)
	}
}

// NewFileExtensionChecker 创建文件扩展名检查器
func NewFileExtensionChecker() *FileExtensionChecker {
	staticExtensionsMu.RLock()
	defer staticExtensionsMu.RUnlock()

	var exts []string
	if len(globalStaticExtensions) > 0 {
		exts = make([]string, len(globalStaticExtensions))
		copy(exts, globalStaticExtensions)
	} else {
		exts = make([]string, len(defaultStaticExtensions))
		copy(exts, defaultStaticExtensions)
	}

	return &FileExtensionChecker{
		extensions: exts,
	}
}

// PathChecker 路径检查工具
type PathChecker struct {
	paths []string
}

// NewPathChecker 创建路径检查器
func NewPathChecker() *PathChecker {
	staticPathsMu.RLock()
	defer staticPathsMu.RUnlock()

	var paths []string
	if len(globalStaticPaths) > 0 {
		paths = make([]string, len(globalStaticPaths))
		copy(paths, globalStaticPaths)
	} else {
		paths = make([]string, len(defaultStaticPaths))
		copy(paths, defaultStaticPaths)
	}

	return &PathChecker{
		paths: paths,
	}
}

// IsStaticPath 检查URL路径是否匹配静态目录黑名单
func (c *PathChecker) IsStaticPath(urlPath string) bool {
	// 解析 URL 获取路径部分
	var pathPart string
	if strings.Contains(urlPath, "://") {
		if u, err := url.Parse(urlPath); err == nil {
			pathPart = u.Path
		} else {
			pathPart = urlPath
		}
	} else {
		pathPart = urlPath
	}

	if pathPart == "" {
		return false
	}

	lowerPath := strings.ToLower(pathPart)

	for _, p := range c.paths {
		// 检查路径中是否包含黑名单目录（例如 /assets/）
		// 使用 contains 而不是 hasPrefix，因为可能是 /v1/assets/
		if strings.Contains(lowerPath, p) {
			return true
		}
	}
	return false
}

// IsStaticFile 检查URL是否为静态文件
func (c *FileExtensionChecker) IsStaticFile(urlPath string) bool {
	var pathPart string
	if strings.Contains(urlPath, "://") || strings.Contains(urlPath, "?") || strings.Contains(urlPath, "#") {
		if u, err := url.Parse(urlPath); err == nil {
			pathPart = u.Path
		} else {
			pathPart = urlPath
		}
	} else {
		pathPart = urlPath
	}

	lowerPath := strings.ToLower(pathPart)
	for _, ext := range c.extensions {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}
	return false
}

// IsStaticResource 使用统一的静态路径/后缀规则判断资源是否应被视为静态资源。
func IsStaticResource(rawURL string) bool {
	pathChecker := NewPathChecker()
	if pathChecker.IsStaticPath(rawURL) {
		return true
	}

	checker := NewFileExtensionChecker()
	return checker.IsStaticFile(rawURL)
}

var (
	defaultUserAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	}
	uaRand   = rand.New(rand.NewSource(time.Now().UnixNano()))
	uaRandMu sync.Mutex
)

func DefaultList() []string {
	result := make([]string, len(defaultUserAgents))
	copy(result, defaultUserAgents)
	return result
}

func GetEffectiveList() []string {
	return DefaultList()
}

func IsRandomEnabled() bool {
	return true
}

func Primary() string {
	list := GetEffectiveList()
	if len(list) == 0 {
		return ""
	}
	return list[0]
}

func Pick() string {
	list := GetEffectiveList()
	if len(list) == 0 {
		return ""
	}
	if !IsRandomEnabled() || len(list) == 1 {
		return list[0]
	}
	uaRandMu.Lock()
	idx := uaRand.Intn(len(list))
	uaRandMu.Unlock()
	return list[idx]
}
