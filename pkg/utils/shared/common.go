package shared

import (
	"net/url"
	"regexp"
	"strings"
	"sync"
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
	// 检查是否以http://或https://开头
	return strings.HasPrefix(strings.ToLower(rawURL), "http://") ||
		strings.HasPrefix(strings.ToLower(rawURL), "https://")
}

// isSupportedScheme 检查协议是否被支持
func (v *URLValidator) isSupportedScheme(scheme string) bool {
	supportedSchemes := []string{"http", "https"}
	lowerScheme := strings.ToLower(scheme)

	for _, supported := range supportedSchemes {
		if lowerScheme == supported {
			return true
		}
	}
	return false
}

// TitleExtractor 标题提取工具
type TitleExtractor struct{}

var (
	titleRegex         = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
	numericEntityRegex = regexp.MustCompile(`&#(\d+);`)
	whitespaceRegex    = regexp.MustCompile(`\s+`)
)

// NewTitleExtractor 创建标题提取器
func NewTitleExtractor() *TitleExtractor {
	return &TitleExtractor{}
}

// ExtractTitle 从HTML内容中提取标题（便捷函数）
func ExtractTitle(body string) string {
	return NewTitleExtractor().ExtractTitle(body)
}

// ExtractTitle 从HTML内容中提取标题（修复：添加严格边界检查）
func (e *TitleExtractor) ExtractTitle(body string) string {
	if body == "" {
		return "空标题"
	}

	// 使用正则表达式提取title标签内容
	matches := titleRegex.FindStringSubmatch(body)

	// 修复：严格的边界检查，防止index out of range panic
	if len(matches) >= 2 {
		// 额外检查：确保matches[1]确实存在且可访问
		if len(matches) > 1 && matches[1] != "" {
			title := strings.TrimSpace(matches[1])
			if title == "" {
				return "空标题"
			}

			// 清理HTML实体和多余空白字符
			title = e.CleanTitle(title)

			// 限制标题长度
			if len(title) > 100 {
				title = title[:100] + "..."
			}

			return title
		}
	}

	return "无标题"
}

// CleanTitle 清理标题内容
func (e *TitleExtractor) CleanTitle(title string) string {
	// 替换常见HTML实体
	title = strings.ReplaceAll(title, "&amp;", "&")
	title = strings.ReplaceAll(title, "&lt;", "<")
	title = strings.ReplaceAll(title, "&gt;", ">")
	title = strings.ReplaceAll(title, "&quot;", "\"")
	title = strings.ReplaceAll(title, "&apos;", "'")
	title = strings.ReplaceAll(title, "&nbsp;", " ")
	title = strings.ReplaceAll(title, "&#39;", "'")
	title = strings.ReplaceAll(title, "&#34;", "\"")
	title = strings.ReplaceAll(title, "&copy;", "©")
	title = strings.ReplaceAll(title, "&reg;", "®")
	title = strings.ReplaceAll(title, "&trade;", "™")

	// 处理数字实体 &#数字;
	title = numericEntityRegex.ReplaceAllStringFunc(title, func(match string) string {
		return match // 暂时保持原样，避免复杂解析，后续可引入 html/entity 包
	})

	// 清理多余空白字符
	title = whitespaceRegex.ReplaceAllString(title, " ")

	return strings.TrimSpace(title)
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
	lowerPath := strings.ToLower(urlPath)
	for _, ext := range c.extensions {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}
	return false
}
