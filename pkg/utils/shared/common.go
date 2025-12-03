package shared

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
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
	titleRegex := `(?i)<title[^>]*>(.*?)</title>`
	re := regexp.MustCompile(titleRegex)
	matches := re.FindStringSubmatch(body)

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
	numericEntityRegex := regexp.MustCompile(`&#(\d+);`)
	title = numericEntityRegex.ReplaceAllStringFunc(title, func(match string) string {
		return match // 暂时保持原样，避免复杂解析，后续可引入 html/entity 包
	})

	// 清理多余空白字符
	title = regexp.MustCompile(`\s+`).ReplaceAllString(title, " ")

	return strings.TrimSpace(title)
}

// SanitizeFilename 清理文件名中的非法字符
func SanitizeFilename(name string) string {
	replacer := strings.NewReplacer(
		":", "_",
		"/", "_",
		"\\", "_",
		"?", "_",
		"*", "_",
		"|", "_",
		"<", "_",
		">", "_",
		"\"", "_",
	)
	return strings.Trim(replacer.Replace(name), "_")
}

// FileExtensionChecker 文件扩展名检查工具
type FileExtensionChecker struct{}

// NewFileExtensionChecker 创建文件扩展名检查器
func NewFileExtensionChecker() *FileExtensionChecker {
	return &FileExtensionChecker{}
}

// IsStaticFile 检查URL是否为静态文件
func (c *FileExtensionChecker) IsStaticFile(urlPath string) bool {
	staticExtensions := []string{
		".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
		".woff", ".woff2", ".ttf", ".eot", ".map", ".pdf", ".zip",
		".rar", ".tar", ".gz", ".doc", ".docx", ".xls", ".xlsx",
	}

	lowerPath := strings.ToLower(urlPath)
	for _, ext := range staticExtensions {
		if strings.HasSuffix(lowerPath, ext) {
			return true
		}
	}
	return false
}

// ParseTargets 解析目标列表，支持 CIDR、IP范围、域名、URL
// 返回去重后的IP列表
func ParseTargets(targets []string) ([]string, error) {
	uniqueIPs := make(map[string]struct{})

	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		// 1. 尝试解析为 CIDR
		if _, ipnet, err := net.ParseCIDR(target); err == nil {
			ips := cidrToIPs(ipnet)
			for _, ip := range ips {
				uniqueIPs[ip] = struct{}{}
			}
			continue
		}

		// 2. 尝试解析为 IP 范围 (e.g., 192.168.1.1-10, 192.168.1.1-192.168.1.10)
		if strings.Contains(target, "-") {
			ips, err := rangeToIPs(target)
			if err == nil && len(ips) > 0 {
				for _, ip := range ips {
					uniqueIPs[ip] = struct{}{}
				}
				continue
			}
			// 如果解析范围失败，可能是一个带横杠的域名，继续后续处理
		}

		// 3. 处理 URL/域名/单一IP
		// 提取 Host
		host := target
		if strings.Contains(target, "://") {
			if u, err := url.Parse(target); err == nil {
				host = u.Host
			}
		}
		// 去除端口
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}

		// 解析 IP
		if ip := net.ParseIP(host); ip != nil {
			uniqueIPs[ip.String()] = struct{}{}
		} else {
			// 域名解析
			if ips, err := net.LookupIP(host); err == nil {
				for _, ip := range ips {
					// 优先使用 IPv4
					if ip4 := ip.To4(); ip4 != nil {
						uniqueIPs[ip4.String()] = struct{}{}
					} else {
						uniqueIPs[ip.String()] = struct{}{}
					}
				}
			}
		}
	}

	if len(uniqueIPs) == 0 {
		return nil, fmt.Errorf("未找到有效的 IP 目标")
	}

	// 转换为切片并排序
	result := make([]string, 0, len(uniqueIPs))
	for ip := range uniqueIPs {
		result = append(result, ip)
	}
	sort.Strings(result)
	return result, nil
}

// cidrToIPs 将 CIDR 转换为 IP 列表
func cidrToIPs(n *net.IPNet) []string {
	var ips []string
	for ip := n.IP.Mask(n.Mask); n.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// rangeToIPs 解析 IP 范围
func rangeToIPs(target string) ([]string, error) {
	parts := strings.Split(target, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("无效的范围格式")
	}
	startIPStr := strings.TrimSpace(parts[0])
	endPart := strings.TrimSpace(parts[1])

	startIP := net.ParseIP(startIPStr)
	if startIP == nil {
		return nil, fmt.Errorf("无效的起始 IP")
	}
	startIP = startIP.To4()
	if startIP == nil {
		return nil, fmt.Errorf("仅支持 IPv4 范围")
	}

	var endIP net.IP

	// 检查 endPart 是完整 IP 还是数字后缀
	if strings.Contains(endPart, ".") {
		endIP = net.ParseIP(endPart)
		if endIP == nil {
			return nil, fmt.Errorf("无效的结束 IP")
		}
		endIP = endIP.To4()
	} else {
		// 数字后缀模式 (e.g. 192.168.1.1-10)
		endNum, err := strconv.Atoi(endPart)
		if err != nil {
			return nil, fmt.Errorf("无效的结束后缀")
		}
		// 构造结束 IP
		endIP = make(net.IP, 4)
		copy(endIP, startIP)
		endIP[3] = byte(endNum)
	}

	if endIP == nil {
		return nil, fmt.Errorf("无法解析结束 IP")
	}

	// 生成范围内的所有 IP
	var ips []string
	startVal := ipToUInt32(startIP)
	endVal := ipToUInt32(endIP)

	if startVal > endVal {
		return nil, fmt.Errorf("起始 IP 大于结束 IP")
	}

	// 限制一次生成的 IP 数量，防止 OOM
	if endVal-startVal > 65536 {
		return nil, fmt.Errorf("IP 范围过大 (>65536)")
	}

	for i := startVal; i <= endVal; i++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		ips = append(ips, ip.String())
	}

	return ips, nil
}

func ipToUInt32(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}
