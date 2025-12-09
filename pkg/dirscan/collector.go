package dirscan

import (
	"net/url"
	"regexp"
	"strings"
	"sync"

	"veo/pkg/utils/logger"
	"veo/pkg/utils/shared"
	"veo/proxy"
)

// 类型定义

// Collector URL采集器，用于采集和过滤经过代理的URL
type Collector struct {
	proxy.BaseAddon
	urlMap             map[string]int  // 最终采集的URL访问计数映射
	pendingURLs        map[string]bool // 待处理的URL（已过滤静态资源）
	includeStatusCodes []int           // 需要采集的状态码白名单
	staticExtensions   []string        // 静态文件扩展名列表
	staticPaths        []string        // 静态路径列表
	allowedHosts       []string        // 允许的主机列表
	mu                 sync.RWMutex    // 读写锁，保证并发安全
	collectionEnabled  bool            // 收集功能是否启用
	collectionPaused   bool            // 收集是否暂停（等待用户输入）
}

// 构造函数

// NewCollector 创建新的Collector实例
func NewCollector() *Collector {
	logger.Debugf("创建Collector实例")

	// 默认状态码
	defaultStatusCodes := []int{200, 301, 302, 403, 404, 500}

	collector := &Collector{
		urlMap:             make(map[string]int),
		pendingURLs:        make(map[string]bool),
		includeStatusCodes: defaultStatusCodes,
		collectionEnabled:  true, // 默认启用收集功能
	}

	return collector
}

// addon接口实现

// Requestheaders 处理请求头，进行URL采集和过滤
func (c *Collector) Requestheaders(f *proxy.Flow) {
	enabled := c.IsCollectionEnabled()
	if !enabled {
		return
	}

	// 检查收集是否暂停
	if c.IsCollectionPaused() {
		logger.Debugf("收集已暂停，跳过URL: %s", f.Request.URL.String())
		return
	}

	originalURL := f.Request.URL.String()

	// 先修复协议相对URL，然后再提取主机信息进行过滤
	var hostToCheck string
	if strings.HasPrefix(originalURL, "//") {
		// 协议相对URL，先修复后再提取主机
		fixedURL := c.fixProtocolRelativeURL(originalURL)
		if fixedURL != "" {
			if parsedURL, err := url.Parse(fixedURL); err == nil {
				hostToCheck = parsedURL.Host
			} else {
				hostToCheck = f.Request.URL.Host // 回退到原始主机
			}
		} else {
			hostToCheck = f.Request.URL.Host // 回退到原始主机
		}
	} else {
		hostToCheck = f.Request.URL.Host
	}

	// 检查主机是否被允许
	if !c.isHostAllowed(hostToCheck) {
		logger.Debugf("主机被拒绝: %s (原URL: %s)", hostToCheck, originalURL)
		return
	}

	// 过滤静态资源
	if c.isStaticResource(originalURL) {
		logger.Debugf("静态资源跳过: %s", originalURL)
		return
	}

	// 清理URL参数
	cleanedURL := c.cleanURLParams(originalURL)
	if cleanedURL == "" {
		logger.Debugf("URL清理失败: %s", originalURL)
		return
	}

	// 添加到待处理列表
	c.addToPendingList(cleanedURL, originalURL)
}

// Responseheaders 处理响应头，过滤有效URL并根据需要采集
func (c *Collector) Responseheaders(f *proxy.Flow) {
	enabled := c.IsCollectionEnabled()
	if !enabled {
		return
	}

	// 检查收集是否暂停
	if c.IsCollectionPaused() {
		logger.Debugf("收集已暂停，跳过URL: %s", f.Request.URL.String())
		return
	}

	originalURL := f.Request.URL.String()
	statusCode := f.Response.StatusCode

	// 再次检查主机是否被允许（与Requestheaders阶段一致）
	var hostToCheck string
	if strings.HasPrefix(originalURL, "//") {
		// 协议相对URL，先修复后再提取主机
		fixedURL := c.fixProtocolRelativeURL(originalURL)
		if fixedURL != "" {
			if parsedURL, err := url.Parse(fixedURL); err == nil {
				hostToCheck = parsedURL.Host
			} else {
				hostToCheck = f.Request.URL.Host // 回退到原始主机
			}
		} else {
			hostToCheck = f.Request.URL.Host // 回退到原始主机
		}
	} else {
		hostToCheck = f.Request.URL.Host
	}

	// 检查主机是否被允许
	if !c.isHostAllowed(hostToCheck) {
		logger.Debugf("响应阶段主机被拒绝: %s (原URL: %s)", hostToCheck, originalURL)
		return
	}

	// 关键修复：对URL进行同样的清理，确保与Requestheaders阶段一致
	cleanedURL := c.cleanURLParams(originalURL)
	if cleanedURL == "" {
		logger.Debugf("URL清理失败: %s", originalURL)
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// 使用清理后的URL来查找待处理列表
	if !c.pendingURLs[cleanedURL] {
		logger.Debugf("URL不在待处理列表: %s", cleanedURL)
		return // 不在待处理列表中，可能是静态资源或重复请求
	}

	// 从待处理列表中移除
	delete(c.pendingURLs, cleanedURL)

	// 根据状态码决定是否最终采集
	if c.isValidStatusCode(statusCode) {
		c.addToFinalCollection(cleanedURL, statusCode)
	} else {
		logger.Debugf("状态码%d不符合条件，丢弃: %s", statusCode, cleanedURL)
	}
}

// 公共接口方法

// GetURLCount 获取当前采集的URL数量
func (c *Collector) GetURLCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.urlMap)
}

// GetURLMap 获取当前采集的URL映射（线程安全）
func (c *Collector) GetURLMap() map[string]int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// 返回副本，避免外部修改
	result := make(map[string]int, len(c.urlMap))
	for k, v := range c.urlMap {
		result[k] = v
	}
	return result
}

// ClearURLMap 清空URL映射和待处理列表
func (c *Collector) ClearURLMap() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.urlMap = make(map[string]int)
	c.pendingURLs = make(map[string]bool)
	logger.Debug("URL收集器已清空")
}

// PrintCollectedURLs 打印当前采集的所有URL
func (c *Collector) PrintCollectedURLs() {
	c.mu.RLock()
	defer c.mu.RUnlock()

	logger.Debugf("当前采集URL数量: %d", len(c.urlMap))
	for url, count := range c.urlMap {
		logger.Debugf(" %s (访问次数: %d)", url, count)
	}
}

// CleanURLParams 清理URL参数的公共方法（用于测试）
func (c *Collector) CleanURLParams(rawURL string) string {
	return c.cleanURLParams(rawURL)
}

// 私有辅助方法 - 主机过滤

// isHostAllowed 检查主机是否被允许
func (c *Collector) isHostAllowed(host string) bool {
	// 如果没有设置允许列表，默认允许所有
	if len(c.allowedHosts) == 0 {
		return true
	}
	// TODO: 实现更复杂的通配符匹配逻辑
	return true
}

// 私有辅助方法 - 静态资源过滤

// isStaticResource 检查URL是否为静态资源
func (c *Collector) isStaticResource(url string) bool {
	lowerURL := strings.ToLower(url)

	// 检查是否包含静态目录
	if c.containsStaticPath(lowerURL, c.staticPaths) {
		logger.Debugf("匹配静态目录，过滤: %s", url)
		return true
	}

	// 检查是否以静态文件扩展名结尾
	isStatic := c.hasStaticExtension(lowerURL, c.staticExtensions)
	if isStatic {
		logger.Debugf("匹配静态扩展名，过滤: %s", url)
		return true
	}

	return false
}

// containsStaticPath 检查URL是否包含静态目录
func (c *Collector) containsStaticPath(lowerURL string, staticPaths []string) bool {
	for _, dir := range staticPaths {
		if strings.Contains(lowerURL, strings.ToLower(dir)) {
			return true
		}
	}
	return false
}

// hasStaticExtension 检查URL是否以静态文件扩展名结尾（使用共享工具）
func (c *Collector) hasStaticExtension(lowerURL string, extensions []string) bool {
	checker := shared.NewFileExtensionChecker()
	return checker.IsStaticFile(lowerURL)
}

// 私有辅助方法 - URL格式验证

// isValidURLFormat 验证URL格式是否合法，并尝试修复协议相对URL
// 返回值：(是否有效, 修复后的URL)
func (c *Collector) isValidURLFormat(rawURL string) (bool, string) {
	// 1. 基本格式检查
	if rawURL == "" {
		return false, ""
	}

	fixedURL := rawURL // 默认使用原URL

	// 2. 检查并修复协议相对URL（如 //example.com）
	if strings.HasPrefix(rawURL, "//") {
		repaired := c.fixProtocolRelativeURL(rawURL)
		if repaired != "" {
			logger.Debugf("协议相对URL已修复: %s -> %s", rawURL, repaired)
			// 使用修复后的URL继续验证
			fixedURL = repaired
		} else {
			logger.Debugf("协议相对URL修复失败: %s", rawURL)
			return false, ""
		}
	}

	// 3. 检查是否包含协议
	if !c.hasValidScheme(fixedURL) {
		logger.Debugf("URL缺少协议: %s", fixedURL)
		return false, ""
	}

	// 4. 尝试解析URL
	parsedURL, err := url.Parse(fixedURL)
	if err != nil {
		logger.Debugf("URL解析失败: %s", fixedURL)
		return false, ""
	}

	// 5. 检查是否有有效的主机名
	if parsedURL.Host == "" {
		logger.Debugf("URL缺少主机名: %s", fixedURL)
		return false, ""
	}

	// 6. 检查协议是否为HTTP或HTTPS
	if !c.isSupportedScheme(parsedURL.Scheme) {
		logger.Debugf("不支持的协议 %s: %s", parsedURL.Scheme, fixedURL)
		return false, ""
	}

	return true, fixedURL
}

// fixProtocolRelativeURL 修复协议相对URL
func (c *Collector) fixProtocolRelativeURL(rawURL string) string {
	// 移除开头的 "//"
	if !strings.HasPrefix(rawURL, "//") {
		return ""
	}

	hostAndPath := rawURL[2:] // 去掉 "//"
	if hostAndPath == "" {
		return ""
	}

	// 分离主机部分和路径部分
	var host, path string
	slashIndex := strings.Index(hostAndPath, "/")
	if slashIndex == -1 {
		// 没有路径部分
		host = hostAndPath
		path = ""
	} else {
		// 有路径部分
		host = hostAndPath[:slashIndex]
		path = hostAndPath[slashIndex:]
	}

	// 检查主机部分是否以端口443结尾
	if strings.HasSuffix(host, ":443") {
		// 移除 :443 后缀，添加 https:// 前缀
		hostWithoutPort := host[:len(host)-4] // 移除 ":443"
		fixedURL := "https://" + hostWithoutPort + path
		logger.Debugf("检测到443端口，修复为HTTPS: %s", fixedURL)
		return fixedURL
	} else {
		// 其他情况，添加 http:// 前缀
		fixedURL := "http://" + hostAndPath
		logger.Debugf("修复为HTTP: %s", fixedURL)
		return fixedURL
	}
}

// hasValidScheme 检查URL是否包含有效的协议
func (c *Collector) hasValidScheme(rawURL string) bool {
	// 检查是否以http://或https://开头
	return strings.HasPrefix(strings.ToLower(rawURL), "http://") ||
		strings.HasPrefix(strings.ToLower(rawURL), "https://")
}

// isSupportedScheme 检查协议是否被支持
func (c *Collector) isSupportedScheme(scheme string) bool {
	supportedSchemes := []string{"http", "https"}
	lowerScheme := strings.ToLower(scheme)

	for _, supported := range supportedSchemes {
		if lowerScheme == supported {
			return true
		}
	}
	return false
}

// 私有辅助方法 - URL参数清理

// cleanPathID 清理URL路径中的末尾ID（纯数字）
// 如果进行了修改，返回true
func (c *Collector) cleanPathID(u *url.URL) bool {
	path := u.Path
	if path == "" || path == "/" {
		return false
	}

	// 移除末尾斜杠以便正确提取最后一段
	trimmedPath := strings.TrimRight(path, "/")

	// 查找最后一个分隔符
	lastSlash := strings.LastIndex(trimmedPath, "/")
	if lastSlash == -1 {
		return false
	}

	// 提取最后一段
	lastSegment := trimmedPath[lastSlash+1:]

	// 检查是否为纯数字
	isNumeric := true
	if lastSegment == "" {
		isNumeric = false
	} else {
		for _, r := range lastSegment {
			if r < '0' || r > '9' {
				isNumeric = false
				break
			}
		}
	}

	if isNumeric {
		// 是数字，去除最后一段
		u.Path = trimmedPath[:lastSlash]
		return true
	}

	return false
}

// cleanURLParams 清理URL参数，移除无效参数
func (c *Collector) cleanURLParams(rawURL string) string {
	// 首先验证URL格式是否合法，并获取修复后的URL
	valid, fixedURL := c.isValidURLFormat(rawURL)
	if !valid {
		logger.Debugf("URL格式不合法: %s", rawURL)
		return ""
	}

	// 如果URL被修复了，记录修复信息
	if fixedURL != rawURL {
		logger.Debugf("URL已自动修复: %s -> %s", rawURL, fixedURL)
	}

	parsedURL, err := url.Parse(fixedURL)
	if err != nil {
		logger.Debugf("URL解析失败: %s", fixedURL)
		return ""
	}

	// 尝试清理路径中的数字ID
	pathCleaned := c.cleanPathID(parsedURL)

	// 如果没有查询参数，且路径未被清理，返回修复后的URL
	if parsedURL.RawQuery == "" && !pathCleaned {
		return fixedURL
	}

	// 获取有效参数
	validParams := c.filterValidParams(parsedURL.Query())

	// 重构URL
	if validParams == "" {
		parsedURL.RawQuery = ""
	} else {
		parsedURL.RawQuery = validParams
	}

	return parsedURL.String()
}

// filterValidParams 过滤有效的查询参数
func (c *Collector) filterValidParams(params url.Values) string {
	validParams := url.Values{}

	for key, values := range params {
		if c.isValidParam(key, values) {
			validParams[key] = values
		}
	}

	return validParams.Encode()
}

// isValidParam 检查参数是否有效
func (c *Collector) isValidParam(key string, values []string) bool {
	lowerKey := strings.ToLower(key)

	// 1. 检查是否是明确的无效参数
	if c.isInvalidParam(lowerKey) {
		return false
	}

	// 2. 检查参数值是否像时间戳
	if c.isTimestampParam(values) {
		return false
	}

	// 3. 白名单检查：只保留认证相关的重要参数
	return c.isAuthParam(lowerKey)
}

// isInvalidParam 检查是否是明确的无效参数
func (c *Collector) isInvalidParam(lowerKey string) bool {
	invalidParams := c.getInvalidParams()
	return invalidParams[lowerKey]
}

// isTimestampParam 检查参数值是否像时间戳
func (c *Collector) isTimestampParam(values []string) bool {
	timestampPatterns := c.getTimestampPatterns()

	for _, value := range values {
		for _, pattern := range timestampPatterns {
			if matched, _ := regexp.MatchString(pattern, value); matched {
				return true
			}
		}
	}
	return false
}

// isAuthParam 检查是否是认证相关参数
func (c *Collector) isAuthParam(lowerKey string) bool {
	authParams := c.getAuthParams()
	return authParams[lowerKey]
}

// 私有辅助方法 - 参数配置

// getInvalidParams 获取无效参数列表
func (c *Collector) getInvalidParams() map[string]bool {
	return map[string]bool{
		"_t":        true, // 时间戳
		"time":      true, // 时间参数
		"timestamp": true, // 时间戳
		"_":         true, // jQuery时间戳
		"cachebust": true, // 缓存破坏参数
		"nocache":   true, // 无缓存参数
		"v":         true, // 版本参数（通常是时间戳）
		"version":   true, // 版本参数
		"rand":      true, // 随机数
		"random":    true, // 随机数
		"_random":   true, // 随机数
		"cb":        true, // 回调参数（通常是时间戳）
		"callback":  true, // 回调参数
	}
}

// getTimestampPatterns 获取时间戳模式列表
func (c *Collector) getTimestampPatterns() []string {
	return []string{
		"^\\d{10}$",   // 10位时间戳
		"^\\d{13}$",   // 13位时间戳（毫秒）
		"^\\d{16}$",   // 16位时间戳（微秒）
		"^[0-9]{8,}$", // 8位以上数字
	}
}

// getAuthParams 获取认证相关参数列表
func (c *Collector) getAuthParams() map[string]bool {
	return map[string]bool{
		// 认证令牌相关
		"token":         true, // 认证令牌
		"auth":          true, // 认证参数
		"authorization": true, // 授权参数
		"bearer":        true, // Bearer令牌
		"jwt":           true, // JWT令牌
		"access_token":  true, // 访问令牌
		"refresh_token": true, // 刷新令牌
		"api_key":       true, // API密钥
		"apikey":        true, // API密钥
		"secret":        true, // 密钥
		"session":       true, // 会话ID
		"sessionid":     true, // 会话ID
		"sid":           true, // 会话ID简写
		"jsessionid":    true, // Java会话ID
		"phpsessid":     true, // PHP会话ID

		// 用户身份相关
		"userid":    true, // 用户ID
		"user_id":   true, // 用户ID
		"uid":       true, // 用户ID简写
		"username":  true, // 用户名
		"account":   true, // 账户
		"email":     true, // 邮箱
		"role":      true, // 角色
		"group":     true, // 用户组
		"tenant":    true, // 租户
		"tenant_id": true, // 租户ID

		// 权限相关
		"permission": true, // 权限
		"scope":      true, // 权限范围
		"access":     true, // 访问权限
		"privilege":  true, // 特权

	}
}

// SetIncludeStatusCodes 设置需要采集的状态码白名单
func (c *Collector) SetIncludeStatusCodes(codes []int) {
	c.includeStatusCodes = codes
}

// SetStaticExtensions 设置静态文件扩展名列表
func (c *Collector) SetStaticExtensions(exts []string) {
	c.staticExtensions = exts
}

// SetStaticPaths 设置静态路径列表
func (c *Collector) SetStaticPaths(paths []string) {
	c.staticPaths = paths
}

// SetAllowedHosts 设置允许的主机列表
func (c *Collector) SetAllowedHosts(hosts []string) {
	c.allowedHosts = hosts
}

// 私有辅助方法 - 状态码处理

// isValidStatusCode 检查状态码是否有效
func (c *Collector) isValidStatusCode(code int) bool {
	for _, includeCode := range c.includeStatusCodes {
		if includeCode == code {
			return true
		}
	}
	return false
}

// 私有辅助方法 - URL收集管理

// addToPendingList 添加到待处理列表
func (c *Collector) addToPendingList(cleanedURL, originalURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.pendingURLs == nil {
		c.pendingURLs = make(map[string]bool)
	}

	// 添加到待处理列表（不重复添加）
	if !c.pendingURLs[cleanedURL] {
		c.pendingURLs[cleanedURL] = true
		if cleanedURL != originalURL {
			logger.Debugf("清理并暂存: %s -> %s", originalURL, cleanedURL)
		} else {
			logger.Debugf("暂存URL: %s", cleanedURL)
		}
	}
}

// addToFinalCollection 添加到最终收集列表
func (c *Collector) addToFinalCollection(url string, statusCode int) {
	if c.urlMap == nil {
		c.urlMap = make(map[string]int)
	}

	// 确保存储的是修复后的完整URL，而不是协议相对URL
	finalURL := url
	if strings.HasPrefix(url, "//") {
		fixedURL := c.fixProtocolRelativeURL(url)
		if fixedURL != "" {
			finalURL = fixedURL
			logger.Debugf("最终采集URL修复: %s -> %s", url, finalURL)
		}
	}

	if _, exists := c.urlMap[finalURL]; !exists {
		c.urlMap[finalURL] = 1
		logger.Debugf("状态码%d符合条件，最终采集: %s", statusCode, finalURL)

		// 用户关心的核心信息：采集到的URL
		logger.Infof("Record URL: [ %s ]", finalURL)

		// 立即生成并显示扫描URL预览
	} else {
		logger.Debugf("URL已存在，跳过重复: %s", finalURL)
	}
}

// 收集控制方法

// EnableCollection 启用URL收集功能
func (c *Collector) EnableCollection() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.collectionEnabled = true
	logger.Debug("URL收集功能已启用")
}

// DisableCollection 禁用URL收集功能
func (c *Collector) DisableCollection() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.collectionEnabled = false
	logger.Debug("URL收集功能已禁用")
}

// IsCollectionEnabled 检查收集功能是否启用
func (c *Collector) IsCollectionEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.collectionEnabled
}

// 收集状态控制方法

// PauseCollection 暂停URL收集
// 在扫描完成后调用，等待用户手动触发下一轮采集
func (c *Collector) PauseCollection() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.collectionPaused = true
	logger.Info("URL Collector Stopped")
}

// ResumeCollection 恢复URL收集
// 在用户按回车键后调用，恢复正常的URL采集流程
func (c *Collector) ResumeCollection() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.collectionPaused = false
	logger.Info("URL Collector Resume")
}

// IsCollectionPaused 检查收集是否暂停
// 返回当前的暂停状态
func (c *Collector) IsCollectionPaused() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.collectionPaused
}
