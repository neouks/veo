package dirscan

import (
	"net/url"
	"sync"

	"veo/pkg/utils/logger"
	"veo/proxy"
)

// Collector URL采集器
type Collector struct {
	proxy.BaseAddon
	urlMap             map[string]int  // 最终采集的URL访问计数映射
	pendingURLs        map[string]bool // 待处理的URL（已过滤静态资源）
	includeStatusCodes []int           // 需要采集的状态码白名单
	allowedHosts       []string        // 允许的主机列表
	mu                 sync.RWMutex    // 读写锁
	collectionEnabled  bool            // 收集功能是否启用
	collectionPaused   bool            // 收集是否暂停
	
	cleaner            *URLCleaner     // URL清理器
}

// NewCollector 创建新的Collector实例
func NewCollector() *Collector {
	logger.Debugf("创建Collector实例")
	return &Collector{
		urlMap:             make(map[string]int),
		pendingURLs:        make(map[string]bool),
		includeStatusCodes: []int{200, 301, 302, 403, 404, 500},
		collectionEnabled:  true,
		cleaner:            NewURLCleaner(),
	}
}

// Requestheaders 处理请求头
func (c *Collector) Requestheaders(f *proxy.Flow) {
	if !c.IsCollectionEnabled() || c.IsCollectionPaused() {
		return
	}

	rawURL := f.Request.URL.String()
	if rawURL == "" {
		return
	}

	hostToCheck := c.getHostForCheck(rawURL, f.Request.URL.Host)
	if !c.isHostAllowed(hostToCheck) {
		return
	}

	// 静态资源过滤
	if c.cleaner.IsStaticResource(rawURL) {
		return
	}

	// URL清理
	cleanedURL := c.cleaner.CleanURLParams(rawURL)
	if cleanedURL == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pendingURLs[cleanedURL] {
		return
	}
	c.pendingURLs[cleanedURL] = true
	logger.Debugf("暂存URL: %s", cleanedURL)
}

// Responseheaders 处理响应头
func (c *Collector) Responseheaders(f *proxy.Flow) {
	if !c.IsCollectionEnabled() || c.IsCollectionPaused() {
		return
	}

	rawURL := f.Request.URL.String()
	statusCode := f.Response.StatusCode

	cleanedURL := c.cleaner.CleanURLParams(rawURL)
	if cleanedURL == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// 必须在Request中见过
	if !c.pendingURLs[cleanedURL] {
		return
	}

	delete(c.pendingURLs, cleanedURL)

	// 检查状态码
	isValidCode := false
	for _, code := range c.includeStatusCodes {
		if code == statusCode {
			isValidCode = true
			break
		}
	}
	if !isValidCode {
		return
	}

	c.urlMap[cleanedURL]++
	if c.urlMap[cleanedURL] == 1 {
		logger.Infof("Record URL: [ %s ]", cleanedURL)
	}
}

func (c *Collector) GetURLCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.urlMap)
}

func (c *Collector) GetURLMap() map[string]int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make(map[string]int, len(c.urlMap))
	for k, v := range c.urlMap { result[k] = v }
	return result
}

func (c *Collector) ClearURLMap() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.urlMap = make(map[string]int)
	c.pendingURLs = make(map[string]bool)
}

// 代理配置设置
func (c *Collector) SetIncludeStatusCodes(codes []int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.includeStatusCodes = codes
}

func (c *Collector) SetStaticExtensions(exts []string) { c.cleaner.SetStaticExtensions(exts) }
func (c *Collector) SetStaticPaths(paths []string) { c.cleaner.SetStaticPaths(paths) }

func (c *Collector) SetAllowedHosts(hosts []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.allowedHosts = hosts
}

func (c *Collector) EnableCollection() { 
	c.mu.Lock(); defer c.mu.Unlock(); c.collectionEnabled = true 
}
func (c *Collector) DisableCollection() { 
	c.mu.Lock(); defer c.mu.Unlock(); c.collectionEnabled = false 
}
func (c *Collector) IsCollectionEnabled() bool {
	c.mu.RLock(); defer c.mu.RUnlock(); return c.collectionEnabled
}
func (c *Collector) PauseCollection() { 
	c.mu.Lock(); defer c.mu.Unlock(); c.collectionPaused = true 
}
func (c *Collector) ResumeCollection() { 
	c.mu.Lock(); defer c.mu.Unlock(); c.collectionPaused = false 
}
func (c *Collector) IsCollectionPaused() bool {
	c.mu.RLock(); defer c.mu.RUnlock(); return c.collectionPaused
}

// isHostAllowed 简单主机检查
func (c *Collector) isHostAllowed(host string) bool {
	c.mu.RLock()
	hosts := c.allowedHosts
	c.mu.RUnlock()

	if len(hosts) == 0 {
		return true
	}
	// 这里为了KISS，只做简单匹配。如果需要通配符，应该在allowedHosts设置时就解析好正则
	for _, h := range hosts {
		if h == host {
			return true
		}
	}
	return false
}

func (c *Collector) getHostForCheck(rawURL, fallback string) string {
	if fallback != "" {
		return fallback
	}

	// 兜底：处理协议相对URL等情况
	if ok, fixed := c.cleaner.validateAndFixURL(rawURL); ok {
		if u, err := url.Parse(fixed); err == nil {
			return u.Host
		}
	}

	return ""
}

// 为了兼容测试
func (c *Collector) CleanURLParams(rawURL string) string {
	return c.cleaner.CleanURLParams(rawURL)
}

func (c *Collector) PrintCollectedURLs() {
	c.mu.RLock()
	defer c.mu.RUnlock()
	logger.Debugf("当前采集URL数量: %d", len(c.urlMap))
	for url, count := range c.urlMap {
		logger.Debugf(" %s (访问次数: %d)", url, count)
	}
}
