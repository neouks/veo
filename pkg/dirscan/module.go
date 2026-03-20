//go:build passive

package dirscan

import (
	"sync"

	"veo/pkg/logger"
	"veo/proxy"
)

type Collector struct {
	proxy.BaseAddon
	urlMap             map[string]int  // 最终采集的URL访问计数映射
	pendingURLs        map[string]bool // 待处理的URL（已过滤静态资源）
	includeStatusCodes []int           // 需要采集的状态码白名单
	mu                 sync.RWMutex    // 读写锁
	collectionEnabled  bool            // 收集功能是否启用

	cleaner *URLCleaner // URL清理器
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
	if !c.IsCollectionEnabled() {
		return
	}

	rawURL := f.Request.URL.String()
	if rawURL == "" {
		return
	}

	// 静态资源过滤
	if c.cleaner.IsStaticResource(rawURL) {
		return
	}

	// 目录级URL归一化
	cleanedURL := c.cleaner.NormalizeCollectedURL(rawURL)
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
	if !c.IsCollectionEnabled() {
		return
	}

	rawURL := f.Request.URL.String()
	statusCode := f.Response.StatusCode

	cleanedURL := c.cleaner.NormalizeCollectedURL(rawURL)
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
	for k, v := range c.urlMap {
		result[k] = v
	}
	return result
}

func (c *Collector) ClearURLMap() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.urlMap = make(map[string]int)
	c.pendingURLs = make(map[string]bool)
}

func (c *Collector) EnableCollection() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.collectionEnabled = true
}

func (c *Collector) DisableCollection() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.collectionEnabled = false
}

func (c *Collector) IsCollectionEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.collectionEnabled
}
