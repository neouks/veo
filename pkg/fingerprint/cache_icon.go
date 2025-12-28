package fingerprint

import (
	"crypto/md5"
	"fmt"
	"sync"

	"veo/pkg/utils/httpclient"
	"veo/pkg/utils/logger"
)

// IconCache 图标缓存管理组件
// 负责缓存图标哈希值和匹配结果，避免重复请求和计算
type IconCache struct {
	hashCache  map[string]string        // 图标URL -> MD5哈希值 (包括 "FAILED" 状态)
	matchCache map[string]bool          // 缓存键(URL+Hash) -> 匹配结果
	inflight   map[string]chan struct{} // 正在进行的请求: URL -> 完成通知通道
	mu         sync.RWMutex             // 读写锁
}

// NewIconCache 创建新的图标缓存实例
func NewIconCache() *IconCache {
	return &IconCache{
		hashCache:  make(map[string]string),
		matchCache: make(map[string]bool),
		inflight:   make(map[string]chan struct{}),
	}
}

// CheckMatch 检查图标哈希是否匹配（包含获取、计算、缓存全流程）
// 这是对外提供的统一入口，封装了去重和缓存逻辑
func (c *IconCache) CheckMatch(iconURL string, expectedHash string, client httpclient.HTTPClientInterface) (bool, bool) {
	// 1. 检查匹配结果缓存（最快路径）
	matchKey := c.buildMatchCacheKey(iconURL, expectedHash)
	c.mu.RLock()
	if match, exists := c.matchCache[matchKey]; exists {
		c.mu.RUnlock()
		return match, true
	}
	c.mu.RUnlock()

	// 2. 获取图标哈希（内部处理去重和请求）
	actualHash, err := c.GetHash(iconURL, client)
	if err != nil {
		return false, false
	}

	// 3. 比较并缓存结果
	match := actualHash == expectedHash

	c.mu.Lock()
	c.matchCache[matchKey] = match
	c.mu.Unlock()

	return match, true
}

// GetHash 获取图标哈希值（带缓存和请求合并）
// 实现了 Singleflight 模式，确保同一个URL在同一时间只发起一个请求
func (c *IconCache) GetHash(iconURL string, client httpclient.HTTPClientInterface) (string, error) {
	// 1. 快速路径：检查缓存
	c.mu.RLock()
	val, ok := c.hashCache[iconURL]
	c.mu.RUnlock()
	if ok {
		return c.handleCachedHash(iconURL, val)
	}

	// 2. 慢速路径：加锁检查是否正在请求
	c.mu.Lock()
	// 双重检查缓存（防止在获取锁期间已有请求完成）
	if val, ok := c.hashCache[iconURL]; ok {
		c.mu.Unlock()
		return c.handleCachedHash(iconURL, val)
	}

	// 检查是否有正在进行的请求
	if ch, ok := c.inflight[iconURL]; ok {
		// 有其他协程正在请求，释放锁并等待
		c.mu.Unlock()
		<-ch // 等待请求完成通道关闭
		// 递归调用自身再次获取（此时应该命中缓存）
		return c.GetHash(iconURL, client)
	}

	// 标记当前URL正在请求
	ch := make(chan struct{})
	c.inflight[iconURL] = ch
	c.mu.Unlock()

	// 3. 执行网络请求（无锁状态）
	hash, err := c.performRequest(iconURL, client)

	// 4. 保存结果并通知等待者
	c.mu.Lock()
	if err != nil {
		c.hashCache[iconURL] = "FAILED"
	} else {
		c.hashCache[iconURL] = hash
	}
	// 移除inflight标记并关闭通道广播
	delete(c.inflight, iconURL)
	close(ch)
	c.mu.Unlock()

	if err != nil {
		return "", err
	}
	return hash, nil
}

// handleCachedHash 处理缓存命中的返回值
func (c *IconCache) handleCachedHash(iconURL, val string) (string, error) {
	if val == "FAILED" {
		return "", fmt.Errorf("图标请求失败（缓存结果）")
	}
	return val, nil
}

// performRequest 执行实际的网络请求和哈希计算
func (c *IconCache) performRequest(iconURL string, client httpclient.HTTPClientInterface) (string, error) {
	if client == nil {
		return "", fmt.Errorf("HTTP客户端为空")
	}

	logger.Debugf("发起图标请求: %s", iconURL)
	body, statusCode, err := client.MakeRequest(iconURL)

	if err != nil {
		logger.Debugf("图标网络请求失败: %s, %v", iconURL, err)
		return "", err
	}

	if statusCode != 200 {
		logger.Debugf("图标请求非200状态: %s, code=%d", iconURL, statusCode)
		return "", fmt.Errorf("状态码 %d", statusCode)
	}

	hash := fmt.Sprintf("%x", md5.Sum([]byte(body)))
	logger.Debugf("图标哈希计算完成: %s -> %s", iconURL, hash)
	return hash, nil
}

// Clear 清空缓存
func (c *IconCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hashCache = make(map[string]string)
	c.matchCache = make(map[string]bool)
	// 注意：不清理 inflight，避免正在运行的请求panic
}

// GetMatchResult 获取匹配结果缓存 (For tests and internal use)
func (c *IconCache) GetMatchResult(iconURL, expectedHash string) (bool, bool) {
	key := c.buildMatchCacheKey(iconURL, expectedHash)
	c.mu.RLock()
	defer c.mu.RUnlock()
	result, exists := c.matchCache[key]
	return result, exists
}

// SetMatchResult 设置匹配结果缓存 (For tests and internal use)
func (c *IconCache) SetMatchResult(iconURL, expectedHash string, match bool) {
	key := c.buildMatchCacheKey(iconURL, expectedHash)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.matchCache[key] = match
}

// buildMatchCacheKey 构建匹配缓存键
func (c *IconCache) buildMatchCacheKey(iconURL, expectedHash string) string {
	return iconURL + "||" + expectedHash
}
