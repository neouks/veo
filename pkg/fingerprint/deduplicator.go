package fingerprint

import (
	"net/url"
	"sort"
	"strings"
	"sync"
)

// Deduplicator 基于内存的指纹结果去重器
// 用于防止重复输出相同的指纹识别结果
// 线程安全
type Deduplicator struct {
	cache map[string]bool
	mu    sync.RWMutex
}

// NewDeduplicator 创建新的内存去重器
func NewDeduplicator() *Deduplicator {
	return &Deduplicator{
		cache: make(map[string]bool),
	}
}

// ShouldOutput 检查是否应该输出（去重）
// 返回 true 表示应该输出（首次出现），false 表示已重复
func (d *Deduplicator) ShouldOutput(urlStr string, fingerprintNames []string) bool {
	cacheKey := d.generateCacheKey(urlStr, fingerprintNames)

	d.mu.Lock()
	defer d.mu.Unlock()

	// 检查是否已输出
	if d.cache[cacheKey] {
		return false // 已重复,不应输出
	}

	// 标记为已输出
	d.cache[cacheKey] = true
	return true // 应该输出
}

// Clear 清空去重缓存
func (d *Deduplicator) Clear() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cache = make(map[string]bool)
}

// Count 获取已缓存的项目数量
func (d *Deduplicator) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.cache)
}

// generateCacheKey 生成去重缓存键
// 结合URL和指纹名称生成细粒度的缓存键
func (d *Deduplicator) generateCacheKey(rawURL string, fingerprintNames []string) string {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	var builder strings.Builder
	builder.Grow(len(parsedURL.Host) + len(parsedURL.Path) + 50)

	// 添加主机和路径信息
	builder.WriteString(parsedURL.Host)
	builder.WriteByte('|')
	builder.WriteString(parsedURL.Path)
	builder.WriteByte('|')

	// 对指纹名称排序以确保一致性（同时去重，避免输入中出现重复名称导致 key 不稳定）
	if len(fingerprintNames) == 0 {
		return builder.String()
	}

	if len(fingerprintNames) == 1 {
		name := strings.TrimSpace(fingerprintNames[0])
		builder.WriteString(name)
		return builder.String()
	}

	// 创建排序副本
	sortedNames := make([]string, 0, len(fingerprintNames))
	for _, name := range fingerprintNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		sortedNames = append(sortedNames, name)
	}
	if len(sortedNames) == 0 {
		return builder.String()
	}

	sort.Strings(sortedNames)
	unique := make([]string, 0, len(sortedNames))
	for _, name := range sortedNames {
		if len(unique) == 0 || unique[len(unique)-1] != name {
			unique = append(unique, name)
		}
	}

	builder.WriteString(strings.Join(unique, ","))
	return builder.String()
}
