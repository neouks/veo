package dirscan

import (
	"crypto/md5"
	"fmt"
	"strings"
	"sync"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
)

// ============================================================================
// 过滤策略接口定义 (原interfaces.go内容)
// ============================================================================

// FilterStrategy 过滤策略接口
type FilterStrategy interface {
	// Filter 执行过滤操作
	Filter(responses []interfaces.HTTPResponse) []interfaces.HTTPResponse

	// Reset 重置过滤器状态
	Reset()
}

// StatusCodeFilterStrategy 状态码过滤策略接口
type StatusCodeFilterStrategy interface {
	FilterStrategy

	// GetValidStatusCodes 获取有效状态码列表
	GetValidStatusCodes() []int

	// UpdateValidStatusCodes 更新有效状态码列表
	UpdateValidStatusCodes(codes []int)
}

// HashFilterStrategy 哈希过滤策略接口
type HashFilterStrategy interface {
	FilterStrategy

	// GetInvalidPageHashes 获取无效页面哈希统计
	GetInvalidPageHashes() []interfaces.PageHash

	// GetThreshold 获取过滤阈值
	GetThreshold() int

	// UpdateThreshold 更新过滤阈值
	UpdateThreshold(threshold int)

	// GetPageHashCount 获取页面哈希统计数量
	GetPageHashCount() int
}

// SecondaryFilterStrategy 二次筛选策略接口
type SecondaryFilterStrategy interface {
	FilterStrategy

	// GetSecondaryHashResults 获取二次筛选哈希统计
	GetSecondaryHashResults() []interfaces.PageHash

	// GetThreshold 获取二次筛选阈值
	GetThreshold() int

	// UpdateThreshold 更新二次筛选阈值
	UpdateThreshold(threshold int)

	// GetSecondaryHashCount 获取二次筛选哈希统计数量
	GetSecondaryHashCount() int
}

// ContentTypeFilterStrategy Content-Type过滤策略接口
type ContentTypeFilterStrategy interface {
	FilterStrategy

	// GetFilteredContentTypes 获取需要过滤的Content-Type列表
	GetFilteredContentTypes() []string

	// UpdateFilteredContentTypes 更新需要过滤的Content-Type列表
	UpdateFilteredContentTypes(contentTypes []string)

	// IsContentTypeFiltered 检查指定Content-Type是否应该被过滤
	IsContentTypeFiltered(contentType string) bool
}

// ============================================================================
// 状态码过滤器 (原status_go内容)
// ============================================================================

// StatusCodeFilter 状态码过滤器策略
type StatusCodeFilter struct {
	validStatusCodes []int
}

// NewStatusCodeFilter 创建状态码过滤器
func NewStatusCodeFilter(validStatusCodes []int) *StatusCodeFilter {
	if len(validStatusCodes) == 0 {
		validStatusCodes = []int{200, 403, 500, 302, 301, 405} // 默认状态码
	}

	return &StatusCodeFilter{
		validStatusCodes: validStatusCodes,
	}
}

// Filter 执行状态码过滤
func (sf *StatusCodeFilter) Filter(responses []interfaces.HTTPResponse) []interfaces.HTTPResponse {
	validResponses := make([]interfaces.HTTPResponse, 0)

	for _, response := range responses {
		if sf.isValidStatusCode(response.StatusCode) {
			validResponses = append(validResponses, response)
		}
	}

	return validResponses
}

// isValidStatusCode 检查状态码是否有效
func (sf *StatusCodeFilter) isValidStatusCode(statusCode int) bool {
	for _, validCode := range sf.validStatusCodes {
		if statusCode == validCode {
			return true
		}
	}
	return false
}

// GetValidStatusCodes 获取有效状态码列表
func (sf *StatusCodeFilter) GetValidStatusCodes() []int {
	result := make([]int, len(sf.validStatusCodes))
	copy(result, sf.validStatusCodes)
	return result
}

// UpdateValidStatusCodes 更新有效状态码列表
func (sf *StatusCodeFilter) UpdateValidStatusCodes(codes []int) {
	sf.validStatusCodes = make([]int, len(codes))
	copy(sf.validStatusCodes, codes)
}

// Reset 重置过滤器状态（StatusCodeFilter无状态，所以空实现）
func (sf *StatusCodeFilter) Reset() {
	// StatusCodeFilter是无状态的，不需要重置
}

// ============================================================================
// 基础哈希过滤器 (合并hash_go和secondary_go的公共部分)
// ============================================================================

// BaseHashFilter 基础哈希过滤器，提供公共功能
type BaseHashFilter struct {
	pageHashMap map[string]*interfaces.PageHash // 页面哈希映射
	threshold   int                             // 过滤阈值
	tolerance   int64                           // 容错阈值
	mu          sync.RWMutex                    // 读写锁
}

// newBaseHashFilter 创建基础哈希过滤器
func newBaseHashFilter(threshold int, tolerance int64) *BaseHashFilter {
	if threshold <= 0 {
		threshold = 2 // 默认阈值
	}
	// 注意：tolerance=0 是有效值，表示禁用容错过滤
	// 只有tolerance<0时才使用默认值
	if tolerance < 0 {
		tolerance = 50 // 默认容错阈值
	}

	return &BaseHashFilter{
		pageHashMap: make(map[string]*interfaces.PageHash),
		threshold:   threshold,
		tolerance:   tolerance,
	}
}

// isInvalidPage 判断是否为无效页面（通用逻辑）
func (bf *BaseHashFilter) isInvalidPage(response interfaces.HTTPResponse, hashFunc func(interfaces.HTTPResponse) string) bool {
	// 生成页面哈希
	hash := hashFunc(response)

	bf.mu.Lock()
	defer bf.mu.Unlock()

	// 检查哈希是否已存在
	if pageHash, exists := bf.pageHashMap[hash]; exists {
		// 增加计数
		pageHash.Count++
		// 检查是否超过阈值
		return pageHash.Count > bf.threshold
	} else {
		// 首次出现，记录哈希信息
		bf.pageHashMap[hash] = &interfaces.PageHash{
			Hash:          hash,
			Count:         1,
			StatusCode:    response.StatusCode,
			Title:         response.Title,
			ContentLength: response.ContentLength,
			ContentType:   response.ContentType,
		}
		return false
	}
}

// calculateTolerantContentLength 计算容错的ContentLength（统一实现）
func (bf *BaseHashFilter) calculateTolerantContentLength(originalLength int64) int64 {
	// 当tolerance为0时，直接返回原始长度（禁用容错过滤）
	if bf.tolerance == 0 {
		return originalLength
	}

	// [优化] 基于量级的动态容错机制
	// 解决Soft 404页面因反射参数（如URL）导致长度差异较大，无法归入同一桶的问题
	// 采用分级固定步长策略，避免因Length本身作为基数计算Tolerance导致的桶错位问题

	var step int64
	if originalLength < 1000 {
		// 小文件：使用配置的tolerance（默认50）
		// [优化] 移除对tolerance的强制限制，允许用户配置更大的容错值
		// 对于WAF页面，通常包含时间戳或RequestID，差异可能在50-100字节之间
		step = bf.tolerance
		if step < 20 { // 最小步长限制，防止过小
			step = 20
		}
	} else if originalLength < 5000 {
		// 1k-5k：容错500（足以覆盖大部分URL反射差异）
		step = 500
	} else if originalLength < 10000 {
		// 5k-10k：容错1000
		step = 1000
	} else {
		// >10k：容错2000
		step = 2000
	}

	// 确保step不小于配置的基础tolerance（如果用户配置了很大的值）
	if step < bf.tolerance {
		step = bf.tolerance
	}

	// 使用四舍五入进行分桶
	tolerantLength := ((originalLength + step/2) / step) * step
	return tolerantLength
}

// getPageHashes 获取页面哈希统计（通用方法）
func (bf *BaseHashFilter) getPageHashes(filterFunc func(*interfaces.PageHash) bool) []interfaces.PageHash {
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	hashes := make([]interfaces.PageHash, 0)
	for _, pageHash := range bf.pageHashMap {
		if filterFunc == nil || filterFunc(pageHash) {
			hashes = append(hashes, *pageHash)
		}
	}

	return hashes
}

// GetThreshold 获取过滤阈值
func (bf *BaseHashFilter) GetThreshold() int {
	bf.mu.RLock()
	defer bf.mu.RUnlock()
	return bf.threshold
}

// UpdateThreshold 更新过滤阈值
func (bf *BaseHashFilter) UpdateThreshold(threshold int) {
	bf.mu.Lock()
	defer bf.mu.Unlock()
	bf.threshold = threshold
}

// Reset 重置过滤器状态
func (bf *BaseHashFilter) Reset() {
	bf.mu.Lock()
	defer bf.mu.Unlock()
	bf.pageHashMap = make(map[string]*interfaces.PageHash)
}

// GetPageHashCount 获取页面哈希统计数量
func (bf *BaseHashFilter) GetPageHashCount() int {
	bf.mu.RLock()
	defer bf.mu.RUnlock()
	return len(bf.pageHashMap)
}

// ============================================================================
// 主要哈希过滤器 (原hash_go内容，使用基类)
// ============================================================================

// HashFilter 哈希过滤器策略
type HashFilter struct {
	*BaseHashFilter
}

// NewHashFilter 创建哈希过滤器（支持自定义容错阈值）
func NewHashFilter(threshold int, tolerance int64) *HashFilter {
	// 注意：tolerance=0 表示禁用容错过滤（只有完全相同的页面才会被过滤）
	// tolerance<0 表示使用默认值
	if tolerance < 0 {
		tolerance = 50 // 默认50字节容错
	}

	if tolerance == 0 {
		logger.Debugf("创建主要过滤器 - 重复阈值: %d, 容错阈值: 0 字节 (禁用容错过滤)", threshold)
	} else {
		logger.Debugf("创建主要过滤器 - 重复阈值: %d, 容错阈值: %d 字节", threshold, tolerance)
	}

	return &HashFilter{
		BaseHashFilter: newBaseHashFilter(threshold, tolerance),
	}
}

// Filter 执行哈希过滤
func (hf *HashFilter) Filter(responses []interfaces.HTTPResponse) []interfaces.HTTPResponse {
	validPages := make([]interfaces.HTTPResponse, 0)

	for _, response := range responses {
		if !hf.isInvalidPage(response, hf.generatePageHash) {
			validPages = append(validPages, response)
		}
	}

	return validPages
}

// generatePageHash 生成页面哈希（状态码+标题+容错ContentLength）
func (hf *HashFilter) generatePageHash(response interfaces.HTTPResponse) string {
	// 计算容错的ContentLength范围
	tolerantLength := hf.calculateTolerantContentLength(response.ContentLength)

	// 组合状态码、标题和容错ContentLength生成哈希
	hashSource := fmt.Sprintf("%d|%s|%d",
		response.StatusCode,
		strings.TrimSpace(response.Title),
		tolerantLength)

	// 计算MD5哈希
	hash := fmt.Sprintf("%x", md5.Sum([]byte(hashSource)))

	return hash
}

// GetInvalidPageHashes 获取无效页面哈希统计
func (hf *HashFilter) GetInvalidPageHashes() []interfaces.PageHash {
	return hf.getPageHashes(func(pageHash *interfaces.PageHash) bool {
		return pageHash.Count > hf.threshold
	})
}

// ============================================================================
// 二次筛选过滤器 (原secondary_go内容，使用基类)
// ============================================================================

// SecondaryFilter 二次筛选过滤器策略
type SecondaryFilter struct {
	*BaseHashFilter
}

// NewSecondaryFilter 创建二次筛选过滤器（支持自定义容错阈值）
func NewSecondaryFilter(threshold int, tolerance int64) *SecondaryFilter {
	if threshold <= 0 {
		threshold = 1 // 二次筛选默认阈值
	}

	// 二次筛选使用更小的容错阈值
	if tolerance == 0 {
		// tolerance=0 表示禁用容错过滤
		logger.Debugf("创建二次过滤器 - 重复阈值: %d, 容错阈值: 0 字节 (禁用容错过滤)", threshold)
	} else if tolerance < 0 {
		// tolerance<0 表示使用默认值
		tolerance = 20 // 默认20字节容错
		logger.Debugf("创建二次过滤器 - 重复阈值: %d, 容错阈值: %d 字节", threshold, tolerance)
	} else {
		// 二次筛选的容错阈值为主要过滤器的40%
		tolerance = tolerance * 40 / 100
		if tolerance < 20 {
			tolerance = 20 // 最小20字节
		}
		logger.Debugf("创建二次过滤器 - 重复阈值: %d, 容错阈值: %d 字节", threshold, tolerance)
	}

	return &SecondaryFilter{
		BaseHashFilter: newBaseHashFilter(threshold, tolerance),
	}
}

// Filter 执行二次筛选过滤
func (sf *SecondaryFilter) Filter(responses []interfaces.HTTPResponse) []interfaces.HTTPResponse {
	validPages := make([]interfaces.HTTPResponse, 0)

	for _, response := range responses {
		if !sf.isInvalidPage(response, sf.generateSecondaryPageHash) {
			validPages = append(validPages, response)
		}
	}

	return validPages
}

// generateSecondaryPageHash 为二次筛选生成页面哈希（标题+容错内容长度+状态码）
func (sf *SecondaryFilter) generateSecondaryPageHash(response interfaces.HTTPResponse) string {
	// 计算容错的ContentLength范围
	tolerantLength := sf.calculateTolerantContentLength(response.ContentLength)

	// 组合标题、容错ContentLength和状态码生成哈希
	hashSource := fmt.Sprintf("%s|%d|%d",
		strings.TrimSpace(response.Title),
		tolerantLength,
		response.StatusCode)

	// 计算MD5哈希
	hash := fmt.Sprintf("%x", md5.Sum([]byte(hashSource)))

	return hash
}

// GetSecondaryHashResults 获取二次筛选哈希统计
func (sf *SecondaryFilter) GetSecondaryHashResults() []interfaces.PageHash {
	return sf.getPageHashes(func(pageHash *interfaces.PageHash) bool {
		return pageHash.Count > sf.threshold
	})
}

// GetSecondaryHashCount 获取二次筛选哈希统计数量
func (sf *SecondaryFilter) GetSecondaryHashCount() int {
	return sf.GetPageHashCount()
}

// ============================================================================
// Content-Type过滤器
// ============================================================================

// ContentTypeFilter Content-Type过滤器策略
type ContentTypeFilter struct {
	filteredContentTypes []string // 需要过滤的Content-Type列表
	mu                   sync.RWMutex
}

// NewContentTypeFilter 创建Content-Type过滤器
func NewContentTypeFilter(filteredContentTypes []string) *ContentTypeFilter {
	if filteredContentTypes == nil {
		// 默认过滤图片类型
		filteredContentTypes = []string{
			"image/png",
			"image/jpeg",
			"image/jpg",
			"image/gif",
			"image/webp",
			"image/svg+xml",
			"image/bmp",
			"image/ico",
			"image/tiff",
		}
	}

	return &ContentTypeFilter{
		filteredContentTypes: filteredContentTypes,
	}
}

// Filter 执行Content-Type过滤
func (ctf *ContentTypeFilter) Filter(responses []interfaces.HTTPResponse) []interfaces.HTTPResponse {
	ctf.mu.RLock()
	defer ctf.mu.RUnlock()

	validResponses := make([]interfaces.HTTPResponse, 0)

	for _, response := range responses {
		if !ctf.IsContentTypeFiltered(response.ContentType) {
			validResponses = append(validResponses, response)
		}
	}

	return validResponses
}

// Reset 重置过滤器状态
func (ctf *ContentTypeFilter) Reset() {
	// Content-Type过滤器无状态，无需重置
}

// GetFilteredContentTypes 获取需要过滤的Content-Type列表
func (ctf *ContentTypeFilter) GetFilteredContentTypes() []string {
	ctf.mu.RLock()
	defer ctf.mu.RUnlock()

	result := make([]string, len(ctf.filteredContentTypes))
	copy(result, ctf.filteredContentTypes)
	return result
}

// UpdateFilteredContentTypes 更新需要过滤的Content-Type列表
func (ctf *ContentTypeFilter) UpdateFilteredContentTypes(contentTypes []string) {
	ctf.mu.Lock()
	defer ctf.mu.Unlock()

	ctf.filteredContentTypes = make([]string, len(contentTypes))
	copy(ctf.filteredContentTypes, contentTypes)
}

// IsContentTypeFiltered 检查指定Content-Type是否应该被过滤
func (ctf *ContentTypeFilter) IsContentTypeFiltered(contentType string) bool {
	ctf.mu.RLock()
	defer ctf.mu.RUnlock()

	return checkContentTypeAgainstRules(contentType, ctf.filteredContentTypes)
}
