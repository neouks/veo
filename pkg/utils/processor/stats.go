package processor

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
)

// ProcessingStats 处理统计信息 (原progress.go内容)
type ProcessingStats struct {
	TotalCount     int64
	SuccessCount   int64
	FailureCount   int64
	SkippedCount   int64
	ProcessedCount int64
	StartTime      time.Time
	TimeoutCount   int64 // 超时次数
}

// StatsUpdater 统计更新器接口
type StatsUpdater interface {
	IncrementCompletedRequests()
	IncrementTimeouts()
	SetTotalRequests(count int64)
	AddTotalRequests(count int64) // 累加总请求数（用于批量扫描）
	IncrementCompletedHosts()     // 增加已完成主机数
}

// ============================================================================
// 进度统计相关方法 (原progress.go内容)
// ============================================================================

// initializeProcessingStats 初始化处理统计
func (rp *RequestProcessor) initializeProcessingStats(totalURLs int, maxConcurrent int, randomUA bool) *ProcessingStats {
	stats := &ProcessingStats{
		TotalCount: int64(totalURLs),
		StartTime:  time.Now(),
	}

	// 根据模块上下文调整日志级别
	if rp.GetModuleContext() == "fingerprint" {
		// 指纹识别模式：使用DEBUG级别，避免日志冗余
		logger.Debug(fmt.Sprintf("开始处理 %d 个URL，并发数: %d，随机UA: %v",
			stats.TotalCount, maxConcurrent, randomUA))
	} else {
		// 目录扫描模式：使用DEBUG级别，因为在engine中已经显示了
		logger.Debug(fmt.Sprintf("开始处理 %d 个URL，并发数: %d，随机UA: %v",
			stats.TotalCount, maxConcurrent, randomUA))
	}

	return stats
}

// updateProcessingStats 更新处理统计
func (rp *RequestProcessor) updateProcessingStats(response *interfaces.HTTPResponse, targetURL string,
	responses *[]*interfaces.HTTPResponse, responsesMu *sync.Mutex, stats *ProcessingStats) {

	atomic.AddInt64(&stats.ProcessedCount, 1)

	if response != nil {
		responsesMu.Lock()
		*responses = append(*responses, response)
		responsesMu.Unlock()

		atomic.AddInt64(&stats.SuccessCount, 1)

		// 更新统计显示器
		if rp.statsUpdater != nil {
			rp.statsUpdater.IncrementCompletedRequests()
		}
	} else {
		atomic.AddInt64(&stats.FailureCount, 1)

		// 检查是否是超时错误（通过检查错误信息而不是URL）
		// 注意：这里需要传递错误信息，但当前架构中没有传递错误信息
		// 暂时使用简单的超时统计逻辑
		atomic.AddInt64(&stats.TimeoutCount, 1)
		
		// 修复：失败的请求也应该计入已完成请求数，因为它们已经结束了（无论是超时还是错误）
		// 否则会导致 Request 进度条永远达不到 100%
		if rp.statsUpdater != nil {
			rp.statsUpdater.IncrementCompletedRequests() // 修复点：失败请求也计入完成
			rp.statsUpdater.IncrementTimeouts()
		}
	}
}

// finalizeProcessing 完成处理
func (rp *RequestProcessor) finalizeProcessing(stats *ProcessingStats) {
	rp.logProcessingResults(stats)
}

// logProcessingResults 记录处理结果
func (rp *RequestProcessor) logProcessingResults(stats *ProcessingStats) {
	// 根据模块上下文调整日志级别
	if rp.GetModuleContext() == "fingerprint" {
		// 指纹识别模式：使用DEBUG级别，避免日志冗余
		logger.Debug(fmt.Sprintf("\r总计: %d, 成功: %d, 失败: %d, 跳过: %d",
			stats.TotalCount, stats.SuccessCount, stats.FailureCount, stats.SkippedCount))
	} else {
		// 其他模式（如目录扫描）：使用INFO级别
		logger.Debugf("\r总计: %d, 成功: %d, 失败: %d, 跳过: %d",
			stats.TotalCount, stats.SuccessCount, stats.FailureCount, stats.SkippedCount)
	}
}
