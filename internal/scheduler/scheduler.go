package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"
	"veo/internal/core/config"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
	"veo/pkg/dirscan"
	processor "veo/pkg/utils/processor"
)

// TargetScheduler 目标调度器（多目标并发优化）
type TargetScheduler struct {
	targets                []string
	maxTargetWorkers       int
	urlConcurrentPerTarget int
	config                 *config.Config
	results                map[string][]*interfaces.HTTPResponse
	resultsMu              sync.RWMutex
	ctx                    context.Context
	cancel                 context.CancelFunc
	baseRequestProcessor   *processor.RequestProcessor // 基础请求处理器（支持统计更新）
	recursive              bool                        // 是否递归模式
}

// TargetWorker 目标工作器
type TargetWorker struct {
	id               int
	target           string
	urlGenerator     *dirscan.URLGenerator
	requestProcessor *processor.RequestProcessor
	ctx              context.Context
	recursive        bool
}

// TargetResult 目标扫描结果
type TargetResult struct {
	Target    string
	Responses []*interfaces.HTTPResponse
	Error     error
	Duration  time.Duration
}

// NewTargetScheduler 创建目标调度器
func NewTargetScheduler(targets []string, cfg *config.Config) *TargetScheduler {
	ctx, cancel := context.WithCancel(context.Background())

	// 计算资源分配
	maxTargetWorkers, urlConcurrentPerTarget := calculateResourceAllocation(targets, cfg)

	return &TargetScheduler{
		targets:                targets,
		maxTargetWorkers:       maxTargetWorkers,
		urlConcurrentPerTarget: urlConcurrentPerTarget,
		config:                 cfg,
		results:                make(map[string][]*interfaces.HTTPResponse),
		ctx:                    ctx,
		cancel:                 cancel,
		baseRequestProcessor:   nil, // 初始化为nil，需要外部设置
	}
}

// SetRecursive 设置是否递归模式
func (ts *TargetScheduler) SetRecursive(recursive bool) {
	ts.recursive = recursive
}

// SetBaseRequestProcessor 设置基础请求处理器（支持统计更新）
func (ts *TargetScheduler) SetBaseRequestProcessor(processor *processor.RequestProcessor) {
	ts.baseRequestProcessor = processor
	logger.Debug("设置基础请求处理器，支持统计更新")
}

// ExecuteConcurrentScan 执行并发扫描（修复：添加超时和取消机制）
func (ts *TargetScheduler) ExecuteConcurrentScan() (map[string][]*interfaces.HTTPResponse, error) {
	// 创建带超时的context
	scanCtx, scanCancel := context.WithTimeout(ts.ctx, 10*time.Minute)
	defer scanCancel()

	var wg sync.WaitGroup
	resultChan := make(chan TargetResult, len(ts.targets))

	// 创建目标工作器信号量
	targetSem := make(chan struct{}, ts.maxTargetWorkers)

	// 启动目标工作器
	for i, target := range ts.targets {
		wg.Add(1)
		go func(index int, targetURL string) {
			defer func() {
				if r := recover(); r != nil {
					logger.Errorf("目标处理panic恢复: %v, 目标: %s", r, targetURL)
				}
				wg.Done()
			}()

			// 阻塞等待信号量，除非扫描上下文被取消
			select {
			case targetSem <- struct{}{}:
				defer func() {
					<-targetSem
				}()
			case <-scanCtx.Done():
				logger.Debugf("目标 %s: 扫描被取消", targetURL)
				return
			}

			ts.processTargetWithTimeout(scanCtx, index, targetURL, resultChan)
		}(i, target)
	}

	// 等待所有目标完成（修复：添加超时保护）
	done := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Errorf("等待目标完成时panic: %v", r)
			}
			close(done)
		}()
		wg.Wait()
		close(resultChan)
	}()

	// 收集结果（修复：添加超时和取消支持）
	return ts.collectResultsWithTimeout(scanCtx, resultChan, done)
}

// processTarget 处理单个目标
func (ts *TargetScheduler) processTarget(index int, target string, resultChan chan<- TargetResult) {
	ts.processTargetWithTimeout(ts.ctx, index, target, resultChan)
}

// processTargetWithTimeout 处理单个目标（新增：支持超时和取消）
func (ts *TargetScheduler) processTargetWithTimeout(ctx context.Context, index int, target string, resultChan chan<- TargetResult) {
	startTime := time.Now()

	logger.Debugf("开始处理目标 [%d/%d]: %s", index+1, len(ts.targets), target)

	// 创建目标工作器
	worker := ts.createTargetWorker(index, target)

	// 生成扫描URL（添加超时检查）
	select {
	case <-ctx.Done():
		logger.Debugf("目标 %s: 生成URL时被取消", target)
		return
	default:
	}

	scanURLs := worker.generateScanURLs()
	if len(scanURLs) == 0 {
		select {
		case resultChan <- TargetResult{
			Target: target,
			Error:  fmt.Errorf("未生成扫描URL"),
		}:
		case <-ctx.Done():
			logger.Debugf("目标 %s: 发送错误结果时被取消", target)
		case <-time.After(5 * time.Second):
			logger.Warnf("目标 %s: 发送错误结果超时", target)
		}
		return
	}

	logger.Debugf("%s 生成了 %d 个扫描URL", target, len(scanURLs))

	// 执行HTTP请求（添加超时检查）
	select {
	case <-ctx.Done():
		logger.Debugf("目标 %s: 执行请求时被取消", target)
		return
	default:
	}

	responses := worker.executeRequestsWithTimeout(ctx, scanURLs)

	// 更新已完成主机数统计（每个目标完成时调用一次）
	if ts.baseRequestProcessor != nil {
		statsUpdater := ts.baseRequestProcessor.GetStatsUpdater()
		if statsUpdater != nil {
			statsUpdater.IncrementCompletedHosts()
			logger.Debugf("目标 %s 完成，更新已完成主机数", target)
		}
	}

	duration := time.Since(startTime)
	result := TargetResult{
		Target:    target,
		Responses: responses,
		Duration:  duration,
	}

	// 发送结果（修复：添加超时避免永久阻塞）
	select {
	case resultChan <- result:
		logger.Debugf("目标 %s 处理完成，耗时: %v", target, duration)
	case <-ctx.Done():
		logger.Debugf("目标 %s: 发送结果时被取消", target)
	case <-time.After(10 * time.Second):
		logger.Warnf("目标 %s: 发送结果超时", target)
	}
}

// collectResultsWithTimeout 收集结果（新增：支持超时和取消）
func (ts *TargetScheduler) collectResultsWithTimeout(ctx context.Context, resultChan <-chan TargetResult, done <-chan struct{}) (map[string][]*interfaces.HTTPResponse, error) {
	timeout := 15 * time.Minute // 总体超时时间

	for {
		select {
		case result, ok := <-resultChan:
			if !ok {
				// 结果通道已关闭，所有目标处理完成
				logger.Debugf("所有目标处理完成，共收集 %d 个结果", len(ts.results))
				return ts.results, nil
			}

			if result.Error != nil {
				logger.Errorf("%s 扫描失败: %v", result.Target, result.Error)
				continue
			}

			ts.resultsMu.Lock()
			ts.results[result.Target] = result.Responses
			ts.resultsMu.Unlock()

			logger.Debugf("收集到目标 %s 的结果，响应数: %d", result.Target, len(result.Responses))

		case <-done:
			// 等待goroutine完成
			logger.Debugf("等待目标处理完成")

		case <-ctx.Done():
			logger.Warnf("目标调度被取消，已收集 %d 个结果", len(ts.results))
			return ts.results, ctx.Err()

		case <-time.After(timeout):
			logger.Warnf("目标调度超时，已收集 %d 个结果", len(ts.results))
			return ts.results, fmt.Errorf("目标调度超时")
		}
	}
}

// createTargetWorker 创建目标工作器
func (ts *TargetScheduler) createTargetWorker(id int, target string) *TargetWorker {
	// 创建请求处理器配置
	requestConfig := &processor.RequestConfig{
		Timeout:        time.Duration(ts.config.Addon.Request.Timeout) * time.Second,
		MaxRetries:     3,
		MaxConcurrent:  ts.urlConcurrentPerTarget,
		FollowRedirect: true,
		MaxBodySize:    ts.config.Addon.Request.MaxResponseBodySize,
	}

	// 创建新的请求处理器
	requestProcessor := processor.NewRequestProcessor(requestConfig)

	// 如果有基础请求处理器，复制其统计更新器
	if ts.baseRequestProcessor != nil {
		// 获取基础请求处理器的统计更新器并设置到新处理器
		// 注意：这里需要添加一个方法来获取统计更新器
		ts.copyStatsUpdater(ts.baseRequestProcessor, requestProcessor)
		logger.Debugf("创建请求处理器并复制统计更新器: target-%s", extractDomainFromURL(target))
	} else {
		logger.Debugf("创建新的请求处理器（不支持统计更新）: target-%s", extractDomainFromURL(target))
	}

	// 设置目标上下文
	requestProcessor.SetModuleContext(fmt.Sprintf("target-%s", extractDomainFromURL(target)))

	return &TargetWorker{
		id:               id,
		target:           target,
		urlGenerator:     dirscan.NewURLGenerator(),
		requestProcessor: requestProcessor,
		ctx:              ts.ctx,
		recursive:        ts.recursive,
	}
}

// copyStatsUpdater 复制统计更新器
func (ts *TargetScheduler) copyStatsUpdater(source, target *processor.RequestProcessor) {
	// 获取源处理器的统计更新器
	statsUpdater := source.GetStatsUpdater()
	if statsUpdater != nil {
		// 设置到目标处理器
		target.SetStatsUpdater(statsUpdater)
		// 设置批量扫描模式
		target.SetBatchMode(true)
		logger.Debug("成功复制统计更新器并设置批量模式")
	} else {
		logger.Debug("源处理器没有统计更新器")
	}
}

// generateScanURLs 生成扫描URL
func (tw *TargetWorker) generateScanURLs() []string {
	if tw.recursive {
		// 递归模式：只扫描当前目录层级，不回溯父目录
		return tw.urlGenerator.GenerateRecursiveURLs([]string{tw.target})
	}
	// 默认模式：扫描所有层级
	return tw.urlGenerator.GenerateURLs([]string{tw.target})
}

// executeRequests 执行HTTP请求
func (tw *TargetWorker) executeRequests(urls []string) []*interfaces.HTTPResponse {
	return tw.requestProcessor.ProcessURLs(urls)
}

// executeRequestsWithTimeout 执行HTTP请求（新增：支持超时和取消）
func (tw *TargetWorker) executeRequestsWithTimeout(ctx context.Context, urls []string) []*interfaces.HTTPResponse {
	// 创建带超时的context
	requestCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	// 使用channel接收结果，支持超时
	resultChan := make(chan []*interfaces.HTTPResponse, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Errorf("目标Worker %d 执行请求panic: %v", tw.id, r)
				resultChan <- nil
			}
		}()

		responses := tw.requestProcessor.ProcessURLs(urls)
		resultChan <- responses
	}()

	select {
	case responses := <-resultChan:
		return responses
	case <-requestCtx.Done():
		logger.Warnf("目标Worker %d 执行请求超时或被取消", tw.id)
		return []*interfaces.HTTPResponse{}
	}
}

// calculateResourceAllocation 计算资源分配（重构：统一并发控制）
func calculateResourceAllocation(targets []string, cfg *config.Config) (int, int) {
	targetCount := len(targets)
	totalConcurrent := cfg.Addon.Request.Threads

	// 统一并发控制：使用简化的资源分配策略
	// 使用配置中的总并发数作为最大目标并发数的基础
	maxTargetConcurrent := totalConcurrent / 10 // 目标并发数为总并发数的1/10
	if maxTargetConcurrent < 5 {
		maxTargetConcurrent = 5 // 最小目标并发数
	}
	if maxTargetConcurrent > 50 {
		maxTargetConcurrent = 50 // 最大目标并发数限制
	}
	minURLConcurrentPerTarget := 5 // 默认每目标最小URL并发数

	// 场景1：单目标 - 全部资源分配给该目标
	if targetCount == 1 {
		return 1, totalConcurrent
	}

	// 场景2：少量目标 - 平均分配资源
	if targetCount <= maxTargetConcurrent {
		urlConcurrentPerTarget := totalConcurrent / targetCount
		if urlConcurrentPerTarget < minURLConcurrentPerTarget {
			urlConcurrentPerTarget = minURLConcurrentPerTarget
		}
		return targetCount, urlConcurrentPerTarget
	}

	// 场景3：大量目标 - 限制目标并发数
	urlConcurrentPerTarget := totalConcurrent / maxTargetConcurrent
	if urlConcurrentPerTarget < minURLConcurrentPerTarget {
		urlConcurrentPerTarget = minURLConcurrentPerTarget
	}

	return maxTargetConcurrent, urlConcurrentPerTarget
}

// extractDomainFromURL 从URL中提取域名
func extractDomainFromURL(rawURL string) string {
	// 简单的域名提取，用于日志标识
	if len(rawURL) > 50 {
		return rawURL[:47] + "..."
	}
	return rawURL
}

// Stop 停止调度器
func (ts *TargetScheduler) Stop() {
	if ts.cancel != nil {
		ts.cancel()
	}
}
