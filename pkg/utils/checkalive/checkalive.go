package checkalive

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"veo/internal/core/config"
	"veo/pkg/utils/logger"
	"veo/pkg/utils/useragent"
)

// ConnectivityChecker 连通性检测器
type ConnectivityChecker struct {
	config *config.Config
}

// NewConnectivityChecker 创建连通性检测器
func NewConnectivityChecker(cfg *config.Config) *ConnectivityChecker {
	return &ConnectivityChecker{
		config: cfg,
	}
}

// CheckTarget 检测目标连通性
// 返回第一个可连通的URL，如果都不可连通则返回空字符串
func (cc *ConnectivityChecker) CheckTarget(urls []string) string {
	logger.Debugf("开始检测目标连通性，候选URL: %v", urls)

	for i, targetURL := range urls {
		logger.Debugf("检测URL [%d/%d]: %s", i+1, len(urls), targetURL)
		if cc.isReachable(targetURL) {
			logger.Debugf("目标可连通: %s", targetURL)
			return targetURL
		}
		logger.Debugf("目标不可连通: %s", targetURL)
	}

	logger.Debugf("所有URL都不可连通: %v", urls)
	return ""
}

// isReachable 检测单个URL是否可连通（简化版：仅基于网络连接判断）
func (cc *ConnectivityChecker) isReachable(targetURL string) bool {
	logger.Debugf("开始HTTP连通性检测: %s", targetURL)

	// 简化版：仅基于网络连接判断，不考虑HTTP状态码
	return cc.isReachableWithRedirect(targetURL, 0) // 不再需要重定向参数，但保持接口兼容
}

// isReachableWithRedirect 检测URL连通性（简化版：仅基于网络连接判断）
func (cc *ConnectivityChecker) isReachableWithRedirect(targetURL string, maxRedirects int) bool {
	// 获取超时时间
	timeout := cc.getTimeout()
	startTime := time.Now()

	logger.Debugf("发送HTTP请求: %s (超时: %v)", targetURL, timeout)

	// 创建HTTP客户端
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // 跳过TLS验证，适用于安全扫描
			},
			ResponseHeaderTimeout: timeout,
		},
	}

	// 创建请求
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		logger.Debugf("创建请求失败: %s, 错误: %v", targetURL, err)
		return false
	}

	// 设置请求头
	ua := useragent.Pick()
	if ua == "" {
		ua = "veo-Connectivity/1.0"
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")

	// 发送请求
	resp, err := client.Do(req)
	elapsed := time.Since(startTime)

	if err != nil {
		logger.Debugf("HTTP请求失败: %s, 耗时: %v, 错误: %v", targetURL, elapsed, err)
		return false
	}
	defer resp.Body.Close()

	// 简化判断：只要能成功建立HTTP连接并收到响应，就认为目标存活
	logger.Debugf("目标可连通: %s [%d] 耗时: %v", targetURL, resp.StatusCode, elapsed)
	return true
}

// getTimeout 从配置中获取超时时间（连通性优化）
func (cc *ConnectivityChecker) getTimeout() time.Duration {
	// 从配置中读取超时时间
	if cc.config != nil && cc.config.Addon.Request.Timeout > 0 {
		timeout := time.Duration(cc.config.Addon.Request.Timeout) * time.Second
		logger.Debugf("使用配置的连通性超时时间: %v", timeout)
		return timeout
	}

	// 连通性优化：默认超时时间5秒，快速丢弃无效目标
	defaultTimeout := 5 * time.Second
	logger.Debugf("使用默认连通性超时时间: %v", defaultTimeout)
	return defaultTimeout
}

// BatchCheck 批量检测目标连通性（连通性并发优化：智能选择并发或顺序检测）
func (cc *ConnectivityChecker) BatchCheck(targets []string) []string {
	// 连通性并发优化：根据目标数量决定是否使用并发检测
	// 判断是否启用并发检测（重构：简化判断逻辑）
	if len(targets) >= 3 {
		return cc.BatchCheckConcurrent(targets)
	}

	// 小批量目标或禁用并发时使用顺序检测
	return cc.BatchCheckSequential(targets)
}

// BatchCheckSequential 顺序批量检测目标连通性（保持原有逻辑）
func (cc *ConnectivityChecker) BatchCheckSequential(targets []string) []string {
	// 用户体验优化：详细的开始日志
	logger.Debugf("开始目标连通性检测，目标数量: %d", len(targets))

	var reachableTargets []string
	var droppedTargets []string
	parser := NewTargetParser()

	for _, target := range targets {
		// 标准化URL
		urls := parser.NormalizeURL(target)

		// 检测连通性
		reachableURL := cc.CheckTarget(urls)
		if reachableURL != "" {
			reachableTargets = append(reachableTargets, reachableURL)
		} else {
			droppedTargets = append(droppedTargets, target)
			logger.Debugf("跳过不可连通的目标: %s", target)
		}
	}

	// 用户体验优化：详细的完成统计日志
	logger.Debugf("有效目标: %d，丢弃目标: %d",
		len(reachableTargets), len(droppedTargets))

	return reachableTargets
}

// ValidateAndNormalize 验证并标准化目标列表
func (cc *ConnectivityChecker) ValidateAndNormalize(targets []string) ([]string, error) {
	logger.Debugf("开始验证和标准化目标列表")

	var validTargets []string
	parser := NewTargetParser()

	for _, target := range targets {
		// 验证URL格式
		if err := parser.ValidateURL(target); err != nil {
			logger.Warnf("跳过无效目标 %s: %v", target, err)
			continue
		}

		// 标准化URL
		urls := parser.NormalizeURL(target)
		if len(urls) > 0 {
			// 取第一个标准化的URL
			validTargets = append(validTargets, urls[0])
		}
	}

	if len(validTargets) == 0 {
		return nil, fmt.Errorf("没有有效的目标")
	}

	logger.Debugf("验证完成，有效目标: %d/%d",
		len(validTargets), len(targets))

	return validTargets, nil
}

// 工作池实现

// ConnectivityWorkerPool 连通性检测工作池（连通性并发优化）
type ConnectivityWorkerPool struct {
	workerCount int
	taskChan    chan ConnectivityTask
	resultChan  chan ConnectivityResult
	workers     []*ConnectivityWorker
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
}

// ConnectivityTask 连通性检测任务
type ConnectivityTask struct {
	Target string
	URLs   []string
	Index  int
	Total  int
}

// ConnectivityResult 连通性检测结果
type ConnectivityResult struct {
	Target       string
	ReachableURL string
	Success      bool
	Duration     time.Duration
	Error        error
	Index        int
}

// ConnectivityWorker 连通性检测工作器
type ConnectivityWorker struct {
	id         int
	checker    *ConnectivityChecker
	taskChan   <-chan ConnectivityTask
	resultChan chan<- ConnectivityResult
	ctx        context.Context
}

// ConnectivityStats 连通性检测统计（复用RequestProcessor模式）
type ConnectivityStats struct {
	TotalCount     int64
	SuccessCount   int64
	FailureCount   int64
	ProcessedCount int64
	StartTime      time.Time
}

// NewConnectivityWorkerPool 创建连通性工作池
func NewConnectivityWorkerPool(workerCount int, checker *ConnectivityChecker) *ConnectivityWorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	pool := &ConnectivityWorkerPool{
		workerCount: workerCount,
		taskChan:    make(chan ConnectivityTask, workerCount*2), // 缓冲队列
		resultChan:  make(chan ConnectivityResult, workerCount*2),
		workers:     make([]*ConnectivityWorker, workerCount),
		ctx:         ctx,
		cancel:      cancel,
	}

	// 创建工作线程
	for i := 0; i < workerCount; i++ {
		worker := &ConnectivityWorker{
			id:         i,
			checker:    checker,
			taskChan:   pool.taskChan,
			resultChan: pool.resultChan,
			ctx:        ctx,
		}
		pool.workers[i] = worker
	}

	return pool
}

// Start 启动工作池
func (cwp *ConnectivityWorkerPool) Start() {
	for _, worker := range cwp.workers {
		cwp.wg.Add(1)
		go worker.run(&cwp.wg)
	}
}

// Stop 停止工作池
func (cwp *ConnectivityWorkerPool) Stop() {
	cwp.cancel()
	close(cwp.taskChan)
	cwp.wg.Wait()
	close(cwp.resultChan)
}

// SubmitTask 提交任务
func (cwp *ConnectivityWorkerPool) SubmitTask(task ConnectivityTask) {
	select {
	case cwp.taskChan <- task:
	case <-cwp.ctx.Done():
		return
	}
}

// GetResult 获取结果
func (cwp *ConnectivityWorkerPool) GetResult() <-chan ConnectivityResult {
	return cwp.resultChan
}

// run Worker的运行方法
func (cw *ConnectivityWorker) run(wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case task, ok := <-cw.taskChan:
			if !ok {
				return
			}

			// 处理连通性检测任务
			startTime := time.Now()
			reachableURL := cw.checker.CheckTarget(task.URLs)
			duration := time.Since(startTime)

			// 发送结果
			result := ConnectivityResult{
				Target:       task.Target,
				ReachableURL: reachableURL,
				Success:      reachableURL != "",
				Duration:     duration,
				Index:        task.Index,
			}

			select {
			case cw.resultChan <- result:
			case <-cw.ctx.Done():
				return
			}

		case <-cw.ctx.Done():
			return
		}
	}
}

// calculateOptimalConcurrency 计算最优并发数（连通性优化）
func (cc *ConnectivityChecker) calculateOptimalConcurrency(targetCount int, configConcurrency int) int {
	// 使用配置的并发数作为基础
	baseConcurrency := configConcurrency
	if baseConcurrency <= 0 {
		baseConcurrency = 15 // 默认并发数
	}

	// 根据目标数量调整
	if targetCount <= 5 {
		return min(targetCount, 5) // 小批量：低并发
	} else if targetCount <= 20 {
		return min(targetCount, baseConcurrency) // 中批量：标准并发
	} else {
		return min(targetCount, baseConcurrency) // 大批量：使用配置的并发数
	}
}

// min 返回两个整数中的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// BatchCheckConcurrent 并发批量检测目标连通性（连通性并发优化）
func (cc *ConnectivityChecker) BatchCheckConcurrent(targets []string) []string {
	concurrency := cc.dynamicConcurrency(len(targets))

	logger.Debugf("启用并发连通性检测，目标数量: %d，并发数: %d", len(targets), concurrency)

	workerPool := NewConnectivityWorkerPool(concurrency, cc)
	workerPool.Start()
	defer workerPool.Stop()

	stats := &ConnectivityStats{
		TotalCount: int64(len(targets)),
		StartTime:  time.Now(),
	}

	progressDone := cc.startProgressDisplay(stats)

	// 提交所有任务
	parser := NewTargetParser()
	go func() {
		for i, target := range targets {
			urls := parser.NormalizeURL(target)
			task := ConnectivityTask{
				Target: target,
				URLs:   urls,
				Index:  i,
				Total:  len(targets),
			}
			workerPool.SubmitTask(task)
		}
	}()

	// 收集结果
	var reachableTargets []string
	var droppedTargets []string
	processedCount := 0

	for processedCount < len(targets) {
		select {
		case result := <-workerPool.GetResult():
			processedCount++
			atomic.AddInt64(&stats.ProcessedCount, 1)

			if result.Success {
				reachableTargets = append(reachableTargets, result.ReachableURL)
				atomic.AddInt64(&stats.SuccessCount, 1)
			} else {
				droppedTargets = append(droppedTargets, result.Target)
				atomic.AddInt64(&stats.FailureCount, 1)
				logger.Debugf("跳过不可连通的目标: %s", result.Target)
			}

		case <-time.After(30 * time.Second):
			logger.Warnf("连通性检测超时，已处理: %d/%d", processedCount, len(targets))
			goto finish
		}
	}

finish:
	close(progressDone)

	logger.Debugf("\r有效目标: %d，丢弃目标: %d，耗时: %v",
		len(reachableTargets), len(droppedTargets), time.Since(stats.StartTime).Round(time.Second))

	return reachableTargets
}

func (cc *ConnectivityChecker) dynamicConcurrency(targetCount int) int {
	cfg := config.GetConfig()
	base := 15
	if cfg != nil && cfg.Module.Dirscan {
		base = 20
	}
	if base < 1 {
		base = 1
	}

	if targetCount <= 1 {
		return 1
	}
	if targetCount <= 4 {
		if targetCount < base {
			return targetCount
		}
		return base
	}

	maxPossible := runtime.NumCPU() * 4
	if maxPossible < 1 {
		maxPossible = 1
	}

	if base > maxPossible {
		base = maxPossible
	}

	if targetCount < base {
		return targetCount
	}
	if targetCount < base*2 {
		return base
	}

	limit := base * 2
	if limit > maxPossible {
		limit = maxPossible
	}
	if limit < 1 {
		limit = 1
	}
	return limit
}

// 进度显示

// 日志修复：连通性检测进度显示同步锁
var connectivityProgressMutex sync.Mutex
var lastConnectivityProgress string

// startProgressDisplay 启动连通性进度显示（连通性并发优化）
func (cc *ConnectivityChecker) startProgressDisplay(stats *ConnectivityStats) chan struct{} {
	progressDone := make(chan struct{})

	go func() {
		ticker := time.NewTicker(300 * time.Millisecond) // 与RequestProcessor保持一致的更新频率
		defer ticker.Stop()

		for {
			select {
			case <-progressDone:
				cc.showFinalConnectivityProgress(stats)
				return
			case <-ticker.C:
				cc.showConnectivityProgress(stats)
			}
		}
	}()

	return progressDone
}

// showConnectivityProgress 显示连通性检测进度（连通性并发优化 + 日志修复）
func (cc *ConnectivityChecker) showConnectivityProgress(stats *ConnectivityStats) {
	current := atomic.LoadInt64(&stats.ProcessedCount)
	if current == 0 {
		return
	}

	total := stats.TotalCount
	percentage := float64(current) / float64(total) * 100
	elapsed := time.Since(stats.StartTime)

	// 计算预估剩余时间（复用RequestProcessor的ETA计算逻辑）
	var eta string
	if current > 0 {
		avgTimePerTarget := elapsed / time.Duration(current)
		remaining := time.Duration(total-current) * avgTimePerTarget
		eta = fmt.Sprintf("ETA: %v", remaining.Round(time.Second))
	} else {
		eta = "ETA..."
	}

	// 生成进度条（复用RequestProcessor的进度条生成逻辑）
	progressBar := cc.generateConnectivityProgressBar(percentage)

	// 日志修复：构建进度信息并避免重复显示
	progressInfo := fmt.Sprintf("Alive Checking: %d/%d (%.1f%%) %s Time: %v %s\r",
		current, total, percentage, progressBar, elapsed.Round(time.Second), eta)

	// 日志修复：使用同步锁防止重复显示相同的进度信息
	connectivityProgressMutex.Lock()
	if progressInfo != lastConnectivityProgress {
		fmt.Printf("\r%s", progressInfo)
		lastConnectivityProgress = progressInfo
	}
	connectivityProgressMutex.Unlock()
}

// generateConnectivityProgressBar 生成连通性进度条（连通性并发优化）
func (cc *ConnectivityChecker) generateConnectivityProgressBar(percentage float64) string {
	// 复用RequestProcessor的进度条生成逻辑
	const barLength = 20
	filled := int(percentage / 100 * barLength)

	bar := "["
	for i := 0; i < barLength; i++ {
		if i < filled {
			bar += "="
		} else if i == filled {
			bar += ">"
		} else {
			bar += " "
		}
	}
	bar += "]"

	return bar
}

// showFinalConnectivityProgress 显示最终连通性进度（连通性并发优化 + 日志修复）
func (cc *ConnectivityChecker) showFinalConnectivityProgress(stats *ConnectivityStats) {
	current := atomic.LoadInt64(&stats.ProcessedCount)
	total := stats.TotalCount
	percentage := float64(current) / float64(total) * 100

	// 日志修复：清除当前行并显示最终进度
	fmt.Printf("\rAlive Checking: %d/%d (%.1f%%) Done\n", current, total, percentage)
}
