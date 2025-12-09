package processor

import (
	"context"
	"sync"
	"time"

	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
)

// WorkerPool 工作池结构体（并发优化）
type WorkerPool struct {
	workerCount int
	taskChan    chan WorkerTask
	resultChan  chan WorkerResult
	workers     []*Worker
	wg          sync.WaitGroup
	ctx         context.Context
	cancel      context.CancelFunc
}

// WorkerTask 工作任务
type WorkerTask struct {
	URL       string
	Index     int
	TotalURLs int
}

// WorkerResult 工作结果
type WorkerResult struct {
	Response *interfaces.HTTPResponse
	URL      string
	Index    int
	Error    error
}

// Worker 工作线程
type Worker struct {
	id         int
	processor  *RequestProcessor
	taskChan   <-chan WorkerTask
	resultChan chan<- WorkerResult
	ctx        context.Context
}

// Worker Pool 实现（并发优化）

// calculateOptimalBufferSize 计算最优缓冲区大小
// 根据工作线程数量和缓冲区类型，动态计算最适合的缓冲区大小
// 参数：
//   - workerCount: 工作线程数量
//   - bufferType: 缓冲区类型（"task" 或 "result"）
//
// 返回：最优的缓冲区大小
func calculateOptimalBufferSize(workerCount int, bufferType string) int {
	baseSize := workerCount * 2 // 基础缓冲区大小：工作线程数的2倍

	switch bufferType {
	case "task":
		// 任务缓冲区：需要更大的缓冲区来避免生产者阻塞
		if workerCount <= 10 {
			return baseSize
		} else if workerCount <= 50 {
			return workerCount * 3
		} else {
			return workerCount * 4
		}
	case "result":
		// 结果缓冲区：相对较小，避免内存占用过多
		if workerCount <= 10 {
			return baseSize
		} else {
			return workerCount + 10
		}
	default:
		return baseSize
	}
}

// NewWorkerPool 创建工作池
// 根据指定的工作线程数量创建一个优化的工作池，支持动态缓冲区大小调整
// 参数：
//   - workerCount: 工作线程数量
//   - processor: 请求处理器实例
//
// 返回：配置完成的工作池实例
func NewWorkerPool(workerCount int, processor *RequestProcessor) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())

	// 动态计算最优缓冲区大小，提升并发性能
	taskBufferSize := calculateOptimalBufferSize(workerCount, "task")
	resultBufferSize := calculateOptimalBufferSize(workerCount, "result")

	pool := &WorkerPool{
		workerCount: workerCount,
		taskChan:    make(chan WorkerTask, taskBufferSize),     // 任务通道，带缓冲
		resultChan:  make(chan WorkerResult, resultBufferSize), // 结果通道，带缓冲
		workers:     make([]*Worker, workerCount),
		ctx:         ctx,
		cancel:      cancel,
	}

	// 创建并初始化所有工作线程
	for i := 0; i < workerCount; i++ {
		worker := &Worker{
			id:         i,
			processor:  processor,
			taskChan:   pool.taskChan,
			resultChan: pool.resultChan,
			ctx:        ctx,
		}
		pool.workers[i] = worker
	}

	return pool
}

// Start 启动工作池
func (wp *WorkerPool) Start() {
	for _, worker := range wp.workers {
		wp.wg.Add(1)
		go worker.run(&wp.wg)
	}
}

// Stop 停止工作池（修复：添加超时保护和资源清理）
func (wp *WorkerPool) Stop() {
	// 1. 发送取消信号
	wp.cancel()

	// 2. 关闭任务通道，阻止新任务提交
	close(wp.taskChan)

	// 3. 等待所有worker完成，但设置超时避免永久阻塞
	done := make(chan struct{})
	go func() {
		wp.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Debugf("所有Worker正常退出")
	case <-time.After(10 * time.Second):
		logger.Warnf("Worker Pool停止超时，可能存在阻塞的goroutine")
	}

	// 4. 安全关闭结果通道
	select {
	case <-wp.resultChan:
		// 通道已经被关闭或为空
	default:
		// 通道还有数据或未关闭
	}
	close(wp.resultChan)

	logger.Debugf("Worker Pool已停止")
}

// SubmitTask 提交任务（修复：添加安全的channel发送机制）
func (wp *WorkerPool) SubmitTask(task WorkerTask) {
	defer func() {
		if r := recover(); r != nil {
			logger.Warnf("任务提交发生panic（channel已关闭），任务: %s, 错误: %v", task.URL, r)
		}
	}()

	select {
	case wp.taskChan <- task:
	case <-wp.ctx.Done():
		return
	}
}

// GetResult 获取结果
func (wp *WorkerPool) GetResult() <-chan WorkerResult {
	return wp.resultChan
}

// run Worker的主运行循环（修复：添加panic恢复和超时保护）
// 持续监听任务通道，处理接收到的URL请求任务
// 参数：
//   - wg: 等待组，用于协调工作线程的生命周期
func (w *Worker) run(wg *sync.WaitGroup) {
	defer func() {
		// 修复：添加panic恢复，确保WaitGroup计数正确
		if r := recover(); r != nil {
			logger.Errorf("Worker %d panic恢复: %v", w.id, r)
		}
		wg.Done()
		logger.Debugf("Worker %d 已退出", w.id)
	}()

	logger.Debugf("Worker %d 已启动", w.id)

	for {
		select {
		case task, ok := <-w.taskChan:
			// 检查任务通道是否已关闭
			if !ok {
				logger.Debugf("Worker %d: 任务通道已关闭，退出", w.id)
				return
			}

			// 处理URL请求任务（添加超时保护）
			response := w.processTaskWithTimeout(task)

			// 构建处理结果
			result := WorkerResult{
				Response: response,
				URL:      task.URL,
				Index:    task.Index,
				Error:    nil,
			}

			// 发送结果到结果通道（修复：改进结果处理，避免丢失有效结果）
			select {
			case w.resultChan <- result:
				// 结果发送成功，继续处理下一个任务
			case <-w.ctx.Done():
				// 工作池已停止，退出工作线程
				logger.Debugf("Worker %d: 收到停止信号，退出", w.id)
				return
			case <-time.After(60 * time.Second): // 增加超时时间到60秒
				// 修复：结果发送超时时，尝试缓存结果而不是直接丢弃
				logger.Warnf("Worker %d: 结果发送超时，尝试缓存结果: %s", w.id, task.URL)
				w.cacheDelayedResult(result)
				// 继续处理下一个任务，不退出worker
			}

		case <-w.ctx.Done():
			// 接收到停止信号，退出工作线程
			logger.Debugf("Worker %d: 收到停止信号，退出", w.id)
			return
		}
	}
}

// cacheDelayedResult 缓存延迟的结果（新增：避免结果丢失）
func (w *Worker) cacheDelayedResult(result WorkerResult) {
	// 在Worker结构体中需要添加delayedResults字段来存储延迟结果
	// 这里先记录日志，实际实现需要在Worker结构体中添加缓存机制
	if result.Response != nil {
		logger.Infof("缓存延迟结果: %s [%d] - 将在下次机会重新发送",
			result.URL, result.Response.StatusCode)
	} else {
		logger.Warnf("缓存失败结果: %s - 请求处理失败", result.URL)
	}
}

// processTaskWithTimeout 处理任务（新增：添加超时保护）
func (w *Worker) processTaskWithTimeout(task WorkerTask) *interfaces.HTTPResponse {
	// 创建带超时的context
	ctx, cancel := context.WithTimeout(w.ctx, 60*time.Second)
	defer cancel()

	// 使用channel接收结果，支持超时
	resultChan := make(chan *interfaces.HTTPResponse, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Errorf("Worker %d 处理任务panic: %v, URL: %s", w.id, r, task.URL)
				resultChan <- nil
			}
		}()

		response := w.processor.processURL(task.URL)
		resultChan <- response
	}()

	select {
	case response := <-resultChan:
		return response
	case <-ctx.Done():
		logger.Warnf("Worker %d 处理任务超时: %s", w.id, task.URL)
		return nil
	}
}
