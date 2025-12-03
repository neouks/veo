package gogo

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
	"veo/pkg/portscan"
	"veo/pkg/utils/logger"
)

// DefaultRate 默认扫描速率
const DefaultRate = 1000

// DefaultTimeout 默认超时时间
const DefaultTimeout = 3 * time.Second

// Scanner 端口扫描器
type Scanner struct {
	Rate    int
	Timeout time.Duration
	Threads int
}

// Option 扫描器配置选项
type Option func(*Scanner)

// WithRate 设置扫描速率
func WithRate(rate int) Option {
	return func(s *Scanner) {
		if rate > 0 {
			s.Rate = rate
		}
	}
}

// WithTimeout 设置超时时间
func WithTimeout(timeout time.Duration) Option {
	return func(s *Scanner) {
		if timeout > 0 {
			s.Timeout = timeout
		}
	}
}

// WithThreads 设置并发线程数
func WithThreads(threads int) Option {
	return func(s *Scanner) {
		if threads > 0 {
			s.Threads = threads
		}
	}
}

// NewScanner 创建新的扫描器实例
func NewScanner(opts ...Option) *Scanner {
	s := &Scanner{
		Rate:    DefaultRate,
		Timeout: DefaultTimeout,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Scan 执行同步端口扫描
func (s *Scanner) Scan(ctx context.Context, targets []string, portsExpr string) ([]portscan.OpenPortResult, error) {
	// 1. 解析目标IP
	ips, err := portscan.ResolveTargetsToIPs(targets)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("未找到有效目标IP")
	}

	// 2. 解析端口
	ports, err := portscan.ParsePortExpression(portsExpr)
	if err != nil {
		return nil, fmt.Errorf("解析端口失败: %v", err)
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("未找到有效端口")
	}

	logger.Infof("开始端口扫描，目标数: %d，端口数: %d，速率: %d", len(ips), len(ports), s.Rate)

	// 3. 执行扫描
	return s.scanCore(ctx, ips, ports)
}

// ScanStream 执行流式端口扫描
func (s *Scanner) ScanStream(ctx context.Context, targets []string, portsExpr string) (<-chan portscan.OpenPortResult, error) {
	// 1. 解析目标IP
	ips, err := portscan.ResolveTargetsToIPs(targets)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("未找到有效目标IP")
	}

	// 2. 解析端口
	ports, err := portscan.ParsePortExpression(portsExpr)
	if err != nil {
		return nil, fmt.Errorf("解析端口失败: %v", err)
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("未找到有效端口")
	}

	logger.Infof("开始流式端口扫描，目标数: %d，端口数: %d，速率: %d", len(ips), len(ports), s.Rate)

	out := make(chan portscan.OpenPortResult, 100) // Buffer a bit
	go func() {
		defer close(out)
		s.scanCoreStream(ctx, ips, ports, out)
	}()

	return out, nil
}

// scanCore 执行扫描核心逻辑 (同步)
func (s *Scanner) scanCore(ctx context.Context, ips []string, ports []int) ([]portscan.OpenPortResult, error) {
	var results []portscan.OpenPortResult
	var mutex sync.Mutex

	out := make(chan portscan.OpenPortResult, 100)
	done := make(chan struct{})

	// 收集结果
	go func() {
		defer close(done)
		for r := range out {
			mutex.Lock()
			results = append(results, r)
			mutex.Unlock()
		}
	}()

	s.scanCoreStream(ctx, ips, ports, out)
	// scanCoreStream closes internal channels but we passed 'out'.
	// scanCoreStream does NOT close 'out'. We must close it here after scanCoreStream returns.
	close(out)
	<-done

	return deduplicateResults(results), nil
}

// scanCoreStream 执行扫描核心逻辑 (流式)
func (s *Scanner) scanCoreStream(ctx context.Context, ips []string, ports []int, out chan<- portscan.OpenPortResult) {
	// 任务通道
	totalTasks := int64(len(ips) * len(ports))
	taskCh := make(chan task, s.Rate)
	var wg sync.WaitGroup

	// 并发控制
	concurrency := s.Threads
	if concurrency <= 0 {
		concurrency = s.Rate * 2
		if concurrency > 2000 {
			concurrency = 2000 // 限制最大并发数，防止 fd 耗尽
		}
		if concurrency < 100 {
			concurrency = 100
		}
	}

	// 速率限制器
	limiter := newRateLimiter(s.Rate)
	defer limiter.Stop()

	// 进度统计
	var progress int64
	progressDone := make(chan struct{})
	go s.printProgress(totalTasks, &progress, progressDone)

	// 启动Workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range taskCh {
				// 检查上下文取消
				select {
				case <-ctx.Done():
					return
				default:
				}

				// 等待令牌
				limiter.Wait()

				if s.checkPort(t.ip, t.port) {
					result := portscan.OpenPortResult{
						IP:   t.ip,
						Port: t.port,
					}
					select {
					case out <- result:
					case <-ctx.Done():
						return
					}
				}
				atomic.AddInt64(&progress, 1)
			}
		}()
	}

	// 生成任务
	go func() {
		defer close(taskCh)
		for _, ip := range ips {
			for _, port := range ports {
				select {
				case <-ctx.Done():
					return
				case taskCh <- task{ip: ip, port: port}:
				}
			}
		}
	}()

	wg.Wait()
	close(progressDone)
}

type task struct {
	ip   string
	port int
}

// checkPort 检查端口是否开放 (Connect Scan)
func (s *Scanner) checkPort(ip string, port int) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	d := net.Dialer{Timeout: s.Timeout}
	conn, err := d.Dial("tcp", address)
	if err != nil {
		logger.Debugf("端口未开放 %s:%d: %v", ip, port, err)
		return false
	}
	conn.Close()
	return true
}

func (s *Scanner) printProgress(total int64, current *int64, done <-chan struct{}) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			// 打印最终进度
			curr := atomic.LoadInt64(current)
			if total > 0 {
				fmt.Printf("\rPortScan Progress: %.2f%% (%d/%d)\n", float64(curr)/float64(total)*100, curr, total)
			}
			return
		case <-ticker.C:
			curr := atomic.LoadInt64(current)
			if total > 0 {
				fmt.Printf("\rPortScan Progress: %.2f%% (%d/%d)", float64(curr)/float64(total)*100, curr, total)
			}
		}
	}
}

// 速率限制器
type rateLimiter struct {
	ticker *time.Ticker
	rate   int
}

func newRateLimiter(rate int) *rateLimiter {
	// 简单实现：每个 tick 允许执行一次，频率为 rate
	return &rateLimiter{
		ticker: time.NewTicker(time.Second / time.Duration(rate)),
		rate:   rate,
	}
}

func (r *rateLimiter) Wait() {
	<-r.ticker.C
}

func (r *rateLimiter) Stop() {
	r.ticker.Stop()
}

func deduplicateResults(results []portscan.OpenPortResult) []portscan.OpenPortResult {
	unique := make(map[string]struct{})
	var clean []portscan.OpenPortResult
	for _, r := range results {
		key := fmt.Sprintf("%s:%d", r.IP, r.Port)
		if _, exists := unique[key]; !exists {
			unique[key] = struct{}{}
			clean = append(clean, r)
		}
	}
	return clean
}
