package dirscan

import (
	"sync"
	"time"
	"veo/pkg/utils/interfaces"
	requests "veo/pkg/utils/processor"
)

// 核心类型定义

// ScanResult 扫描结果
type ScanResult struct {
	Target        string                     `json:"target"`         // 扫描目标
	CollectedURLs []string                   `json:"collected_urls"` // 收集的URL
	ScanURLs      []string                   `json:"scan_urls"`      // 生成的扫描URL
	Responses     []*interfaces.HTTPResponse `json:"responses"`      // HTTP响应
	FilterResult  *interfaces.FilterResult   `json:"filter_result"`  // 过滤结果
	StartTime     time.Time                  `json:"start_time"`     // 开始时间
	EndTime       time.Time                  `json:"end_time"`       // 结束时间
	Duration      time.Duration              `json:"duration"`       // 扫描耗时
}

// EngineConfig 引擎配置
type EngineConfig struct {
	MaxConcurrency   int           `yaml:"max_concurrency"`   // 最大并发数
	RequestTimeout   time.Duration `yaml:"request_timeout"`   // 请求超时时间
	EnableCollection bool          `yaml:"enable_collection"` // 是否启用URL收集
	EnableFiltering  bool          `yaml:"enable_filtering"`  // 是否启用响应过滤
	ProxyURL         string        `yaml:"proxy_url"`         // 上游代理地址
}

// Statistics 统计信息
type Statistics struct {
	TotalCollected  int64     `json:"total_collected"`  // 总收集URL数
	TotalGenerated  int64     `json:"total_generated"`  // 总生成URL数
	TotalRequests   int64     `json:"total_requests"`   // 总请求数
	SuccessRequests int64     `json:"success_requests"` // 成功请求数
	FilteredResults int64     `json:"filtered_results"` // 过滤后结果数
	ValidResults    int64     `json:"valid_results"`    // 有效结果数
	StartTime       time.Time `json:"start_time"`       // 启动时间
	LastScanTime    time.Time `json:"last_scan_time"`   // 最后扫描时间
	TotalScans      int64     `json:"total_scans"`      // 总扫描次数
}

// Engine 目录扫描引擎
type Engine struct {
	config           *EngineConfig
	stats            *Statistics
	mu               sync.RWMutex
	lastScanResult   *ScanResult
	filterConfig     *FilterConfig
	requestProcessor *requests.RequestProcessor
}

// ScanStatus 扫描状态
type ScanStatus int

const (
	StatusIdle     ScanStatus = iota // 空闲状态
	StatusScanning                   // 扫描中
	StatusPaused                     // 暂停状态
	StatusError                      // 错误状态
)

// 默认配置

// getDefaultConfig 获取默认配置
func getDefaultConfig() *EngineConfig {
	return &EngineConfig{
		MaxConcurrency:   20, // 默认并发数
		RequestTimeout:   30 * time.Second,
		EnableCollection: true,
		EnableFiltering:  true,
	}
}
