package dirscan

import (
	"fmt"
	"strings"
	"time"

	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
)

// Addon实现

// DirscanAddon 目录扫描插件
type DirscanAddon struct {
	engine    *Engine
	collector *Collector
	enabled   bool
	status    ScanStatus
	depth     int // 递归扫描深度
}

// NewDirscanAddon 创建目录扫描插件
func NewDirscanAddon(config *EngineConfig) (*DirscanAddon, error) {
	// 创建引擎
	engine := NewEngine(config)
	collectorInstance := NewCollector()

	addon := &DirscanAddon{
		engine:    engine,
		collector: collectorInstance,
		enabled:   true,
		status:    StatusIdle,
		depth:     0, // 默认深度为0，可通过SetDepth方法修改
	}

	logger.Debug("目录扫描插件初始化完成")
	return addon, nil
}

// CreateDefaultAddon 创建默认配置的目录扫描插件
func CreateDefaultAddon() (*DirscanAddon, error) {
	config := getDefaultConfig()
	return NewDirscanAddon(config)
}

// SetProxy 设置代理
func (da *DirscanAddon) SetProxy(proxyURL string) {
	if da.engine != nil {
		da.engine.SetProxy(proxyURL)
	}
}

// 核心接口方法

// Enable 启用插件
func (da *DirscanAddon) Enable() {
	da.enabled = true
	if da.collector != nil {
		da.collector.EnableCollection()
	}
	logger.Debugf("目录扫描插件已启用")
}

// Disable 禁用插件
func (da *DirscanAddon) Disable() {
	da.enabled = false
	if da.collector != nil {
		da.collector.DisableCollection()
	}
	logger.Debugf("目录扫描插件已禁用")
}

// GetCollectedURLs 获取收集的URL
func (da *DirscanAddon) GetCollectedURLs() []string {
	if da.collector == nil {
		return []string{}
	}

	urlMap := da.collector.GetURLMap()
	urls := make([]string, 0, len(urlMap))
	for url := range urlMap {
		urls = append(urls, url)
	}

	return urls
}

// GetScanResults 获取扫描结果
func (da *DirscanAddon) GetScanResults() *ScanResult {
	return da.engine.GetLastScanResult()
}

// ClearResults 清空结果
func (da *DirscanAddon) ClearResults() {
	da.engine.ClearResults()
	if da.collector != nil {
		da.collector.ClearURLMap()
	}
	logger.Info("扫描结果已清空")
}

// TriggerScan 触发扫描
func (da *DirscanAddon) TriggerScan() (*ScanResult, error) {
	if !da.enabled {
		return nil, fmt.Errorf("插件未启用")
	}

	if da.collector == nil {
		return nil, fmt.Errorf("collector未初始化")
	}

	// 获取初始收集的URL
	collectedURLs := da.GetCollectedURLs()
	if len(collectedURLs) == 0 {
		return nil, fmt.Errorf("没有收集到URL，无法开始扫描")
	}

	da.status = StatusScanning
	defer func() { da.status = StatusIdle }()

	// 暂停采集
	da.collector.DisableCollection()
	defer da.collector.EnableCollection()

	// 获取配置的深度
	depth := da.depth

	// 初始化聚合结果
	finalResult := &ScanResult{
		StartTime:     time.Now(),
		CollectedURLs: collectedURLs,
		FilterResult: &interfaces.FilterResult{
			ValidPages: make([]interfaces.HTTPResponse, 0),
		},
	}

	currentTargets := collectedURLs
	alreadyScanned := make(map[string]bool)

	// 预先标记初始目标
	for _, t := range currentTargets {
		alreadyScanned[t] = true
		if !strings.HasSuffix(t, "/") {
			alreadyScanned[t+"/"] = true
		}
	}

	// 递归循环
	for d := 0; d <= depth; d++ {
		if len(currentTargets) == 0 {
			break
		}

		if d > 0 {
			logger.Infof("正在进行第 %d 层递归目录扫描，目标数量: %d", d, len(currentTargets))
		}

		// 创建临时收集器
		tempCollector := &RecursionCollector{
			urls: make(map[string]int),
		}
		for _, t := range currentTargets {
			tempCollector.urls[t] = 1
		}

		// 执行扫描
		scanResult, err := da.engine.PerformScanWithOptions(tempCollector, d > 0)
		if err != nil {
			logger.Errorf("Scan failed at depth %d: %v", d, err)
			// 继续处理部分结果
		}

		if scanResult != nil {
			// 聚合响应
			finalResult.Responses = append(finalResult.Responses, scanResult.Responses...)
			finalResult.ScanURLs = append(finalResult.ScanURLs, scanResult.ScanURLs...)

			// 聚合有效页面 (用于提取下一层目标和最终报告)
			if scanResult.FilterResult != nil {
				finalResult.FilterResult.ValidPages = append(finalResult.FilterResult.ValidPages, scanResult.FilterResult.ValidPages...)
			}

			// 更新元数据
			finalResult.Target = scanResult.Target // 使用最后一个作为Target，或者保留初始的
		}

		// 提取下一层目标
		if d < depth && scanResult != nil && scanResult.FilterResult != nil {
			newTargets := ExtractNextLevelTargets(scanResult.FilterResult.ValidPages, alreadyScanned)

			var validNewTargets []string
			for _, nt := range newTargets {
				alreadyScanned[nt] = true
				validNewTargets = append(validNewTargets, nt)
			}
			currentTargets = validNewTargets
		}
	}

	// 扫描完成后清空已采集的URL，等待下一轮采集
	da.collector.ClearURLMap()

	finalResult.EndTime = time.Now()
	finalResult.Duration = finalResult.EndTime.Sub(finalResult.StartTime)

	return finalResult, nil
}

// GetStatus 获取扫描状态
func (da *DirscanAddon) GetStatus() ScanStatus {
	return da.status
}

// 配置和依赖注入方法

// 控制台设置接口已移除，保持简洁依赖

// GetCollector 获取collector（用于依赖注入）
func (da *DirscanAddon) GetCollector() *Collector {
	return da.collector
}

// SetCollector 注入外部的URL采集器实例，确保与代理侧使用同一实例
//
// 参数:
//   - c: *Collector 外部创建并用于代理拦截的URL采集器
//
// 返回:
//   - 无
//
// 说明:
//   - 在被动代理模式下，代理服务器会将经过的URL写入其注册的Collector实例。
//     若目录扫描插件内部持有不同的Collector实例，将导致“按回车触发扫描”时取不到已采集的URL。
//     通过本方法将外部Collector注入到插件中，可确保两端使用同一个实例，避免“没有收集到URL”的问题。
func (da *DirscanAddon) SetCollector(c *Collector) {
	if c == nil {
		return
	}
	da.collector = c
	logger.Debug("目录扫描插件Collector已注入为外部实例")
}

// 字典预加载方法

// 字典预加载逻辑已经迁移到生成器内部（无须处理）

// SetDepth 设置递归扫描深度
func (da *DirscanAddon) SetDepth(depth int) {
	da.depth = depth
}

// Proxy.Addon接口实现

// GetName 获取插件名称
func (da *DirscanAddon) GetName() string {
	return "DirscanAddon"
}

// String 字符串表示
func (da *DirscanAddon) String() string {
	return "DirscanAddon - 目录扫描插件"
}
