package dirscan

import (
	"context"
	"errors"
	"strings"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
	"veo/pkg/utils/shared"
)

// LayerScanner 单层扫描器接口
// 负责执行单个层级的扫描任务（不论是并发还是顺序）
// depth: 当前递归深度（0表示初始层）
type LayerScanner func(targets []string, filter *ResponseFilter, depth int) ([]interfaces.HTTPResponse, error)

// RunRecursiveScan 执行通用递归扫描
// 统一封装了递归深度控制、状态去重、下一层提取和验证逻辑
func RunRecursiveScan(
	ctx context.Context,
	initialTargets []string,
	maxDepth int,
	layerScanner LayerScanner,
	sharedFilter *ResponseFilter,
) ([]interfaces.HTTPResponse, error) {
	var allResults []interfaces.HTTPResponse

	// 初始化递归变量
	currentTargets := initialTargets
	alreadyScanned := make(map[string]bool)

	// 预先标记初始目标
	for _, t := range initialTargets {
		alreadyScanned[t] = true
		// 同时也标记带斜杠的版本（如果不带斜杠），防止重复扫描
		if !strings.HasSuffix(t, "/") {
			alreadyScanned[t+"/"] = true
		}
	}

	for d := 0; d <= maxDepth; d++ {
		// 检查Context取消
		select {
		case <-ctx.Done():
			if maxDepth > 0 {
				logger.Warn("递归扫描被取消")
			} else {
				logger.Warn("扫描被取消")
			}
			return allResults, nil
		default:
		}

		if len(currentTargets) == 0 {
			break
		}

		if d > 0 {
			logger.Infof("正在进行第 %d 层递归目录扫描，目标数量: %d", d, len(currentTargets))
			// 仅在DEBUG模式下打印所有目标，避免日志刷屏
			if len(currentTargets) <= 5 {
				for _, target := range currentTargets {
					logger.Debugf("  └─ 递归目标: %s", target)
				}
			}
		}

		// 决定当前层使用的过滤器
		// 第0层通常使用站点默认过滤器（如果sharedFilter为nil），或者统一使用sharedFilter
		// 这里简化逻辑：如果有sharedFilter，全程使用；否则由LayerScanner自行决定（通常是不对的）
		// 为了强一致性，建议必须传递sharedFilter用于递归层（d>0）
		// 如果 maxDepth=0，sharedFilter 可能为 nil
		var currentFilter *ResponseFilter
		if d > 0 {
			currentFilter = sharedFilter
		} else if sharedFilter != nil {
			// 如果提供了共享过滤器，第0层也使用它（例如 Addon 模式）
			currentFilter = sharedFilter
		}

		// 执行单层扫描
		results, err := layerScanner(currentTargets, currentFilter, d)
		if err != nil {
			if errors.Is(err, ErrNoValidHTTPResponse) {
				target := ""
				if len(currentTargets) == 1 {
					target = currentTargets[0]
				}
				if target != "" {
					logger.Errorf("Scanning For %s Error，No Valid HTTP response received", target)
				} else {
					logger.Errorf("Scanning Error，No Valid HTTP response received")
				}
			} else {
				logger.Errorf("目录扫描出错 (Depth %d): %v", d, err)
			}
			// 继续处理部分结果，不中断整个流程
		}

		if len(results) > 0 {
			allResults = append(allResults, results...)
		}

		// 如果还没达到最大深度，提取下一层目标
		if d < maxDepth {
			newTargets := ExtractNextLevelTargets(results, alreadyScanned)

			// 再次去重并加入已扫描集合
			var finalTargets []string
			for _, nt := range newTargets {
				if !alreadyScanned[nt] {
					alreadyScanned[nt] = true
					finalTargets = append(finalTargets, nt)
				}
			}
			currentTargets = finalTargets
		}
	}

	return allResults, nil
}

// ExtractNextLevelTargets 提取下一层需要递归扫描的目标
func ExtractNextLevelTargets(results []interfaces.HTTPResponse, alreadyScanned map[string]bool) []string {
	var newTargets []string
	// 本轮去重，防止同一次结果中有重复
	thisRoundTargets := make(map[string]struct{})
	fileChecker := shared.NewFileExtensionChecker()
	pathChecker := shared.NewPathChecker()

	for _, resp := range results {
		// 只处理状态码为200或403的页面作为目录递归的基础
		// 403通常意味着目录存在但禁止访问，可能有子目录可访问
		if resp.StatusCode != 200 && resp.StatusCode != 403 {
			continue
		}

		targetURL := resp.URL
		if targetURL == "" {
			continue
		}

		// 检查是否是静态文件（如 .css, .js, .png 等）
		// 如果是静态文件，不进行递归
		if fileChecker.IsStaticFile(targetURL) {
			continue
		}

		// 检查是否在静态目录黑名单中（如 /assets/, /css/ 等）
		if pathChecker.IsStaticPath(targetURL) {
			logger.Debugf("跳过黑名单目录: %s", targetURL)
			continue
		}

		// 规范化URL，确保以/结尾
		if !strings.HasSuffix(targetURL, "/") {
			// 如果没有以/结尾，且不是静态文件，我们假设它是目录
			// 之前的逻辑是如果有扩展名就跳过，这会导致 v1.0 这样的目录被跳过
			// 现在使用 IsStaticFile 精确判断，所以这里可以直接添加 /
			targetURL += "/"
		}

		// 检查是否已经扫描过
		if alreadyScanned[targetURL] {
			continue
		}

		// 检查本轮是否已经添加
		if _, ok := thisRoundTargets[targetURL]; ok {
			continue
		}

		thisRoundTargets[targetURL] = struct{}{}
		newTargets = append(newTargets, targetURL)

		// 标记为已扫描（注意：调用者负责维护全局的alreadyScanned，或者我们在这里更新）
		// 这里为了纯函数特性，我们只读取alreadyScanned，调用方负责合并
		// 但为了方便，我们假设调用方会把返回的newTargets加入alreadyScanned
		// 或者我们在下一轮循环前加入
	}

	logger.Debugf("从 %d 个结果中提取到 %d 个新递归目标", len(results), len(newTargets))
	if len(newTargets) > 0 {
		count := 5
		if len(newTargets) < count {
			count = len(newTargets)
		}
		logger.Debugf("递归目标示例 (Top %d):", count)
		for i := 0; i < count; i++ {
			logger.Debugf("  -> %s", newTargets[i])
		}
	}
	return newTargets
}

// RecursionCollector 用于递归扫描的临时收集器
type RecursionCollector struct {
	urls map[string]int
}

// NewRecursionCollector 创建递归扫描用的临时收集器
func NewRecursionCollector(targets []string) *RecursionCollector {
	urls := make(map[string]int, len(targets))
	for _, t := range targets {
		if t == "" {
			continue
		}
		urls[t] = 1
	}
	return &RecursionCollector{urls: urls}
}

// GetURLMap 获取收集的URL映射表
func (rc *RecursionCollector) GetURLMap() map[string]int {
	return rc.urls
}

// GetURLCount 获取收集的URL数量
func (rc *RecursionCollector) GetURLCount() int {
	return len(rc.urls)
}
