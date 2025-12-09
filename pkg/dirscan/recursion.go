package dirscan

import (
	"path"
	"strings"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
)

// ExtractNextLevelTargets 从扫描结果中提取下一层级的扫描目标
// results: 上一轮扫描的有效结果
// alreadyScanned: 已经扫描过的URL集合（用于去重）
// 返回: 新的待扫描URL列表
func ExtractNextLevelTargets(results []interfaces.HTTPResponse, alreadyScanned map[string]bool) []string {
	var newTargets []string
	// 本轮去重，防止同一次结果中有重复
	thisRoundTargets := make(map[string]struct{})

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

		// 规范化URL，确保以/结尾
		if !strings.HasSuffix(targetURL, "/") {
			// 如果不是以/结尾，需要判断是否是文件
			// 如果有明显的后缀名，且不是常见的目录形式，则跳过
			ext := path.Ext(targetURL)
			if ext != "" {
				// 有后缀名，检查是否是静态资源或已知文件类型
				// 这里简单判断，如果有后缀通常认为是文件，除非特定的如 /v1.0/ 这种
				// 但 /v1.0/ 会匹配 HasSuffix("/")
				// 所以这里如果有后缀，我们保守点不递归，除非它看起来像目录
				// 对于 actuator 这种没有后缀的，会走到下面
				continue
			}
			targetURL += "/"
		}

		// 过滤SPA路由（Vue/React等前端路由）
		if strings.Contains(targetURL, "/#/") {
			logger.Debugf("跳过前端路由: %s", targetURL)
			continue
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
	return newTargets
}

// RecursionCollector 用于递归扫描的临时收集器
type RecursionCollector struct {
	urls map[string]int
}

// GetURLMap 获取收集的URL映射表
func (rc *RecursionCollector) GetURLMap() map[string]int {
	return rc.urls
}

// GetURLCount 获取收集的URL数量
func (rc *RecursionCollector) GetURLCount() int {
	return len(rc.urls)
}
