package cli

import (
	"fmt"
	"net/url"
	"strings"

	"veo/internal/scheduler"
	"veo/pkg/dirscan"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
)

func (sc *ScanController) runDirscanModule(targets []string) ([]interfaces.HTTPResponse, error) {
	originalContext := sc.requestProcessor.GetModuleContext()
	sc.requestProcessor.SetModuleContext("dirscan")
	defer func() {
		sc.requestProcessor.SetModuleContext(originalContext)
	}()

	// [强制配置] 在运行目录扫描前，强制更新 RequestProcessor 的重定向配置
	reqConfig := sc.requestProcessor.GetConfig()
	if !reqConfig.FollowRedirect || reqConfig.MaxRedirects < 3 {
		reqConfig.FollowRedirect = true
		if reqConfig.MaxRedirects < 3 {
			reqConfig.MaxRedirects = 5
		}
		sc.requestProcessor.UpdateConfig(reqConfig)
		logger.Debug("Dirscan模块运行前强制启用重定向跟随 (MaxRedirects=5)")
	}

	// 模块启动提示
	dictInfo := "config/dict/common.txt"
	if strings.TrimSpace(sc.wordlistPath) != "" {
		dictInfo = sc.wordlistPath
	}
	// 模块开始前空行，提升可读性
	logger.Infof("Start Dirscan, Loaded Dict: %s", dictInfo)
	logger.Debugf("开始目录扫描，目标数量: %d", len(targets))

	var allResults []interfaces.HTTPResponse

	// 初始化递归变量
	currentTargets := targets
	alreadyScanned := make(map[string]bool)

	// 预先标记初始目标
	for _, t := range targets {
		alreadyScanned[t] = true
		// 同时也标记带斜杠的版本（如果不带斜杠），防止重复扫描
		if !strings.HasSuffix(t, "/") {
			alreadyScanned[t+"/"] = true
		}
	}

	// 递归循环: 0 (Base) -> Depth
	maxDepth := sc.args.Depth
	// 如果 args.Depth == 0，表示关闭递归（只扫第0层）

	for d := 0; d <= maxDepth; d++ {
		if len(currentTargets) == 0 {
			break
		}

		if d > 0 {
			// 打印递归扫描提示
			logger.Infof("正在进行第 %d 层递归目录扫描，目标数量: %d", d, len(currentTargets))
		}

		var results []interfaces.HTTPResponse
		var err error

		// 多目标优化：判断是否使用并发扫描
		if len(currentTargets) > 1 {
			results, err = sc.runConcurrentDirscan(currentTargets, d > 0)
		} else {
			results, err = sc.runSequentialDirscan(currentTargets, d > 0)
		}

		if err != nil {
			logger.Errorf("目录扫描出错 (Depth %d): %v", d, err)
		}

		if len(results) > 0 {
			allResults = append(allResults, results...)
		}

		// 如果还没达到最大深度，提取下一层目标
		if d < maxDepth {
			newTargets := dirscan.ExtractNextLevelTargets(results, alreadyScanned)

			// 更新已扫描集合
			var validNewTargets []string
			for _, nt := range newTargets {
				alreadyScanned[nt] = true
				validNewTargets = append(validNewTargets, nt)
			}
			currentTargets = validNewTargets
		}
	}

	return allResults, nil
}

func (sc *ScanController) runConcurrentDirscan(targets []string, recursive bool) ([]interfaces.HTTPResponse, error) {
	logger.Debugf("目标数量: %d", len(targets))

	// 创建目标调度器
	scheduler := scheduler.NewTargetScheduler(targets, sc.config)
	scheduler.SetRecursive(recursive)

	// 设置基础请求处理器，确保统计更新正常工作
	scheduler.SetBaseRequestProcessor(sc.requestProcessor)

	// 执行并发扫描
	targetResults, err := scheduler.ExecuteConcurrentScan()
	if err != nil {
		return nil, fmt.Errorf("多目标并发扫描失败: %v", err)
	}

	// [修改] 对每个目标的结果独立应用过滤器，然后合并
	var allResults []interfaces.HTTPResponse
	for target, responses := range targetResults {
		logger.Debugf("处理目标 %s 的 %d 个响应", target, len(responses))

		// 转换为接口类型
		var targetResponses []interfaces.HTTPResponse
		for _, resp := range responses {
			httpResp := interfaces.HTTPResponse{
				URL:             resp.URL,
				StatusCode:      resp.StatusCode,
				ContentLength:   resp.ContentLength,
				ContentType:     resp.ContentType,
				Body:            resp.ResponseBody,
				ResponseHeaders: resp.ResponseHeaders,
				RequestHeaders:  resp.RequestHeaders,
				ResponseBody:    resp.ResponseBody,
				Title:           resp.Title,
				Server:          resp.Server,
				Duration:        resp.Duration,
				IsDirectory:     strings.HasSuffix(resp.URL, "/"),
			}
			targetResponses = append(targetResponses, httpResp)
		}

		// [新增] 对单个目标立即应用过滤器
		if len(targetResponses) > 0 {
			filterResult, err := sc.applyFilterForTarget(targetResponses, target)
			if err != nil {
				logger.Errorf("目标 %s 过滤器应用失败: %v", target, err)
				// 如果过滤失败，使用原始结果
				allResults = append(allResults, targetResponses...)
			} else {
				// 使用过滤后的结果
				allResults = append(allResults, filterResult.ValidPages...)

				// 收集被过滤的页面用于报告
				sc.collectedResultsMu.Lock()
				sc.collectedPrimaryFiltered = append(sc.collectedPrimaryFiltered, filterResult.PrimaryFilteredPages...)
				sc.collectedStatusFiltered = append(sc.collectedStatusFiltered, filterResult.StatusFilteredPages...)
				sc.collectedResultsMu.Unlock()
			}
		}
	}

	return allResults, nil
}

func (sc *ScanController) runSequentialDirscan(targets []string, recursive bool) ([]interfaces.HTTPResponse, error) {
	var allResults []interfaces.HTTPResponse

	for _, target := range targets {
		// 生成扫描URL
		scanURLs := sc.generateDirscanURLs(target, recursive)
		logger.Debugf("为 %s 生成了 %d 个扫描URL", target, len(scanURLs))

		// 发起HTTP请求
		responses := sc.requestProcessor.ProcessURLs(scanURLs)

		// 转换为接口类型
		var targetResponses []interfaces.HTTPResponse
		for _, resp := range responses {
			httpResp := interfaces.HTTPResponse{
				URL:             resp.URL,
				StatusCode:      resp.StatusCode,
				ContentLength:   resp.ContentLength,
				ContentType:     resp.ContentType,
				Body:            resp.ResponseBody,
				ResponseHeaders: resp.ResponseHeaders,
				RequestHeaders:  resp.RequestHeaders,
				ResponseBody:    resp.ResponseBody,
				Title:           resp.Title,
				Server:          resp.Server,
				Duration:        resp.Duration,
				IsDirectory:     strings.HasSuffix(resp.URL, "/"),
			}
			targetResponses = append(targetResponses, httpResp)
		}

		// [新增] 对单个目标立即应用过滤器
		if len(targetResponses) > 0 {
			filterResult, err := sc.applyFilterForTarget(targetResponses, target)
			if err != nil {
				logger.Errorf("目标 %s 过滤器应用失败: %v", target, err)
				// 如果过滤失败，使用原始结果
				allResults = append(allResults, targetResponses...)
			} else {
				// 使用过滤后的结果
				allResults = append(allResults, filterResult.ValidPages...)

				// 收集被过滤的页面用于报告
				sc.collectedResultsMu.Lock()
				sc.collectedPrimaryFiltered = append(sc.collectedPrimaryFiltered, filterResult.PrimaryFilteredPages...)
				sc.collectedStatusFiltered = append(sc.collectedStatusFiltered, filterResult.StatusFilteredPages...)
				sc.collectedResultsMu.Unlock()
			}
		}

		// 更新已完成主机数统计（单目标扫描）
		if sc.statsDisplay.IsEnabled() {
			sc.statsDisplay.IncrementCompletedHosts()
			logger.Debugf("单目标扫描完成目标 %s，更新已完成主机数", target)
		}
	}
	return allResults, nil
}

func (sc *ScanController) generateDirscanURLs(target string, recursive bool) []string {
	parsedURL, err := url.Parse(target)
	if err != nil {
		logger.Errorf("URL解析失败: %v", err)
		return []string{target}
	}

	baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	path := strings.Trim(parsedURL.Path, "/")
	if path == "" {
		if recursive {
			return sc.urlGenerator.GenerateRecursiveURLs([]string{baseURL})
		}
		return sc.urlGenerator.GenerateURLs([]string{baseURL})
	}

	pathParts := strings.Split(path, "/")
	var scanTargets []string

	currentPath := ""
	for _, part := range pathParts {
		currentPath += "/" + part
		scanTarget := baseURL + currentPath
		if !strings.HasSuffix(scanTarget, "/") {
			scanTarget += "/"
		}
		scanTargets = append(scanTargets, scanTarget)
	}

	if recursive {
		// 递归模式：只扫描最终的目标路径，不生成中间路径的扫描任务
		// 但这里的 scanTargets 生成逻辑其实是把每一层都加进去了
		// 如果是递归模式，我们其实只关心最后一个 scanTarget
		if len(scanTargets) > 0 {
			lastTarget := scanTargets[len(scanTargets)-1]
			return sc.urlGenerator.GenerateRecursiveURLs([]string{lastTarget})
		}
		return sc.urlGenerator.GenerateRecursiveURLs(scanTargets)
	}
	return sc.urlGenerator.GenerateURLs(scanTargets)
}
