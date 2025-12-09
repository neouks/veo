package cli

import (
	"fmt"
	"net/url"
	"strings"

	modulepkg "veo/pkg/core/module"
	"veo/pkg/dirscan"
	"veo/pkg/fingerprint"
	report "veo/pkg/reporter"
	"veo/pkg/types"
	"veo/pkg/utils/formatter"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
	sharedutils "veo/pkg/utils/shared"
)

func (sc *ScanController) applyFilterForTarget(responses []interfaces.HTTPResponse, target string) (*interfaces.FilterResult, error) {
	logger.Debugf("开始对目标 %s 应用过滤器，响应数量: %d", target, len(responses))

	// 提取站点Key（Scheme + Host）作为过滤器复用的依据
	// 这样同一站点的不同目录扫描（递归）可以共享Hash过滤状态
	targetKey := sc.extractBaseURL(target)

	sc.siteFiltersMu.Lock()
	responseFilter, exists := sc.siteFilters[targetKey]
	if !exists {
		// 如果不存在，创建新的过滤器
		responseFilter = dirscan.CreateResponseFilterFromExternal()
		responseFilter.EnableFingerprintSnippet(sc.showFingerprintSnippet)
		responseFilter.EnableFingerprintRuleDisplay(sc.showFingerprintRule)

		// [新增] 如果指纹引擎可用，设置到过滤器中（启用二次识别）
		if sc.fingerprintEngine != nil {
			responseFilter.SetFingerprintEngine(sc.fingerprintEngine)
			logger.Debugf("目录扫描模块已启用指纹二次识别功能，引擎类型: %T", sc.fingerprintEngine)
		} else {
			logger.Debugf("指纹引擎为nil，未启用二次识别")
		}

		sc.siteFilters[targetKey] = responseFilter
		logger.Debugf("为站点 %s 创建新的过滤器", targetKey)
	} else {
		logger.Debugf("复用站点 %s 的过滤器状态", targetKey)
	}
	sc.siteFiltersMu.Unlock()

	// [关键修改] 不再调用 responseFilter.Reset()
	// 因为我们希望在递归扫描过程中保留Hash过滤的历史记录
	// 从而避免上一层已经出现过的页面内容在下一层再次出现时被误判为新页面

	// 应用过滤器
	filterResult := responseFilter.FilterResponses(responses)
	logger.Debugf("过滤器返回 - ValidPages: %d, PrimaryFiltered: %d, StatusFiltered: %d",
		len(filterResult.ValidPages), len(filterResult.PrimaryFilteredPages), len(filterResult.StatusFilteredPages))

	// [去重] 全局结果去重，只显示未显示过的URL
	sc.displayedURLsMu.Lock()
	var uniqueValidPages []interfaces.HTTPResponse
	for _, page := range filterResult.ValidPages {
		if !sc.displayedURLs[page.URL] {
			sc.displayedURLs[page.URL] = true
			uniqueValidPages = append(uniqueValidPages, page)
		}
	}
	filterResult.ValidPages = uniqueValidPages
	sc.displayedURLsMu.Unlock()

	// 显示单个目标的过滤结果（现在会包含指纹信息）
	logger.Debugf("目标 %s 过滤完成:", target)
	responseFilter.PrintFilterResult(filterResult)

	logger.Debugf("目标 %s 过滤完成 - 原始响应: %d, 有效结果: %d",
		target, len(responses), len(filterResult.ValidPages))

	return filterResult, nil
}

func (sc *ScanController) buildScanParams() map[string]interface{} {
	params := map[string]interface{}{
		"threads":                   sc.maxConcurrent,
		"timeout":                   sc.timeoutSeconds,
		"retry":                     sc.retryCount,
		"dir_targets_count":         0,
		"fingerprint_targets_count": 0,
		"fingerprint_rules_loaded":  0,
	}

	if sc.args.HasModule(string(modulepkg.ModuleDirscan)) {
		params["dir_targets_count"] = len(sc.lastTargets)
	}

	if sc.args.HasModule(string(modulepkg.ModuleFinger)) {
		params["fingerprint_targets_count"] = len(sc.lastTargets)
	}

	if sc.fingerprintEngine != nil {
		if stats := sc.fingerprintEngine.GetStats(); stats != nil {
			params["fingerprint_rules_loaded"] = stats.RulesLoaded
		}
	}

	return params
}

func (sc *ScanController) generateReport(filterResult *interfaces.FilterResult) error {
	reportPath := strings.TrimSpace(sc.reportPath)
	if reportPath == "" {
		logger.Debug("未指定输出路径，跳过报告生成")
		return nil
	}

	// 构造配置
	reportConfig := &ReportConfig{
		Modules:                sc.args.Modules,
		OutputPath:             reportPath,
		ShowFingerprintSnippet: sc.showFingerprintSnippet,
		ScanParams:             sc.buildScanParams(),
	}

	// 准备指纹结果（如果有）
	// 注意：在 finalizeScan 中已经传递了 fingerprintResults，它是 sc.lastFingerprintResults
	// dirResults 对应 sc.lastDirscanResults
	// filterResult 包含了 ValidPages，但我们需要分离的 dirscan 和 finger 结果来生成 JSON
	// 对于 Excel 报告，GenerateReport 内部会使用 filterResult

	var dirResults, fingerResults []interfaces.HTTPResponse
	if sc.lastDirscanResults != nil {
		dirResults = sc.lastDirscanResults
	}
	if sc.lastFingerprintResults != nil {
		fingerResults = sc.lastFingerprintResults
	}

	// 调用统一的报告生成函数
	err := GenerateReport(reportConfig, dirResults, fingerResults, filterResult, sc.fingerprintEngine)
	if err != nil {
		return fmt.Errorf("报告生成失败: %v", err)
	}

	return nil
}

func (sc *ScanController) generateConsoleJSON(dirPages, fingerprintPages []interfaces.HTTPResponse, filterResult *interfaces.FilterResult) (string, error) {
	var matches []types.FingerprintMatch
	var stats *report.FingerprintStats
	if sc.fingerprintEngine != nil {
		if raw := sc.fingerprintEngine.GetMatches(); len(raw) > 0 {
			matches = convertFingerprintMatches(raw, sc.showFingerprintSnippet)
		}
		stats = toReporterStats(sc.fingerprintEngine.GetStats())
	}

	if len(fingerprintPages) == 0 && sc.args.HasModule(string(modulepkg.ModuleFinger)) {
		fingerprintPages = filterResult.ValidPages
	}

	params := sc.buildScanParams()

	return report.GenerateCombinedJSON(dirPages, fingerprintPages, matches, stats, params)
}

func (sc *ScanController) convertToFingerprintResponse(resp *interfaces.HTTPResponse) *fingerprint.HTTPResponse {
	if resp == nil {
		return nil
	}

	// 转换响应头格式（interfaces.HTTPResponse.ResponseHeaders已经是map[string][]string）
	headers := resp.ResponseHeaders
	if headers == nil {
		headers = make(map[string][]string)
	}

	// 关键修复：处理响应体解压缩和编码转换
	processedBody := sc.processResponseBody(resp)

	// 提取处理后的标题（使用解压缩和编码转换后的内容）
	title := sc.extractTitleFromHTML(processedBody)

	logger.Debugf("响应体处理完成: %s (原始: %d bytes, 处理后: %d bytes)",
		resp.URL, len(resp.ResponseBody), len(processedBody))

	return &fingerprint.HTTPResponse{
		URL:             resp.URL,
		Method:          "GET", // 主动扫描默认使用GET方法
		StatusCode:      resp.StatusCode,
		ResponseHeaders: headers,
		Body:            processedBody, // 使用处理后的响应体
		ContentType:     resp.ContentType,
		ContentLength:   int64(len(processedBody)), // 更新为处理后的长度
		Server:          resp.Server,
		Title:           title, // 使用处理后的标题
	}
}

func (sc *ScanController) processResponseBody(resp *interfaces.HTTPResponse) string {
	if resp == nil || resp.ResponseBody == "" {
		return ""
	}

	rawBody := resp.ResponseBody

	// 步骤1: 检查Content-Encoding并解压缩
	decompressedBody := sc.decompressResponseBody(rawBody, resp.ResponseHeaders)

	// 步骤2: 字符编码检测和转换
	convertedBody := sc.encodingDetector.DetectAndConvert(decompressedBody, resp.ContentType)

	logger.Debugf("响应体处理: %s (原始: %d -> 解压: %d -> 转换: %d bytes)",
		resp.URL, len(rawBody), len(decompressedBody), len(convertedBody))

	return convertedBody
}

func (sc *ScanController) decompressResponseBody(body string, headers map[string][]string) string {
	if body == "" {
		return ""
	}

	// 获取Content-Encoding头部
	var contentEncoding string
	if headers != nil {
		if encodingHeaders, exists := headers["Content-Encoding"]; exists && len(encodingHeaders) > 0 {
			contentEncoding = encodingHeaders[0]
		}
	}

	decompressed := sharedutils.DecompressByEncoding([]byte(body), contentEncoding)
	return string(decompressed)
}

func (sc *ScanController) extractTitleFromHTML(body string) string {
	return sharedutils.ExtractTitle(body)
}

func (sc *ScanController) formatFingerprintDisplay(name, rule string) string {
	return formatter.FormatFingerprintDisplay(name, rule, sc.showFingerprintRule)
}

func (sc *ScanController) highlightSnippetLines(snippet, matcher string) []string {
	if snippet == "" {
		return nil
	}
	snippet = strings.ReplaceAll(snippet, "\r\n", "\n")
	snippet = strings.ReplaceAll(snippet, "\r", "\n")
	rawLines := strings.Split(snippet, "\n")
	var lines []string
	for _, raw := range rawLines {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		highlighted := formatter.HighlightSnippet(raw, matcher)
		if highlighted != "" {
			lines = append(lines, highlighted)
		}
	}
	if len(lines) == 0 {
		if highlighted := formatter.HighlightSnippet(strings.TrimSpace(snippet), matcher); highlighted != "" {
			lines = append(lines, highlighted)
		}
	}
	return lines
}

// extractBaseURL 从完整URL中提取基础URL（协议+主机）
func (sc *ScanController) extractBaseURL(rawURL string) string {
	if parsedURL, err := url.Parse(rawURL); err == nil {
		return fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	}
	return rawURL
}

// extractHostKey 提取主机键（用于探测缓存）
func (sc *ScanController) extractHostKey(rawURL string) string {
	if parsedURL, err := url.Parse(rawURL); err == nil {
		return parsedURL.Host // 包含端口的主机名
	}
	return rawURL
}
