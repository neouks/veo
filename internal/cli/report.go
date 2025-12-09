package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	modulepkg "veo/pkg/core/module"
	"veo/pkg/fingerprint"
	report "veo/pkg/reporter"
	"veo/pkg/types"
	"veo/pkg/utils/formatter"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
)

// ReportConfig 报告生成配置
type ReportConfig struct {
	Modules                []string
	OutputPath             string
	ShowFingerprintSnippet bool
	// ScanParams 用于JSON报告的扫描参数
	ScanParams map[string]interface{}
}

// GenerateReport 生成报告（通用函数）
func GenerateReport(config *ReportConfig, dirResults, fingerprintResults []interfaces.HTTPResponse, filterResult *interfaces.FilterResult, fpEngine *fingerprint.Engine) error {
	reportPath := strings.TrimSpace(config.OutputPath)
	if reportPath == "" {
		logger.Debug("未指定输出路径，跳过报告生成")
		return nil
	}

	if _, err := os.Stat(reportPath); err == nil {
		logger.Infof("Override Files: %s", reportPath)
	}

	finalPath, err := generateCustomReport(config, dirResults, fingerprintResults, filterResult, fpEngine, reportPath)
	if err != nil {
		return fmt.Errorf("报告生成失败: %v", err)
	}

	logger.Infof("Report Output Success: %s", finalPath)
	return nil
}

func generateCustomReport(config *ReportConfig, dirResults, fingerprintResults []interfaces.HTTPResponse, filterResult *interfaces.FilterResult, fpEngine *fingerprint.Engine, outputPath string) (string, error) {
	logger.Debugf("开始生成自定义报告到: %s", outputPath)

	lowerOutput := strings.ToLower(outputPath)
	switch {
	case strings.HasSuffix(lowerOutput, ".json"):
		// 指纹匹配信息
		var matches []types.FingerprintMatch
		var stats *fingerprint.Statistics
		if fpEngine != nil {
			if raw := fpEngine.GetMatches(); len(raw) > 0 {
				matches = convertFingerprintMatches(raw, config.ShowFingerprintSnippet)
			}
			stats = fpEngine.GetStats()
		}

		// 确保指纹结果列表不为空（如果只有dirscan结果，filterResult中可能包含所有）
		if len(fingerprintResults) == 0 && hasModule(config.Modules, string(modulepkg.ModuleFinger)) {
			fingerprintResults = filterResult.ValidPages
		}

		jsonStr, err := report.GenerateCombinedJSON(dirResults, fingerprintResults, matches, toReporterStats(stats), config.ScanParams)
		if err != nil {
			return "", err
		}
		if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
			return "", fmt.Errorf("创建输出目录失败: %v", err)
		}
		if err := os.WriteFile(outputPath, []byte(jsonStr), 0o644); err != nil {
			return "", fmt.Errorf("写入JSON文件失败: %v", err)
		}
		return outputPath, nil
	case strings.HasSuffix(lowerOutput, ".xlsx"):
		reportType := determineExcelReportType(config.Modules)
		return report.GenerateExcelReport(filterResult, reportType, outputPath)
	default:
		reportType := determineExcelReportType(config.Modules)
		deducedPath := outputPath
		if filepath.Ext(outputPath) == "" {
			deducedPath = outputPath + ".xlsx"
		} else {
			deducedPath = strings.TrimSuffix(outputPath, filepath.Ext(outputPath)) + ".xlsx"
		}
		logger.Warnf("不支持的报告后缀，默认为xlsx输出: %s", deducedPath)
		return report.GenerateExcelReport(filterResult, reportType, deducedPath)
	}
}

func determineExcelReportType(modules []string) report.ExcelReportType {
	var hasDirscan, hasFingerprint bool
	for _, moduleName := range modules {
		if moduleName == string(modulepkg.ModuleDirscan) {
			hasDirscan = true
		}
		if moduleName == string(modulepkg.ModuleFinger) {
			hasFingerprint = true
		}
	}

	switch {
	case hasDirscan && hasFingerprint:
		return report.ExcelReportDirscanAndFingerprint
	case hasDirscan:
		return report.ExcelReportDirscan
	default:
		return report.ExcelReportFingerprint
	}
}

// 辅助函数：检查模块是否存在
func hasModule(modules []string, module string) bool {
	for _, m := range modules {
		if m == module {
			return true
		}
	}
	return false
}

// 辅助转换函数 (复用 scanner.go 中的逻辑，为了避免循环依赖，这里重新定义或需要 scanner.go 导出)
// 由于 scanner.go 是 main package 的一部分 (internal/cli)，可以直接在这里使用
// 但 convertFingerprintMatches 目前是 ScanController 的未导出方法或独立函数
// 我们需要确保这些辅助函数可用

func convertFingerprintMatches(matches []*fingerprint.FingerprintMatch, includeSnippet bool) []types.FingerprintMatch {
	if len(matches) == 0 {
		return nil
	}

	converted := make([]types.FingerprintMatch, 0, len(matches))
	for _, match := range matches {
		if match == nil {
			continue
		}

		convertedMatch := types.FingerprintMatch{
			URL:       match.URL,
			RuleName:  match.RuleName,
			Matcher:   match.DSLMatched,
			Timestamp: match.Timestamp,
		}
		if includeSnippet {
			convertedMatch.Snippet = match.Snippet
		}
		converted = append(converted, convertedMatch)
	}

	return converted
}

func toReporterStats(stats *fingerprint.Statistics) *report.FingerprintStats {
	if stats == nil {
		return nil
	}
	return &report.FingerprintStats{
		TotalRequests:    stats.TotalRequests,
		MatchedRequests:  stats.MatchedRequests,
		FilteredRequests: stats.FilteredRequests,
		RulesLoaded:      stats.RulesLoaded,
		StartTime:        stats.StartTime,
		LastMatchTime:    stats.LastMatchTime,
	}
}

// FormatFingerprintDisplay 包装 formatter
func FormatFingerprintDisplay(name, rule string, showRule bool) string {
	return formatter.FormatFingerprintDisplay(name, rule, showRule)
}
