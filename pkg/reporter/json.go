package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"veo/pkg/types"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
)

// CombinedAPIResponse 统一的API/CLI JSON响应结构
type CombinedAPIResponse struct {
	Fingerprint []FingerprintAPIPage `json:"fingerprint,omitempty"`
	Dirscan     []DirscanAPIPage     `json:"dirscan,omitempty"`
}

type FingerprintAPIPage struct {
	URL         string                      `json:"url"`
	StatusCode  int                         `json:"status_code"`
	Title       string                      `json:"title,omitempty"`
	ContentType string                      `json:"content_type,omitempty"`
	DurationMs  int64                       `json:"duration_ms"`
	Matches     []SDKFingerprintMatchOutput `json:"matches,omitempty"`
}

type DirscanAPIPage struct {
	URL           string                      `json:"url"`
	StatusCode    int                         `json:"status_code"`
	Title         string                      `json:"title,omitempty"`
	ContentLength int64                       `json:"content_length"`
	ContentType   string                      `json:"content_type,omitempty"`
	DurationMs    int64                       `json:"duration_ms"`
	Fingerprints  []SDKFingerprintMatchOutput `json:"fingerprints,omitempty"`
}

type SDKFingerprintMatchOutput struct {
	RuleName    string `json:"rule_name"`
	RuleContent string `json:"rule_content,omitempty"`
}

// buildCombinedAPIResponse 构建统一的API/CLI JSON响应结构
func (jrg *JSONReportGenerator) buildCombinedAPIResponse(dirPages []interfaces.HTTPResponse, fpPages []interfaces.HTTPResponse, matches []types.FingerprintMatch, stats *FingerprintStats, scanParams map[string]interface{}) CombinedAPIResponse {
	dirPagesAPI := makeDirscanPageResults(dirPages)
	fpPagesAPI := makeFingerprintPageResults(fpPages, matches)

	return CombinedAPIResponse{
		Fingerprint: fpPagesAPI,
		Dirscan:     dirPagesAPI,
	}
}
type JSONReportGenerator struct {
	startTime  time.Time
	outputPath string
}

// NewJSONReportGenerator 创建新的JSON报告生成器
func NewJSONReportGenerator() *JSONReportGenerator {
	return &JSONReportGenerator{
		startTime: time.Now(),
	}
}

// NewCustomJSONReportGenerator 创建自定义输出路径的JSON报告生成器
func NewCustomJSONReportGenerator(outputPath string) *JSONReportGenerator {
	return &JSONReportGenerator{
		startTime:  time.Now(),
		outputPath: outputPath,
	}
}

// GenerateDirscanReport 生成目录扫描JSON报告
func (jrg *JSONReportGenerator) GenerateDirscanReport(filterResult *interfaces.FilterResult, target string, scanParams map[string]interface{}) (string, error) {
	dirPages := extractResponses(filterResult)
	resp := jrg.buildCombinedAPIResponse(dirPages, nil, nil, nil, scanParams)
	return jrg.saveCombinedResponse(resp, target, "dirscan")
}

// FingerprintStats 报告所需的指纹统计摘要
type FingerprintStats struct {
	TotalRequests    int64     `json:"total_requests"`
	MatchedRequests  int64     `json:"matched_requests"`
	FilteredRequests int64     `json:"filtered_requests"`
	RulesLoaded      int       `json:"rules_loaded"`
	StartTime        time.Time `json:"start_time"`
	LastMatchTime    time.Time `json:"last_match_time"`
}

// GenerateFingerprintReport 生成指纹识别JSON报告
func (jrg *JSONReportGenerator) GenerateFingerprintReport(responses []interfaces.HTTPResponse, matches []types.FingerprintMatch, stats *FingerprintStats, target string, scanParams map[string]interface{}) (string, error) {
	resp := jrg.buildCombinedAPIResponse(nil, responses, matches, stats, scanParams)
	return jrg.saveCombinedResponse(resp, target, "fingerprint")
}

func GenerateCombinedJSON(dirPages []interfaces.HTTPResponse, fingerprintPages []interfaces.HTTPResponse, matches []types.FingerprintMatch, stats *FingerprintStats, scanParams map[string]interface{}) (string, error) {
	generator := NewJSONReportGenerator()
	result := generator.buildCombinedAPIResponse(dirPages, fingerprintPages, matches, stats, scanParams)
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("JSON序列化失败: %v", err)
	}
	return string(data), nil
}

// GenerateCustomCombinedJSON 生成合并JSON报告（写入指定文件）
func GenerateCustomCombinedJSON(dirPages []interfaces.HTTPResponse, fingerprintPages []interfaces.HTTPResponse, matches []types.FingerprintMatch, stats *FingerprintStats, target string, scanParams map[string]interface{}, outputPath string) (string, error) {
	jrg := NewCustomJSONReportGenerator(outputPath)
	result := jrg.buildCombinedAPIResponse(dirPages, fingerprintPages, matches, stats, scanParams)
	return jrg.saveCombinedResponse(result, target, "combined")
}

// extractResponses 提取过滤结果中的有效页面
func extractResponses(filterResult *interfaces.FilterResult) []interfaces.HTTPResponse {
	if filterResult == nil {
		return nil
	}

	pages := filterResult.ValidPages
	if len(pages) == 0 {
		return nil
	}

	copied := make([]interfaces.HTTPResponse, len(pages))
	copy(copied, pages)
	return copied
}

// buildCombinedAPIResponse 构建统一的API/CLI JSON响应结构
// func (jrg *JSONReportGenerator) buildCombinedAPIResponse(dirPages []interfaces.HTTPResponse, fpPages []interfaces.HTTPResponse, matches []types.FingerprintMatch, stats *FingerprintStats, scanParams map[string]interface{}) CombinedAPIResponse {
// 	dirPagesAPI := makeDirscanPageResults(dirPages)
// 	fpPagesAPI := makeFingerprintPageResults(fpPages, matches)
//
// 	return CombinedAPIResponse{
// 		Fingerprint: fpPagesAPI,
// 		Dirscan:     dirPagesAPI,
// 	}
// }

func (jrg *JSONReportGenerator) saveCombinedResponse(resp CombinedAPIResponse, target, scanType string) (string, error) {
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return "", fmt.Errorf("JSON序列化失败: %v", err)
	}

	var filePath string

	if jrg.outputPath != "" {
		filePath = jrg.outputPath
		outputDir := filepath.Dir(filePath)
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return "", fmt.Errorf("创建输出目录失败: %v", err)
		}
	} else {
		timestamp := time.Now().Format("20060102_150405")
		safeName := sanitizeFilename(target)
		prefix := scanType
		if prefix == "" {
			prefix = "combined"
		}
		fileName := fmt.Sprintf("%s_%s_%s.json", prefix, safeName, timestamp)

		outputDir := "./reports"
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return "", fmt.Errorf("创建输出目录失败: %v", err)
		}

		filePath = filepath.Join(outputDir, fileName)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return "", fmt.Errorf("写入JSON文件失败: %v", err)
	}

	logger.Debugf("JSON报告已生成: %s", filePath)
	return filePath, nil
}

// makeDirscanPageResults 构造目录扫描结果列表
func makeDirscanPageResults(pages []interfaces.HTTPResponse) []DirscanAPIPage {
	if len(pages) == 0 {
		return nil
	}

	results := make([]DirscanAPIPage, 0, len(pages))
	for _, page := range pages {
		length := page.ContentLength
		if length == 0 {
			length = page.Length
		}

		results = append(results, DirscanAPIPage{
			URL:           page.URL,
			StatusCode:    page.StatusCode,
			Title:         page.Title,
			ContentLength: length,
			DurationMs:    page.Duration,
			ContentType:   page.ContentType,
			Fingerprints:  toSDKMatchesFromInterfaces(page.Fingerprints),
		})
	}

	return results
}

// makeFingerprintPageResults 构造指纹识别结果列表
func makeFingerprintPageResults(pages []interfaces.HTTPResponse, matches []types.FingerprintMatch) []FingerprintAPIPage {
	if len(pages) == 0 && len(matches) == 0 {
		return nil
	}

	matchMap := groupMatchesByURL(matches)
	results := make([]FingerprintAPIPage, 0, len(pages)+len(matchMap))
	seen := make(map[string]bool, len(pages))

	for _, page := range pages {
		length := page.ContentLength
		if length == 0 {
			length = page.Length
		}

		existing := toSDKMatchesFromInterfaces(page.Fingerprints)
		fps := matchMap[page.URL]
		if len(fps) > 0 {
			existing = mergeFingerprintOutputs(existing, fps)
		}
		results = append(results, FingerprintAPIPage{
			URL:         page.URL,
			StatusCode:  page.StatusCode,
			Title:       page.Title,
			ContentType: page.ContentType,
			DurationMs:  page.Duration,
			Matches:     existing,
		})
		seen[page.URL] = true
	}

	// 对于仅有指纹匹配记录但没有响应的URL，也进行输出
	for url, fps := range matchMap {
		if seen[url] {
			continue
		}
		if len(fps) == 0 {
			continue
		}
		results = append(results, FingerprintAPIPage{
			URL:     url,
			Matches: fps,
		})
	}

	return results
}

// groupMatchesByURL 将指纹匹配结果按URL分组
func groupMatchesByURL(matches []types.FingerprintMatch) map[string][]SDKFingerprintMatchOutput {
	if len(matches) == 0 {
		return nil
	}

	grouped := make(map[string][]SDKFingerprintMatchOutput)
	for _, match := range matches {
		url := match.URL
		grouped[url] = append(grouped[url], SDKFingerprintMatchOutput{
			RuleName:    match.RuleName,
			RuleContent: match.DSLMatched,
		})
	}
	return grouped
}

func toSDKMatchesFromInterfaces(matches []interfaces.FingerprintMatch) []SDKFingerprintMatchOutput {
	if len(matches) == 0 {
		return nil
	}

	outputs := make([]SDKFingerprintMatchOutput, 0, len(matches))
	for _, match := range matches {
		outputs = append(outputs, SDKFingerprintMatchOutput{
			RuleName:    match.RuleName,
			RuleContent: match.Matcher,
		})
	}

	return outputs
}

func mergeFingerprintOutputs(base []SDKFingerprintMatchOutput, extra []SDKFingerprintMatchOutput) []SDKFingerprintMatchOutput {
	if len(extra) == 0 {
		return base
	}

	if len(base) == 0 {
		merged := make([]SDKFingerprintMatchOutput, len(extra))
		copy(merged, extra)
		return merged
	}

	keyIndex := make(map[string]int, len(base))
	for idx, item := range base {
		key := item.RuleName + "|" + item.RuleContent
		keyIndex[key] = idx
	}

	for _, item := range extra {
		key := item.RuleName + "|" + item.RuleContent
		if _, ok := keyIndex[key]; ok {
			continue
		}
		keyIndex[key] = len(base)
		base = append(base, item)
	}

	return base
}

// sanitizeFilename 清理文件名中的非法字符
func sanitizeFilename(filename string) string {
	replacer := strings.NewReplacer(
		":", "_",
		"/", "_",
		"\\", "_",
		"?", "_",
		"*", "_",
		"|", "_",
		"<", "_",
		">", "_",
		"\"", "_",
	)
	return replacer.Replace(filename)
}
