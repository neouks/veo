package fingerprint

import (
	"encoding/json"
	"fmt"

	"veo/pkg/utils/logger"
)

// JSONOutputFormatter JSON输出格式化器
// 以JSON格式输出指纹识别结果，便于机器解析
type JSONOutputFormatter struct {
	deduplicator *Deduplicator
}

// NewJSONOutputFormatter 创建JSON输出格式化器
func NewJSONOutputFormatter() *JSONOutputFormatter {
	return &JSONOutputFormatter{
		deduplicator: NewDeduplicator(),
	}
}

// JSONResult 用于JSON输出的结构体
type JSONResult struct {
	URL           string              `json:"url"`
	StatusCode    int                 `json:"status_code"`
	Title         string              `json:"title"`
	ContentLength int64               `json:"content_length"`
	ContentType   string              `json:"content_type"`
	Fingerprints  []*FingerprintMatch `json:"fingerprints,omitempty"`
	Tags          []string            `json:"tags,omitempty"`
}

// FormatMatch 实现OutputFormatter接口
func (f *JSONOutputFormatter) FormatMatch(matches []*FingerprintMatch, response *HTTPResponse, tags ...string) {
	if len(matches) == 0 || response == nil {
		return
	}

	uniqueMatches := uniqueMatchesByRuleName(matches)
	if len(uniqueMatches) == 0 {
		return
	}

	// 收集指纹名称(用于去重)
	fingerprintNames := make([]string, 0, len(uniqueMatches))
	for _, match := range uniqueMatches {
		fingerprintNames = append(fingerprintNames, match.RuleName)
	}

	// 去重检查
	if !f.ShouldOutput(response.URL, fingerprintNames) {
		return
	}

	// 构造结果对象
	res := JSONResult{
		URL:           response.URL,
		StatusCode:    response.StatusCode,
		Title:         response.Title,
		ContentLength: response.ContentLength,
		ContentType:   response.ContentType,
		Fingerprints:  uniqueMatches,
		Tags:          tags,
	}

	// 序列化并输出
	if data, err := json.Marshal(res); err == nil {
		// 使用fmt.Println直接输出纯JSON，避免logger添加额外的时间戳前缀
		// 除非logger已经配置为JSON模式。这里假设为了兼容性，直接输出到标准输出。
		// 但为了保持与veo的日志系统一致，我们还是用logger.Info，
		// 但通常JSON模式下用户可能希望纯净输出。
		// 考虑到这是一个CLI工具，JSON输出通常意味着 --json 参数，
		// 此时通常应该只输出 JSON。
		// 这里我们使用 fmt.Println 确保输出是原始 JSON 字符串。
		fmt.Println(string(data))
	} else {
		logger.Errorf("JSON序列化失败: %v", err)
	}
}

// FormatNoMatch 实现OutputFormatter接口
func (f *JSONOutputFormatter) FormatNoMatch(response *HTTPResponse) {
	// 即使没有指纹匹配，如果需要JSON输出所有请求，也可以在这里实现。
	// 但通常指纹识别只关注命中的结果。
	// 如果需要输出无匹配结果，可以在这里添加逻辑。
	// 目前保持与ConsoleOutputFormatter一致的逻辑：
	// ConsoleFormatter 在 outputNoMatchInfo 中也是有条件的 (logMatches)。
	// 如果 JSON 模式下用户希望看到所有尝试过的 URL，可以输出。
	// 这里暂不输出无匹配项，以免污染 JSON 流。
}

// ShouldOutput 实现OutputFormatter接口
func (f *JSONOutputFormatter) ShouldOutput(urlStr string, fingerprintNames []string) bool {
	return f.deduplicator.ShouldOutput(urlStr, fingerprintNames)
}
