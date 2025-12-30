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
	onOutput     func(response *HTTPResponse, matches []*FingerprintMatch, tags []string)
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

	if f.onOutput != nil {
		f.onOutput(response, uniqueMatches, tags)
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

	if data, err := json.Marshal(res); err == nil {
		fmt.Println(string(data))
	} else {
		logger.Errorf("JSON序列化失败: %v", err)
	}
}

// FormatNoMatch 实现OutputFormatter接口
func (f *JSONOutputFormatter) FormatNoMatch(response *HTTPResponse) {
	if response == nil {
		return
	}

	if !f.ShouldOutput(response.URL, nil) {
		return
	}

	if f.onOutput != nil {
		f.onOutput(response, nil, nil)
	}

	res := JSONResult{
		URL:           response.URL,
		StatusCode:    response.StatusCode,
		Title:         response.Title,
		ContentLength: response.ContentLength,
		ContentType:   response.ContentType,
	}

	if data, err := json.Marshal(res); err == nil {
		fmt.Println(string(data))
	} else {
		logger.Errorf("JSON序列化失败: %v", err)
	}
}

// ShouldOutput 实现OutputFormatter接口
func (f *JSONOutputFormatter) ShouldOutput(urlStr string, fingerprintNames []string) bool {
	return f.deduplicator.ShouldOutput(urlStr, fingerprintNames)
}

// SetOutputHook 设置输出回调（仅在实际输出时触发）
func (f *JSONOutputFormatter) SetOutputHook(hook func(response *HTTPResponse, matches []*FingerprintMatch, tags []string)) {
	f.onOutput = hook
}
