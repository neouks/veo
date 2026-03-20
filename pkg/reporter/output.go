package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"veo/pkg/types"
)

// CombinedAPIResponse 统一的API/CLI JSON响应结构
type CombinedAPIResponse struct {
	Fingerprint []FingerprintAPIPage `json:"fingerprint,omitempty"`
	Dirscan     []DirscanAPIPage     `json:"dirscan,omitempty"`
}

type FingerprintAPIPage struct {
	Timestamp     string                      `json:"timestamp"`
	URL           string                      `json:"url"`
	StatusCode    int                         `json:"status_code"`
	Title         string                      `json:"title,omitempty"`
	ContentLength int64                       `json:"content_length"`
	ContentType   string                      `json:"content_type,omitempty"`
	DurationMs    int64                       `json:"duration_ms"`
	Matches       []SDKFingerprintMatchOutput `json:"matches,omitempty"`
}

type DirscanAPIPage struct {
	Timestamp     string                      `json:"timestamp"`
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
	Snippet     string `json:"snippet,omitempty"`
}

type fingerprintMatchGroup struct {
	URL       string
	Timestamp time.Time
	Matches   []SDKFingerprintMatchOutput
}

const outputTimestampLayout = "2006/01/02 15:04:05"

func formatOutputTimestamp(ts time.Time) string {
	return firstNonZeroTime(ts).Local().Format(outputTimestampLayout)
}

func firstNonZeroTime(candidates ...time.Time) time.Time {
	for _, candidate := range candidates {
		if !candidate.IsZero() {
			return candidate
		}
	}
	return time.Now()
}

func buildCombinedAPIResponse(dirPages []types.HTTPResponse, fpPages []types.HTTPResponse, matches []types.FingerprintMatch) CombinedAPIResponse {
	return CombinedAPIResponse{
		Fingerprint: makeFingerprintPageResults(fpPages, matches),
		Dirscan:     makeDirscanPageResults(dirPages),
	}
}

// GenerateCombinedJSON 生成合并 JSON（仅负责序列化，不做文件 IO）
func GenerateCombinedJSON(dirPages []types.HTTPResponse, fingerprintPages []types.HTTPResponse, matches []types.FingerprintMatch) (string, error) {
	result := buildCombinedAPIResponse(dirPages, fingerprintPages, matches)
	data, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("JSON序列化失败: %v", err)
	}
	return string(data), nil
}

// makeDirscanPageResults 构造目录扫描结果列表
func makeDirscanPageResults(pages []types.HTTPResponse) []DirscanAPIPage {
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
			Timestamp:     formatOutputTimestamp(page.Timestamp),
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
func makeFingerprintPageResults(pages []types.HTTPResponse, matches []types.FingerprintMatch) []FingerprintAPIPage {
	if len(pages) == 0 && len(matches) == 0 {
		return nil
	}

	matchMap := groupMatchesByURL(matches)
	results := make([]FingerprintAPIPage, 0, len(pages)+len(matchMap))
	index := make(map[string]int, len(pages))

	for _, page := range pages {
		key := NormalizeFingerprintURLKey(page.URL)
		group := matchMap[key]
		var fps []SDKFingerprintMatchOutput
		if group != nil {
			fps = group.Matches
		}
		if existingIdx, ok := index[key]; ok {
			existing := results[existingIdx]
			existing.Matches = mergeFingerprintOutputs(existing.Matches, toSDKMatchesFromInterfaces(page.Fingerprints))
			if len(fps) > 0 {
				existing.Matches = mergeFingerprintOutputs(existing.Matches, fps)
			}
			if existing.ContentLength == 0 {
				if page.ContentLength > 0 {
					existing.ContentLength = page.ContentLength
				} else if page.Length > 0 {
					existing.ContentLength = page.Length
				}
			}
			if existing.StatusCode == 0 {
				existing.StatusCode = page.StatusCode
			}
			if existing.Title == "" {
				existing.Title = page.Title
			}
			if existing.ContentType == "" {
				existing.ContentType = page.ContentType
			}
			if existing.DurationMs == 0 {
				existing.DurationMs = page.Duration
			}
			if existing.Timestamp == "" {
				existing.Timestamp = formatOutputTimestamp(firstNonZeroTime(page.Timestamp, groupTimestamp(group)))
			}
			results[existingIdx] = existing
		} else {
			contentLength := page.ContentLength
			if contentLength == 0 {
				contentLength = page.Length
			}
			existing := toSDKMatchesFromInterfaces(page.Fingerprints)
			if len(fps) > 0 {
				existing = mergeFingerprintOutputs(existing, fps)
			}
			results = append(results, FingerprintAPIPage{
				Timestamp:     formatOutputTimestamp(firstNonZeroTime(page.Timestamp, groupTimestamp(group))),
				URL:           page.URL,
				StatusCode:    page.StatusCode,
				Title:         page.Title,
				ContentLength: contentLength,
				ContentType:   page.ContentType,
				DurationMs:    page.Duration,
				Matches:       existing,
			})
			index[key] = len(results) - 1
		}
		delete(matchMap, key)
	}

	// 对于仅有指纹匹配记录但没有响应的URL，也进行输出
	for _, group := range matchMap {
		if group == nil || len(group.Matches) == 0 {
			continue
		}
		results = append(results, FingerprintAPIPage{
			Timestamp: formatOutputTimestamp(group.Timestamp),
			URL:       group.URL,
			Matches:   group.Matches,
		})
	}

	return results
}

// groupMatchesByURL 将指纹匹配结果按URL分组
func groupMatchesByURL(matches []types.FingerprintMatch) map[string]*fingerprintMatchGroup {
	if len(matches) == 0 {
		return nil
	}

	grouped := make(map[string]*fingerprintMatchGroup)
	for _, match := range matches {
		key := NormalizeFingerprintURLKey(match.URL)
		ruleContent := match.Matcher
		if ruleContent == "" {
			ruleContent = match.DSLMatched
		}
		group := grouped[key]
		if group == nil {
			group = &fingerprintMatchGroup{
				URL: match.URL,
			}
			grouped[key] = group
		}
		if group.Timestamp.IsZero() && !match.Timestamp.IsZero() {
			group.Timestamp = match.Timestamp
		}
		group.Matches = append(group.Matches, SDKFingerprintMatchOutput{
			RuleName:    match.RuleName,
			RuleContent: ruleContent,
			Snippet:     match.Snippet,
		})
	}
	return grouped
}

func groupTimestamp(group *fingerprintMatchGroup) time.Time {
	if group == nil {
		return time.Time{}
	}
	return group.Timestamp
}

func toSDKMatchesFromInterfaces(matches []types.FingerprintMatch) []SDKFingerprintMatchOutput {
	if len(matches) == 0 {
		return nil
	}

	outputs := make([]SDKFingerprintMatchOutput, 0, len(matches))
	for _, match := range matches {
		ruleContent := match.Matcher
		if ruleContent == "" {
			ruleContent = match.DSLMatched
		}
		outputs = append(outputs, SDKFingerprintMatchOutput{
			RuleName:    match.RuleName,
			RuleContent: ruleContent,
			Snippet:     match.Snippet,
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
		if baseIdx, ok := keyIndex[key]; ok {
			if base[baseIdx].Snippet == "" && item.Snippet != "" {
				base[baseIdx].Snippet = item.Snippet
			}
			continue
		}
		keyIndex[key] = len(base)
		base = append(base, item)
	}

	return base
}

// NormalizeFingerprintURLKey 统一指纹结果的URL归一化键
func NormalizeFingerprintURLKey(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return trimmed
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)

	host := strings.ToLower(parsed.Host)
	if h, p, err := net.SplitHostPort(host); err == nil {
		if (parsed.Scheme == "http" && p == "80") || (parsed.Scheme == "https" && p == "443") {
			host = h
		}
	}
	parsed.Host = host

	if parsed.Path == "" {
		parsed.Path = "/"
	}

	return parsed.String()
}

type RealtimeCSVReporter struct {
	mu     sync.Mutex
	file   *os.File
	writer *csv.Writer
	path   string
	closed bool
}

func NewRealtimeCSVReporter(outputPath string) (*RealtimeCSVReporter, error) {
	outputPath = strings.TrimSpace(outputPath)
	if outputPath == "" {
		return nil, fmt.Errorf("output path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("failed to open output file: %w", err)
	}

	r := &RealtimeCSVReporter{
		file:   f,
		writer: csv.NewWriter(f),
		path:   outputPath,
	}

	if stat, err := f.Stat(); err == nil && stat.Size() == 0 {
		if err := r.writer.Write([]string{"Timestamp", "URL", "Host", "StatusCode", "Title", "Content-Length", "Fingerprint"}); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("failed to write CSV header: %w", err)
		}
		r.writer.Flush()
		if werr := r.writer.Error(); werr != nil {
			_ = f.Close()
			return nil, fmt.Errorf("failed to write CSV header: %w", werr)
		}
	}

	return r, nil
}

func (r *RealtimeCSVReporter) Path() string {
	if r == nil {
		return ""
	}
	return r.path
}

func (r *RealtimeCSVReporter) WriteResponse(resp *types.HTTPResponse) error {
	if r == nil || resp == nil {
		return nil
	}

	fingerprints := make([]string, 0, len(resp.Fingerprints))
	for _, fp := range resp.Fingerprints {
		if fp.RuleName != "" {
			fingerprints = append(fingerprints, fp.RuleName)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return fmt.Errorf("realtime csv reporter 已关闭")
	}

	length := resp.ContentLength
	if length < 0 {
		length = 0
	}

	host := ""
	if parsed, err := url.Parse(resp.URL); err == nil {
		host = parsed.Host
	}

	if err := r.writer.Write([]string{
		formatOutputTimestamp(resp.Timestamp),
		resp.URL,
		host,
		strconv.Itoa(resp.StatusCode),
		resp.Title,
		strconv.FormatInt(length, 10),
		strings.Join(fingerprints, "|"),
	}); err != nil {
		return err
	}

	r.writer.Flush()
	if err := r.writer.Error(); err != nil {
		return err
	}

	return nil
}

func (r *RealtimeCSVReporter) Close() error {
	if r == nil {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true

	r.writer.Flush()
	werr := r.writer.Error()
	syncErr := r.file.Sync()
	closeErr := r.file.Close()

	if werr != nil {
		return werr
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func GenerateRealtimeCSVReport(filterResult *types.FilterResult, outputPath string) (string, error) {
	if filterResult == nil {
		return "", fmt.Errorf("过滤结果为空")
	}

	reporter, err := NewRealtimeCSVReporter(outputPath)
	if err != nil {
		return "", err
	}

	for _, page := range filterResult.ValidPages {
		if page == nil {
			continue
		}
		if err := reporter.WriteResponse(page); err != nil {
			_ = reporter.Close()
			return "", err
		}
	}

	if err := reporter.Close(); err != nil {
		return "", err
	}

	return reporter.Path(), nil
}
