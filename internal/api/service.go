package api

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"veo/internal/core/config"
	internaldirscan "veo/pkg/dirscan"
	fingerprintinternal "veo/pkg/fingerprint"
	portconfig "veo/pkg/portscan"
	portscanpkg "veo/pkg/portscan"
	gogoscanner "veo/pkg/portscan/gogo"
	portservice "veo/pkg/portscan/service"
	"veo/pkg/utils/httpclient"
	"veo/pkg/utils/interfaces"
	requests "veo/pkg/utils/processor"
	sharedutils "veo/pkg/utils/shared"
)

type DirscanPage struct {
	URL           string   `json:"url"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title,omitempty"`
	ContentLength int64    `json:"content_length"`
	ContentType   string   `json:"content_type,omitempty"`
	DurationMs    int64    `json:"duration_ms"`
	Fingerprints  []string `json:"fingerprints,omitempty"`
}

type FingerprintPage struct {
	URL          string                   `json:"url"`
	StatusCode   int                      `json:"status_code"`
	Title        string                   `json:"title"`
	ContentType  string                   `json:"content_type,omitempty"`
	Matches      []FingerprintMatchResult `json:"matches"`
	ResponseTime int64                    `json:"duration_ms"`
}

type FingerprintMatchResult struct {
	RuleName string `json:"rule_name"`
	Snippet  string `json:"snippet,omitempty"`
	DSL      string `json:"dsl,omitempty"`
}

func RunDirscanService(req *DirscanRequest) ([]DirscanPage, error) {
	targets := sanitizeTargets(req.Targets)
	if len(targets) == 0 {
		return nil, errors.New("targets required")
	}

	wordList := ""
	if req.DirscanConfig != nil {
		wordList = strings.TrimSpace(req.DirscanConfig.WordList)
	}

	cleanup, err := applyScanOverrides(req.ScanOptionOverrides, wordList)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	return runDirscanCore(targets, req.DirscanConfig)
}

func RunFingerprintService(req *FingerprintRequest) ([]FingerprintPage, error) {
	targets := sanitizeTargets(req.Targets)
	if len(targets) == 0 {
		return nil, errors.New("targets required")
	}

	cleanup, err := applyScanOverrides(req.ScanOptionOverrides, "")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	engine, err := createFingerprintEngine(req.FingerprintConfig)
	if err != nil {
		return nil, err
	}

	reqConfig := buildRequestProcessorConfig()
	processor := requests.NewRequestProcessor(reqConfig)
	processor.SetCustomHeaders(config.GetCustomHeaders())

	responses := processor.ProcessURLs(targets)
	if len(responses) == 0 {
		return nil, errors.New("no responses")
	}

	snippetEnabled := true
	if req.FingerprintConfig != nil && req.FingerprintConfig.ShowSnippet != nil {
		snippetEnabled = *req.FingerprintConfig.ShowSnippet
	}

	results := make([]FingerprintPage, 0, len(responses))
	for idx, resp := range responses {
		if resp == nil {
			return nil, fmt.Errorf("empty response for %s", targets[idx])
		}
		fpResp := convertToFingerprintResponse(resp)
		matches := fingerprintMatches(engine, fpResp, snippetEnabled)
		results = append(results, FingerprintPage{
			URL:          resp.URL,
			StatusCode:   resp.StatusCode,
			Title:        resp.Title,
			ContentType:  resp.ContentType,
			ResponseTime: resp.Duration,
			Matches:      matches,
		})
	}

	// 主动 path 探测（覆盖包含 path 字段的规则）
	if extra := runFingerprintPathProbing(engine, processor, targets, snippetEnabled); len(extra) > 0 {
		results = append(results, extra...)
	}
	if extra404 := runFingerprint404Probing(engine, processor, targets, snippetEnabled); len(extra404) > 0 {
		results = append(results, extra404...)
	}

	return results, nil
}

func RunPortscanService(req *PortscanRequest) ([]portscanpkg.OpenPortResult, error) {
	if req == nil || req.Config == nil {
		return nil, errors.New("portscan config required")
	}

	targets := sanitizeTargets(req.Targets)
	if len(targets) == 0 {
		return nil, errors.New("portscan requires targets")
	}

	cleanup, err := applyScanOverrides(req.ScanOptionOverrides, "")
	if err != nil {
		return nil, err
	}
	defer cleanup()

	if strings.TrimSpace(req.Config.Ports) == "" {
		return nil, errors.New("portscan_config.ports required")
	}

	portsExpr, _, err := portconfig.ResolveExpression(req.Config.Ports)
	if err != nil {
		return nil, err
	}

	resolvedTargets, err := portscanpkg.ResolveTargetsToIPs(targets)
	if err != nil {
		return nil, err
	}
	if len(resolvedTargets) == 0 {
		return nil, errors.New("no valid targets for portscan")
	}

	var scannerOpts []gogoscanner.Option
	if req.Config.Rate > 0 {
		scannerOpts = append(scannerOpts, gogoscanner.WithRate(req.Config.Rate))
	}

	scanner := gogoscanner.NewScanner(scannerOpts...)
	results, err := scanner.Scan(context.Background(), resolvedTargets, portsExpr)
	if err != nil {
		return nil, err
	}

	results = deduplicatePorts(results)
	enableServiceProbe := true
	if req.Config.Service != nil {
		enableServiceProbe = *req.Config.Service
	}
	if enableServiceProbe && len(results) > 0 {
		results = portservice.IdentifyServices(context.Background(), results, portservice.Options{})
		results = deduplicatePorts(results)
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].IP == results[j].IP {
			return results[i].Port < results[j].Port
		}
		return results[i].IP < results[j].IP
	})

	return results, nil
}

// Utility functions (mostly adapted from pkg/sdk/scan)

func sanitizeTargets(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	result := make([]string, 0, len(values))
	for _, raw := range values {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func buildDirscanEngineConfig() *internaldirscan.EngineConfig {
	reqCfg := config.GetRequestConfig()
	threads := 200
	timeout := 3
	if reqCfg != nil {
		if reqCfg.Threads > 0 {
			threads = reqCfg.Threads
		}
		if reqCfg.Timeout > 0 {
			timeout = reqCfg.Timeout
		}
	}

	return &internaldirscan.EngineConfig{
		MaxConcurrency:   threads,
		RequestTimeout:   time.Duration(timeout) * time.Second,
		EnableCollection: false,
		EnableFiltering:  true,
		EnableReporting:  false,
	}
}

func buildDirscanFilter(cfg *DirscanModuleConfig) *internaldirscan.FilterConfig {
	if cfg == nil {
		return nil
	}
	if len(cfg.ValidStatusCodes) == 0 && cfg.Filter <= 0 {
		return nil
	}

	filterCfg := internaldirscan.DefaultFilterConfig()
	if len(cfg.ValidStatusCodes) > 0 {
		filterCfg.ValidStatusCodes = append([]int(nil), cfg.ValidStatusCodes...)
	}
	if cfg.Filter > 0 {
		filterCfg.FilterTolerance = cfg.Filter
	}
	return filterCfg
}

type staticCollector struct {
	urls map[string]int
}

func newStaticCollector(targets []string) *staticCollector {
	urls := make(map[string]int, len(targets))
	for _, target := range targets {
		trimmed := strings.TrimSpace(target)
		if trimmed == "" {
			continue
		}
		urls[trimmed] = 1
	}
	return &staticCollector{urls: urls}
}

func (c *staticCollector) GetURLMap() map[string]int {
	result := make(map[string]int, len(c.urls))
	for k, v := range c.urls {
		result[k] = v
	}
	return result
}

func (c *staticCollector) GetURLCount() int {
	return len(c.urls)
}

func convertToFingerprintResponse(page *interfaces.HTTPResponse) *fingerprintinternal.HTTPResponse {
	if page == nil {
		return nil
	}

	body := prepareBody(page)
	headers := make(map[string][]string, len(page.ResponseHeaders))
	for key, values := range page.ResponseHeaders {
		copied := make([]string, len(values))
		copy(copied, values)
		headers[key] = copied
	}
	method := page.Method
	if method == "" {
		method = "GET"
	}

	return &fingerprintinternal.HTTPResponse{
		URL:             page.URL,
		Method:          method,
		StatusCode:      page.StatusCode,
		ResponseHeaders: headers,
		Body:            body,
		ContentType:     page.ContentType,
		ContentLength:   page.ContentLength,
		Server:          page.Server,
		Title:           page.Title,
	}
}

func prepareBody(page *interfaces.HTTPResponse) string {
	if page == nil {
		return ""
	}
	body := page.ResponseBody
	if body == "" {
		body = page.Body
	}
	if body == "" {
		return ""
	}
	decompressed := decompressResponseBody(body, page.ResponseHeaders)
	return fingerprintinternal.GetEncodingDetector().DetectAndConvert(decompressed, page.ContentType)
}

func decompressResponseBody(body string, headers map[string][]string) string {
	if body == "" {
		return ""
	}
	encoding := strings.ToLower(getHeaderValue(headers, "Content-Encoding"))
	if encoding == "" {
		return body
	}
	data := []byte(body)
	switch {
	case strings.Contains(encoding, "gzip"):
		if decoded, err := decompressGzip(data); err == nil {
			return decoded
		}
	case strings.Contains(encoding, "deflate"):
		if decoded, err := decompressDeflate(data); err == nil {
			return decoded
		}
	case strings.Contains(encoding, "br"):
		if decoded, err := decompressBrotli(data); err == nil {
			return decoded
		}
	}
	return body
}

func decompressGzip(data []byte) (string, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	defer reader.Close()
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func decompressDeflate(data []byte) (string, error) {
	reader := flate.NewReader(bytes.NewReader(data))
	defer reader.Close()
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func decompressBrotli(data []byte) (string, error) {
	reader := brotli.NewReader(bytes.NewReader(data))
	decoded, err := io.ReadAll(reader)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func getHeaderValue(headers map[string][]string, key string) string {
	if headers == nil {
		return ""
	}
	if values, ok := headers[key]; ok && len(values) > 0 {
		return values[0]
	}
	if values, ok := headers[strings.ToLower(key)]; ok && len(values) > 0 {
		return values[0]
	}
	return ""
}

func groupResponsesByURL(responses []*interfaces.HTTPResponse) map[string][]*interfaces.HTTPResponse {
	if len(responses) == 0 {
		return nil
	}
	group := make(map[string][]*interfaces.HTTPResponse, len(responses))
	for _, resp := range responses {
		if resp == nil || resp.URL == "" {
			continue
		}
		group[resp.URL] = append(group[resp.URL], resp)
	}
	return group
}

func selectFullResponse(page interfaces.HTTPResponse, fullMap map[string][]*interfaces.HTTPResponse) *interfaces.HTTPResponse {
	if fullMap != nil {
		if candidates, ok := fullMap[page.URL]; ok {
			for _, candidate := range candidates {
				if candidate == nil {
					continue
				}
				if candidate.StatusCode == page.StatusCode {
					return candidate
				}
			}
		}
	}
	copy := page
	return &copy
}

func createFingerprintEngine(cfg *FingerprintModuleConfig) (*fingerprintinternal.Engine, error) {
	engineCfg := &fingerprintinternal.EngineConfig{
		RulesPath:       "config/fingerprint/",
		MaxConcurrency:  20,
		EnableFiltering: true,
		MaxBodySize:     1 * 1024 * 1024,
		LogMatches:      true,
	}

	engine := fingerprintinternal.NewEngine(engineCfg)
	if engineCfg.RulesPath != "" {
		if err := engine.LoadRules(engineCfg.RulesPath); err != nil {
			return nil, err
		}
	}

	snippet := false
	if cfg != nil && cfg.ShowSnippet != nil {
		snippet = *cfg.ShowSnippet
	}
	engine.EnableSnippet(snippet)

	showRule := false
	if cfg != nil && cfg.ShowRule != nil {
		showRule = *cfg.ShowRule
	}
	engine.EnableRuleLogging(showRule)
	return engine, nil
}

func fingerprintMatches(engine *fingerprintinternal.Engine, resp *fingerprintinternal.HTTPResponse, snippet bool) []FingerprintMatchResult {
	if engine == nil || resp == nil {
		return nil
	}
	return convertFingerprintMatchResults(engine.AnalyzeResponse(resp), snippet)
}

func convertFingerprintMatchResults(matches []*fingerprintinternal.FingerprintMatch, snippet bool) []FingerprintMatchResult {
	if len(matches) == 0 {
		return nil
	}
	results := make([]FingerprintMatchResult, 0, len(matches))
	for _, match := range matches {
		if match == nil {
			continue
		}
		item := FingerprintMatchResult{
			RuleName: match.RuleName,
			DSL:      match.DSLMatched,
		}
		if snippet {
			item.Snippet = match.Snippet
		}
		results = append(results, item)
	}
	if len(results) == 0 {
		return nil
	}
	return results
}

func deduplicatePorts(results []portscanpkg.OpenPortResult) []portscanpkg.OpenPortResult {
	if len(results) <= 1 {
		return results
	}
	seen := make(map[string]portscanpkg.OpenPortResult, len(results))
	for _, r := range results {
		ip := strings.TrimSpace(r.IP)
		if ip == "" || r.Port <= 0 {
			continue
		}
		key := fmt.Sprintf("%s:%d", ip, r.Port)
		if existing, ok := seen[key]; ok {
			if strings.TrimSpace(existing.Service) == "" && strings.TrimSpace(r.Service) != "" {
				seen[key] = r
			}
			continue
		}
		seen[key] = portscanpkg.OpenPortResult{IP: ip, Port: r.Port, Service: strings.TrimSpace(r.Service)}
	}

	deduped := make([]portscanpkg.OpenPortResult, 0, len(seen))
	for _, r := range seen {
		deduped = append(deduped, r)
	}
	return deduped
}
func runDirscanCore(targets []string, moduleCfg *DirscanModuleConfig) ([]DirscanPage, error) {
	engineCfg := buildDirscanEngineConfig()
	engine := internaldirscan.NewEngine(engineCfg)

	if cfg := buildDirscanFilter(moduleCfg); cfg != nil {
		engine.SetFilterConfig(cfg)
	}

	collector := newStaticCollector(targets)
	result, err := engine.PerformScan(collector)
	if err != nil {
		return nil, err
	}
	if result == nil || result.FilterResult == nil {
		return []DirscanPage{}, nil
	}

	fullMap := groupResponsesByURL(result.Responses)
	records := make([]DirscanPage, 0, len(result.FilterResult.ValidPages))
	for _, page := range result.FilterResult.ValidPages {
		if page.URL == "" {
			continue
		}
		source := selectFullResponse(page, fullMap)
		length := source.ContentLength
		if length == 0 {
			length = source.Length
		}

		records = append(records, DirscanPage{
			URL:           source.URL,
			StatusCode:    source.StatusCode,
			Title:         source.Title,
			ContentLength: length,
			ContentType:   source.ContentType,
			DurationMs:    source.Duration,
		})
	}

	return records, nil
}

func runFingerprintPathProbing(engine *fingerprintinternal.Engine, processor *requests.RequestProcessor, targets []string, includeSnippet bool) []FingerprintPage {
	if engine == nil || !engine.HasPathRules() {
		return nil
	}
	pathRules := engine.GetPathRules()
	if len(pathRules) == 0 {
		return nil
	}

	httpClient := httpclient.CreateClientWithUserAgent(processor.GetUserAgent())
	seenHosts := make(map[string]struct{})
	var pages []FingerprintPage

	for _, target := range targets {
		baseURL, hostKey := extractBaseURLAndHost(target)
		if baseURL == "" || hostKey == "" {
			continue
		}
		if _, exists := seenHosts[hostKey]; exists {
			continue
		}
		seenHosts[hostKey] = struct{}{}

		for _, rule := range pathRules {
			if rule == nil || len(rule.Paths) == 0 {
				continue
			}
			headers := rule.GetHeaderMap()
			for _, rawPath := range rule.Paths {
				probePath := strings.TrimSpace(rawPath)
				if probePath == "" {
					continue
				}
				probeURL := buildProbeURL(baseURL, probePath)
				body, statusCode, err := makeFingerprintRequest(httpClient, probeURL, headers)
				if err != nil {
					continue
				}

				resp := &fingerprintinternal.HTTPResponse{
					URL:             probeURL,
					Method:          "GET",
					StatusCode:      statusCode,
					ResponseHeaders: map[string][]string{},
					Body:            body,
					ContentType:     "",
					ContentLength:   int64(len(body)),
					Server:          "",
					Title:           sharedutils.ExtractTitle(body),
				}

				match := engine.MatchSpecificRule(rule, resp, httpClient, baseURL)
				if match == nil {
					continue
				}

				matchResults := convertFingerprintMatchResults([]*fingerprintinternal.FingerprintMatch{match}, includeSnippet)
				if len(matchResults) == 0 {
					continue
				}

				page := FingerprintPage{
					URL:         probeURL,
					StatusCode:  statusCode,
					Title:       resp.Title,
					ContentType: "text/html",
					Matches:     matchResults,
				}
				pages = append(pages, page)
			}
		}
	}

	return pages
}

func runFingerprint404Probing(engine *fingerprintinternal.Engine, processor *requests.RequestProcessor, targets []string, includeSnippet bool) []FingerprintPage {
	if engine == nil {
		return nil
	}
	httpClient := httpclient.CreateClientWithUserAgent(processor.GetUserAgent())
	seenHosts := make(map[string]struct{})
	var pages []FingerprintPage

	for _, target := range targets {
		baseURL, hostKey := extractBaseURLAndHost(target)
		if baseURL == "" || hostKey == "" {
			continue
		}
		if _, exists := seenHosts[hostKey]; exists {
			continue
		}
		seenHosts[hostKey] = struct{}{}

		notFoundURL := buildProbeURL(baseURL, "/404test")
		body, statusCode, err := httpClient.MakeRequest(notFoundURL)
		if err != nil {
			continue
		}

		resp := &fingerprintinternal.HTTPResponse{
			URL:             notFoundURL,
			Method:          "GET",
			StatusCode:      statusCode,
			ResponseHeaders: map[string][]string{},
			Body:            body,
			ContentType:     "text/html",
			ContentLength:   int64(len(body)),
			Server:          "",
			Title:           sharedutils.ExtractTitle(body),
		}

		rawMatches := engine.AnalyzeResponseWithClientSilent(resp, httpClient)
		matchResults := convertFingerprintMatchResults(rawMatches, includeSnippet)
		if len(matchResults) == 0 {
			continue
		}

		pages = append(pages, FingerprintPage{
			URL:         notFoundURL,
			StatusCode:  statusCode,
			Title:       resp.Title,
			ContentType: resp.ContentType,
			Matches:     matchResults,
		})
	}

	return pages
}

func extractBaseURLAndHost(raw string) (string, string) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", ""
	}
	base := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	return base, parsed.Host
}

func buildProbeURL(baseURL, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	base := strings.TrimRight(baseURL, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

func makeFingerprintRequest(httpClient httpclient.HTTPClientInterface, target string, headers map[string]string) (string, int, error) {
	if len(headers) > 0 {
		if headerClient, ok := httpClient.(httpclient.HeaderAwareClient); ok {
			return headerClient.MakeRequestWithHeaders(target, headers)
		}
	}
	return httpClient.MakeRequest(target)
}

type requestConfigSnapshot struct {
	Threads  int
	Retry    int
	Timeout  int
	RandomUA *bool
}

func applyScanOverrides(overrides ScanOptionOverrides, wordList string) (func(), error) {
	originalHeaders := config.GetCustomHeaders()
	originalWordlists := internaldirscan.GetWordlistPaths()
	requestSnapshot := captureRequestConfigSnapshot()

	if err := applyRequestOverrides(overrides); err != nil {
		restoreRequestConfigSnapshot(requestSnapshot)
		return nil, err
	}

	trimmedWordlist := strings.TrimSpace(wordList)
	if trimmedWordlist != "" {
		internaldirscan.SetWordlistPaths([]string{trimmedWordlist})
	}

	if headers := parseHeaderOverrides(overrides.Header); len(headers) > 0 {
		headerMap, err := buildHeaderMap(headers)
		if err != nil {
			restoreRequestConfigSnapshot(requestSnapshot)
			internaldirscan.SetWordlistPaths(originalWordlists)
			return nil, err
		}
		config.SetCustomHeaders(headerMap)
	}

	cleanup := func() {
		restoreRequestConfigSnapshot(requestSnapshot)
		config.SetCustomHeaders(originalHeaders)
		internaldirscan.SetWordlistPaths(originalWordlists)
	}
	return cleanup, nil
}

func applyRequestOverrides(overrides ScanOptionOverrides) error {
	cfg := config.GetRequestConfig()
	if cfg == nil {
		return fmt.Errorf("request config unavailable")
	}

	if v, err := parseOverrideInt(overrides.Threads); err != nil {
		return fmt.Errorf("invalid threads: %w", err)
	} else if v > 0 {
		cfg.Threads = v
	}

	if v, err := parseOverrideInt(overrides.Retry); err != nil {
		return fmt.Errorf("invalid retry: %w", err)
	} else if v > 0 {
		cfg.Retry = v
	}

	if v, err := parseOverrideInt(overrides.Timeout); err != nil {
		return fmt.Errorf("invalid timeout: %w", err)
	} else if v > 0 {
		cfg.Timeout = v
	}

	if overrides.RandomUA != nil {
		cfg.RandomUA = boolPtr(*overrides.RandomUA)
	}

	return nil
}

func parseOverrideInt(raw string) (int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return 0, nil
	}
	value, err := strconv.Atoi(trimmed)
	if err != nil {
		return 0, err
	}
	if value < 0 {
		return 0, fmt.Errorf("value must be non-negative: %d", value)
	}
	return value, nil
}

func parseHeaderOverrides(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	parts := strings.FieldsFunc(trimmed, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ';'
	})

	headers := make([]string, 0, len(parts))
	for _, part := range parts {
		if header := strings.TrimSpace(part); header != "" {
			headers = append(headers, header)
		}
	}
	return headers
}

func buildHeaderMap(headers []string) (map[string]string, error) {
	parsed := make(map[string]string)
	for _, header := range headers {
		h := strings.TrimSpace(header)
		if h == "" {
			continue
		}
		if strings.ContainsAny(h, "\r\n") {
			return nil, fmt.Errorf("头部不能包含换行符: %q", h)
		}
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("无效的头部格式: %s (需要 Header: Value)", h)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if key == "" {
			return nil, fmt.Errorf("头部名称不能为空: %s", h)
		}
		if value == "" {
			return nil, fmt.Errorf("头部值不能为空: %s", h)
		}
		parsed[key] = value
	}
	return parsed, nil
}

func boolPtr(v bool) *bool {
	val := v
	return &val
}

func captureRequestConfigSnapshot() requestConfigSnapshot {
	cfg := config.GetRequestConfig()
	snapshot := requestConfigSnapshot{
		Threads: cfg.Threads,
		Retry:   cfg.Retry,
		Timeout: cfg.Timeout,
	}
	if cfg.RandomUA != nil {
		val := *cfg.RandomUA
		snapshot.RandomUA = &val
	}
	return snapshot
}

func restoreRequestConfigSnapshot(snapshot requestConfigSnapshot) {
	cfg := config.GetRequestConfig()
	cfg.Threads = snapshot.Threads
	cfg.Retry = snapshot.Retry
	cfg.Timeout = snapshot.Timeout
	cfg.RandomUA = snapshot.RandomUA
}

func buildRequestProcessorConfig() *requests.RequestConfig {
	cfg := config.GetRequestConfig()
	timeout := 10
	retry := 0
	threads := 200
	randomUA := true
	if cfg != nil {
		if cfg.Timeout > 0 {
			timeout = cfg.Timeout
		}
		if cfg.Retry >= 0 {
			retry = cfg.Retry
		}
		if cfg.Threads > 0 {
			threads = cfg.Threads
		}
		if cfg.RandomUA != nil {
			randomUA = *cfg.RandomUA
		}
	}
	return &requests.RequestConfig{
		Timeout:         time.Duration(timeout) * time.Second,
		MaxRetries:      retry,
		MaxConcurrent:   threads,
		FollowRedirect:  true,
		RandomUserAgent: randomUA,
	}
}
