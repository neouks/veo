package cli

import (
	"fmt"
	"os"
	"strings"

	"veo/pkg/fingerprint"
	"veo/pkg/formatter"
	"veo/pkg/logger"
	reporter "veo/pkg/reporter"
	sharedutils "veo/pkg/shared"
	interfaces "veo/pkg/types"
)

func isJSONReportPath(path string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(path)), ".json")
}

func toValueSlice(pages []*interfaces.HTTPResponse) []interfaces.HTTPResponse {
	result := make([]interfaces.HTTPResponse, 0, len(pages))
	for _, p := range pages {
		if p != nil {
			result = append(result, *p)
		}
	}
	return result
}

func toPointerSlice(pages []interfaces.HTTPResponse) []*interfaces.HTTPResponse {
	result := make([]*interfaces.HTTPResponse, len(pages))
	for i := range pages {
		result[i] = &pages[i]
	}
	return result
}

type fingerprintOutputHookSetter interface {
	SetOutputHook(func(response *fingerprint.HTTPResponse, matches []*fingerprint.FingerprintMatch, tags []string))
}

func (sc *ScanController) attachRealtimeReporter() {
	if sc.realtimeReporter == nil || sc.fingerprintEngine == nil {
		return
	}

	hook := func(resp *fingerprint.HTTPResponse, matches []*fingerprint.FingerprintMatch, tags []string) {
		if resp == nil {
			return
		}
		page := *resp
		if len(matches) > 0 {
			page.Fingerprints = convertFingerprintMatches(matches, false)
		} else {
			page.Fingerprints = nil
		}
		_ = sc.realtimeReporter.WriteResponse(&page)
	}

	formatter := sc.fingerprintEngine.GetConfig().OutputFormatter
	if outputHookSetter, ok := formatter.(fingerprintOutputHookSetter); ok {
		outputHookSetter.SetOutputHook(hook)
	}
}

func (sc *ScanController) finalizeScan(allResults, dirResults, fingerprintResults []interfaces.HTTPResponse) error {
	logger.Debugf("所有模块执行完成，总结果数: %d", len(allResults))

	filterResult := sc.buildFilterResult(allResults, fingerprintResults)

	sc.lastDirscanResults = dirResults
	sc.lastFingerprintResults = fingerprintResults

	if sc.realtimeReporter != nil {
		logger.Infof("Report Output Success: %s", sc.realtimeReporter.Path())
	}

	if sc.statsDisplay.IsEnabled() {
		sc.statsDisplay.ShowFinalStats()
		sc.statsDisplay.Disable()
	}

	sc.outputConsoleJSON(dirResults, fingerprintResults, filterResult)
	sc.outputJSONReport(dirResults, fingerprintResults, filterResult)

	return nil
}

func (sc *ScanController) buildFilterResult(allResults, fingerprintResults []interfaces.HTTPResponse) *interfaces.FilterResult {
	onlyFingerprint := len(sc.args.Modules) == 1 && sc.args.Modules[0] == moduleFinger
	if onlyFingerprint {
		pages := fingerprintResults
		if len(pages) == 0 {
			pages = allResults
		}
		return &interfaces.FilterResult{
			ValidPages: toPointerSlice(pages),
		}
	}

	filterResult := &interfaces.FilterResult{
		ValidPages:           toPointerSlice(allResults),
		PrimaryFilteredPages: toPointerSlice(sc.collectedPrimaryFiltered),
		StatusFilteredPages:  toPointerSlice(sc.collectedStatusFiltered),
	}
	logger.Debugf("构造FilterResult - ValidPages: %d, PrimaryFiltered: %d, StatusFiltered: %d",
		len(allResults), len(sc.collectedPrimaryFiltered), len(sc.collectedStatusFiltered))
	if len(allResults) > 0 {
		logger.Debugf("所有目标过滤完成，最终有效结果: %d", len(allResults))
	}
	return filterResult
}

func (sc *ScanController) outputConsoleJSON(dirResults, fingerprintResults []interfaces.HTTPResponse, filterResult *interfaces.FilterResult) {
	if !sc.args.JSONOutput {
		return
	}

	jsonStr, err := sc.generateConsoleJSON(dirResults, fingerprintResults, filterResult)
	if err != nil {
		logger.Errorf("Failed to generate JSON output: %v", err)
		return
	}
	fmt.Println(jsonStr)
}

func (sc *ScanController) outputJSONReport(dirResults, fingerprintResults []interfaces.HTTPResponse, filterResult *interfaces.FilterResult) {
	if !isJSONReportPath(sc.reportPath) {
		return
	}

	jsonStr, err := sc.generateJSONReport(dirResults, fingerprintResults, filterResult)
	if err != nil {
		logger.Errorf("Failed to generate JSON report: %v", err)
		return
	}
	if writeErr := os.WriteFile(sc.reportPath, []byte(jsonStr), 0644); writeErr != nil {
		logger.Errorf("Failed to write JSON report: %v", writeErr)
		return
	}
	logger.Infof("Report Output Success: %s", sc.reportPath)
}

func (sc *ScanController) generateJSONReport(dirPages, fingerprintPages []interfaces.HTTPResponse, filterResult *interfaces.FilterResult) (string, error) {
	return sc.generateJSON(dirPages, fingerprintPages, filterResult, true)
}

func (sc *ScanController) shouldIncludeConsoleSnippet() bool {
	return sc.showFingerprintSnippet || (sc.args != nil && sc.args.JSONOutput)
}

func (sc *ScanController) generateConsoleJSON(dirPages, fingerprintPages []interfaces.HTTPResponse, filterResult *interfaces.FilterResult) (string, error) {
	return sc.generateJSON(dirPages, fingerprintPages, filterResult, sc.shouldIncludeConsoleSnippet())
}

func (sc *ScanController) generateJSON(dirPages, fingerprintPages []interfaces.HTTPResponse, filterResult *interfaces.FilterResult, includeSnippet bool) (string, error) {
	var matches []interfaces.FingerprintMatch
	if sc.fingerprintEngine != nil {
		if raw := sc.fingerprintEngine.GetMatches(); len(raw) > 0 {
			matches = convertFingerprintMatches(raw, includeSnippet)
		}
	}

	if len(fingerprintPages) == 0 && sc.args.HasModule(moduleFinger) {
		fingerprintPages = toValueSlice(filterResult.ValidPages)
	}

	return reporter.GenerateCombinedJSON(dirPages, fingerprintPages, matches)
}

func convertFingerprintMatches(matches []*fingerprint.FingerprintMatch, includeSnippet bool) []interfaces.FingerprintMatch {
	if len(matches) == 0 {
		return nil
	}

	converted := make([]interfaces.FingerprintMatch, 0, len(matches))
	for _, match := range matches {
		if match == nil {
			continue
		}

		matcher := match.Matcher
		if matcher == "" {
			matcher = match.DSLMatched
		}
		dslMatched := match.DSLMatched
		if dslMatched == "" {
			dslMatched = matcher
		}
		convertedMatch := interfaces.FingerprintMatch{
			URL:        match.URL,
			RuleName:   match.RuleName,
			Matcher:    matcher,
			DSLMatched: dslMatched,
			Timestamp:  match.Timestamp,
		}
		if includeSnippet {
			convertedMatch.Snippet = match.Snippet
		}
		converted = append(converted, convertedMatch)
	}

	return converted
}

const urlDisplayLimit = 60

func printHTTPResponseResult(page *interfaces.HTTPResponse, showSnippet bool, showRule bool) {
	if page == nil {
		return
	}

	matches := page.Fingerprints
	var fingerprintUnion string
	if len(matches) > 0 {
		fingerprintUnion = formatFingerprintMatchesList(matches, showRule)
	}

	fingerprintParts := []string{}
	if strings.TrimSpace(fingerprintUnion) != "" {
		fingerprintParts = append(fingerprintParts, fingerprintUnion)
	}

	displayURL, detailURL := formatter.SplitURLForLog(page.URL, urlDisplayLimit)
	line := formatter.FormatLogLineWithURLSuffix(
		displayURL,
		detailURL,
		page.StatusCode,
		page.Title,
		page.ContentLength,
		page.ContentType,
		fingerprintParts,
		len(matches) > 0,
	)

	var messageBuilder strings.Builder
	messageBuilder.WriteString(line)

	if showSnippet && len(matches) > 0 {
		var snippetLines []string
		for _, m := range matches {
			snippet := strings.TrimSpace(m.Snippet)
			if snippet == "" {
				continue
			}
			highlighted := formatter.HighlightSnippet(snippet, m.Matcher)
			if highlighted == "" {
				continue
			}
			snippetLines = append(snippetLines, highlighted)
		}
		if len(snippetLines) > 0 {
			messageBuilder.WriteString("\n")
			for idx, snippetLine := range snippetLines {
				if idx > 0 {
					messageBuilder.WriteString("\n")
				}
				messageBuilder.WriteString("  ")
				messageBuilder.WriteString(formatter.FormatSnippetArrow())
				messageBuilder.WriteString(snippetLine)
			}
		}
	}

	logger.Info(messageBuilder.String())
}

func formatFingerprintMatchesList(matches []interfaces.FingerprintMatch, showRule bool) string {
	if len(matches) == 0 {
		return ""
	}

	parts := make([]string, 0, len(matches))
	for i := range matches {
		match := matches[i]
		display := formatter.FormatFingerprintDisplay(match.RuleName, match.Matcher, showRule)
		if display != "" {
			parts = append(parts, display)
		}
	}

	return strings.Join(parts, " ")
}

func (sc *ScanController) convertToFingerprintResponse(resp *interfaces.HTTPResponse) *fingerprint.HTTPResponse {
	if resp == nil {
		return nil
	}

	headers := resp.ResponseHeaders
	if headers == nil {
		headers = make(map[string][]string)
	}

	processedBody := ""
	if resp.ResponseBody != "" {
		if resp.BodyDecoded {
			processedBody = resp.ResponseBody
		} else {
			rawBody := resp.ResponseBody
			var contentEncoding string
			if headers != nil {
				if encodingHeaders, exists := headers["Content-Encoding"]; exists && len(encodingHeaders) > 0 {
					contentEncoding = encodingHeaders[0]
				}
			}

			decompressed := sharedutils.DecompressByEncoding([]byte(rawBody), contentEncoding)
			processedBody = fingerprint.GetEncodingDetector().DetectAndConvert(string(decompressed), resp.ContentType)
		}
	}

	title := sharedutils.ExtractTitle(processedBody)

	logger.Debugf("响应体处理完成: %s (原始: %d bytes, 处理后: %d bytes)",
		resp.URL, len(resp.ResponseBody), len(processedBody))

	return &fingerprint.HTTPResponse{
		URL:             resp.URL,
		Method:          "GET",
		StatusCode:      resp.StatusCode,
		ResponseHeaders: headers,
		Body:            processedBody,
		ContentType:     resp.ContentType,
		ContentLength:   int64(len(processedBody)),
		Server:          resp.Server,
		Title:           title,
	}
}
