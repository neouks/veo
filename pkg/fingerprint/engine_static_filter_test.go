package fingerprint

import "testing"

type staticFilterFormatter struct {
	matchCount   int
	noMatchCount int
}

func (f *staticFilterFormatter) FormatMatch(matches []*FingerprintMatch, response *HTTPResponse, tags ...string) {
	f.matchCount++
}

func (f *staticFilterFormatter) FormatNoMatch(response *HTTPResponse) {
	f.noMatchCount++
}

func (f *staticFilterFormatter) ShouldOutput(url string, fingerprintNames []string) bool {
	return true
}

func TestAnalyzeResponseStaticFileDoesNotOutputNoMatch(t *testing.T) {
	engine := NewEngine(nil)
	formatter := &staticFilterFormatter{}
	engine.config.OutputFormatter = formatter

	resp := &HTTPResponse{
		URL:         "https://example.com/jis-web/css/chunk-vendors.4cd41c92.css",
		StatusCode:  200,
		ContentType: "text/css",
		Body:        "body { color: red; }",
	}

	matches := engine.AnalyzeResponseWithClient(resp, nil)
	if len(matches) != 0 {
		t.Fatalf("expected no matches for static file, got %d", len(matches))
	}
	if formatter.matchCount != 0 {
		t.Fatalf("expected no match output for static file, got %d", formatter.matchCount)
	}
	if formatter.noMatchCount != 0 {
		t.Fatalf("expected filtered static file to suppress no-match output, got %d", formatter.noMatchCount)
	}
}
