package types

import (
	"time"
)

// Common Types for Modules

// HTTPResponse represents an HTTP response, used across modules.
type HTTPResponse struct {
	URL             string              `json:"url"`
	Method          string              `json:"method"`
	StatusCode      int                 `json:"status_code"`
	Title           string              `json:"title"`
	ContentLength   int64               `json:"content_length"`
	ContentType     string              `json:"content_type"`
	Body            string              `json:"body"`
	ResponseHeaders map[string][]string `json:"response_headers"`
	RequestHeaders  map[string][]string `json:"request_headers"`
	BodyDecoded     bool                `json:"-"`
	Server          string              `json:"server"`
	IsDirectory     bool                `json:"is_directory"`
	Length          int64               `json:"length"` // Used for reporting
	Duration        int64               `json:"duration"`
	Depth           int                 `json:"depth"`
	ResponseBody    string              `json:"response_body"` // Used for reporting
	Fingerprints    []FingerprintMatch  `json:"fingerprints,omitempty"`
}

// FingerprintMatch represents a fingerprint match result.
type FingerprintMatch struct {
	URL        string    `json:"url"`
	RuleName   string    `json:"rule_name"`
	Matcher    string    `json:"matcher"`     // The specific matcher/DSL that matched
	DSLMatched string    `json:"dsl_matched"` // Alias for Matcher, used by fingerprint engine
	Technology string    `json:"technology"`  // Technology name
	Timestamp  time.Time `json:"timestamp"`
	Snippet    string    `json:"snippet,omitempty"`
}

// FilterResult represents the result of response filtering.
type FilterResult struct {
	StatusFilteredPages  []*HTTPResponse `json:"status_filtered_pages"`
	PrimaryFilteredPages []*HTTPResponse `json:"primary_filtered_pages"`
	ValidPages           []*HTTPResponse `json:"valid_pages"`
	InvalidPageHashes    []PageHash      `json:"invalid_page_hashes"`
	SecondaryHashResults []PageHash      `json:"secondary_hash_results"`
	TotalProcessed       int             `json:"total_processed"`
	StatusFiltered       int             `json:"status_filtered"`
	PrimaryFiltered      int             `json:"primary_filtered"`
	SecondaryFiltered    int             `json:"secondary_filtered"`
}

// PageHash represents hash information for a page.
type PageHash struct {
	Hash          string `json:"hash"`
	Count         int    `json:"count"`
	StatusCode    int    `json:"status_code"`
	Title         string `json:"title"`
	ContentLength int64  `json:"content_length"`
	ContentType   string `json:"content_type"`
}
