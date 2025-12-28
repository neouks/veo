package fingerprint

import (
	"testing"
	"veo/pkg/types"
)

func TestEvaluateContainsAll(t *testing.T) {
	parser := NewDSLParser()

	tests := []struct {
		name     string
		dsl      string
		body     string
		headers  map[string][]string
		expected bool
	}{
		{
			name:     "match body with all strings",
			dsl:      "contains_all(body, 'foo', 'bar')",
			body:     "this is foo and bar",
			expected: true,
		},
		{
			name:     "fail body missing one string",
			dsl:      "contains_all(body, 'foo', 'baz')",
			body:     "this is foo and bar",
			expected: false,
		},
		{
			name:     "match body case insensitive",
			dsl:      "contains_all(body, 'FOO', 'Bar')",
			body:     "this is foo and bar",
			expected: true,
		},
		{
			name:     "match header",
			dsl:      "contains_all(header, 'X-Test', 'Value')",
			body:     "",
			headers:  map[string][]string{"X-Test": {"Value"}, "Other": {"Header"}},
			expected: true,
		},
		{
			name:     "fail header missing string",
			dsl:      "contains_all(header, 'X-Test', 'Missing')",
			body:     "",
			headers:  map[string][]string{"X-Test": {"Value"}},
			expected: false,
		},
		{
			name:     "verify bug fix: body without 'body' string",
			dsl:      "contains_all(body, 'foo', 'bar')",
			body:     "foo and bar", // Does NOT contain the word "body"
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(map[string][]string)
			if tt.headers != nil {
				headers = make(map[string][]string, len(tt.headers))
				for k, v := range tt.headers {
					if len(v) == 0 {
						continue
					}
					dup := make([]string, len(v))
					copy(dup, v)
					headers[k] = dup
				}
			}

			ctx := &DSLContext{
				Body:    tt.body,
				Headers: headers,
				Response: &types.HTTPResponse{
					Title:  "Test Title",
					Server: "Test Server",
				},
			}
			result := parser.EvaluateDSL(tt.dsl, ctx)
			if result != tt.expected {
				t.Errorf("EvaluateDSL(%q) = %v, want %v", tt.dsl, result, tt.expected)
			}
		})
	}
}
