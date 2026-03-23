package shared

import "testing"

func TestFileExtensionCheckerIgnoresQueryAndFragment(t *testing.T) {
	checker := NewFileExtensionChecker()

	tests := []string{
		"https://example.com/app.css?v=1",
		"https://example.com/app.js#hash",
		"/assets/main.css?build=123",
	}

	for _, target := range tests {
		if !checker.IsStaticFile(target) {
			t.Fatalf("expected static file to be detected: %s", target)
		}
	}
}

func TestIsStaticResourceUsesPathAndExtensionRules(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://example.com/jis-web/css/chunk-vendors.4cd41c92.css", true},
		{"https://example.com/assets/app?v=1", true},
		{"https://example.com/api/system/user/list", false},
	}

	for _, tt := range tests {
		if got := IsStaticResource(tt.url); got != tt.want {
			t.Fatalf("IsStaticResource(%q) = %v, want %v", tt.url, got, tt.want)
		}
	}
}
