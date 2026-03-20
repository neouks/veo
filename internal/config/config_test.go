package config

import "testing"

func TestMatchPatternWildcard(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		text    string
		pattern string
		want    bool
	}{
		{
			name:    "subdomain wildcard matches nested subdomain",
			text:    "test.123.baidu.com",
			pattern: "*.baidu.com",
			want:    true,
		},
		{
			name:    "subdomain wildcard does not match root domain",
			text:    "baidu.com",
			pattern: "*.baidu.com",
			want:    false,
		},
		{
			name:    "ip prefix wildcard matches same segment",
			text:    "10.0.0.25",
			pattern: "10.0.0.*",
			want:    true,
		},
		{
			name:    "ip prefix wildcard rejects different segment",
			text:    "10.0.1.25",
			pattern: "10.0.0.*",
			want:    false,
		},
		{
			name:    "exact host remains exact",
			text:    "api.baidu.com",
			pattern: "api.baidu.com",
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := matchPattern(tt.text, tt.pattern)
			if got != tt.want {
				t.Fatalf("matchPattern(%q, %q) = %v, want %v", tt.text, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestIsHostAllowedWithWildcardTargets(t *testing.T) {
	t.Parallel()

	original := GlobalConfig
	t.Cleanup(func() {
		GlobalConfig = original
	})

	GlobalConfig = &Config{
		Hosts: HostsConfig{
			Allow: []string{"*.baidu.com", "10.0.0.*"},
		},
	}

	tests := []struct {
		host string
		want bool
	}{
		{host: "test.123.baidu.com:8080", want: true},
		{host: "baidu.com:8080", want: false},
		{host: "10.0.0.18", want: true},
		{host: "10.0.1.18", want: false},
	}

	for _, tt := range tests {
		if got := IsHostAllowed(tt.host); got != tt.want {
			t.Fatalf("IsHostAllowed(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}
