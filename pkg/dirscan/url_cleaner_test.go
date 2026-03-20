package dirscan

import "testing"

func TestURLCleanerNormalizeCollectedURL(t *testing.T) {
	t.Parallel()

	cleaner := NewURLCleaner()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "api method with query collapses to parent directory",
			raw:  "https://api.sdcyzbtrz.com:30002/api-system/v1/sysDictData/getSysDictByTypeId?typeId=9AF61BB9-36D1-4C80-84DF-0FCC956264F2",
			want: "https://api.sdcyzbtrz.com:30002/api-system/v1/sysDictData/",
		},
		{
			name: "directory path keeps trailing slash",
			raw:  "https://example.com/api-system/v1/sysDictData/",
			want: "https://example.com/api-system/v1/sysDictData/",
		},
		{
			name: "single segment path collapses to root",
			raw:  "https://example.com/login",
			want: "https://example.com/",
		},
		{
			name: "root path stays root",
			raw:  "https://example.com/?token=abc",
			want: "https://example.com/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := cleaner.NormalizeCollectedURL(tt.raw)
			if got != tt.want {
				t.Fatalf("NormalizeCollectedURL(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}
