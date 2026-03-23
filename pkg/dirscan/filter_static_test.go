package dirscan

import (
	"testing"

	interfaces "veo/pkg/types"
)

func TestResponseFilterDropsStaticResourceURL(t *testing.T) {
	filter := NewResponseFilter(DefaultFilterConfig())

	result := filter.FilterResponses([]*interfaces.HTTPResponse{
		{
			URL:         "https://example.com/jis-web/css/chunk-vendors.4cd41c92.css",
			StatusCode:  200,
			ContentType: "text/css",
		},
	})

	if len(result.ValidPages) != 0 {
		t.Fatalf("expected static resource to be filtered out, got %d valid pages", len(result.ValidPages))
	}
}
