package processor

import (
	"bytes"
	"compress/gzip"
	"testing"
	"time"
)

func TestProcessResponse_BodyDecodedTracksActualDecode(t *testing.T) {
	t.Parallel()

	compress := func(t *testing.T, body string) string {
		t.Helper()

		var buf bytes.Buffer
		writer := gzip.NewWriter(&buf)
		if _, err := writer.Write([]byte(body)); err != nil {
			t.Fatalf("compress body: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close gzip writer: %v", err)
		}
		return buf.String()
	}

	tests := []struct {
		name        string
		body        string
		headers     map[string][]string
		wantDecoded bool
	}{
		{
			name: "identity body remains decoded in dirscan",
			body: "<html><title>ok</title></html>",
			headers: map[string][]string{
				"Content-Type": {"text/html; charset=utf-8"},
			},
			wantDecoded: true,
		},
		{
			name: "compressed body stays undecoded in dirscan",
			body: compress(t, "<html><title>waf</title></html>"),
			headers: map[string][]string{
				"Content-Type":     {"text/html; charset=utf-8"},
				"Content-Encoding": {"gzip"},
			},
			wantDecoded: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rp := NewRequestProcessor(&RequestConfig{
				DecompressResponse: false,
			})
			rp.SetModuleContext("dirscan")

			resp, err := rp.processResponse(
				"https://example.com/test",
				403,
				tt.body,
				tt.headers,
				nil,
				time.Now(),
			)
			if err != nil {
				t.Fatalf("process response: %v", err)
			}
			if resp == nil {
				t.Fatal("expected response")
			}
			if resp.BodyDecoded != tt.wantDecoded {
				t.Fatalf("expected BodyDecoded=%v, got %v", tt.wantDecoded, resp.BodyDecoded)
			}
		})
	}
}
