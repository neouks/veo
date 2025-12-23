package httpclient

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"veo/pkg/utils/redirect"
)

func TestHTTPClientRedirectFollowing(t *testing.T) {
	// 创建测试服务器链：Server1 -> Server2 -> Server3
	server3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Final destination"))
	}))
	defer server3.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, server3.URL, http.StatusFound)
	}))
	defer server2.Close()

	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, server2.URL, http.StatusFound)
	}))
	defer server1.Close()

	tests := []struct {
		name           string
		followRedirect bool
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "跟随重定向",
			followRedirect: true,
			expectedStatus: 200,
			expectedBody:   "Final destination",
		},
		{
			name:           "不跟随重定向",
			followRedirect: false,
			expectedStatus: 302,
			expectedBody:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Timeout:        5 * time.Second,
				FollowRedirect: tt.followRedirect,
				MaxRedirects:   5,
				UserAgent:      "Test-Agent",
				SkipTLSVerify:  true,
			}
			client := New(config)

			body, statusCode, err := client.MakeRequest(server1.URL)
			if err != nil {
				t.Fatalf("请求失败: %v", err)
			}

			if statusCode != tt.expectedStatus {
				t.Errorf("期望状态码 %d，实际得到 %d", tt.expectedStatus, statusCode)
			}

			if tt.followRedirect && body != tt.expectedBody {
				t.Errorf("期望响应体 %q，实际得到 %q", tt.expectedBody, body)
			}
		})
	}
}

func TestHTTPClientMaxRedirects(t *testing.T) {
	// 创建无限重定向的服务器
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.String(), http.StatusFound)
	}))
	defer server.Close()

	config := &Config{
		Timeout:        5 * time.Second,
		FollowRedirect: true,
		MaxRedirects:   2, // 限制最大重定向次数
		UserAgent:      "Test-Agent",
		SkipTLSVerify:  true,
	}
	client := New(config)

	_, statusCode, headers, err := client.MakeRequestFull(server.URL)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	// 达到最大重定向次数后，应返回最后一次的重定向响应
	if statusCode != http.StatusFound {
		t.Errorf("期望状态码 %d，实际得到 %d", http.StatusFound, statusCode)
	}
	if got := redirect.GetHeaderFirst(headers, "Location"); got == "" {
		t.Error("期望重定向响应包含 Location 头部")
	}
}

func TestHTTPClientDefaultConfig(t *testing.T) {
	client := New(nil) // 使用默认配置

	if client.followRedirect != true {
		t.Error("默认配置应该启用重定向跟随")
	}

	if client.maxRedirects != 5 {
		t.Errorf("默认最大重定向次数应该是5，实际得到 %d", client.maxRedirects)
	}
}

func TestHTTPClientTLSConfiguration(t *testing.T) {
	// 创建使用自签名证书的HTTPS测试服务器
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("TLS response"))
	}))
	defer server.Close()

	tests := []struct {
		name          string
		skipTLSVerify bool
		expectError   bool
	}{
		{
			name:          "跳过TLS验证",
			skipTLSVerify: true,
			expectError:   false,
		},
		{
			name:          "启用TLS验证（自签名证书应该失败）",
			skipTLSVerify: false,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Timeout:        5 * time.Second,
				FollowRedirect: true,
				MaxRedirects:   5,
				UserAgent:      "Test-Agent",
				SkipTLSVerify:  tt.skipTLSVerify,
			}
			client := New(config)

			_, _, err := client.MakeRequest(server.URL)

			if tt.expectError && err == nil {
				t.Error("期望TLS验证失败时返回错误")
			}

			if !tt.expectError && err != nil {
				t.Errorf("期望TLS请求成功，但得到错误: %v", err)
			}
		})
	}
}

