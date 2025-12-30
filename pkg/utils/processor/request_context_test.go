package processor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRequestProcessor_ProcessURLsWithContext_CancelStopsEarly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 模拟慢响应，便于观察取消是否能提前停止后续URL处理
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	rp := NewRequestProcessor(&RequestConfig{
		Timeout:            2 * time.Second,
		MaxRetries:         0,
		MaxConcurrent:      1,
		FollowRedirect:     false,
		DecompressResponse: true,
	})

	urls := make([]string, 0, 50)
	for i := 0; i < 50; i++ {
		urls = append(urls, srv.URL)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// 等待请求开始后再取消，避免测试变成“零请求直接返回”的路径
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_ = rp.ProcessURLsWithContext(ctx, urls)
	elapsed := time.Since(start)

	// 若未能停止派发剩余URL，50*200ms 约等于 10s；取消后应明显更快返回
	if elapsed > 3*time.Second {
		t.Fatalf("expected ProcessURLsWithContext to stop early after cancel; took %v", elapsed)
	}
}
