package cli

import (
	"fmt"

	"veo/pkg/utils/httpclient"
	"veo/pkg/utils/logger"
	requests "veo/pkg/utils/processor"
)

// requestProcessorHTTPClient 将目录扫描的 RequestProcessor 适配为 HTTPClientInterface。
type requestProcessorHTTPClient struct {
	processor *requests.RequestProcessor
}

var (
	_ httpclient.HTTPClientInterface = (*requestProcessorHTTPClient)(nil)
	_ httpclient.HeaderAwareClient   = (*requestProcessorHTTPClient)(nil)
)

func newRequestProcessorHTTPClient(rp *requests.RequestProcessor) httpclient.HTTPClientInterface {
	return &requestProcessorHTTPClient{processor: rp}
}

func (c *requestProcessorHTTPClient) MakeRequest(rawURL string) (string, int, error) {
	body, status, _, err := c.makeRequestInternal(rawURL, nil)
	return body, status, err
}

func (c *requestProcessorHTTPClient) MakeRequestWithHeaders(rawURL string, headers map[string]string) (string, int, error) {
	body, status, _, err := c.makeRequestInternal(rawURL, headers)
	return body, status, err
}

func (c *requestProcessorHTTPClient) MakeRequestFull(rawURL string) (string, int, map[string][]string, error) {
	return c.makeRequestInternal(rawURL, nil)
}

func (c *requestProcessorHTTPClient) makeRequestInternal(rawURL string, headers map[string]string) (string, int, map[string][]string, error) {
	if c == nil || c.processor == nil {
		return "", 0, nil, fmt.Errorf("request processor 未初始化")
	}

	resp, err := c.processor.DoRequest(rawURL, headers)
	if err != nil {
		return "", 0, nil, err
	}
	if resp == nil {
		return "", 0, nil, fmt.Errorf("请求返回空响应: %s", rawURL)
	}

	logger.Debugf("RequestProcessorAdapter 命中复用连接: %s [%d]", rawURL, resp.StatusCode)
	return resp.Body, resp.StatusCode, resp.ResponseHeaders, nil
}
