package cli

import (
	"fmt"
	"net/url"
	"strings"

	modulepkg "veo/pkg/core/module"
	"veo/pkg/fingerprint"
	report "veo/pkg/reporter"
	"veo/pkg/types"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
	sharedutils "veo/pkg/utils/shared"
)

func (sc *ScanController) generateConsoleJSON(dirPages, fingerprintPages []interfaces.HTTPResponse, filterResult *interfaces.FilterResult) (string, error) {
	var matches []types.FingerprintMatch
	if sc.fingerprintEngine != nil {
		if raw := sc.fingerprintEngine.GetMatches(); len(raw) > 0 {
			matches = convertFingerprintMatches(raw, sc.showFingerprintSnippet)
		}
	}

	if len(fingerprintPages) == 0 && sc.args.HasModule(string(modulepkg.ModuleFinger)) {
		fingerprintPages = toValueSlice(filterResult.ValidPages)
	}

	return report.GenerateCombinedJSON(dirPages, fingerprintPages, matches)
}

func (sc *ScanController) convertToFingerprintResponse(resp *interfaces.HTTPResponse) *fingerprint.HTTPResponse {
	if resp == nil {
		return nil
	}

	// 转换响应头格式（interfaces.HTTPResponse.ResponseHeaders已经是map[string][]string）
	headers := resp.ResponseHeaders
	if headers == nil {
		headers = make(map[string][]string)
	}

	// 关键修复：处理响应体解压缩和编码转换
	processedBody := sc.processResponseBody(resp)

	// 提取处理后的标题（使用解压缩和编码转换后的内容）
	title := sc.extractTitleFromHTML(processedBody)

	logger.Debugf("响应体处理完成: %s (原始: %d bytes, 处理后: %d bytes)",
		resp.URL, len(resp.ResponseBody), len(processedBody))

	return &fingerprint.HTTPResponse{
		URL:             resp.URL,
		Method:          "GET", // 主动扫描默认使用GET方法
		StatusCode:      resp.StatusCode,
		ResponseHeaders: headers,
		Body:            processedBody, // 使用处理后的响应体
		ContentType:     resp.ContentType,
		ContentLength:   int64(len(processedBody)), // 更新为处理后的长度
		Server:          resp.Server,
		Title:           title, // 使用处理后的标题
	}
}

func (sc *ScanController) processResponseBody(resp *interfaces.HTTPResponse) string {
	if resp == nil || resp.ResponseBody == "" {
		return ""
	}

	if resp.BodyDecoded {
		return resp.ResponseBody
	}

	rawBody := resp.ResponseBody

	// 步骤1: 检查Content-Encoding并解压缩
	decompressedBody := sc.decompressResponseBody(rawBody, resp.ResponseHeaders)

	// 步骤2: 字符编码检测和转换
	convertedBody := fingerprint.GetEncodingDetector().DetectAndConvert(decompressedBody, resp.ContentType)

	logger.Debugf("响应体处理: %s (原始: %d -> 解压: %d -> 转换: %d bytes)",
		resp.URL, len(rawBody), len(decompressedBody), len(convertedBody))

	return convertedBody
}

func (sc *ScanController) decompressResponseBody(body string, headers map[string][]string) string {
	if body == "" {
		return ""
	}

	// 获取Content-Encoding头部
	var contentEncoding string
	if headers != nil {
		if encodingHeaders, exists := headers["Content-Encoding"]; exists && len(encodingHeaders) > 0 {
			contentEncoding = encodingHeaders[0]
		}
	}

	decompressed := sharedutils.DecompressByEncoding([]byte(body), contentEncoding)
	return string(decompressed)
}

func (sc *ScanController) extractTitleFromHTML(body string) string {
	return sharedutils.ExtractTitle(body)
}

// extractBaseURL 从完整URL中提取基础URL（协议+主机）
func (sc *ScanController) extractBaseURL(rawURL string) string {
	if parsedURL, err := url.Parse(rawURL); err == nil {
		return fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	}
	return rawURL
}

// extractBaseURLWithPath 从完整URL中提取基础URL（协议+主机+路径），去除查询参数和片段
func (sc *ScanController) extractBaseURLWithPath(rawURL string) string {
	if parsedURL, err := url.Parse(rawURL); err == nil {
		path := parsedURL.Path
		// 移除末尾的斜杠，保证一致性，除非路径就是根目录
		if path != "/" {
			path = strings.TrimRight(path, "/")
		}
		if path == "" {
			path = "/" // 理论上Parse不会返回空path如果只是host，但为了保险
		}
		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, path)
	}
	return rawURL
}
