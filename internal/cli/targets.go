package cli

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"veo/internal/config"
	"veo/pkg/httpclient"
	"veo/pkg/logger"
)

func (sc *ScanController) parseTargets(targetStrs []string) ([]string, error) {
	logger.Debugf("开始解析目标")

	var allTargets []string

	if len(targetStrs) > 0 {
		logger.Debugf("处理命令行目标，数量: %d", len(targetStrs))
		for _, targetStr := range targetStrs {
			parts := strings.Split(targetStr, ",")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part != "" {
					allTargets = append(allTargets, part)
				}
			}
		}
	}

	if sc.args.TargetFile != "" {
		logger.Debugf("处理目标文件: %s", sc.args.TargetFile)
		parser := NewTargetParser()
		fileTargets, err := parser.ParseFile(sc.args.TargetFile)
		if err != nil {
			return nil, err
		}
		allTargets = append(allTargets, fileTargets...)
		logger.Debugf("从文件读取到 %d 个目标", len(fileTargets))
	}

	if len(allTargets) == 0 {
		return nil, fmt.Errorf("no valid targets")
	}

	deduplicator := NewDeduplicator()
	uniqueTargets, stats := deduplicator.DeduplicateWithStats(allTargets)

	if stats.DuplicateCount > 0 {
		logger.Debugf("去重完成: 原始 %d 个，去重后 %d 个，重复 %d 个 (%.1f%%)",
			stats.OriginalCount, stats.UniqueCount, stats.DuplicateCount, stats.DuplicateRate)
	}

	checker := NewConnectivityChecker(sc.config)
	var validTargets []string

	if sc.args.NetworkCheck {
		validTargets = checker.BatchCheck(uniqueTargets)
		if len(validTargets) == 0 {
			return nil, fmt.Errorf("no reachable targets")
		}
	} else {
		var err error
		validTargets, err = checker.ValidateAndNormalize(uniqueTargets)
		if err != nil {
			return nil, err
		}
	}

	logger.Debugf("目标解析完成: 最终有效目标 %d 个", len(validTargets))
	return validTargets, nil
}

type ConnectivityChecker struct {
	client *httpclient.Client
	config *config.Config
}

func NewConnectivityChecker(cfg *config.Config) *ConnectivityChecker {
	httpCfg := httpclient.DefaultConfig()
	if cfg != nil && cfg.Addon.Request.Timeout > 0 {
		httpCfg.Timeout = time.Duration(cfg.Addon.Request.Timeout) * time.Second
	} else {
		httpCfg.Timeout = 5 * time.Second
	}
	httpCfg.FollowRedirect = false
	httpCfg.SkipTLSVerify = true

	return &ConnectivityChecker{
		client: httpclient.New(httpCfg),
		config: cfg,
	}
}

func (cc *ConnectivityChecker) BatchCheck(targets []string) []string {
	if len(targets) == 0 {
		return nil
	}

	logger.Debugf("开始目标连通性检测，目标数量: %d", len(targets))
	parser := NewTargetParser()
	var candidates []string
	for _, t := range targets {
		candidates = append(candidates, parser.NormalizeURL(t)...)
	}

	var validTargets []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	concurrency := 20
	if cc.config != nil && cc.config.Module.Dirscan {
		concurrency = 50
	}
	sem := make(chan struct{}, concurrency)

	var processedCount int64
	total := len(candidates)

	logger.Info("Starting target reachability check...")
	for _, targetURL := range candidates {
		wg.Add(1)
		go func(urlStr string) {
			sem <- struct{}{}
			defer func() {
				<-sem
				wg.Done()
			}()

			if cc.isReachable(urlStr) {
				mu.Lock()
				validTargets = append(validTargets, urlStr)
				mu.Unlock()
			}

			current := atomic.AddInt64(&processedCount, 1)
			if total > 0 && (current%5 == 0 || current == int64(total)) {
				fmt.Printf("\r存活性检测: %d/%d (%.1f%%)", current, total, float64(current)/float64(total)*100)
			}
		}(targetURL)
	}

	wg.Wait()
	fmt.Println()

	logger.Debugf("有效目标: %d/%d", len(validTargets), len(candidates))
	if len(validTargets) > 0 {
		logger.Debug("存活目标列表:")
		for _, target := range validTargets {
			logger.Debugf("  %s", target)
		}
	}

	return validTargets
}

func (cc *ConnectivityChecker) isReachable(urlStr string) bool {
	_, statusCode, err := cc.client.MakeRequest(urlStr)
	if err != nil {
		logger.Debugf("目标不可连通: %s (%v)", urlStr, err)
		return false
	}
	logger.Debugf("目标可连通: %s [%d]", urlStr, statusCode)
	return true
}

func (cc *ConnectivityChecker) ValidateAndNormalize(targets []string) ([]string, error) {
	logger.Debugf("开始验证和标准化目标列表")

	parser := NewTargetParser()
	validTargets := make([]string, 0, len(targets))
	for _, target := range targets {
		if err := parser.ValidateURL(target); err != nil {
			logger.Warnf("Skipping invalid target %s: %v", target, err)
			continue
		}
		urls := parser.NormalizeURL(target)
		if len(urls) > 0 {
			validTargets = append(validTargets, urls[0])
		}
	}

	if len(validTargets) == 0 {
		return nil, fmt.Errorf("no valid targets")
	}
	return validTargets, nil
}

type Deduplicator struct {
	seen map[string]bool
}

func NewDeduplicator() *Deduplicator {
	return &Deduplicator{
		seen: make(map[string]bool),
	}
}

func (d *Deduplicator) Deduplicate(targets []string) []string {
	logger.Debugf("开始去重，原始目标数量: %d", len(targets))

	result := make([]string, 0, len(targets))
	for _, target := range targets {
		normalized := d.normalizeForDedup(target)
		if !d.seen[normalized] {
			d.seen[normalized] = true
			result = append(result, target)
			continue
		}
		logger.Debugf("发现重复目标: %s (标准化: %s)", target, normalized)
	}

	logger.Debugf("去重完成，去重后目标数量: %d", len(result))
	return result
}

func (d *Deduplicator) normalizeForDedup(target string) string {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	parsedURL, err := url.Parse(target)
	if err != nil {
		return strings.ToLower(target)
	}

	host := strings.ToLower(parsedURL.Host)
	pathValue := parsedURL.Path
	if pathValue != "/" && strings.HasSuffix(pathValue, "/") {
		pathValue = strings.TrimSuffix(pathValue, "/")
	}
	if pathValue == "" {
		pathValue = "/"
	}

	normalized := parsedURL.Scheme + "://" + host + pathValue
	if parsedURL.RawQuery != "" {
		normalized += "?" + parsedURL.RawQuery
	}
	return normalized
}

type DeduplicationStats struct {
	OriginalCount  int
	UniqueCount    int
	DuplicateCount int
	DuplicateRate  float64
}

func (d *Deduplicator) DeduplicateWithStats(targets []string) ([]string, *DeduplicationStats) {
	originalCount := len(targets)
	result := d.Deduplicate(targets)
	duplicateCount := originalCount - len(result)
	duplicateRate := 0.0
	if originalCount > 0 {
		duplicateRate = float64(duplicateCount) / float64(originalCount) * 100
	}

	return result, &DeduplicationStats{
		OriginalCount:  originalCount,
		UniqueCount:    len(result),
		DuplicateCount: duplicateCount,
		DuplicateRate:  duplicateRate,
	}
}

type TargetParser struct{}

func NewTargetParser() *TargetParser {
	return &TargetParser{}
}

func (tp *TargetParser) ParseFile(filePath string) ([]string, error) {
	logger.Debugf("开始解析目标文件: %s", filePath)

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open target file: %v", err)
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error while reading target file: %v", err)
	}

	logger.Debugf("从文件解析到 %d 个目标", len(targets))
	return targets, nil
}

func (tp *TargetParser) NormalizeURL(target string) []string {
	logger.Debugf("开始标准化目标: %s", target)

	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return []string{target}
	}

	host, port, err := tp.parseHostPort(target)
	if err != nil {
		logger.Debugf("解析主机端口失败: %v，同时尝试HTTP和HTTPS协议", err)
		return []string{"http://" + target, "https://" + target}
	}

	protocols := tp.determineProtocols(port)
	urls := make([]string, 0, len(protocols))
	for _, protocol := range protocols {
		urls = append(urls, formatHostURL(protocol, host, port))
	}

	logger.Debugf("目标 %s 标准化为: %v", target, urls)
	return urls
}

func (tp *TargetParser) parseHostPort(target string) (string, int, error) {
	if strings.Contains(target, ":") {
		host, portStr, err := net.SplitHostPort(target)
		if err != nil {
			return "", 0, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return "", 0, fmt.Errorf("invalid port number: %s", portStr)
		}
		return host, port, nil
	}
	return target, 0, nil
}

func (tp *TargetParser) determineProtocols(port int) []string {
	if port == 80 {
		return []string{"http"}
	}
	if port == 443 {
		return []string{"https"}
	}
	return []string{"http", "https"}
}

func formatHostURL(protocol, host string, port int) string {
	if port == 0 || (port == 80 && protocol == "http") || (port == 443 && protocol == "https") {
		return fmt.Sprintf("%s://%s", protocol, host)
	}
	return fmt.Sprintf("%s://%s:%d", protocol, host, port)
}

func (tp *TargetParser) ValidateURL(target string) error {
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "http://" + target
	}

	parsedURL, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid URL format: %v", err)
	}
	if parsedURL.Host == "" {
		return fmt.Errorf("URL is missing a hostname")
	}
	return nil
}
