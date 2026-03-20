package fingerprint

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"veo/pkg/logger"

	"gopkg.in/yaml.v3"
)

const (
	RemoteRulesURL   = "https://raw.githubusercontent.com/Nuclei-Template-Hub/VEO-Fingerprint/refs/heads/main/finger.yaml"
	DefaultRulesFile = "finger.yaml"
)

// RuleManager 负责指纹规则的加载、解析和管理
// 它是线程安全的，并提供优化的规则快照访问
type RuleManager struct {
	rules           map[string]*FingerprintRule // 规则存储：Key -> Rule
	rulesSnapshot   []*FingerprintRule          // 规则快照：优化的切片，用于快速迭代
	loadedSummaries []string                    // 加载摘要信息
	mu              sync.RWMutex                // 读写锁
}

// NewRuleManager 创建规则管理器实例
func NewRuleManager() *RuleManager {
	return &RuleManager{
		rules: make(map[string]*FingerprintRule),
	}
}

// LoadRules 加载指纹识别规则（支持单文件或目录）
func (rm *RuleManager) LoadRules(rulesPath string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	logger.Debugf("开始加载指纹规则: %s", rulesPath)

	// 检查路径是文件还是目录
	fileInfo, err := os.Stat(rulesPath)
	if err != nil {
		return fmt.Errorf("rules path does not exist: %v", err)
	}

	var yamlFiles []string

	if fileInfo.IsDir() {
		// 目录模式：扫描所有.yaml文件
		logger.Debugf("检测到目录路径，扫描所有YAML文件: %s", rulesPath)

		files, err := os.ReadDir(rulesPath)
		if err != nil {
			return fmt.Errorf("failed to read directory: %v", err)
		}

		for _, file := range files {
			if !file.IsDir() && strings.HasSuffix(strings.ToLower(file.Name()), ".yaml") {
				yamlFiles = append(yamlFiles, filepath.Join(rulesPath, file.Name()))
			}
		}

		if len(yamlFiles) == 0 {
			return fmt.Errorf("no YAML files found in directory: %s", rulesPath)
		}

		logger.Debugf("找到 %d 个YAML文件", len(yamlFiles))
	} else {
		// 文件模式：加载单个文件
		yamlFiles = append(yamlFiles, rulesPath)
	}

	// 加载所有YAML文件
	rm.loadedSummaries = nil
	totalRulesLoaded := 0
	for _, yamlFile := range yamlFiles {
		count, err := rm.loadSingleYAMLFile(yamlFile)
		if err != nil {
			logger.Warnf("Failed to load fingerprint rule file: %s, error: %v", filepath.Base(yamlFile), err)
			continue
		}
		summary := fmt.Sprintf("%s:%d", filepath.Base(yamlFile), count)
		rm.loadedSummaries = append(rm.loadedSummaries, summary)
		// 降级为调试日志，避免在模块启动前重复打印
		logger.Debugf("Loaded FingerPrint Rules: %s", summary)
		totalRulesLoaded += count
	}

	// 更新快照
	rm.updateSnapshot()
	logger.Debugf("规则加载完成，共加载 %d 条规则", totalRulesLoaded)
	return nil
}

// updateSnapshot 更新规则快照（内部方法，假设已持有锁）
// 将map转换为slice，以便后续无锁或低锁遍历
func (rm *RuleManager) updateSnapshot() {
	snapshot := make([]*FingerprintRule, 0, len(rm.rules))
	for _, rule := range rm.rules {
		snapshot = append(snapshot, rule)
	}
	rm.rulesSnapshot = snapshot
}

// GetRulesSnapshot 获取规则快照
// 返回预计算的规则切片，避免每次调用都进行 map 拷贝和内存分配
func (rm *RuleManager) GetRulesSnapshot() []*FingerprintRule {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.rulesSnapshot
}

// GetRulesCount 获取加载的规则数量
func (rm *RuleManager) GetRulesCount() int {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return len(rm.rules)
}

// GetLoadedSummaryString 返回已加载规则文件的摘要字符串
func (rm *RuleManager) GetLoadedSummaryString() string {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return strings.Join(rm.loadedSummaries, " ")
}

// loadSingleYAMLFile 加载单个YAML文件
func (rm *RuleManager) loadSingleYAMLFile(filePath string) (int, error) {
	// 读取YAML文件
	data, err := os.ReadFile(filePath)
	if err != nil {
		return 0, fmt.Errorf("failed to read file: %v", err)
	}

	// 解析YAML
	var rulesMap map[string]*FingerprintRule
	if err := yaml.Unmarshal(data, &rulesMap); err != nil {
		return 0, fmt.Errorf("failed to parse YAML: %v", err)
	}

	// 处理规则
	loadedCount := 0
	isSensitiveFile := strings.Contains(strings.ToLower(filepath.Base(filePath)), "sensitive")
	for ruleName, rule := range rulesMap {
		if rule != nil {
			rule.ID = ruleName
			rule.Name = ruleName
			if isSensitiveFile && strings.TrimSpace(rule.Category) == "" {
				rule.Category = "sensitive"
			}

			// 检查规则ID冲突
			if existingRule, exists := rm.rules[ruleName]; exists {
				logger.Warnf("Rule ID conflict: %s (file: %s overrides the previous rule)",
					ruleName, filepath.Base(filePath))
				logger.Debugf("  原规则DSL: %v", existingRule.DSL)
				logger.Debugf("  新规则DSL: %v", rule.DSL)
			}

			rm.rules[ruleName] = rule
			loadedCount++
		}
	}

	return loadedCount, nil
}

// GetPathRules 获取所有包含 path 字段的规则
// 这替代了 Engine 中旧的 GetPathRules 方法
func (rm *RuleManager) GetPathRules() []*FingerprintRule {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	var pathRules []*FingerprintRule
	for _, rule := range rm.rules {
		if rule != nil && rule.HasPaths() {
			pathRules = append(pathRules, rule)
		}
	}
	return pathRules
}

// GetHeaderRules 获取所有包含 header 字段的规则
func (rm *RuleManager) GetHeaderRules() []*FingerprintRule {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	var headerRules []*FingerprintRule
	for _, rule := range rm.rules {
		if rule != nil && rule.HasHeaders() {
			headerRules = append(headerRules, rule)
		}
	}
	return headerRules
}

// GetHeaderRulesCount 获取 header 规则数量
func (rm *RuleManager) GetHeaderRulesCount() int {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	count := 0
	for _, rule := range rm.rules {
		if rule != nil && rule.HasHeaders() {
			count++
		}
	}
	return count
}

// GetPathRulesCount 获取 path 规则数量
func (rm *RuleManager) GetPathRulesCount() int {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	count := 0
	for _, rule := range rm.rules {
		if rule != nil {
			count += len(rule.Paths)
		}
	}
	return count
}

// HasPathRules 检查是否有 path 规则
func (rm *RuleManager) HasPathRules() bool {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	for _, rule := range rm.rules {
		if rule != nil && rule.HasPaths() {
			return true
		}
	}
	return false
}

// GetIconRules 获取所有包含 icon() 函数的规则
func (rm *RuleManager) GetIconRules() []*FingerprintRule {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	var iconRules []*FingerprintRule
	for _, rule := range rm.rules {
		if rule != nil {
			for _, dsl := range rule.DSL {
				if strings.Contains(dsl, "icon(") {
					iconRules = append(iconRules, rule)
					break
				}
			}
		}
	}
	return iconRules
}

type Updater struct {
	LocalPath string
	RemoteURL string
}

func NewUpdater(localPath string) *Updater {
	return &Updater{
		LocalPath: localPath,
		RemoteURL: RemoteRulesURL,
	}
}

func (u *Updater) CheckForUpdates() (bool, string, string, error) {
	localVersion, err := u.GetLocalVersion()
	if err != nil {
		if os.IsNotExist(err) {
			return true, "0.0", "unknown", nil
		}
		return false, "", "", fmt.Errorf("读取本地指纹库失败: %v", err)
	}

	remoteVersion, err := u.GetRemoteVersion()
	if err != nil {
		return false, localVersion, "", fmt.Errorf("检查云端版本失败: %v", err)
	}

	return u.compareVersions(localVersion, remoteVersion), localVersion, remoteVersion, nil
}

func (u *Updater) UpdateRules() error {
	logger.Infof("Downloading latest fingerprint rules from cloud: %s", u.RemoteURL)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(u.RemoteURL)
	if err != nil {
		return fmt.Errorf("下载失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("下载失败，HTTP状态码: %d", resp.StatusCode)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("读取响应内容失败: %v", err)
	}

	version := u.extractVersion(content)
	if version == "" {
		return fmt.Errorf("下载的内容无效或未包含版本信息")
	}

	dir := filepath.Dir(u.LocalPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %v", err)
	}

	if err := os.WriteFile(u.LocalPath, content, 0644); err != nil {
		return fmt.Errorf("写入文件失败: %v", err)
	}

	logger.Infof("Fingerprint rules updated successfully! Version: %s", version)
	return nil
}

func (u *Updater) GetLocalVersion() (string, error) {
	content, err := os.ReadFile(u.LocalPath)
	if err != nil {
		return "", err
	}
	return u.extractVersion(content), nil
}

func (u *Updater) GetRemoteVersion() (string, error) {
	client := &http.Client{Timeout: 1 * time.Second}

	req, err := http.NewRequest("GET", u.RemoteURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Range", "bytes=0-1024")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 206 {
		return "", fmt.Errorf("HTTP请求失败: %d", resp.StatusCode)
	}

	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	version := u.extractVersion(content)
	if version == "" {
		return "", fmt.Errorf("未找到版本信息")
	}
	return version, nil
}

func (u *Updater) extractVersion(content []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "# version:") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return ""
}

func (u *Updater) compareVersions(v1, v2 string) bool {
	if v1 == "" || v2 == "" {
		return true
	}

	f1, err1 := strconv.ParseFloat(v1, 64)
	f2, err2 := strconv.ParseFloat(v2, 64)
	if err1 == nil && err2 == nil {
		return f1 < f2
	}

	return v1 != v2
}
