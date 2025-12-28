package dirscan

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"
	"veo/pkg/utils/logger"
)

const defaultWordlistPath = "config/dict/common.txt"

var (
	globalDictCache *DictionaryCache
	cacheOnce       sync.Once
	cacheMutex      sync.Mutex

	wordlistMu      sync.RWMutex
	customWordlists []string
)

type DictionaryCache struct {
	entries []string
	loaded  bool
	mu      sync.RWMutex
}

type DictionaryManager struct{}

func getCache() *DictionaryCache {
	cacheOnce.Do(func() {
		globalDictCache = &DictionaryCache{
			entries: make([]string, 0),
		}
	})
	return globalDictCache
}

func getConfiguredWordlists() []string {
	wordlistMu.RLock()
	paths := append([]string(nil), customWordlists...)
	wordlistMu.RUnlock()

	if len(paths) == 0 {
		return []string{defaultWordlistPath}
	}

	sanitized := make([]string, 0, len(paths))
	seen := make(map[string]struct{})
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if _, exists := seen[path]; exists {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			logger.Warnf("字典文件不可用: %s (%v)", path, err)
			continue
		}
		seen[path] = struct{}{}
		sanitized = append(sanitized, path)
	}

	if len(sanitized) == 0 {
		return []string{defaultWordlistPath}
	}

	return sanitized
}

func SetWordlistPaths(paths []string) {
	wordlistMu.Lock()
	customWordlists = append([]string(nil), paths...)
	wordlistMu.Unlock()

	cache := getCache()
	cache.mu.Lock()
	cache.entries = nil
	cache.loaded = false
	cache.mu.Unlock()
}

func (dm *DictionaryManager) LoadDictionaries() error {
	cache := getCache()
	if !cache.isLoaded() {
		cacheMutex.Lock()
		if !cache.isLoaded() {
			dm.loadToCache()
		}
		cacheMutex.Unlock()
	}

	return nil
}

func (dm *DictionaryManager) loadToCache() {
	cache := getCache()

	cache.mu.Lock()
	defer cache.mu.Unlock()

	wordlists := getConfiguredWordlists()
	entries := make([]string, 0)
	total := 0
	var warnings []string

	logger.Debugf("开始加载字典文件，共 %d 个文件", len(wordlists))

	for _, path := range wordlists {
		dictEntries, lineCount, commentCount, err := readWordlist(path)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", path, err))
			continue
		}

		entries = append(entries, dictEntries...)
		total += len(dictEntries)
		logger.Debugf("字典文件加载完成: %s, 总行数 %d, 注释行 %d, 有效条目 %d",
			path, lineCount, commentCount, len(dictEntries))
	}

	if len(entries) == 0 {
		logger.Warnf("未能加载任何自定义字典，尝试使用默认字典: %s", defaultWordlistPath)
		fallbackEntries, lineCount, commentCount, err := readWordlist(defaultWordlistPath)
		if err == nil {
			entries = append(entries, fallbackEntries...)
			total = len(fallbackEntries)
			logger.Debugf("默认字典加载完成: %s, 总行数 %d, 注释行 %d, 有效条目 %d",
				defaultWordlistPath, lineCount, commentCount, len(fallbackEntries))
		} else {
			logger.Warnf("默认字典加载失败: %v", err)
		}
	}

	cache.entries = entries
	cache.loaded = true

	logger.Debugf("字典加载完成，成功加载 %d 个条目", total)
	if len(warnings) > 0 {
		logger.Warnf("字典加载警告: %s", strings.Join(warnings, "; "))
	}
}

func readWordlist(path string) ([]string, int, int, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("打开字典文件失败: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	entries := make([]string, 0, 1000)
	lineCount := 0
	commentCount := 0

	for scanner.Scan() {
		lineCount++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			if strings.HasPrefix(line, "#") {
				commentCount++
			}
			continue
		}
		entries = append(entries, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, lineCount, commentCount, fmt.Errorf("读取字典文件失败: %w", err)
	}

	return entries, lineCount, commentCount, nil
}

func (cache *DictionaryCache) isLoaded() bool {
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	return cache.loaded
}

func (dm *DictionaryManager) GetCommonDictionary() []string {
	_ = dm.LoadDictionaries()
	cache := getCache()
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	return append([]string(nil), cache.entries...)
}

// GetCommonDictionarySize 返回字典条目数（避免拷贝）
func GetCommonDictionarySize() int {
	dm := &DictionaryManager{}
	_ = dm.LoadDictionaries()
	cache := getCache()
	cache.mu.RLock()
	defer cache.mu.RUnlock()
	return len(cache.entries)
}
func (dm *DictionaryManager) Reset() {
	cache := getCache()
	cache.mu.Lock()
	cache.entries = nil
	cache.loaded = false
	cache.mu.Unlock()

	logger.Debug("字典管理器已重置")
}
