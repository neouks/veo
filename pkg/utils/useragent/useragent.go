package useragent

import (
	"math/rand"
	"sync"
	"time"
)

var (
	defaultUserAgents = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	}

	rng   = rand.New(rand.NewSource(time.Now().UnixNano()))
	rngMu sync.Mutex
)

// DefaultList 返回默认的User-Agent列表副本
func DefaultList() []string {
	result := make([]string, len(defaultUserAgents))
	copy(result, defaultUserAgents)
	return result
}

// GetEffectiveList 返回有效的User-Agent列表（目前仅返回默认列表，可扩展为支持传入自定义列表）
func GetEffectiveList() []string {
	return DefaultList()
}

// IsRandomEnabled 判断是否启用随机User-Agent (默认启用，可扩展配置)
func IsRandomEnabled() bool {
	return true
}

// Primary 返回首选的User-Agent（不考虑随机设置）
func Primary() string {
	list := GetEffectiveList()
	if len(list) == 0 {
		return ""
	}
	return list[0]
}

// Pick 返回根据随机策略选择的User-Agent
func Pick() string {
	list := GetEffectiveList()
	if len(list) == 0 {
		return ""
	}
	if !IsRandomEnabled() || len(list) == 1 {
		return list[0]
	}
	rngMu.Lock()
	idx := rng.Intn(len(list))
	rngMu.Unlock()
	return list[idx]
}

