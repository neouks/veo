package fingerprint

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"veo/pkg/types"

	"gopkg.in/yaml.v3"
)

// 核心类型定义

// HTTPClientInterface 已移动到 internal/utils/httpclient 包
// 这里保留注释供参考，实际定义在 httpclient_adapter.go 中作为类型别名

// FingerprintRule 指纹识别规则
type FingerprintRule struct {
	ID        string     `yaml:"-"`                   // 规则ID（从YAML key生成）
	Name      string     `yaml:"-"`                   // 规则名称（从YAML key生成）
	DSL       []string   `yaml:"dsl"`                 // DSL表达式列表
	Condition string     `yaml:"condition,omitempty"` // 条件逻辑 (and/or，默认or)
	Category  string     `yaml:"category,omitempty"`  // 分类（可选）
	Paths     StringList `yaml:"path,omitempty"`      // 主动探测路径（支持多值）
	Headers   StringList `yaml:"header,omitempty"`    // 主动探测自定义头部（支持多值）
}

// FingerprintMatch 指纹匹配结果
type FingerprintMatch = types.FingerprintMatch

// HTTPResponse 响应数据结构
type HTTPResponse = types.HTTPResponse

// EngineConfig 引擎配置（优化版，移除未使用字段）
type EngineConfig struct {
	RulesPath       string `yaml:"rules_path"`       // 规则文件路径
	MaxConcurrency  int    `yaml:"max_concurrency"`  // 最大并发数
	EnableFiltering bool   `yaml:"enable_filtering"` // 是否启用文件过滤
	MaxBodySize     int    `yaml:"max_body_size"`    // 最大响应体大小
	LogMatches      bool   `yaml:"log_matches"`      // 是否记录匹配日志
}

// Engine 指纹识别引擎
type Engine struct {
	config                   *EngineConfig
	rules                    map[string]*FingerprintRule // 规则映射表
	matches                  []*FingerprintMatch         // 匹配结果
	dslParser                *DSLParser                  // DSL解析器
	mu                       sync.RWMutex                // 读写锁
	stats                    *Statistics                 // 统计信息
	outputCache              map[string]bool             // 已输出指纹的域名缓存
	outputMutex              sync.RWMutex                // 输出缓存的读写锁
	iconCache                map[string]string           // 图标缓存：URL->MD5哈希值
	iconMutex                sync.RWMutex                // 图标缓存的读写锁
	iconMatchCache           map[string]bool             // icon() 比较缓存：URL+Hash -> 匹配结果
	iconMatchMutex           sync.RWMutex
	staticExtensions         []string
	staticContentTypes       []string
	staticFileFilterEnabled  bool
	contentTypeFilterEnabled bool
	showSnippet              bool
	showRules                bool
	consoleSnippetEnabled    bool // 控制是否在控制台输出指纹匹配片段
	loadedSummaries          []string // 已加载规则文件摘要，例如 finger.yaml:754
}

// StringList 支持标量或数组的字符串列表解析
type StringList []string

// UnmarshalYAML 支持将标量或序列解析为字符串切片
func (sl *StringList) UnmarshalYAML(value *yaml.Node) error {
	if value == nil {
		*sl = nil
		return nil
	}

	switch value.Kind {
	case yaml.ScalarNode:
		trimmed := strings.TrimSpace(value.Value)
		if trimmed == "" {
			*sl = nil
			return nil
		}
		*sl = []string{trimmed}
		return nil
	case yaml.SequenceNode:
		result := make([]string, 0, len(value.Content))
		for _, node := range value.Content {
			if node == nil {
				continue
			}
			if node.Kind == yaml.ScalarNode {
				trimmed := strings.TrimSpace(node.Value)
				if trimmed != "" {
					result = append(result, trimmed)
				}
			}
		}
		if len(result) == 0 {
			*sl = nil
			return nil
		}
		*sl = result
		return nil
	case yaml.AliasNode:
		if value.Alias != nil {
			return sl.UnmarshalYAML(value.Alias)
		}
		return nil
	default:
		return fmt.Errorf("unsupported YAML node for string list: %v", value.Kind)
	}
}

// HasPaths 判断规则是否包含主动探测路径
func (r *FingerprintRule) HasPaths() bool {
	return len(r.Paths) > 0
}

// HasHeaders 判断规则是否包含自定义Header
func (r *FingerprintRule) HasHeaders() bool {
	return len(r.Headers) > 0
}

// GetHeaderMap 将header定义转换为键值映射
func (r *FingerprintRule) GetHeaderMap() map[string]string {
	if len(r.Headers) == 0 {
		return nil
	}
	headers := make(map[string]string)
	for _, line := range r.Headers {
		key, value, ok := parseHeaderLine(line)
		if !ok {
			continue
		}
		headers[key] = value
	}
	if len(headers) == 0 {
		return nil
	}
	return headers
}

func parseHeaderLine(line string) (string, string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", "", false
	}
	parts := strings.SplitN(trimmed, ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])
	if key == "" {
		return "", "", false
	}
	return key, value, true
}

// Statistics 统计信息
type Statistics struct {
	TotalRequests    int64     `json:"total_requests"`    // 总请求数
	MatchedRequests  int64     `json:"matched_requests"`  // 匹配的请求数
	FilteredRequests int64     `json:"filtered_requests"` // 过滤的请求数
	RulesLoaded      int       `json:"rules_loaded"`      // 加载的规则数
	StartTime        time.Time `json:"start_time"`        // 启动时间
	LastMatchTime    time.Time `json:"last_match_time"`   // 最后匹配时间
}

// DSLContext DSL表达式上下文（增强版，支持主动探测）
type DSLContext struct {
	Response   *HTTPResponse
	Headers    map[string][]string
	Body       string
	URL        string
	Method     string
	HTTPClient interface{} // HTTP客户端（用于icon()函数主动探测）- 临时使用interface{}
	BaseURL    string      // 基础URL（协议+主机，用于构造完整图标路径）
	Engine     *Engine     // 引擎实例（用于访问图标缓存）
}

// DSLParser DSL解析器
type DSLParser struct {
}

// 静态文件过滤相关

var (
	// StaticFileExtensions 静态文件扩展名
	StaticFileExtensions = []string{
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
		".css", ".woff", ".woff2", ".ttf", ".eot",
		".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".mkv",
	}

	// StaticContentTypes 静态内容类型
	StaticContentTypes = []string{
		"video/",
		"audio/",
		"application/zip",
		"application/x-rar-compressed",
		"application/x-7z-compressed",
		"application/pdf",
		"application/msword",
		"application/vnd.ms-excel",
		"application/vnd.ms-powerpoint",
	}
)
