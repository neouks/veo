package auth

import (
	"net/http"
	"strings"
	"sync"

	"veo/pkg/utils/logger"
)

// AuthDetector 认证检测器
type AuthDetector struct {
	detectedSchemes map[string]string // 检测到的认证头部
	mu              sync.RWMutex
	OnAuthFound     func(map[string]string)
}

// NewAuthDetector 创建认证检测器
func NewAuthDetector() *AuthDetector {
	return &AuthDetector{
		detectedSchemes: make(map[string]string),
	}
}

// SetCallbacks 设置回调函数
func (ad *AuthDetector) SetCallbacks(onAuthFound func(map[string]string)) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	ad.OnAuthFound = onAuthFound
}

// LearnFromRequest 从HTTP请求中学习Authorization认证信息（被动代理模式）
func (ad *AuthDetector) LearnFromRequest(req *http.Request, url string) map[string]string {
	authHeaders := make(map[string]string)
	// logger.Debugf("开始从请求中学习认证头部: %s", url) // Reduce log noise

	// 检测Authorization头部
	if authHeader := req.Header.Get("Authorization"); authHeader != "" {
		authHeaders["Authorization"] = authHeader
		logger.Debugf("学习到Authorization头部: %s", ad.maskSensitiveValue(authHeader))

		// 解析Authorization类型
		authType := ad.parseAuthorizationType(authHeader)
		if authType != "" {
			logger.Debugf("识别认证类型: %s", authType)
		}
	}

	customAuthHeaders := ad.detectCustomAuthHeaders(req)
	for headerName, headerValue := range customAuthHeaders {
		authHeaders[headerName] = headerValue
		logger.Debugf("学习到自定义认证头部: %s = %s", headerName, ad.maskSensitiveValue(headerValue))
	}

	if len(authHeaders) > 0 {
		ad.updateDetectedSchemes(authHeaders)
	} else {
		// logger.Debug("请求中未发现认证头部") // Reduce log noise
	}

	return authHeaders
}

// updateDetectedSchemes 更新检测到的认证方案并触发回调
func (ad *AuthDetector) updateDetectedSchemes(newHeaders map[string]string) {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	updated := false
	for key, value := range newHeaders {
		// 如果是新的或者值不同（通常取最新的）
		if oldVal, exists := ad.detectedSchemes[key]; !exists || (value != "" && oldVal != value) {
			ad.detectedSchemes[key] = value
			updated = true
		}
	}

	if updated && ad.OnAuthFound != nil {
		// 在锁内调用回调，注意回调不要死锁
		// 最好异步调用或者Copy后调用
		// 这里为了简单，且OnAuthFound通常只是更新配置，假设它是快速的
		ad.OnAuthFound(newHeaders)
	}
}

// detectCustomAuthHeaders 检测自定义认证头部（如 X-Access-Token 等）
func (ad *AuthDetector) detectCustomAuthHeaders(req *http.Request) map[string]string {
	customHeaders := make(map[string]string)

	// 遍历所有请求头部，查找自定义认证头部
	for headerName, headerValues := range req.Header {
		if ad.isCustomAuthHeader(headerName) && len(headerValues) > 0 {
			// 使用第一个值（通常只有一个值）
			customHeaders[headerName] = headerValues[0]
		}
	}

	return customHeaders
}

// isCustomAuthHeader 检测是否为自定义认证头部
func (ad *AuthDetector) isCustomAuthHeader(headerName string) bool {
	// 自定义认证头部列表（大小写不敏感）
	customAuthHeaderNames := []string{
		"x-access-token",  // 常见的自定义token头部
		"x-api-key",       // API密钥头部
		"x-auth-token",    // 自定义认证token
		"x-csrf-token",    // CSRF token头部
		"x-xsrf-token",    // XSRF token头部
		"x-session-token", // 会话token头部
		"x-user-token",    // 用户token头部
		"api-key",         // API密钥（无x-前缀）
		"apikey",          // API密钥（无分隔符）
		"access-token",    // 访问token（无x-前缀）
		"auth-token",      // 认证token（无x-前缀）
		"session-token",   // 会话token（无x-前缀）
		"user-token",      // 用户token（无x-前缀）
	}

	headerNameLower := strings.ToLower(headerName)
	for _, authHeaderName := range customAuthHeaderNames {
		if headerNameLower == authHeaderName {
			return true
		}
	}
	return false
}

// parseAuthorizationType 解析Authorization头部的认证类型
func (ad *AuthDetector) parseAuthorizationType(authHeader string) string {
	authHeader = strings.TrimSpace(authHeader)
	parts := strings.Fields(authHeader)
	if len(parts) > 0 {
		authType := strings.ToLower(parts[0])
		switch authType {
		case "bearer":
			return "Bearer Token"
		case "basic":
			return "Basic Authentication"
		case "digest":
			return "Digest Authentication"
		case "jwt":
			return "JWT Token"
		case "oauth":
			return "OAuth Token"
		default:
			return strings.Title(authType)
		}
	}
	return ""
}

// maskSensitiveValue 遮蔽敏感值用于日志输出
func (ad *AuthDetector) maskSensitiveValue(value string) string {
	if len(value) <= 8 {
		return strings.Repeat("*", len(value))
	}

	// 显示前4个和后4个字符，中间用*代替
	prefix := value[:4]
	suffix := value[len(value)-4:]
	middle := strings.Repeat("*", len(value)-8)

	return prefix + middle + suffix
}
