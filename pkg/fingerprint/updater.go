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
	"time"

	"veo/pkg/utils/logger"
)

const (
	// RemoteRulesURL 指纹库云端地址
	RemoteRulesURL = "https://raw.githubusercontent.com/Nuclei-Template-Hub/VEO-Fingerprint/refs/heads/main/finger.yaml"
	// DefaultRulesFile 默认本地指纹库文件名
	DefaultRulesFile = "finger.yaml"
)

// Updater 指纹库更新器
type Updater struct {
	LocalPath string
	RemoteURL string
}

// NewUpdater 创建更新器
func NewUpdater(localPath string) *Updater {
	return &Updater{
		LocalPath: localPath,
		RemoteURL: RemoteRulesURL,
	}
}

// CheckForUpdates 检查更新
// 返回: hasUpdate, localVersion, remoteVersion, error
func (u *Updater) CheckForUpdates() (bool, string, string, error) {
	// 1. 获取本地版本
	localVersion, err := u.GetLocalVersion()
	if err != nil {
		// 如果本地文件不存在，视为需要更新（或者是首次安装）
		if os.IsNotExist(err) {
			return true, "0.0", "unknown", nil
		}
		return false, "", "", fmt.Errorf("读取本地指纹库失败: %v", err)
	}

	// 2. 获取远程版本
	remoteVersion, err := u.GetRemoteVersion()
	if err != nil {
		return false, localVersion, "", fmt.Errorf("检查云端版本失败: %v", err)
	}

	// 3. 比较版本
	hasUpdate := u.compareVersions(localVersion, remoteVersion)
	return hasUpdate, localVersion, remoteVersion, nil
}

// UpdateRules 执行更新
func (u *Updater) UpdateRules() error {
	logger.Infof("正在从云端下载最新指纹库: %s", u.RemoteURL)

	// 下载文件
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
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

	// 验证内容是否有效（简单检查版本号）
	version := u.extractVersion(content)
	if version == "" {
		return fmt.Errorf("下载的内容无效或未包含版本信息")
	}

	// 写入本地文件
	// 确保目录存在
	dir := filepath.Dir(u.LocalPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("创建目录失败: %v", err)
	}

	if err := os.WriteFile(u.LocalPath, content, 0644); err != nil {
		return fmt.Errorf("写入文件失败: %v", err)
	}

	logger.Infof("指纹库已更新成功! 版本: %s", version)
	return nil
}

// GetLocalVersion 获取本地版本
func (u *Updater) GetLocalVersion() (string, error) {
	content, err := os.ReadFile(u.LocalPath)
	if err != nil {
		return "", err
	}
	return u.extractVersion(content), nil
}

// GetRemoteVersion 获取远程版本
func (u *Updater) GetRemoteVersion() (string, error) {
	client := &http.Client{
		Timeout: 3 * time.Second, // 缩短超时时间到3秒，避免启动阻塞过久
	}
	// 只读取前4KB来获取版本信息，节省流量
	// 注意：如果服务器不支持Range，可能需要下载完整文件，这里简单起见直接GET
	// 考虑到指纹库可能较大，理想情况是只取头部，但为了准确性和简单性，
	// 我们先尝试获取完整内容（或者由于版本信息在头部，可以使用Range头）
	req, err := http.NewRequest("GET", u.RemoteURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Range", "bytes=0-1024") // 尝试只获取前1KB

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
		// 如果Range请求失败没拿到版本（可能版本注释在更后面？一般在第一行），尝试全量
		// 这里暂且认为版本就在头部
		return "", fmt.Errorf("未找到版本信息")
	}
	return version, nil
}

// extractVersion 从内容中提取版本号
// 格式: # version: 1.0
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
		// 如果读到非注释行且非空行，且还没找到版本，可能就没有版本了
		if !strings.HasPrefix(line, "#") && line != "" {
			// 为了宽容度，我们可以多读几行，但通常版本在最上面
		}
	}
	return ""
}

// compareVersions 比较版本号 (v1 < v2 返回 true)
func (u *Updater) compareVersions(v1, v2 string) bool {
	if v1 == "" || v2 == "" {
		return true // 任意为空视为需要更新
	}

	f1, err1 := strconv.ParseFloat(v1, 64)
	f2, err2 := strconv.ParseFloat(v2, 64)

	if err1 == nil && err2 == nil {
		return f1 < f2
	}

	// 如果不是纯数字，使用字符串比较
	return v1 != v2
}
