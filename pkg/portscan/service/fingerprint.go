package service

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"veo/pkg/utils/logger"
	"veo/pkg/utils/useragent"
)

// Action 动作类型
type Action uint8

const (
	ActionRecv = Action(iota)
	ActionSend
)

const (
	refusedStr   = "refused"
	ioTimeoutStr = "i/o timeout"
)

type ruleData struct {
	Action  Action
	Data    []byte
	Regexps []*regexp.Regexp
}

type serviceRule struct {
	Tls       bool
	DataGroup []ruleData
}

var serviceRules = make(map[string]serviceRule)
var readBufPool = &sync.Pool{
	New: func() interface{} {
		return make([]byte, 4096)
	},
}

// PortIdentify 端口识别主入口
func PortIdentify(network string, ip net.IP, port uint16, timeout time.Duration) (string, string, []byte, bool) {
	addr := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
	matched := make(map[string]struct{})

	// 辅助函数：标记服务已检查
	markChecked := func(s string) {
		matched[s] = struct{}{}
		for _, g := range groupFlows[s] {
			matched[g] = struct{}{}
		}
	}

	// 1. 优先端口检查
	if services, ok := portServiceOrder[port]; ok {
		for _, s := range services {
			markChecked(s)
			srv, ver, b, err := matchServiceRule(network, addr, s, timeout, ip, port)
			if srv != "" {
				logger.Debugf("priority port matched %s:%d => %s", ip, port, srv)
				return srv, ver, b, false
			}
			if err {
				return "unknown", "", b, true
			}
		}
	}

	// 2. 纯接收模式优化 (Only-Recv)
	// 建立一次连接，读取 Banner，尝试匹配所有 Only-Recv 规则
	{
		srv, ver, b, err := checkOnlyRecv(network, addr, ip, port, timeout, matched)
		if srv != "" {
			return srv, ver, b, false
		}
		if err {
			return "unknown", "", b, true
		}
		// 标记所有 Only-Recv 服务为已检查
		for _, s := range onlyRecv {
			markChecked(s)
		}
	}

	// 3. 优先服务检查
	for _, s := range serviceOrder {
		if _, ok := matched[s]; ok {
			continue
		}
		markChecked(s)
		srv, ver, b, err := matchServiceRule(network, addr, s, timeout, ip, port)
		if srv != "" {
			return srv, ver, b, false
		}
		if err {
			return "unknown", "", b, true
		}
	}

	// 4. 剩余服务回退检查
	for s := range serviceRules {
		if _, ok := matched[s]; ok {
			continue
		}
		srv, ver, b, err := matchServiceRule(network, addr, s, timeout, ip, port)
		if srv != "" {
			return srv, ver, b, false
		}
		if err {
			return "unknown", "", b, true
		}
	}

	return "unknown", "", nil, false
}

// checkOnlyRecv 执行纯接收模式检查
func checkOnlyRecv(network, addr string, ip net.IP, port uint16, timeout time.Duration, matched map[string]struct{}) (string, string, []byte, bool) {
	conn, err := net.DialTimeout(network, addr, timeout)
	if err != nil {
		return "", "", nil, true
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(timeout))

	buf := readBufPool.Get().([]byte)
	defer readBufPool.Put(buf)

	n, err := conn.Read(buf)
	if n <= 0 {
		return "", "", nil, false
	}
	banner := make([]byte, n)
	copy(banner, buf[:n])

	logger.Debugf("recv banner %s:%d => %q", ip, port, previewBanner(banner))

	// 检查 Only-Recv 规则
	for _, s := range onlyRecv {
		if _, ok := matched[s]; ok {
			continue
		}
		if rule, ok := serviceRules[s]; ok {
			for _, group := range rule.DataGroup {
				if ok, ver := matchRuleData(banner, ip, port, group, ""); ok {
					return s, ver, banner, false
				}
			}
		}
	}

	// 检查 doneRecvFinger (正则直接匹配)
	utf8Banner := convert2utf8(string(banner))
	for s, regex := range doneRecvFinger {
		matches := regex.FindStringSubmatch(utf8Banner)
		if len(matches) > 0 {
			ver := ""
			if len(matches) > 1 {
				ver = matches[1]
			}
			return s, ver, banner, false
		}
	}

	return "", "", banner, false
}

// matchServiceRule 匹配单个服务规则
func matchServiceRule(network, addr, serviceName string, timeout time.Duration, ip net.IP, port uint16) (string, string, []byte, bool) {
	rule, ok := serviceRules[serviceName]
	if !ok {
		return "", "", nil, false
	}

	dialer := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var err error

	if rule.Tls {
		conn, err = tls.DialWithDialer(dialer, network, addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10})
	} else {
		conn, err = dialer.Dial(network, addr)
	}

	if err != nil {
		// 检查是否为连接错误（忽略 TLS 握手错误，当作服务不匹配）
		if rule.Tls {
			// 如果是 TLS 握手导致的 remote error，可能不是 TLS 服务，但也证明端口开放
			// 这里简单处理：连接失败视为该服务不匹配，但如果 TCP 连上了 TLS 握手失败，是否算 DialError？
			// 原逻辑：如果是 IO Timeout 或 Refused，算 DialErr。其他算不匹配。
			if strings.Contains(err.Error(), ioTimeoutStr) || strings.Contains(err.Error(), refusedStr) {
				return "", "", nil, true
			}
			return "", "", nil, false
		}
		return "", "", nil, true
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	buf := readBufPool.Get().([]byte)
	defer readBufPool.Put(buf)

	ua := useragent.Pick()
	if ua == "" {
		ua = useragent.Primary()
	}

	for _, group := range rule.DataGroup {
		if group.Action == ActionSend {
			payload := replacePlaceholders(group.Data, ip, port, ua)
			if _, err := conn.Write(payload); err != nil {
				return "", "", nil, false
			}
		} else {
			n, err := conn.Read(buf)
			if n > 0 {
				banner := make([]byte, n)
				copy(banner, buf[:n])

				logger.Debugf("recv banner %s:%d (%s) => %q", ip, port, serviceName, previewBanner(banner))

				if ok, ver := matchRuleData(banner, ip, port, group, ua); ok {
					return serviceName, ver, banner, false
				}

				// 检查 Group Flows (关联服务)
				for _, s := range groupFlows[serviceName] {
					if subRule, ok := serviceRules[s]; ok {
						for _, subGroup := range subRule.DataGroup {
							if subGroup.Action == ActionRecv {
								if ok, ver := matchRuleData(banner, ip, port, subGroup, ua); ok {
									return s, ver, banner, false
								}
							}
						}
					}
				}

				// HTTP -> HTTPS 回退逻辑
				if serviceName == "http" && bytes.HasPrefix(banner, []byte("HTTP/1.1 400")) {
					return matchServiceRule(network, addr, "https", timeout, ip, port)
				}

				return "", "", banner, false
			}
			if err != nil {
				break
			}
		}
	}
	return "", "", nil, false
}

// matchRuleData 匹配规则数据
func matchRuleData(buf []byte, ip net.IP, port uint16, rule ruleData, ua string) (bool, string) {
	// 字节匹配
	if rule.Data != nil {
		target := replacePlaceholders(rule.Data, ip, port, ua)
		if len(target) > 0 && bytes.Contains(buf, target) {
			return true, ""
		}
	}
	// 正则匹配
	if rule.Regexps != nil {
		utf8Str := convert2utf8(string(buf))
		for _, re := range rule.Regexps {
			matches := re.FindStringSubmatch(utf8Str)
			if len(matches) > 0 {
				ver := ""
				if len(matches) > 1 {
					ver = matches[1]
				}
				return true, ver
			}
		}
	}
	return false, ""
}

// replacePlaceholders 替换占位符
func replacePlaceholders(data []byte, ip net.IP, port uint16, ua string) []byte {
	if data == nil {
		return nil
	}
	res := bytes.Replace(data, []byte("{IP}"), []byte(ip.String()), -1)
	res = bytes.Replace(res, []byte("{PORT}"), []byte(strconv.Itoa(int(port))), -1)
	if ua != "" {
		res = bytes.Replace(res, []byte("{UA}"), []byte(ua), -1)
	} else {
		res = bytes.Replace(res, []byte("{UA}"), []byte{}, -1)
	}
	return res
}

// convert2utf8 转换为 UTF-8 字符串，处理无效字符
func convert2utf8(src string) string {
	var dst strings.Builder
	for _, r := range src {
		if r == utf8.RuneError {
			dst.WriteByte(byte(src[strings.IndexRune(src, r)]))
		} else {
			dst.WriteRune(r)
		}
	}
	return dst.String()
}

func previewBanner(b []byte) string {
	const limit = 256
	if len(b) <= limit {
		return string(b)
	}
	return string(b[:limit]) + "...(truncated)"
}

// HTTPFallbackProbe 尝试对指定 host:port 发送最小化 HTTP 请求
func HTTPFallbackProbe(host string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return false
	}

	requestHost := host
	if port != 80 && port != 0 {
		requestHost = fmt.Sprintf("%s:%d", host, port)
	}
	ua := useragent.Pick()
	if ua == "" {
		ua = useragent.Primary()
	}
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n\r\n", requestHost, ua)
	if _, err := conn.Write([]byte(req)); err != nil {
		return false
	}

	reader := bufio.NewReader(conn)
	buf := make([]byte, 4096)
	n, err := reader.Read(buf)
	if n <= 0 || err != nil {
		return false
	}
	data := string(buf[:n])
	logger.Debugf("HTTP fallback raw response %s:%d => %q", host, port, data)
	dataUpper := strings.ToUpper(data)
	return strings.Contains(dataUpper, "HTTP/")
}
