package portscan

import (
	"fmt"
	"net"
	neturl "net/url"
	"sort"
	"strconv"
	"strings"
)

// DerivePortsFromTargets 从 URL 目标中提取端口（若存在），或按协议给出默认端口
// 参数：
//   - targets: 原始目标列表
//
// 返回：
//   - string: 端口表达式（逗号分隔的端口列表，如 "80,443,8080"），若未能推导返回空
func DerivePortsFromTargets(targets []string) string {
	seen := make(map[int]struct{})
	add := func(p int) {
		if p > 0 && p <= 65535 {
			seen[p] = struct{}{}
		}
	}

	for _, t := range targets {
		raw := strings.TrimSpace(t)
		if raw == "" {
			continue
		}
		if u, err := neturl.Parse(raw); err == nil && u.Host != "" {
			// 端口
			if _, portStr, err := net.SplitHostPort(u.Host); err == nil {
				if v, err := strconv.Atoi(portStr); err == nil {
					add(v)
				}
				continue
			}
			// 协议默认端口
			if strings.EqualFold(u.Scheme, "https") {
				add(443)
			} else if strings.EqualFold(u.Scheme, "http") {
				add(80)
			}
			continue
		}
		// 非URL，不推导
	}
	if len(seen) == 0 {
		return ""
	}
	// 收集端口并排序
	ports := make([]int, 0, len(seen))
	for p := range seen {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	var sb strings.Builder
	for i, p := range ports {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(strconv.Itoa(p))
	}
	return sb.String()
}

// ResolveTargetsToIPs 将输入的目标（URL/域名/IP）解析为IP列表
// 参数：
//   - targets: 原始目标列表，可以是 URL（含协议/端口/路径）、域名、IP（可带端口）
//
// 返回：
//   - []string: 解析得到的去重IP列表
//   - error: 解析失败时返回错误
func ResolveTargetsToIPs(targets []string) ([]string, error) {
	uniq := make(map[string]struct{})
	add := func(ip string) {
		if ip == "" {
			return
		}
		uniq[ip] = struct{}{}
	}
	for _, t := range targets {
		raw := strings.TrimSpace(t)
		if raw == "" {
			continue
		}

		// 直接支持 CIDR 表达式（例如 101.35.191.82/24、10.0.0.1/8）
		if _, _, cidrErr := net.ParseCIDR(raw); cidrErr == nil {
			add(raw)
			continue
		}

		// 直接支持 IP 范围表达式：
		// 1) 完整起止IP：10.0.0.1-10.2.0.0
		// 2) 末段范围：10.0.0.1-254
		if strings.Contains(raw, "-") {
			parts := strings.SplitN(raw, "-", 2)
			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])

			// 情况1：两端均为完整IP
			if net.ParseIP(left) != nil && net.ParseIP(right) != nil {
				add(raw)
				continue
			}

			// 情况2：末段范围 A.B.C.X-Y
			// 验证前缀 A.B.C. 合法，且 X、Y 在 0..255
			if idx := strings.LastIndex(left, "."); idx != -1 {
				prefix := left[:idx+1] // 含结尾的点
				startStr := left[idx+1:]
				endStr := right
				if _, errA := strconv.Atoi(startStr); errA == nil {
					if _, errB := strconv.Atoi(endStr); errB == nil {
						// 验证前缀是合法的前三段：prefix+"0" 应为合法IP
						if net.ParseIP(prefix+"0") != nil {
							add(raw)
							continue
						}
					}
				}
			}
		}

		// 优先按URL解析
		if u, err := neturl.Parse(raw); err == nil && u.Host != "" {
			host := u.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			if ip := net.ParseIP(host); ip != nil {
				add(ip.String())
				continue
			}
			// 解析域名 -> IP 列表（优先IPv4）
			ips, err := net.LookupIP(host)
			if err == nil {
				for _, ip := range ips {
					if ip.To4() != nil {
						add(ip.String())
					}
				}
			}
			continue
		}

		// 尝试 host:port
		if h, _, err := net.SplitHostPort(raw); err == nil {
			raw = h
		}
		if ip := net.ParseIP(raw); ip != nil {
			add(ip.String())
			continue
		}
		// 当作域名
		if raw != "" {
			ips, err := net.LookupIP(raw)
			if err == nil {
				for _, ip := range ips {
					if ip.To4() != nil {
						add(ip.String())
					}
				}
			}
		}
	}
	res := make([]string, 0, len(uniq))
	for ip := range uniq {
		res = append(res, ip)
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("未能从目标中解析到有效IP")
	}
	return res, nil
}

// ParsePortExpression 解析端口表达式 (e.g. "80,443,8000-8100")
func ParsePortExpression(expr string) ([]int, error) {
	portMap := make(map[int]struct{})
	parts := strings.Split(expr, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("无效的端口范围: %s", part)
			}
			start, err1 := strconv.Atoi(rangeParts[0])
			end, err2 := strconv.Atoi(rangeParts[1])
			if err1 != nil || err2 != nil {
				return nil, fmt.Errorf("端口范围必须是数字: %s", part)
			}
			if start > end {
				start, end = end, start
			}
			for i := start; i <= end; i++ {
				if i > 0 && i <= 65535 {
					portMap[i] = struct{}{}
				}
			}
		} else {
			port, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("无效的端口: %s", part)
			}
			if port > 0 && port <= 65535 {
				portMap[port] = struct{}{}
			}
		}
	}

	var ports []int
	for p := range portMap {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports, nil
}
