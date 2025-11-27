# VEO 主被动扫描工具
## 只做三件事

**端口扫描、目录探测、指纹识别**

**欢迎使用任何同类型工具进行准确性和误报对比**。

---
[![asciicast](https://asciinema.org/a/nNomQmVMS7vfU6TKbPtCI7Nd0.svg)](https://asciinema.org/a/nNomQmVMS7vfU6TKbPtCI7Nd0)

## 更新日志 

- 2025/11/20
  ```
  1、优化目录扫描/指纹识别模块HTTP跟随跳转功能，针对状态码返回200，内容为JS/HTML跳转场景进行多种适配，使用正则进行匹配。
  2、优化代码架构，更合理更高效更已读，各模块解偶设计，互相独立，不相互依赖。
  3、大幅优化目录扫描误报率，无效页面过滤算法更加精准。
  4、设计API接口，后续支持通过Web API进行调用。
  5、更新指纹规则库、目录扫描字典。
  ```
  
- 2025/11/14
  ```
  1、修复模块运行顺序与调用问题。
  2、完善主动/被动指纹识别准确性。
  3、新增springboot专项扫描字典。
  4、指纹识别规则新增多path路径请求。
  ```

- 2025/11/05

  ```
  1、优化扫描工作流流程：端口扫描->识别到http/https服务->被动指纹识别->主动指纹识别->目录扫描->无效页面/相似页面过滤->输出结果。
  2、新增目录扫描错误判断，出现多次“connection refused”，中止扫描并丢弃目标。
  3、提升端口扫描速度。
  4、优化目录扫描302跳转判断逻辑，默认不进行跟随跳转。
  ```

- 2025/11/03

  ```
  1、修复被动扫描下，域名匹配问题。
  2、新增存活检测进度显示，优化存活检测并发，提升检测速度。
  3、端口扫描新增常用Web端口，常用服务端口、top5000端口未指定端口范围时，默认扫描常用Web端口，也可使用-p all,top5000,web
  4、修复目录扫描302跳转判断逻辑。
  5、新增指纹信息与目录字典。
  6、新增端口扫描结束后自动判断服务协议，满足http/https则开启新一轮指纹识别->目录扫描。
  ```

- 2025/10/31

  ```
  1、新增端口扫描模块：-m port -u 10.0.0.0/24 -p 80,443
  2、新增参数-na，用来取消目录扫描/指纹识别前的目标存活检测，默认关闭。
  3、新增参数-sV，用来进行端口扫描结果的服务识别，默认关闭。
  ```

- 2025/10/29

  ```
  1、目录扫描新增{{sub_domain}}标识符，用来对目标域名进行拆分进行拼接扫描。
  2、新增端口扫描模块，与指纹识别，目录扫描模块完全分离，插件化实现，可实现高精度的扫描，准确度与速度较为均衡。
  3、新增--rate参数，-p参数，用来指定端口扫描的速率以及扫描端口的范围。命令行包含-p参数才会运行端口扫描模块。
  ```

- 2025/10/28

  ```
  1、修改字典加载模式，默认只加载common.txt字典，剩余字典需用户-w指定。支持多文件选择，例如-w dict/common.txt,dict/xxx.txt
  2、新增-vv参数，对指纹识别/敏感信息识别内容提取高亮，方便查看匹配的具体特征上下文。
  3、精简配置config.yaml配置文件，修改为命令行接收配置参数。
  4、新增优化指纹信息和目录字典。
  5、优化404探测指纹显示方式，统一进行指纹显示的合并。
  6、新增execl报告输出。
  7、新增-nc参数：取消控制台颜色输出，防止windows系统下乱码的情况。
  8、新增--json参数：控制台输出结果变为纯json结果输出，方便其他工具接收输出作为第三方工具的输入。
  ```

  

## 前言

互联网那么多开源的同类型工具，为什么还要重复造轮子。

目前许多优秀的工具基本都有以下几点问题：

1、无效页面的过滤不精准，类似状态码200，实际内容返回404的这种情况，以及泛页面情况的出现，如何准确过滤掉是个问题。

2、不支持被动的目录扫描或者指纹识别，很多有效的目录或者指纹信息往往在二级甚至三级目录下，如何有效的提取到有效目录进行扫描，以及如何主动访问某些目录来去进行主动的指纹识别。

3、字典以及规则库臃肿，参考互联网多数项目的字典和规则库，经过精简剔除后，3000条目的规则或字典往往只有1000条是真实有效有价值的。

4、杂乱的多线程设计，许多扫描器在进行大范围扫描时，会出现假死卡顿等现象，往往在扫描过程中没有实施检测进度以及及时的丢弃目标导致。

## 1. 快速上手

被动扫描时，首次使用请解压ca-cert.zip安装证书。

```bash
# 目录扫描 + 指纹识别 （默认配置，使用内置字典）
./veo -u http://target.com

# 批量目录扫描 + 指纹识别
./veo -l target.txt --stats

# 目录扫描 + 指纹识别 + 端口扫描（默认配置，使用内置字典）
./veo -u http://target.com -p 1-65535

# 目录扫描 + 指纹识别 + 端口扫描，输出json结果
./veo -u http://target.com -p 1-65535 --json

# 使用自定义字典、输出 JSON 报告
./veo -u http://target.com -w dict/custom.txt --output report.json

# 使用自定义字典、输出 HTML 报告
./veo -u http://target.com -w dict/custom.txt --output report.html

# 仅指纹识别
./veo -m finger -u http://target.com

# 仅目录扫描
./veo -m dirscan -u http://target.com

# 仅端口扫描
./veo -m port -u 1.1.1.1 -p 1-65535
./veo -m port -u 1.1.1.1/24 -p 1-65535
./veo -m port -u 1.1.1.1-1.1.1.254 -p 1-65535

# 仅端口扫描+服务识别
./veo -m port -u 1.1.1.1 -p 1-65535 -sV

# 被动扫描（默认监听端口9080）
./veo -u http://target.com --listen -lp 8090
```


## CLI 参数说明

### 目标与模块

| 参数 | 默认值 | 说明 | 示例 |
|------|--------|------|------|
| `-u` | 必填或 `-l` | 目标列表，逗号分隔。支持完整 URL、域名、`host:port`、CIDR、IP 范围。 | `-u http://a.com,https://b.com` |
| `-l` | — | 目标文件路径，每行一个目标；支持注释 `#` 和空行。 | `-l targets.txt` |
| `-m` | `finger,dirscan` | 启用的模块，逗号分隔：`finger` 指纹识别，`dirscan` 目录扫描，`port` 端口扫描。 | `-m port` |
| `--listen` | `false` | 启用被动代理模式（监听 HTTP 流量），默认主动扫描。 | `--listen` |
| `-lp` | `9080` | 被动代理监听端口，仅在 `--listen` 模式下使用。 | `-lp 8080` |

### 扫描行为

| 参数 | 默认值 | 说明 | 示例 |
|------|--------|------|------|
| `--debug` | `false` | 启用调试日志，输出 `[DBG]` 级别信息。 | `--debug` |
| `--stats` | `false` | 显示实时扫描统计（适用于长时间任务）。 | `--stats` |
| `-v` | `false` | 显示指纹匹配规则内容（不含片段）。 | `-v` |
| `-na` | `false` | 跳过存活检测，直接对目标发起扫描。 | `-na` |
| `-vv` | `false` | 显示指纹匹配规则及匹配片段详情。 | `-vv` |
| `-nc` | `false` | 禁用彩色输出，适用于不支持 ANSI 的终端。 | `-nc` |
| `--json` | `false` | 控制台结果以 JSON 输出。 | `--json` |

### 性能调优

| 参数 | 默认值 | 说明 | 示例 |
|------|--------|------|------|
| `-t`, `--threads` | `200` | 全局并发线程数（请求处理、目录扫描等）。 | `-t 100` |
| `--retry` | `3` | 失败重试次数。 | `--retry 5` |
| `--timeout` | `5` 秒 | 全局请求超时时间。 | `--timeout 10` |

## 目录扫描

| 参数 | 默认值 | 说明 | 示例 |
|------|--------|------|------|
| `-w` | 配置文件字典 | 指定自定义目录扫描字典文件（多文件 可逗号分隔）。 | `-w dict/common.txt,dict/admin.txt` |

## 端口扫描

| 参数 | 默认值 | 说明 | 示例 |
|------|--------|------|------|
| `-p` | 必填（启用 port 模块时） | 端口表达式，支持单个、范围、逗号组合。 | `-p 80,443,8000-8100` |
| `--rate` | `2048` | 端口探测速率| `--rate 5012` |
| `-sV` | `false` | 对开放端口执行服务识别（基于内置指纹 + HTTP fallback）。 | `-sV` |

## 输出控制

| 参数 | 默认值 | 说明 | 示例 |
|------|--------|------|------|
| `-o`, `--output` | — | 结果输出到文件，支持 `.json`, `.xlsx`。 | `--output report.json` |
| `--json` | `false` | 控制台输出 JSON（配合 `-o *.json` 会写入合并结果）。 | `--json` |

## HTTP 与过滤

| 参数 | 默认值 | 说明 | 示例 |
|------|--------|------|------|
| `--header` | — | 自定义 HTTP 头，可多次指定。 | `--header "Authorization: Bearer xxx"` |
| `-s` | 配置默认 | 保留的 HTTP 状态码列表，逗号分隔。 | `-s 200,301,302` |
| `--filter` | `50` | 相似页面过滤阈值（字节）。`0` 表示禁用。 | `--filter 100` |

> **注意**  
>  端口扫描需要管理员权限（macOS/Linux 使用 `sudo`，Windows 用管理员命令提示符）。  
当 `-m port` 单独使用时，必须指定 `-p`，建议配合 `-sV` 获取服务信息。默认速率 `2048`。 

---
## 配置文件说明

默认配置位于 `configs/config.yaml`，主要分为以下模块：

### 服务器与主机过滤
```yaml
server:
  listen: ":9080" # 被动扫描时，监听的端口

hosts:
  allow:  # 被动扫描时默认允许的主机
    - "*"
  reject: # 被动扫描时默认拒绝的主机
    - "*.baidu.com"
    - "*.google.*"
```
- `allow` / `reject` 控制可访问的目标域，支持通配符。

### 目录扫描相关配置
```yaml
addon:
  collector:
    GenerationStatusCodes: [200, 403, 401, 500, 405]
    static:
      path: ["/css/", "/js/"]
      extensions: [".css", ".js", ".png", ...]
```
- `GenerationStatusCodes` ：被动扫描时，仅采集符合状态码的URL
- `path`：过滤静态目录
- `extensions`：过滤静态文件

```yaml
addon:
  filter:
    enable: true
    ValidStatusCodes: [200, 401, 403, 405, 302, 301, 500]
    filter_tolerance: 50
```
- `ValidStatusCodes`：目录扫描过滤的状态码
- `filter_tolerance`：相似页面容错字节数（默认 50 字节）。
- 支持开启/关闭主要哈希、二次哈希过滤。

### 请求配置
```yaml
addon:
  request:
    timeout: 5
    retry: 2
    threads: 200
    max_response_body_size: 1048576
```
- `timeout`：单请求超时时间（秒）。
- `retry`：重试次数
- `threads`：最大并发数。
- `max_response_body_size`：响应体限制大小（防止内存占用过大）。

---
## 目录扫描无效页面过滤逻辑

1. **状态码过滤**：默认白名单 `200/301/302/401/403/405/500`，可覆写。
2. **静态资源过滤**：根据 Content-Type / 扩展名排除图片、视频等页面。
3. **主要哈希过滤**：剔除重复或异常页面，默认阈值 3。
4. **二次哈希过滤**：对相似页面进行去重，默认阈值 1。
5. **相似页面容错**：默认 50 字节，可通过配置文件或 SDK 参数调整。
6. **认证头探测**：对 401/403 响应自动提取认证信息，携带认证扫描，出货率更高。
7. **指纹识别**：解压 gzip/deflate/brotli，自动识别编码，执行 DSL 规则，输出 `<rule_name>` 与 `<rule_content>`。

---

## 指纹库编写规则和仓库
https://github.com/Nuclei-Template-Hub/VEO-Fingerprint
---
## SDK 使用

### 安装依赖
确保 `go.mod` 中引用本仓库：
```bash
go get github.com/pphuahua/veo/pkg/sdk/scan
```

### 代码示例
```go
package main

import (
    "fmt"
    "log"
    "time"

    "veo/pkg/sdk/scan"
)

func main() {
    dirCfg := scan.DefaultDirscanConfig()
    dirCfg.MaxConcurrency = 150
    dirCfg.RequestTimeout = 8 * time.Second
    dirCfg.EnableReporting = false
    dirCfg.Filter = &scan.DirscanFilterOptions{
        ValidStatusCodes:     []int{200, 301, 302, 401, 403, 405, 500},
        InvalidPageThreshold: scan.Int(3),
        SecondaryThreshold:   scan.Int(1),
        FilterTolerance:      scan.Int64(50),
    }

    fpCfg := scan.DefaultFingerprintConfig()
    fpCfg.MaxConcurrency = 150
    fpCfg.MaxBodySize = 2 * 1024 * 1024
    fpCfg.LogLevel = "debug"

    autoSkip := true

    cfg := &scan.Config{
        DirTargets:         []string{"http://x.x.x.x/"},
        FingerprintTargets: []string{"http://x.x.x.x/"},
        SkipTLSVerify:      false,
        AutoSkipTLSForIP:   &autoSkip,
        HTTPTimeout:        20 * time.Second,
        Dirscan:            dirCfg,
        Fingerprint:        fpCfg,
    }

    resultJSON, err := scan.RunJSON(cfg)
    if err != nil {
        log.Fatalf("扫描失败: %v", err)
    }

    fmt.Println(string(resultJSON))
}
```

### 常见字段

| 字段 | 说明 |
|------|------|
| `DirTargets` / `FingerprintTargets` | 目录扫描和额外指纹识别 URL 列表 |
| `SkipTLSVerify` / `AutoSkipTLSForIP` | TLS 校验策略，裸 IP 默认自动跳过 |
| `HTTPTimeout` | `RequestProcessor` 的请求超时 |
| `Dirscan.Filter` | 状态码、哈希阈值、容错等过滤参数 |
| `Fingerprint.Filters` | 静态资源过滤选项 |

辅助函数 `scan.Bool` / `scan.Int` / `scan.Int64` 用于快速传入指针参数。

---
## 结语

欢迎提交 Issue/PR。
