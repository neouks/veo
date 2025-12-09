package cli

import (
	"fmt"
	"strings"

	"veo/pkg/utils/checkalive"
	"veo/pkg/utils/logger"
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
		parser := checkalive.NewTargetParser()
		fileTargets, err := parser.ParseFile(sc.args.TargetFile)
		if err != nil {
			return nil, err
		}
		allTargets = append(allTargets, fileTargets...)
		logger.Debugf("从文件读取到 %d 个目标", len(fileTargets))
	}

	if len(allTargets) == 0 {
		return nil, fmt.Errorf("没有有效的目标")
	}

	// 去重
	deduplicator := checkalive.NewDeduplicator()
	uniqueTargets, stats := deduplicator.DeduplicateWithStats(allTargets)

	if stats.DuplicateCount > 0 {
		logger.Debugf("去重完成: 原始 %d 个，去重后 %d 个，重复 %d 个 (%.1f%%)",
			stats.OriginalCount, stats.UniqueCount, stats.DuplicateCount, stats.DuplicateRate)
	}

	// 连通性检测和URL标准化
	checker := checkalive.NewConnectivityChecker(sc.config)
	var validTargets []string

	if sc.args.NetworkCheck {
		validTargets = checker.BatchCheck(uniqueTargets)
		if len(validTargets) == 0 {
			return nil, fmt.Errorf("没有可连通的目标")
		}
	} else {
		// 如果不进行连通性检测，仅进行验证和标准化
		var err error
		validTargets, err = checker.ValidateAndNormalize(uniqueTargets)
		if err != nil {
			return nil, err
		}
	}

	logger.Debugf("目标解析完成: 最终有效目标 %d 个", len(validTargets))
	return validTargets, nil
}
