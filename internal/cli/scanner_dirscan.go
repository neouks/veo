package cli

import (
	"context"
	"strings"
	"sync"

	"veo/pkg/dirscan"
	"veo/pkg/utils/interfaces"
	"veo/pkg/utils/logger"
)

func (sc *ScanController) runDirscanModule(ctx context.Context, targets []string) ([]interfaces.HTTPResponse, error) {
	originalContext := sc.requestProcessor.GetModuleContext()
	sc.requestProcessor.SetModuleContext("dirscan")

	originalBatchMode := sc.requestProcessor.IsBatchMode()
	sc.requestProcessor.SetBatchMode(true)

	defer func() {
		sc.requestProcessor.SetModuleContext(originalContext)
		sc.requestProcessor.SetBatchMode(originalBatchMode)
	}()

	// 模块启动提示
	dictInfo := "config/dict/common.txt"
	if strings.TrimSpace(sc.wordlistPath) != "" {
		dictInfo = sc.wordlistPath
	}
	// 模块开始前空行，提升可读性
	logger.Infof("Start Dirscan, Loaded Dict: %s", dictInfo)
	logger.Debugf("开始目录扫描，目标数量: %d", len(targets))

	maxDepth := 0
	if sc.args.DepthSet {
		maxDepth = sc.args.Depth
	}

	if sc.statsDisplay.IsEnabled() {
		if maxDepth <= 0 {
			dictSize := dirscan.GetCommonDictionarySize()
			if dictSize > 0 {
				totalRequests := int64(len(targets) * dictSize)
				sc.statsDisplay.EnableManualTotalRequests(totalRequests)
				defer sc.statsDisplay.DisableManualTotalRequests()
			}
		} else {
			sc.statsDisplay.DisableManualTotalRequests()
		}
	}

	reqConfig := sc.requestProcessor.GetConfig()
	engineCfg := &dirscan.EngineConfig{
		MaxConcurrency: reqConfig.MaxConcurrent,
		RequestTimeout: reqConfig.Timeout,
		ProxyURL:       reqConfig.ProxyURL,
	}
	engine := dirscan.NewEngine(engineCfg)
	engine.SetRequestProcessor(sc.requestProcessor)

	var allResults []interfaces.HTTPResponse
	var allResultsMu sync.Mutex
	var firstErr error
	hadSuccess := false

	// 定义层级扫描器
	layerScanner := func(layerTargets []string, filter *dirscan.ResponseFilter, depth int) ([]interfaces.HTTPResponse, error) {
		tempCollector := dirscan.NewRecursionCollector(layerTargets)

		recursive := depth > 0
		scanResult, err := engine.PerformScanWithFilter(ctx, tempCollector, recursive, filter)
		if err != nil {
			return nil, err
		}
		if scanResult == nil || scanResult.FilterResult == nil {
			return nil, nil
		}

		validPages := scanResult.FilterResult.ValidPages

		sc.collectedResultsMu.Lock()
		if len(scanResult.FilterResult.PrimaryFilteredPages) > 0 {
			sc.collectedPrimaryFiltered = append(sc.collectedPrimaryFiltered, toValueSlice(scanResult.FilterResult.PrimaryFilteredPages)...)
		}
		if len(scanResult.FilterResult.StatusFilteredPages) > 0 {
			sc.collectedStatusFiltered = append(sc.collectedStatusFiltered, toValueSlice(scanResult.FilterResult.StatusFilteredPages)...)
		}
		sc.collectedResultsMu.Unlock()

		if sc.statsDisplay.IsEnabled() {
			for range layerTargets {
				sc.statsDisplay.IncrementCompletedHosts()
			}
		}

		result := make([]interfaces.HTTPResponse, 0, len(validPages))
		for _, page := range validPages {
			if page != nil {
				result = append(result, *page)
			}
		}

		return result, nil
	}

	for _, target := range targets {
		if ctx.Err() != nil {
			break
		}

		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		targetFilter := dirscan.CreateResponseFilterFromExternal()
		if sc.fingerprintEngine != nil {
			targetFilter.SetFingerprintEngine(sc.fingerprintEngine)
		}
		targetFilter.SetOnValid(func(page *interfaces.HTTPResponse) {
			if page == nil {
				return
			}
			sc.displayedURLsMu.Lock()
			if sc.displayedURLs[page.URL] {
				sc.displayedURLsMu.Unlock()
				return
			}
			sc.displayedURLs[page.URL] = true
			sc.displayedURLsMu.Unlock()

			allResultsMu.Lock()
			allResults = append(allResults, *page)
			allResultsMu.Unlock()

			if sc.realtimeReporter != nil {
				_ = sc.realtimeReporter.WriteResponse(page)
			}
			printHTTPResponseResult(page, sc.showFingerprintSnippet, sc.args.Verbose || sc.args.VeryVerbose)
		})

		_, err := dirscan.RunRecursiveScan(
			ctx,
			[]string{target},
			maxDepth,
			layerScanner,
			targetFilter,
		)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			logger.Warnf("目标目录扫描失败: %s, %v", target, err)
			continue
		}
		hadSuccess = true
	}

	if !hadSuccess && firstErr != nil {
		return nil, firstErr
	}

	return allResults, nil
}
