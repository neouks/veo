package cli

import (
	"context"
	"strings"
	"sync"

	"veo/pkg/dirscan"
	"veo/pkg/logger"
	interfaces "veo/pkg/types"
)

func (sc *ScanController) runDirscanModule(ctx context.Context, targets []string) ([]interfaces.HTTPResponse, error) {
	originalContext := sc.requestProcessor.GetModuleContext()
	sc.requestProcessor.SetModuleContext("dirscan")

	originalBatchMode := sc.requestProcessor.IsBatchMode()
	sc.requestProcessor.SetBatchMode(true)
	originalDecompress := true
	originalFollowRedirect := false
	originalMaxRedirects := 0
	if cfg := sc.requestProcessor.GetConfig(); cfg != nil {
		originalDecompress = cfg.DecompressResponse
		originalFollowRedirect = cfg.FollowRedirect
		originalMaxRedirects = cfg.MaxRedirects
		if originalDecompress || originalFollowRedirect || originalMaxRedirects != 0 {
			updated := *cfg
			updated.DecompressResponse = false
			updated.FollowRedirect = false
			updated.MaxRedirects = 0
			sc.requestProcessor.UpdateConfig(&updated)
		}
	}

	defer func() {
		sc.requestProcessor.SetModuleContext(originalContext)
		sc.requestProcessor.SetBatchMode(originalBatchMode)
		if cfg := sc.requestProcessor.GetConfig(); cfg != nil {
			if cfg.DecompressResponse != originalDecompress || cfg.FollowRedirect != originalFollowRedirect || cfg.MaxRedirects != originalMaxRedirects {
				updated := *cfg
				updated.DecompressResponse = originalDecompress
				updated.FollowRedirect = originalFollowRedirect
				updated.MaxRedirects = originalMaxRedirects
				sc.requestProcessor.UpdateConfig(&updated)
			}
		}
	}()

	dictInfo := "config/dict/common.txt"
	if strings.TrimSpace(sc.wordlistPath) != "" {
		dictInfo = sc.wordlistPath
	}
	logger.Infof("Start Dirscan, Loaded Dict: %s", dictInfo)

	validTargets := make([]string, 0, len(targets))
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		validTargets = append(validTargets, target)
	}

	logger.Debugf("开始目录扫描，目标数量: %d", len(validTargets))

	maxDepth := 0
	if sc.args.DepthSet {
		maxDepth = sc.args.Depth
	}

	if sc.statsDisplay.IsEnabled() {
		if maxDepth <= 0 {
			dictSize := dirscan.GetCommonDictionarySize()
			if dictSize > 0 {
				totalRequests := int64(len(validTargets) * dictSize)
				sc.statsDisplay.EnableManualTotalRequests(totalRequests)
				defer sc.statsDisplay.DisableManualTotalRequests()
			}
		} else {
			sc.statsDisplay.DisableManualTotalRequests()
		}
	}

	reqConfig := sc.requestProcessor.GetConfig()

	var allResults []interfaces.HTTPResponse
	var allResultsMu sync.Mutex
	var firstErr error
	hadSuccess := false

	if len(validTargets) == 0 {
		return allResults, nil
	}

	maxConcurrent := reqConfig.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}

	perTargetConcurrent := maxConcurrent
	if perTargetConcurrent < 1 {
		perTargetConcurrent = 1
	}

	logger.Debugf("目录扫描顺序扫描目标，单目标并发数: %d", perTargetConcurrent)

	for _, target := range validTargets {
		if ctx.Err() != nil {
			break
		}

		currentTarget := target

		workerProcessor := sc.requestProcessor.CloneWithContext("dirscan", 0)
		workerCfg := workerProcessor.GetConfig()
		if workerCfg.MaxConcurrent != perTargetConcurrent {
			workerCfg.MaxConcurrent = perTargetConcurrent
			workerProcessor.UpdateConfig(workerCfg)
		}

		engine := dirscan.NewEngine(&dirscan.EngineConfig{
			MaxConcurrency: perTargetConcurrent,
			RequestTimeout: workerCfg.Timeout,
			ProxyURL:       workerCfg.ProxyURL,
		})
		engine.SetRequestProcessor(workerProcessor)

		runCtx, cancel := context.WithCancel(ctx)

		layerScanner := func(layerTargets []string, filter *dirscan.ResponseFilter, depth int) ([]interfaces.HTTPResponse, error) {
			tempCollector := dirscan.NewRecursionCollector(layerTargets)

			recursive := depth > 0
			scanResult, err := engine.PerformScanWithFilter(runCtx, tempCollector, recursive, filter)
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
			runCtx,
			[]string{currentTarget},
			maxDepth,
			layerScanner,
			targetFilter,
		)
		if cancel != nil {
			cancel()
		}
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			logger.Warnf("Dirscan failed for target %s: %v", currentTarget, err)
			continue
		}

		hadSuccess = true
	}

	if !hadSuccess && firstErr != nil {
		return nil, firstErr
	}

	return allResults, nil
}
