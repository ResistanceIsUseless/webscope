package discovery

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	appconfig "github.com/resistanceisuseless/webscope/pkg/config"
	"github.com/resistanceisuseless/webscope/pkg/modules"
	"github.com/resistanceisuseless/webscope/pkg/types"
)

type Config struct {
	Workers   int
	Timeout   time.Duration
	RateLimit int
	Modules   []string
	Verbose   bool
	AppConfig *appconfig.Config
	Profile   string
}

type Engine struct {
	config         *Config
	modules        []types.DiscoveryModule
	rateLimiter    *RateLimiter
	processedCount int64
	totalCount     int64
	startTime      time.Time
}

type RateLimiter struct {
	ticker   *time.Ticker
	requests chan struct{}
	stop     chan struct{}
	once     sync.Once
}

func NewRateLimiter(requestsPerSecond int) *RateLimiter {
	rl := &RateLimiter{
		ticker:   time.NewTicker(time.Second / time.Duration(requestsPerSecond)),
		requests: make(chan struct{}, requestsPerSecond),
		stop:     make(chan struct{}),
	}

	go func() {
		for {
			select {
			case <-rl.ticker.C:
				select {
				case rl.requests <- struct{}{}:
				default:
				}
			case <-rl.stop:
				return
			}
		}
	}()

	return rl
}

func (rl *RateLimiter) Wait() error {
	select {
	case <-rl.requests:
		return nil
	case <-rl.stop:
		return context.Canceled
	}
}

func (rl *RateLimiter) Stop() {
	rl.once.Do(func() {
		close(rl.stop)
		rl.ticker.Stop()
	})
}

func NewEngine(config *Config) *Engine {
	engine := &Engine{
		config:      config,
		modules:     []types.DiscoveryModule{},
		rateLimiter: NewRateLimiter(config.RateLimit),
	}

	for _, moduleName := range config.Modules {
		switch moduleName {
		case "httpx":
			// Configure httpx module with settings from profile config
			threads := 50
			rateLimit := config.RateLimit
			if config.AppConfig != nil && config.Profile != "" {
				httpxConfig := config.AppConfig.GetHTTPXConfig(config.Profile)
				if httpxConfig.Threads > 0 {
					threads = httpxConfig.Threads
				}
				if httpxConfig.RateLimit > 0 {
					rateLimit = httpxConfig.RateLimit
				}
			}
			engine.modules = append(engine.modules, modules.NewHTTPXModule(threads, config.Timeout, rateLimit))
		case "httpx-lib":
			// Use httpx as a library instead of CLI
			threads := 50
			rateLimit := config.RateLimit
			if config.AppConfig != nil && config.Profile != "" {
				httpxConfig := config.AppConfig.GetHTTPXConfig(config.Profile)
				if httpxConfig.Threads > 0 {
					threads = httpxConfig.Threads
				}
				if httpxConfig.RateLimit > 0 {
					rateLimit = httpxConfig.RateLimit
				}
			}
			engine.modules = append(engine.modules, modules.NewHTTPXLibModule(threads, config.Timeout, rateLimit))
		case "http":
			// Deprecated: Use httpx module instead
			engine.modules = append(engine.modules, modules.NewHTTPModule(config.Timeout))
		case "robots":
			engine.modules = append(engine.modules, modules.NewRobotsModuleWithConfig(config.Timeout, config.AppConfig))
		case "paths":
			engine.modules = append(engine.modules, modules.NewPathsModule(config.Timeout, true, config.AppConfig))
		case "javascript", "js":
			// Pass jsluice config to JavaScript module
			var jsConfig *appconfig.JSluiceConfig
			if config.AppConfig != nil {
				jsConfig = &config.AppConfig.Global.JSluice
			}
			engine.modules = append(engine.modules, modules.NewJavaScriptModule(config.Timeout, jsConfig))
		case "sitemap":
			engine.modules = append(engine.modules, modules.NewSitemapModuleWithConfig(config.Timeout, config.AppConfig))
		case "katana":
			// Configure katana module with settings from profile config
			depth := 3
			rateLimit := config.RateLimit
			if config.AppConfig != nil && config.Profile != "" {
				katanaConfig := config.AppConfig.GetKatanaConfig(config.Profile)
				if katanaConfig.Depth > 0 {
					depth = katanaConfig.Depth
				}
				if katanaConfig.RateLimit > 0 {
					rateLimit = katanaConfig.RateLimit
				}
			}
			engine.modules = append(engine.modules, modules.NewKatanaModule(depth, config.Timeout, rateLimit))
		case "katana-lib":
			// Configure katana library module with profile settings
			var katanaConfig appconfig.KatanaConfig
			if config.Profile != "" && config.AppConfig != nil {
				katanaConfig = config.AppConfig.GetKatanaConfig(config.Profile)
			}
			
			// Set defaults if config is empty
			if katanaConfig.Depth == 0 {
				katanaConfig.Depth = 2
			}
			if katanaConfig.RateLimit == 0 {
				katanaConfig.RateLimit = config.RateLimit
			}
			if katanaConfig.Timeout == 0 {
				katanaConfig.Timeout = int(config.Timeout.Seconds())
			}
			if katanaConfig.Concurrency == 0 {
				katanaConfig.Concurrency = 5
			}
			if katanaConfig.Parallelism == 0 {
				katanaConfig.Parallelism = 5
			}
			if katanaConfig.Strategy == "" {
				katanaConfig.Strategy = "breadth-first"
			}
			
			engine.modules = append(engine.modules, modules.NewKatanaLibModuleWithConfig(katanaConfig, config.Timeout))
		}
	}

	return engine
}

func (e *Engine) Discover(ctx context.Context, targets []types.Target) <-chan types.EngineResult {
	results := make(chan types.EngineResult, len(targets))

	e.totalCount = int64(len(targets))
	e.startTime = time.Now()
	atomic.StoreInt64(&e.processedCount, 0)

	if e.config.Verbose {
		fmt.Fprintf(os.Stderr, "[*] Starting discovery for %d targets with %d workers\n", len(targets), e.config.Workers)

		// Progress ticker
		go func() {
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					processed := atomic.LoadInt64(&e.processedCount)
					elapsed := time.Since(e.startTime)
					rate := float64(processed) / elapsed.Seconds()
					remaining := e.totalCount - processed

					if processed > 0 && rate > 0 {
						eta := time.Duration(float64(remaining) / rate * float64(time.Second))
						fmt.Fprintf(os.Stderr, "[*] Progress: %d/%d targets (%.1f%%) - Rate: %.1f/s - ETA: %s\n",
							processed, e.totalCount,
							float64(processed)/float64(e.totalCount)*100,
							rate,
							eta.Round(time.Second))
					} else {
						fmt.Fprintf(os.Stderr, "[*] Progress: %d/%d targets (%.1f%%) - Starting...\n",
							processed, e.totalCount,
							float64(processed)/float64(e.totalCount)*100)
					}
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	var wg sync.WaitGroup
	targetChan := make(chan types.Target, len(targets))

	for i := 0; i < e.config.Workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			e.worker(ctx, workerID, targetChan, results)
		}(i)
	}

	go func() {
		defer close(targetChan)
		for _, target := range targets {
			select {
			case targetChan <- target:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
		e.rateLimiter.Stop()

		if e.config.Verbose {
			processed := atomic.LoadInt64(&e.processedCount)
			elapsed := time.Since(e.startTime)
			fmt.Fprintf(os.Stderr, "[*] Discovery completed: %d targets in %s\n", processed, elapsed.Round(time.Second))
		}
	}()

	return results
}

func (e *Engine) worker(ctx context.Context, workerID int, targets <-chan types.Target, results chan<- types.EngineResult) {
	for {
		select {
		case target, ok := <-targets:
			if !ok {
				return
			}

			if e.config.Verbose {
				fmt.Fprintf(os.Stderr, "[Worker %d] Processing: %s\n", workerID, target.URL)
			}

			result := e.processTarget(ctx, target)

			atomic.AddInt64(&e.processedCount, 1)

			if e.config.Verbose {
				if result.Error != nil {
					fmt.Fprintf(os.Stderr, "[Worker %d] Error on %s: %v\n", workerID, target.URL, result.Error)
				} else {
					paths := len(result.Discovery.Paths)
					endpoints := len(result.Discovery.Endpoints)
					if paths > 0 || endpoints > 0 {
						fmt.Fprintf(os.Stderr, "[Worker %d] Found on %s: %d paths, %d endpoints\n",
							workerID, target.URL, paths, endpoints)
					}
				}
			}

			select {
			case results <- result:
			case <-ctx.Done():
				return
			}

		case <-ctx.Done():
			return
		}
	}
}

func (e *Engine) processTarget(ctx context.Context, target types.Target) types.EngineResult {
	if err := e.rateLimiter.Wait(); err != nil {
		return types.EngineResult{
			Target: target,
			Error:  err,
		}
	}

	combinedResult := &types.DiscoveryResult{
		Paths:        []types.Path{},
		Endpoints:    []types.Endpoint{},
		Technologies: []types.Technology{},
		Secrets:      []types.Secret{},
		Forms:        []types.Form{},
		Parameters:   []types.Parameter{},
	}

	for _, module := range e.modules {
		select {
		case <-ctx.Done():
			return types.EngineResult{
				Target: target,
				Error:  ctx.Err(),
			}
		default:
		}

		moduleResult, err := module.Discover(target)
		if err != nil {
			if e.config.Verbose {
				fmt.Fprintf(os.Stderr, "[Module %s] Error on %s: %v\n", module.Name(), target.URL, err)
			}
			continue
		}

		combinedResult.Paths = append(combinedResult.Paths, moduleResult.Paths...)
		combinedResult.Endpoints = append(combinedResult.Endpoints, moduleResult.Endpoints...)
		combinedResult.Technologies = append(combinedResult.Technologies, moduleResult.Technologies...)
		combinedResult.Secrets = append(combinedResult.Secrets, moduleResult.Secrets...)
		combinedResult.Forms = append(combinedResult.Forms, moduleResult.Forms...)
		combinedResult.Parameters = append(combinedResult.Parameters, moduleResult.Parameters...)
	}

	return types.EngineResult{
		Target:    target,
		Discovery: combinedResult,
	}
}
