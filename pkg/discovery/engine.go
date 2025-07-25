package discovery

import (
	"context"
	"sync"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/modules"
	"github.com/resistanceisuseless/webscope/pkg/types"
)

type Config struct {
	Workers   int
	Timeout   time.Duration
	RateLimit int
	Modules   []string
	Verbose   bool
}

type Engine struct {
	config      *Config
	modules     []types.DiscoveryModule
	rateLimiter *RateLimiter
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
		case "http":
			engine.modules = append(engine.modules, modules.NewHTTPModule(config.Timeout))
		case "robots":
			engine.modules = append(engine.modules, modules.NewRobotsModule(config.Timeout))
		case "paths":
			engine.modules = append(engine.modules, modules.NewPathsModule(config.Timeout, true))
		case "javascript", "js":
			engine.modules = append(engine.modules, modules.NewJavaScriptModule(config.Timeout))
		}
	}

	return engine
}

func (e *Engine) Discover(ctx context.Context, targets []types.Target) <-chan types.EngineResult {
	results := make(chan types.EngineResult, len(targets))
	
	var wg sync.WaitGroup
	targetChan := make(chan types.Target, len(targets))

	for i := 0; i < e.config.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.worker(ctx, targetChan, results)
		}()
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
	}()

	return results
}

func (e *Engine) worker(ctx context.Context, targets <-chan types.Target, results chan<- types.EngineResult) {
	for {
		select {
		case target, ok := <-targets:
			if !ok {
				return
			}
			
			result := e.processTarget(ctx, target)
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