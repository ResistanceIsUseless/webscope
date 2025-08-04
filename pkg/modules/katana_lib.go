package modules

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
	wsTypes "github.com/resistanceisuseless/webscope/pkg/types"
)

// KatanaLibModule uses katana as a library instead of CLI
type KatanaLibModule struct {
	depth       int
	timeout     time.Duration
	rateLimit   int
	concurrency int
	parallelism int
	jsluice     bool
	formExtract bool
	headless    bool
	strategy    string
}

func NewKatanaLibModule(depth int, timeout time.Duration, rateLimit int) *KatanaLibModule {
	return &KatanaLibModule{
		depth:       depth,
		timeout:     timeout,
		rateLimit:   rateLimit,
		concurrency: 10,
		parallelism: 10,
		jsluice:     true,
		formExtract: true,
		headless:    false, // Use standard mode by default for better performance
		strategy:    "depth-first",
	}
}

func (k *KatanaLibModule) Name() string {
	return "katana-lib"
}

func (k *KatanaLibModule) Priority() int {
	return 2 // High priority for crawling
}

func (k *KatanaLibModule) Discover(target wsTypes.Target) (*wsTypes.DiscoveryResult, error) {
	result := &wsTypes.DiscoveryResult{
		Paths:      []wsTypes.Path{},
		Endpoints:  []wsTypes.Endpoint{},
		Secrets:    []wsTypes.Secret{},
		Parameters: []wsTypes.Parameter{},
		Forms:      []wsTypes.Form{},
	}

	var mu sync.Mutex
	var crawledURLs []string
	var extractedEndpoints []string
	var foundSecrets []wsTypes.Secret
	var foundParams []wsTypes.Parameter
	var foundForms []wsTypes.Form

	// Configure katana options
	options := &types.Options{
		MaxDepth:        k.depth,
		FieldScope:      "rdn", // Restrict to registered domain name
		BodyReadSize:    math.MaxInt,
		Timeout:         int(k.timeout.Seconds()),
		Concurrency:     k.concurrency,
		Parallelism:     k.parallelism,
		Delay:           0,
		RateLimit:       k.rateLimit,
		Strategy:        k.strategy,
		NoScope:         false,
		DisplayOutScope: false,
		StoreResponse:   false,
		OutputFile:      "",
		JSON:            false,
		Silent:          true,
		Verbose:         false,
		NoColors:        true,
		FormExtraction:  k.formExtract,

		OnResult: func(katanaResult output.Result) {
			mu.Lock()
			defer mu.Unlock()

			// Store crawled URL
			crawledURLs = append(crawledURLs, katanaResult.Request.URL)

			// Extract endpoints from response if jsluice is enabled
			if k.jsluice && katanaResult.Response != nil {
				// Process jsluice data if available
				if katanaResult.Response.Resp != nil {
					// This would typically contain jsluice extracted data
					// For now, we'll add the URL as an endpoint
					extractedEndpoints = append(extractedEndpoints, katanaResult.Request.URL)
				}
			}

			// Extract form data if available
			if k.formExtract && katanaResult.Response != nil && katanaResult.Response.Resp != nil {
				// Form extraction would be handled here
				// For now, we'll create a basic form entry
				if katanaResult.Request.Method == "POST" {
					form := wsTypes.Form{
						Action: katanaResult.Request.URL,
						Method: katanaResult.Request.Method,
						Inputs: []wsTypes.FormInput{}, // Would be populated from actual form parsing
						Source: "katana-lib",
					}
					foundForms = append(foundForms, form)
				}
			}
		},
	}

	// Validate target URL
	if target.URL == "" {
		return result, fmt.Errorf("target URL cannot be empty")
	}

	// Create crawler options
	crawlerOptions, err := types.NewCrawlerOptions(options)
	if err != nil {
		return result, fmt.Errorf("failed to create crawler options: %w", err)
	}

	// Create standard engine
	crawler, err := standard.New(crawlerOptions)
	if err != nil {
		return result, fmt.Errorf("failed to create katana crawler: %w", err)
	}
	defer crawler.Close()

	// Disable logging during crawling to keep output clean
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)

	// Start crawling
	err = crawler.Crawl(target.URL)
	if err != nil {
		return result, fmt.Errorf("katana crawling failed: %w", err)
	}

	// Convert results to our types
	for _, url := range crawledURLs {
		path := wsTypes.Path{
			URL:    url,
			Status: 200,   // Katana doesn't always provide status codes in library mode
			Method: "GET", // Default method
			Source: "katana-lib",
		}
		result.Paths = append(result.Paths, path)
	}

	for _, endpoint := range extractedEndpoints {
		ep := wsTypes.Endpoint{
			Path:   endpoint,
			Type:   "crawled",
			Method: "GET",
			Source: "katana-lib",
		}
		result.Endpoints = append(result.Endpoints, ep)
	}

	// Add collected secrets, parameters, and forms
	result.Secrets = append(result.Secrets, foundSecrets...)
	result.Parameters = append(result.Parameters, foundParams...)
	result.Forms = append(result.Forms, foundForms...)

	return result, nil
}

// CrawlBulk crawls multiple targets efficiently
func (k *KatanaLibModule) CrawlBulk(urls []string) ([]*KatanaLibResult, error) {
	var results []*KatanaLibResult
	var mu sync.Mutex

	for _, url := range urls {
		target := wsTypes.Target{URL: url}
		discoveryResult, err := k.Discover(target)
		if err != nil {
			continue // Skip failed targets
		}

		// Convert to KatanaLibResult
		for _, path := range discoveryResult.Paths {
			mu.Lock()
			results = append(results, &KatanaLibResult{
				URL:    path.URL,
				Method: path.Method,
				Status: path.Status,
				Source: "katana-lib",
			})
			mu.Unlock()
		}
	}

	return results, nil
}

// KatanaLibResult represents the result from katana library crawling
type KatanaLibResult struct {
	URL         string                 `json:"url"`
	Method      string                 `json:"method"`
	Status      int                    `json:"status"`
	Source      string                 `json:"source"`
	Endpoints   []string               `json:"endpoints,omitempty"`
	Forms       []wsTypes.Form         `json:"forms,omitempty"`
	JSluiceData map[string]interface{} `json:"jsluice_data,omitempty"`
}
