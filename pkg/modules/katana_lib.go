package modules

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
	"github.com/resistanceisuseless/webscope/pkg/config"
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
	
	// Proxy configuration
	proxyURL       string
	proxyHawkURL   string
}

func NewKatanaLibModule(depth int, timeout time.Duration, rateLimit int) *KatanaLibModule {
	return &KatanaLibModule{
		depth:       2, // Reduce depth for faster crawling by default
		timeout:     timeout,
		rateLimit:   rateLimit,
		concurrency: 5, // Reduce concurrency for cleaner output
		parallelism: 5,
		jsluice:     true,
		formExtract: true,
		headless:    false, // Use standard mode by default for better performance
		strategy:    "breadth-first", // Breadth-first is often more efficient for basic discovery
	}
}

// NewKatanaLibModuleWithConfig creates a new katana library module with custom configuration
func NewKatanaLibModuleWithConfig(cfg config.KatanaConfig, fallbackTimeout time.Duration) *KatanaLibModule {
	timeout := fallbackTimeout
	if cfg.Timeout > 0 {
		timeout = time.Duration(cfg.Timeout) * time.Second
	}
	
	// Set defaults for missing values
	depth := cfg.Depth
	if depth == 0 {
		depth = 2
	}
	
	rateLimit := cfg.RateLimit
	if rateLimit == 0 {
		rateLimit = 20
	}
	
	concurrency := cfg.Concurrency
	if concurrency == 0 {
		concurrency = 5
	}
	
	parallelism := cfg.Parallelism
	if parallelism == 0 {
		parallelism = 5
	}
	
	strategy := cfg.Strategy
	if strategy == "" {
		strategy = "breadth-first"
	}
	
	return &KatanaLibModule{
		depth:       depth,
		timeout:     timeout,
		rateLimit:   rateLimit,
		concurrency: concurrency,
		parallelism: parallelism,
		jsluice:     cfg.JSluice,
		formExtract: cfg.FormExtract,
		headless:    cfg.Headless,
		strategy:    strategy,
		proxyURL:    cfg.ProxyURL,
		proxyHawkURL: cfg.ProxyHawkURL,
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
		MaxDepth:        1, // Very conservative depth for faster results
		FieldScope:      "rdn", // Restrict to registered domain name
		BodyReadSize:    1024 * 1024, // 1MB limit for faster processing
		Timeout:         10, // 10 second timeout
		Concurrency:     3,  // Lower concurrency
		Parallelism:     3,
		Delay:           0,
		RateLimit:       k.rateLimit,
		Strategy:        "breadth-first",
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
	
	// Configure proxy if available
	if k.proxyURL != "" {
		options.Proxy = []string{k.proxyURL}
	} else if k.proxyHawkURL != "" {
		// Use ProxyHawk as SOCKS5 proxy (default port 1080)
		if proxyHawkParsed, err := url.Parse(k.proxyHawkURL); err == nil {
			// Convert WebSocket URL to SOCKS5 proxy URL
			proxyHawkParsed.Scheme = "socks5"
			if proxyHawkParsed.Port() == "8888" {
				proxyHawkParsed.Host = proxyHawkParsed.Hostname() + ":1080"
			}
			options.Proxy = []string{proxyHawkParsed.String()}
		}
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

	// Ensure crawler is properly closed even on panic or timeout
	var crawlerClosed bool
	var closeMutex sync.Mutex
	
	closeCrawler := func() {
		closeMutex.Lock()
		defer closeMutex.Unlock()
		if !crawlerClosed {
			crawler.Close()
			crawlerClosed = true
		}
	}
	defer closeCrawler()

	// Disable logging during crawling to keep output clean
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)

	// Temporarily redirect stdout to suppress katana output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	
	// Consume the output in a goroutine to prevent blocking
	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		io.Copy(io.Discard, r)
	}()

	// Start crawling with timeout - reduced from 30s to 15s for faster recovery
	crawlCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	
	// Run crawling in goroutine with proper error handling
	crawlErr := make(chan error, 1)
	crawlDone := make(chan struct{})
	
	go func() {
		defer close(crawlDone)
		err := crawler.Crawl(target.URL)
		select {
		case crawlErr <- err:
		default:
		}
	}()
	
	select {
	case err = <-crawlErr:
		// Crawling completed normally
	case <-crawlCtx.Done():
		// Timeout reached - force cleanup
		closeCrawler() // Explicitly close crawler on timeout
		err = fmt.Errorf("katana crawling timeout after 15 seconds")
	}
	
	// Clean up stdout redirection
	w.Close()
	os.Stdout = oldStdout
	
	// Wait for output consumer to finish with timeout
	outputTimeout := time.NewTimer(2 * time.Second)
	select {
	case <-outputDone:
		outputTimeout.Stop()
	case <-outputTimeout.C:
		// Output consumer timed out - this is acceptable
	}
	
	// Wait for crawl goroutine to complete with timeout
	crawlTimeout := time.NewTimer(2 * time.Second)
	select {
	case <-crawlDone:
		crawlTimeout.Stop()
	case <-crawlTimeout.C:
		// Crawl goroutine didn't finish - force cleanup
		closeCrawler()
	}
	
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
