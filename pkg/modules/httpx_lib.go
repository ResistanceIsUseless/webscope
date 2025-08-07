package modules

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/httpx/runner"
	"github.com/resistanceisuseless/webscope/pkg/config"
	"github.com/resistanceisuseless/webscope/pkg/types"
)

// HTTPXLibModule uses httpx as a library instead of CLI
type HTTPXLibModule struct {
	threads        int
	timeout        time.Duration
	rateLimit      int
	retries        int
	followRedirect bool
	statusCodes    []string
	
	// Proxy configuration
	proxyURL       string
	proxyHawkURL   string
}

func NewHTTPXLibModule(threads int, timeout time.Duration, rateLimit int) *HTTPXLibModule {
	return &HTTPXLibModule{
		threads:        threads,
		timeout:        timeout,
		rateLimit:      rateLimit,
		retries:        2,
		followRedirect: true,
		statusCodes:    []string{"200", "201", "202", "203", "204", "205", "206", "207", "208", "226", "300", "301", "302", "303", "304", "305", "307", "308", "401", "403"}, // Exclude 404s and 5xx errors for cleaner output
	}
}

func NewHTTPXLibModuleWithConfig(httpxConfig config.HTTPXConfig) *HTTPXLibModule {
	module := &HTTPXLibModule{
		threads:        httpxConfig.Threads,
		timeout:        time.Duration(httpxConfig.Timeout) * time.Second,
		rateLimit:      httpxConfig.RateLimit,
		retries:        httpxConfig.Retries,
		followRedirect: httpxConfig.FollowRedirect,
		statusCodes:    httpxConfig.StatusCodes,
		proxyURL:       httpxConfig.ProxyURL,
		proxyHawkURL:   httpxConfig.ProxyHawkURL,
	}
	
	// Set defaults if not configured
	if module.threads == 0 {
		module.threads = 20
	}
	if module.timeout == 0 {
		module.timeout = 10 * time.Second
	}
	if module.rateLimit == 0 {
		module.rateLimit = 20
	}
	if module.retries == 0 {
		module.retries = 2
	}
	if len(module.statusCodes) == 0 {
		module.statusCodes = []string{"200", "201", "202", "203", "204", "205", "206", "207", "208", "226", "300", "301", "302", "303", "304", "305", "307", "308", "401", "403"}
	}
	
	return module
}

func (h *HTTPXLibModule) Name() string {
	return "httpx-lib"
}

func (h *HTTPXLibModule) Priority() int {
	return 1
}

func (h *HTTPXLibModule) Discover(target types.Target) (*types.DiscoveryResult, error) {
	result := &types.DiscoveryResult{
		Paths:     []types.Path{},
		Endpoints: []types.Endpoint{},
	}

	// Probe the main target
	mainPath := h.probeTarget(target.URL)
	if mainPath != nil {
		mainPath.Source = "httpx-lib"
		result.Paths = append(result.Paths, *mainPath)
	}

	// Discover common paths
	commonPaths := []string{"/robots.txt", "/sitemap.xml", "/favicon.ico", "/.well-known/security.txt"}
	baseURL := strings.TrimSuffix(target.URL, "/")

	for _, pathStr := range commonPaths {
		fullURL := baseURL + pathStr
		if discPath := h.probeTarget(fullURL); discPath != nil {
			discPath.Source = "httpx-lib-common"
			result.Paths = append(result.Paths, *discPath)

			// Add as endpoint
			endpoint := types.Endpoint{
				Path:   pathStr,
				Type:   "common",
				Method: "GET",
				Source: "httpx-lib",
			}
			result.Endpoints = append(result.Endpoints, endpoint)
		}
	}

	return result, nil
}

func (h *HTTPXLibModule) probeTarget(targetURL string) *types.Path {
	var resultPath *types.Path
	var mu sync.Mutex

	// Temporarily redirect stdout to suppress httpx output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	
	// Consume the output in a goroutine to prevent blocking
	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		io.Copy(io.Discard, r)
	}()

	options := runner.Options{
		Methods:         "GET",
		InputTargetHost: goflags.StringSlice{targetURL},
		Threads:         h.threads,
		Timeout:         int(h.timeout.Seconds()),
		RateLimit:       h.rateLimit,
		Retries:         h.retries,
		FollowRedirects: h.followRedirect,
		StatusCode:      true,
		ContentLength:   true,
		ExtractTitle:    true,
		Silent:          true,
		NoFallback:      true,
		OnResult: func(r runner.Result) {
			// Handle error
			if r.Err != nil {
				return
			}

			// Check if status code is allowed
			statusStr := fmt.Sprintf("%d", r.StatusCode)
			if !h.isAllowedStatus(statusStr) {
				return
			}

			mu.Lock()
			resultPath = &types.Path{
				URL:         r.Input,
				Status:      r.StatusCode,
				Length:      r.ContentLength,
				Method:      "GET",
				ContentType: r.ContentType,
				Title:       r.Title,
			}
			mu.Unlock()
		},
	}
	
	// Configure proxy if available
	if h.proxyURL != "" {
		// Determine proxy type based on URL scheme  
		if proxyURLParsed, err := url.Parse(h.proxyURL); err == nil {
			switch proxyURLParsed.Scheme {
			case "http", "https":
				options.HTTPProxy = h.proxyURL
			case "socks5":
				options.SocksProxy = h.proxyURL
			}
		}
	} else if h.proxyHawkURL != "" {
		// Use ProxyHawk as SOCKS5 proxy (default port 1080)
		if proxyHawkParsed, err := url.Parse(h.proxyHawkURL); err == nil {
			// Convert WebSocket URL to SOCKS5 proxy URL
			proxyHawkParsed.Scheme = "socks5"
			if proxyHawkParsed.Port() == "8888" {
				proxyHawkParsed.Host = proxyHawkParsed.Hostname() + ":1080"
			}
			options.SocksProxy = proxyHawkParsed.String()
		}
	}

	// Validate options
	if err := options.ValidateOptions(); err != nil {
		w.Close()
		os.Stdout = oldStdout
		// Wait for output consumer to finish
		select {
		case <-outputDone:
		case <-time.After(1 * time.Second):
		}
		return nil
	}

	// Create and run httpx
	httpxRunner, err := runner.New(&options)
	if err != nil {
		w.Close()
		os.Stdout = oldStdout
		// Wait for output consumer to finish
		select {
		case <-outputDone:
		case <-time.After(1 * time.Second):
		}
		return nil
	}
	
	// Ensure proper cleanup
	var runnerClosed bool
	var closeMutex sync.Mutex
	
	closeRunner := func() {
		closeMutex.Lock()
		defer closeMutex.Unlock()
		if !runnerClosed {
			httpxRunner.Close()
			runnerClosed = true
		}
	}
	defer closeRunner()

	// Run enumeration with timeout
	enumerationDone := make(chan struct{})
	go func() {
		defer close(enumerationDone)
		httpxRunner.RunEnumeration()
	}()
	
	// Wait for enumeration to complete or timeout
	timeout := time.NewTimer(time.Duration(h.timeout.Seconds()+5) * time.Second)
	select {
	case <-enumerationDone:
		timeout.Stop()
	case <-timeout.C:
		// Force cleanup on timeout
		closeRunner()
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

	return resultPath
}

func (h *HTTPXLibModule) ProbeBulk(urls []string) ([]*HTTPXResult, error) {
	var results []*HTTPXResult
	var mu sync.Mutex

	// Temporarily redirect stdout to suppress httpx output
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	
	// Consume the output in a goroutine to prevent blocking
	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		io.Copy(io.Discard, r)
	}()

	// Convert URLs to StringSlice
	targets := goflags.StringSlice{}
	for _, url := range urls {
		targets = append(targets, url)
	}

	options := runner.Options{
		Methods:         "GET",
		InputTargetHost: targets,
		Threads:         h.threads,
		Timeout:         int(h.timeout.Seconds()),
		RateLimit:       h.rateLimit,
		Retries:         h.retries,
		FollowRedirects: h.followRedirect,
		StatusCode:      true,
		ContentLength:   true,
		ExtractTitle:    true,
		Silent:          true,
		NoFallback:      true,
		OnResult: func(r runner.Result) {
			// Handle error
			if r.Err != nil {
				return
			}

			// Check if status code is allowed
			statusStr := fmt.Sprintf("%d", r.StatusCode)
			if !h.isAllowedStatus(statusStr) {
				return
			}

			mu.Lock()
			results = append(results, &HTTPXResult{
				URL:           r.Input,
				StatusCode:    r.StatusCode,
				ContentLength: r.ContentLength,
				ContentType:   r.ContentType,
				Title:         r.Title,
			})
			mu.Unlock()
		},
	}

	// Validate options
	if err := options.ValidateOptions(); err != nil {
		w.Close()
		os.Stdout = oldStdout
		// Wait for output consumer to finish
		select {
		case <-outputDone:
		case <-time.After(1 * time.Second):
		}
		return nil, err
	}

	// Create and run httpx
	httpxRunner, err := runner.New(&options)
	if err != nil {
		w.Close()
		os.Stdout = oldStdout
		// Wait for output consumer to finish
		select {
		case <-outputDone:
		case <-time.After(1 * time.Second):
		}
		return nil, err
	}

	// Ensure proper cleanup
	var runnerClosed bool
	var closeMutex sync.Mutex
	
	closeRunner := func() {
		closeMutex.Lock()
		defer closeMutex.Unlock()
		if !runnerClosed {
			httpxRunner.Close()
			runnerClosed = true
		}
	}
	defer closeRunner()

	// Run enumeration with timeout
	enumerationDone := make(chan struct{})
	go func() {
		defer close(enumerationDone)
		httpxRunner.RunEnumeration()
	}()
	
	// Wait for enumeration to complete or timeout
	timeout := time.NewTimer(time.Duration(h.timeout.Seconds()*float64(len(urls))/10+30) * time.Second)
	select {
	case <-enumerationDone:
		timeout.Stop()
	case <-timeout.C:
		// Force cleanup on timeout
		closeRunner()
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

	return results, nil
}

func (h *HTTPXLibModule) isAllowedStatus(status string) bool {
	for _, allowed := range h.statusCodes {
		if status == allowed {
			return true
		}
	}
	return false
}

// HTTPXLibResult is an alias to HTTPXResult for compatibility
type HTTPXLibResult = HTTPXResult
