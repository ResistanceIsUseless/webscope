// WebScope v2 - Complete rewrite with zero goroutine leaks
// Philosophy: One goroutine per HTTP request, aggressive timeouts, no leaks
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/analysis"
	"github.com/resistanceisuseless/webscope/pkg/config"
	"github.com/resistanceisuseless/webscope/pkg/crawl"
	"github.com/resistanceisuseless/webscope/pkg/discovery"
	"github.com/resistanceisuseless/webscope/pkg/http"
)

const (
	appVersion = "2.0.1"
	appName    = "WebScope"
)

func main() {
	var (
		flowType    string
		target      string
		timeout     int
		rateLimit   int
		maxDepth    int
		maxRequests int
		wordlist    string
		configFile  string
		verbose     bool
		version     bool
	)

	// Parse command line flags
	flag.StringVar(&flowType, "flow", "in-depth", "Discovery flow: quick, in-depth, intense")
	flag.StringVar(&target, "target", "", "Target URL to scan")
	flag.IntVar(&timeout, "timeout", 2, "HTTP timeout in seconds (default: 2)")
	flag.IntVar(&rateLimit, "rate", 10, "Requests per second (default: 10)")
	flag.IntVar(&maxDepth, "depth", 2, "Max crawl depth (for crawl flow)")
	flag.IntVar(&maxRequests, "max-requests", 100, "Max requests (for crawl flow)")
	flag.StringVar(&wordlist, "wordlist", "", "Custom wordlist for deep flow")
	flag.StringVar(&configFile, "config", "", "Config file path")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.BoolVar(&version, "version", false, "Show version")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "WebScope v%s - Static Web Content Analysis Tool\n", appVersion)
		fmt.Fprintf(os.Stderr, "Zero goroutine leaks, aggressive timeouts, controlled discovery\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  webscope -target https://example.com -flow in-depth\n")
		fmt.Fprintf(os.Stderr, "  echo 'https://example.com' | webscope -flow intense\n\n")
		fmt.Fprintf(os.Stderr, "Discovery Flows:\n")
		fmt.Fprintf(os.Stderr, "  quick    - robots.txt + sitemap.xml + basic paths\n")
		fmt.Fprintf(os.Stderr, "  in-depth - Default: + urlfinder + katana + jsluice analysis\n")
		fmt.Fprintf(os.Stderr, "  intense  - + larger paths + deep katana + pattern analysis\n")
		fmt.Fprintf(os.Stderr, "             + GraphQL + WebSocket + smart variations\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if version {
		fmt.Printf("WebScope v%s\n", appVersion)
		os.Exit(0)
	}

	// Load configuration
	var appConfig *config.Config
	var err error
	
	if configFile != "" {
		appConfig, err = config.Load(configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}
	} else {
		// Try default config paths
		for _, path := range config.GetDefaultConfigPaths() {
			if _, err := os.Stat(path); err == nil {
				appConfig, err = config.Load(path)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error loading config from %s: %v\n", path, err)
					os.Exit(1)
				}
				if verbose {
					fmt.Fprintf(os.Stderr, "Loaded config from: %s\n", path)
				}
				break
			}
		}
	}
	
	// Use default config if none found
	if appConfig == nil {
		appConfig = &config.Config{}
	}

	// Get target from flag or stdin
	if target == "" {
		// Check if stdin has data (is piped or redirected)
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			// No input from pipe/redirect and no target flag - show help
			flag.Usage()
			os.Exit(1)
		}
		
		// Read from stdin
		var input string
		if _, err := fmt.Scanln(&input); err != nil {
			fmt.Fprintf(os.Stderr, "Error: No target provided\n")
			flag.Usage()
			os.Exit(1)
		}
		target = strings.TrimSpace(input)
	}

	// Ensure target has protocol
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	// Create HTTP client with aggressive timeouts
	clientConfig := http.ClientConfig{
		Timeout:           time.Duration(timeout) * time.Second,
		RateLimit:         rateLimit,
		MaxRetries:        1,
		MaxResponseSize:   10 * 1024 * 1024,
		DisableKeepAlives: true, // Prevent connection pool issues
		UserAgent:         fmt.Sprintf("%s/%s", appName, appVersion),
	}

	client := http.NewClient(clientConfig)
	defer client.Shutdown()

	// Setup signal handling for fast shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		if verbose {
			fmt.Fprintf(os.Stderr, "\nReceived interrupt signal, shutting down immediately...\n")
		}
		cancel()
		// Force exit after 500ms if graceful shutdown doesn't work
		go func() {
			time.Sleep(500 * time.Millisecond)
			if verbose {
				fmt.Fprintf(os.Stderr, "Force terminating...\n")
			}
			os.Exit(0)
		}()
	}()

	// Execute the selected flow
	if verbose {
		fmt.Fprintf(os.Stderr, "Starting %s flow for %s\n", flowType, target)
	}

	start := time.Now()
	var result *discovery.Result

	switch discovery.FlowType(flowType) {
	case discovery.QuickFlow:
		// Quick flow: robots.txt + sitemap.xml + basic paths
		flow := discovery.NewBasicFlow(client)
		result, err = flow.Execute(ctx, target)

	case discovery.InDepthFlow:
		// In-depth flow: Default comprehensive scan
		flow := discovery.NewStandardFlow(client)
		result, err = flow.Execute(ctx, target)

		// Add crawling for in-depth
		if err == nil {
			crawlerConfig := crawl.CrawlerConfig{
				MaxDepth:    2,
				MaxRequests: 50, // Moderate crawling
			}
			crawler := crawl.NewCrawler(client, crawlerConfig)
			crawlResult, crawlErr := crawler.Crawl(ctx, target, 2)

			if crawlErr == nil && crawlResult != nil {
				// Add crawled pages to result
				for _, page := range crawlResult.Pages {
					result.Paths = append(result.Paths, discovery.Path{
						URL:         page.URL,
						Status:      page.StatusCode,
						ContentType: page.ContentType,
						Title:       page.Title,
						Source:      "katana",
					})
				}

				if verbose {
					fmt.Fprintf(os.Stderr, "Crawled %d pages in %v\n", crawlResult.RequestsCount, crawlResult.CrawlTime)
				}
			}
		}

	case discovery.IntenseFlow:
		// Intense flow: Maximum coverage with larger wordlists
		var wordlistData []string
		if wordlist != "" {
			// Load custom wordlist
			wordlistData = loadWordlist(wordlist)
		}
		
		// Start with deep flow (includes smart variations)
		flow := discovery.NewDeepFlow(client, wordlistData)
		result, err = flow.Execute(ctx, target)

		// Add deep crawling for intense
		if err == nil {
			crawlerConfig := crawl.CrawlerConfig{
				MaxDepth:    maxDepth,
				MaxRequests: maxRequests,
			}
			crawler := crawl.NewCrawler(client, crawlerConfig)
			crawlResult, crawlErr := crawler.Crawl(ctx, target, maxDepth)

			if crawlErr == nil && crawlResult != nil {
				// Add crawled pages to result
				for _, page := range crawlResult.Pages {
					result.Paths = append(result.Paths, discovery.Path{
						URL:         page.URL,
						Status:      page.StatusCode,
						ContentType: page.ContentType,
						Title:       page.Title,
						Source:      "deep-katana",
					})
				}

				// Add discovered forms
				for _, form := range crawlResult.Forms {
					result.Findings = append(result.Findings, discovery.Finding{
						URL:      form.URL,
						Type:     "form",
						Severity: "medium",
						Details:  fmt.Sprintf("Form found: %s %s", form.Method, form.Action),
					})
				}

				if verbose {
					fmt.Fprintf(os.Stderr, "Deep crawled %d pages in %v\n", crawlResult.RequestsCount, crawlResult.CrawlTime)
				}
			}
		}

		// Pattern analysis for intense flow
		if err == nil && result != nil {
			analyzer := analysis.NewPatternAnalyzer()
			analysisResult := analyzer.Analyze(result)

			// Add analysis results
			for _, secret := range analysisResult.Secrets {
				result.Secrets = append(result.Secrets, discovery.Secret{
					Type:    secret.Type,
					Value:   secret.Value,
					Context: secret.Context,
					Source:  "pattern-analysis",
				})
			}

			for _, path := range analysisResult.SensitivePaths {
				result.Findings = append(result.Findings, discovery.Finding{
					URL:      path,
					Type:     "sensitive-path",
					Severity: "high",
					Details:  "Potentially sensitive path discovered",
				})
			}

			for _, endpoint := range analysisResult.Endpoints {
				result.Endpoints = append(result.Endpoints, discovery.Endpoint{
					Path:   endpoint,
					Type:   "api-endpoint",
					Method: "GET",
					Source: "pattern-analysis",
				})
			}

			if verbose {
				fmt.Fprintf(os.Stderr, "Pattern analysis found %d secrets, %d sensitive paths, %d endpoints\n", 
					len(analysisResult.Secrets), len(analysisResult.SensitivePaths), len(analysisResult.Endpoints))
			}
		}

	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown flow type '%s'. Use: quick, in-depth, or intense\n", flowType)
		flag.Usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Output results
	outputResults(result, appConfig, verbose)

	if verbose {
		stats := client.GetStats()
		fmt.Fprintf(os.Stderr, "\nStatistics:\n")
		fmt.Fprintf(os.Stderr, "  Total Requests: %d\n", stats.RequestsTotal)
		fmt.Fprintf(os.Stderr, "  Successful: %d\n", stats.RequestsSuccess)
		fmt.Fprintf(os.Stderr, "  Failed: %d\n", stats.RequestsFailed)
		if stats.RequestsSuccess > 0 {
			avgLatency := stats.TotalLatency / time.Duration(stats.RequestsSuccess)
			fmt.Fprintf(os.Stderr, "  Avg Latency: %v\n", avgLatency)
		}
		fmt.Fprintf(os.Stderr, "  Total Time: %v\n", time.Since(start))
	}
}

func outputResults(result *discovery.Result, appConfig *config.Config, verbose bool) {
	if result == nil {
		return
	}

	// Get allowed status codes from config
	allowedStatuses := getAllowedStatusCodes(appConfig)

	// Output discovered paths with consistent format: URL [STATUS] [MODULE]
	if len(result.Paths) > 0 {
		for _, path := range result.Paths {
			// Check if status code is allowed by configuration
			if allowedStatuses[path.Status] {
				if verbose && path.Source != "" {
					fmt.Printf("%s [%d] [%s]\n", path.URL, path.Status, path.Source)
				} else {
					fmt.Printf("%s [%d]\n", path.URL, path.Status)
				}
			}
		}
	}

	// Output secrets with consistent format if they have URLs
	if len(result.Secrets) > 0 && verbose {
		for _, secret := range result.Secrets {
			if strings.HasPrefix(secret.Value, "http") {
				fmt.Printf("%s [SECRET] [%s]\n", secret.Value, secret.Source)
			}
		}
	}

	// Output findings with consistent format if they have URLs  
	if len(result.Findings) > 0 && verbose {
		for _, finding := range result.Findings {
			if finding.URL != "" && finding.Severity == "high" {
				fmt.Printf("%s [FINDING] [%s]\n", finding.URL, finding.Type)
			}
		}
	}

	if verbose {
		fmt.Printf("\n[*] Discovery completed in %v\n", result.DiscoveryTime)
	}
}

func loadWordlist(path string) []string {
	var wordlist []string

	file, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not load wordlist %s: %v\n", path, err)
		return wordlist
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			wordlist = append(wordlist, line)
		}
	}

	return wordlist
}

// getAllowedStatusCodes gets the allowed status codes from config or returns defaults
func getAllowedStatusCodes(appConfig *config.Config) map[int]bool {
	allowedStatuses := make(map[int]bool)
	
	// Get status codes from config
	httpxConfig := appConfig.GetDefaultHTTPXConfig()
	if len(httpxConfig.StatusCodes) > 0 {
		for _, statusStr := range httpxConfig.StatusCodes {
			if status, err := strconv.Atoi(statusStr); err == nil {
				allowedStatuses[status] = true
			}
		}
	}
	
	// If no config provided, use conservative defaults (successful requests only)
	if len(allowedStatuses) == 0 {
		// Default to successful status codes: 2xx and 3xx
		for i := 200; i < 400; i++ {
			allowedStatuses[i] = true
		}
	}
	
	return allowedStatuses
}