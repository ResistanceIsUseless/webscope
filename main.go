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
	"github.com/resistanceisuseless/webscope/pkg/output"
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
	
	// Create styled output early for config loading messages
	styledOut := output.NewStyledOutput(verbose)

	if configFile != "" {
		appConfig, err = config.Load(configFile)
		if err != nil {
			styledOut.PrintError(fmt.Sprintf("loading config: %v", err))
			os.Exit(1)
		}
	} else {
		// Try default config paths
		for _, path := range config.GetDefaultConfigPaths() {
			if _, err := os.Stat(path); err == nil {
				appConfig, err = config.Load(path)
				if err != nil {
					styledOut.PrintError(fmt.Sprintf("loading config from %s: %v", path, err))
					os.Exit(1)
				}
				styledOut.PrintInfo(fmt.Sprintf("Loaded config from: %s", path))
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

	// Print banner and flow start
	styledOut.PrintBanner(appVersion)
	styledOut.PrintFlowStart(flowType, target)

	// Setup signal handling for fast shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		styledOut.PrintWarning("Received interrupt signal, shutting down immediately...")
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

	start := time.Now()
	var result *discovery.Result

	switch discovery.FlowType(flowType) {
	case discovery.QuickFlow:
		// Quick flow: robots.txt + sitemap.xml + basic paths
		styledOut.PrintSection("Quick Discovery")
		flow := discovery.NewBasicFlow(client)
		result, err = flow.Execute(ctx, target)

	case discovery.InDepthFlow:
		// In-depth flow: Default comprehensive scan
		styledOut.PrintSection("In-Depth Discovery")
		flow := discovery.NewStandardFlow(client)
		result, err = flow.Execute(ctx, target)

		// Add crawling for in-depth
		if err == nil {
			styledOut.PrintProgress("Starting moderate crawling...")
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

				styledOut.PrintInfo(fmt.Sprintf("Crawled %d pages in %v", crawlResult.RequestsCount, crawlResult.CrawlTime))
			}
		}

	case discovery.IntenseFlow:
		// Intense flow: Maximum coverage with larger wordlists
		styledOut.PrintSection("Intense Discovery")
		var wordlistData []string
		if wordlist != "" {
			// Load custom wordlist
			styledOut.PrintProgress(fmt.Sprintf("Loading custom wordlist: %s", wordlist))
			wordlistData = loadWordlist(wordlist)
		}

		// Start with deep flow (includes smart variations)
		styledOut.PrintProgress("Running deep path discovery with smart variations...")
		flow := discovery.NewDeepFlow(client, wordlistData)
		result, err = flow.Execute(ctx, target)

		// Add deep crawling for intense
		if err == nil {
			styledOut.PrintProgress(fmt.Sprintf("Starting deep crawling (depth: %d, max requests: %d)...", maxDepth, maxRequests))
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

				styledOut.PrintInfo(fmt.Sprintf("Deep crawled %d pages in %v", crawlResult.RequestsCount, crawlResult.CrawlTime))
			}
		}

		// Pattern analysis for intense flow
		if err == nil && result != nil {
			styledOut.PrintProgress("Running pattern analysis...")
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

			styledOut.PrintInfo(fmt.Sprintf("Pattern analysis found %d secrets, %d sensitive paths, %d endpoints",
				len(analysisResult.Secrets), len(analysisResult.SensitivePaths), len(analysisResult.Endpoints)))
		}

	default:
		styledOut.PrintError(fmt.Sprintf("Unknown flow type '%s'. Use: quick, in-depth, or intense", flowType))
		flag.Usage()
		os.Exit(1)
	}

	if err != nil {
		styledOut.PrintError(err.Error())
		os.Exit(1)
	}

	// Output results
	styledOut.PrintSection("Results")
	outputResults(result, appConfig, verbose, styledOut)

	// Print statistics
	stats := client.GetStats()
	var avgLatency time.Duration
	if stats.RequestsSuccess > 0 {
		avgLatency = stats.TotalLatency / time.Duration(stats.RequestsSuccess)
	}
	styledOut.PrintStats(int(stats.RequestsTotal), int(stats.RequestsSuccess), int(stats.RequestsFailed), avgLatency, time.Since(start))

	// Print completion
	styledOut.PrintCompletion(result.DiscoveryTime)
}

func outputResults(result *discovery.Result, appConfig *config.Config, verbose bool, styledOut *output.StyledOutput) {
	if result == nil {
		return
	}

	// Get allowed status codes from config
	allowedStatuses := getAllowedStatusCodes(appConfig)

	// Output discovered paths with styled format
	if len(result.Paths) > 0 {
		for _, path := range result.Paths {
			// Check if status code is allowed by configuration
			if allowedStatuses[path.Status] {
				styledOut.PrintPath(path.URL, path.Status, path.Source)
			}
		}
	}

	// Output secrets with styled format if they have URLs
	if len(result.Secrets) > 0 && verbose {
		for _, secret := range result.Secrets {
			if strings.HasPrefix(secret.Value, "http") {
				styledOut.PrintSecret(secret.Value, secret.Type, secret.Source)
			}
		}
	}

	// Output findings with styled format if they have URLs
	if len(result.Findings) > 0 && verbose {
		for _, finding := range result.Findings {
			if finding.URL != "" && finding.Severity == "high" {
				styledOut.PrintFinding(finding.URL, finding.Type)
			}
		}
	}
}

func loadWordlist(path string) []string {
	var wordlist []string

	file, err := os.Open(path)
	if err != nil {
		// Note: We can't use styledOut here as it's not available in this scope
		// But this is fine as the caller will show a progress message
		fmt.Fprintf(os.Stderr, "⚠ Warning: Could not load wordlist %s: %v\n", path, err)
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