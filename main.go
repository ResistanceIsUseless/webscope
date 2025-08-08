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
	"strings"
	"syscall"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/analysis"
	"github.com/resistanceisuseless/webscope/pkg/crawl"
	"github.com/resistanceisuseless/webscope/pkg/discovery"
	"github.com/resistanceisuseless/webscope/pkg/http"
)

const (
	appVersion = "2.0.0"
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

	// Get target from flag or stdin
	if target == "" {
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

	// Setup signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		if verbose {
			fmt.Fprintf(os.Stderr, "\nReceived interrupt signal, shutting down gracefully...\n")
		}
		cancel()
	}()

	// Execute the selected flow
	if verbose {
		fmt.Fprintf(os.Stderr, "Starting %s flow for %s\n", flowType, target)
	}

	start := time.Now()
	var result *discovery.Result
	var err error

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
	outputResults(result, verbose)

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

func outputResults(result *discovery.Result, verbose bool) {
	if result == nil {
		return
	}

	// Output discovered paths
	if len(result.Paths) > 0 {
		fmt.Println("\n[+] Discovered Paths:")
		for _, path := range result.Paths {
			fmt.Printf("  [%d] %s", path.Status, path.URL)
			if verbose && path.Source != "" {
				fmt.Printf(" (source: %s)", path.Source)
			}
			if path.Title != "" {
				fmt.Printf(" - %s", path.Title)
			}
			fmt.Println()
		}
	}

	// Output endpoints
	if len(result.Endpoints) > 0 {
		fmt.Println("\n[+] Discovered Endpoints:")
		for _, endpoint := range result.Endpoints {
			fmt.Printf("  %s %s", endpoint.Method, endpoint.Path)
			if verbose {
				fmt.Printf(" (type: %s, source: %s)", endpoint.Type, endpoint.Source)
			}
			fmt.Println()
		}
	}

	// Output secrets
	if len(result.Secrets) > 0 {
		fmt.Println("\n[!] Discovered Secrets:")
		for _, secret := range result.Secrets {
			fmt.Printf("  [%s] %s", secret.Type, secret.Value)
			if verbose && secret.Context != "" {
				fmt.Printf(" - %s", secret.Context)
			}
			fmt.Println()
		}
	}

	// Output findings
	if len(result.Findings) > 0 {
		fmt.Println("\n[*] Findings:")
		for _, finding := range result.Findings {
			fmt.Printf("  [%s] %s: %s", finding.Severity, finding.Type, finding.URL)
			if finding.Details != "" {
				fmt.Printf(" - %s", finding.Details)
			}
			fmt.Println()
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