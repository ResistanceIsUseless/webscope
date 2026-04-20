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
	"github.com/resistanceisuseless/webscope/pkg/modules"
	"github.com/resistanceisuseless/webscope/pkg/output"
	"github.com/resistanceisuseless/webscope/pkg/types"
)

const (
	appVersion = "2.0.2"
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
		jsonOutput  bool
		jsonPretty  bool
		quiet       bool
		outputFile  string
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
	flag.BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	flag.BoolVar(&jsonPretty, "json-pretty", false, "Pretty-print JSON output")
	flag.BoolVar(&quiet, "quiet", false, "Suppress banner and progress output")
	flag.StringVar(&outputFile, "output", "", "Output file path (- for stdout)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "WebScope v%s - Static Web Content Analysis Tool\n", appVersion)
		fmt.Fprintf(os.Stderr, "Zero goroutine leaks, aggressive timeouts, controlled discovery\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  webscope -target https://example.com -flow in-depth\n")
		fmt.Fprintf(os.Stderr, "  echo 'https://example.com' | webscope -flow intense\n")
		fmt.Fprintf(os.Stderr, "  webscope -target https://example.com -json -output results.json\n\n")
		fmt.Fprintf(os.Stderr, "Discovery Flows:\n")
		fmt.Fprintf(os.Stderr, "  quick    - robots.txt + sitemap.xml + basic paths\n")
		fmt.Fprintf(os.Stderr, "  in-depth - Default: + urlfinder + katana + jsluice analysis\n")
		fmt.Fprintf(os.Stderr, "  intense  - + larger paths + deep katana + pattern analysis\n")
		fmt.Fprintf(os.Stderr, "             + GraphQL + WebSocket + smart variations\n\n")
		fmt.Fprintf(os.Stderr, "Output Options:\n")
		fmt.Fprintf(os.Stderr, "  -json         Output results as JSON\n")
		fmt.Fprintf(os.Stderr, "  -json-pretty  Pretty-print JSON output\n")
		fmt.Fprintf(os.Stderr, "  -quiet        Suppress banner and progress output\n")
		fmt.Fprintf(os.Stderr, "  -output FILE  Write output to file (- for stdout)\n\n")
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

	// Wire up proxy from config if available
	if appConfig != nil {
		httpxConfig := appConfig.GetDefaultHTTPXConfig()
		if httpxConfig.ProxyURL != "" {
			clientConfig.ProxyURL = httpxConfig.ProxyURL
		}
	}

	client := http.NewClient(clientConfig)
	defer client.Shutdown()

	// Print banner and flow start (skip if quiet)
	if !quiet {
		styledOut.PrintBanner(appVersion)
		styledOut.PrintFlowStart(flowType, target)
	}

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
		if !quiet {
			styledOut.PrintSection("Quick Discovery")
		}
		flow := discovery.NewBasicFlow(client)
		result, err = flow.Execute(ctx, target)

	case discovery.InDepthFlow:
		// In-depth flow: Default comprehensive scan
		if !quiet {
			styledOut.PrintSection("In-Depth Discovery")
		}
		flow := discovery.NewStandardFlow(client)
		result, err = flow.Execute(ctx, target)

		// Add crawling for in-depth
		if err == nil {
			if !quiet {
				styledOut.PrintProgress("Starting moderate crawling...")
			}
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

				// Add discovered forms
				for _, form := range crawlResult.Forms {
					df := discovery.Form{
						Action: form.Action,
						Method: form.Method,
						Source: "katana",
					}
					for _, inp := range form.Inputs {
						df.Inputs = append(df.Inputs, discovery.FormInput{
							Name:  inp.Name,
							Type:  inp.Type,
							Value: inp.Value,
						})
						result.Parameters = append(result.Parameters, discovery.Parameter{
							Name:   inp.Name,
							Type:   inp.Type,
							Source: "katana",
						})
					}
					result.Forms = append(result.Forms, df)
				}

				if !quiet {
					styledOut.PrintInfo(fmt.Sprintf("Crawled %d pages in %v", crawlResult.RequestsCount, crawlResult.CrawlTime))
				}
			}
		}

	case discovery.IntenseFlow:
		// Intense flow: Maximum coverage with larger wordlists
		if !quiet {
			styledOut.PrintSection("Intense Discovery")
		}
		var wordlistData []string
		if wordlist != "" {
			// Load custom wordlist
			if !quiet {
				styledOut.PrintProgress(fmt.Sprintf("Loading custom wordlist: %s", wordlist))
			}
			wordlistData = loadWordlist(wordlist)
		}

		// Start with deep flow (includes smart variations)
		if !quiet {
			styledOut.PrintProgress("Running deep path discovery with smart variations...")
		}
		flow := discovery.NewDeepFlow(client, wordlistData)
		result, err = flow.Execute(ctx, target)

		// Add deep crawling for intense
		if err == nil {
			if !quiet {
				styledOut.PrintProgress(fmt.Sprintf("Starting deep crawling (depth: %d, max requests: %d)...", maxDepth, maxRequests))
			}
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
					df := discovery.Form{
						Action: form.Action,
						Method: form.Method,
						Source: "deep-katana",
					}
					for _, inp := range form.Inputs {
						df.Inputs = append(df.Inputs, discovery.FormInput{
							Name:  inp.Name,
							Type:  inp.Type,
							Value: inp.Value,
						})
						result.Parameters = append(result.Parameters, discovery.Parameter{
							Name:   inp.Name,
							Type:   inp.Type,
							Source: "deep-katana",
						})
					}
					result.Forms = append(result.Forms, df)
				}

				if !quiet {
					styledOut.PrintInfo(fmt.Sprintf("Deep crawled %d pages in %v", crawlResult.RequestsCount, crawlResult.CrawlTime))
				}
			}
		}

		// JSRecon analysis for intense flow
		if err == nil && result != nil && len(result.Paths) > 0 {
			if !quiet {
				styledOut.PrintProgress("Running JSRecon analysis...")
			}

			jsreconClient := modules.NewClient(modules.ClientConfig{
				Timeout: 30 * time.Second,
			})

			var analyzedCount int
			var secretsFound int

			for i, path := range result.Paths {
				if i >= 20 {
					break
				}
				if ctx.Err() != nil {
					break
				}

				if !strings.Contains(strings.ToLower(path.ContentType), "javascript") &&
					!strings.HasSuffix(path.URL, ".js") &&
					!strings.HasSuffix(path.URL, ".mjs") {
					continue
				}

				resp, fetchErr := client.Get(ctx, path.URL)
				if fetchErr != nil || resp.Body == "" {
					continue
				}

				jsResult, analyzeErr := jsreconClient.Analyze(resp.Body, path.URL)
				if analyzeErr != nil {
					continue
				}

				analyzedCount++

				for _, finding := range jsResult.Findings {
					if finding.Confidence < 0.3 {
						continue
					}

					result.Findings = append(result.Findings, discovery.Finding{
						URL:      path.URL,
						Type:     "jsrecon-" + finding.Type,
						Severity: mapJSReconSeverity(finding.Type, finding.Confidence),
						Details:  fmt.Sprintf("[%s] %.2f - %s", finding.Subtype, finding.Confidence, finding.Value),
					})

					if isSecretType(finding.Type) {
						secretsFound++
						result.Secrets = append(result.Secrets, discovery.Secret{
							Type:    finding.Type,
							Value:   finding.Value,
							Context: finding.Snippet,
							Source:  "jsrecon",
						})
					}
				}
			}

			if !quiet {
				styledOut.PrintInfo(fmt.Sprintf("JSRecon analyzed %d JS files, found %d secrets", analyzedCount, secretsFound))
			}
		}

		// Advanced JavaScript analysis (jsluice) for intense flow
		if err == nil && result != nil {
			if !quiet {
				styledOut.PrintProgress("Running advanced JavaScript analysis (jsluice)...")
			}

			advJS := modules.NewAdvancedJavaScriptModule(30*time.Second, &appConfig.Global.JSluice)
			jsTarget := types.Target{
				URL:    target,
				Domain: strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://"),
			}
			// Strip path from domain
			if idx := strings.Index(jsTarget.Domain, "/"); idx > 0 {
				jsTarget.Domain = jsTarget.Domain[:idx]
			}

			advResult, advErr := advJS.Discover(jsTarget)
			if advErr == nil && advResult != nil {
				// Merge GraphQL schemas
				for _, schema := range advResult.GraphQLSchemas {
					result.GraphQLSchemas = append(result.GraphQLSchemas, discovery.GraphQLSchema{
						Endpoint: schema.Endpoint,
						Source:   schema.Source,
					})
					for _, q := range schema.Queries {
						result.GraphQLSchemas[len(result.GraphQLSchemas)-1].Queries = append(
							result.GraphQLSchemas[len(result.GraphQLSchemas)-1].Queries, q.Name)
					}
					for _, m := range schema.Mutations {
						result.GraphQLSchemas[len(result.GraphQLSchemas)-1].Mutations = append(
							result.GraphQLSchemas[len(result.GraphQLSchemas)-1].Mutations, m.Name)
					}
				}

				// Merge WebSocket endpoints
				for _, ws := range advResult.WebSockets {
					result.WebSockets = append(result.WebSockets, discovery.WebSocketEndpoint{
						URL:         ws.URL,
						Protocol:    ws.Protocol,
						Subprotocol: ws.Subprotocol,
						Source:      ws.Source,
					})
				}

				// Merge secrets
				for _, s := range advResult.Secrets {
					result.Secrets = append(result.Secrets, discovery.Secret{
						Type:    s.Type,
						Value:   s.Value,
						Context: s.Context,
						Source:  s.Source,
					})
				}

				// Merge endpoints
				for _, e := range advResult.Endpoints {
					result.Endpoints = append(result.Endpoints, discovery.Endpoint{
						Path:   e.Path,
						Type:   e.Type,
						Method: e.Method,
						Source: e.Source,
					})
				}

				// Merge paths (JS files found)
				for _, p := range advResult.Paths {
					result.Paths = append(result.Paths, discovery.Path{
						URL:         p.URL,
						Status:      p.Status,
						ContentType: p.ContentType,
						Source:      p.Source,
					})
				}

				if !quiet {
					styledOut.PrintInfo(fmt.Sprintf("Advanced JS: %d GraphQL endpoints, %d WebSocket endpoints, %d secrets, %d endpoints",
						len(advResult.GraphQLSchemas), len(advResult.WebSockets), len(advResult.Secrets), len(advResult.Endpoints)))
				}
			}
		}

		// Pattern analysis for intense flow
		if err == nil && result != nil {
			if !quiet {
				styledOut.PrintProgress("Running pattern analysis...")
			}
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
	if jsonOutput {
		jsonOut, err := output.CreateJSONFileOutput(outputFile, jsonPretty, verbose)
		if err != nil {
			styledOut.PrintError(fmt.Sprintf("failed to create JSON output: %v", err))
			os.Exit(1)
		}

		stats := client.GetStats()
		var avgLatencyMs int64
		if stats.RequestsSuccess > 0 {
			avgLatencyMs = stats.TotalLatency.Milliseconds() / int64(stats.RequestsSuccess)
		}

		resultData := output.ResultData{
			Target:        target,
			Flow:          flowType,
			StartTime:     start,
			EndTime:       time.Now(),
			DiscoveryTime: result.DiscoveryTime,
		}
		resultData.Stats.RequestsTotal = int(stats.RequestsTotal)
		resultData.Stats.RequestsSuccess = int(stats.RequestsSuccess)
		resultData.Stats.RequestsFailed = int(stats.RequestsFailed)
		resultData.Stats.AvgLatencyMs = avgLatencyMs

		for _, p := range result.Paths {
			resultData.Paths = append(resultData.Paths, output.PathData{
				URL:         p.URL,
				Status:      p.Status,
				Method:      p.Method,
				ContentType: p.ContentType,
				Title:       p.Title,
				Source:      p.Source,
			})
		}

		for _, e := range result.Endpoints {
			resultData.Endpoints = append(resultData.Endpoints, output.EndpointData{
				Path:   e.Path,
				Type:   e.Type,
				Method: e.Method,
				Source: e.Source,
			})
		}

		for _, s := range result.Secrets {
			resultData.Secrets = append(resultData.Secrets, output.SecretData{
				Type:    s.Type,
				Value:   s.Value,
				Context: s.Context,
				Source:  s.Source,
			})
		}

		for _, f := range result.Findings {
			resultData.Findings = append(resultData.Findings, output.FindingData{
				URL:      f.URL,
				Type:     f.Type,
				Severity: f.Severity,
				Details:  f.Details,
			})
		}

		for _, t := range result.Technologies {
			resultData.Technologies = append(resultData.Technologies, output.TechnologyData{
				Name:     t.Name,
				Category: t.Category,
				Version:  t.Version,
				Source:   t.Source,
			})
		}

		for _, f := range result.Forms {
			fd := output.FormData{
				Action: f.Action,
				Method: f.Method,
				Source: f.Source,
			}
			for _, inp := range f.Inputs {
				fd.Inputs = append(fd.Inputs, output.FormInputData{
					Name:  inp.Name,
					Type:  inp.Type,
					Value: inp.Value,
				})
			}
			resultData.Forms = append(resultData.Forms, fd)
		}

		for _, p := range result.Parameters {
			resultData.Parameters = append(resultData.Parameters, output.ParameterData{
				Name:   p.Name,
				Type:   p.Type,
				Source: p.Source,
			})
		}

		for _, g := range result.GraphQLSchemas {
			resultData.GraphQLSchemas = append(resultData.GraphQLSchemas, output.GraphQLData{
				Endpoint:      g.Endpoint,
				Queries:       g.Queries,
				Mutations:     g.Mutations,
				Subscriptions: g.Subscriptions,
				Source:        g.Source,
			})
		}

		for _, ws := range result.WebSockets {
			resultData.WebSockets = append(resultData.WebSockets, output.WebSocketData{
				URL:         ws.URL,
				Protocol:    ws.Protocol,
				Subprotocol: ws.Subprotocol,
				Source:      ws.Source,
			})
		}

		if err := jsonOut.OutputResult(resultData); err != nil {
			styledOut.PrintError(fmt.Sprintf("failed to write JSON output: %v", err))
			os.Exit(1)
		}
		return
	}

	// Standard text output
	if !quiet {
		styledOut.PrintSection("Results")
	}
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
		styledOut.PrintSection("Discovered Paths")
		for _, path := range result.Paths {
			// Check if status code is allowed by configuration
			if allowedStatuses[path.Status] {
				styledOut.PrintPath(path.URL, path.Status, path.Source)
			}
		}
	}

	// Output endpoints with styled format (filter out static files)
	if len(result.Endpoints) > 0 && verbose {
		styledOut.PrintSection("API Endpoints")
		for _, ep := range result.Endpoints {
			// Skip common static files
			if ep.Path == "/robots.txt" || ep.Path == "/favicon.ico" || ep.Type == "common" {
				continue
			}
			styledOut.PrintEndpoint(ep.Path, ep.Type, ep.Method)
		}
	}

	// Output secrets with styled format if they have URLs
	if len(result.Secrets) > 0 && verbose {
		styledOut.PrintSection("Discovered Secrets")
		for _, secret := range result.Secrets {
			if strings.HasPrefix(secret.Value, "http") {
				styledOut.PrintSecret(secret.Value, secret.Type, secret.Source)
			}
		}
	}

	// Output findings with styled format if they have URLs
	if len(result.Findings) > 0 && verbose {
		styledOut.PrintSection("Security Findings")
		for _, finding := range result.Findings {
			if finding.URL != "" && finding.Severity == "high" {
				styledOut.PrintFinding(finding.URL, finding.Type)
			}
		}
	}

	// Show integration summary only for meaningful discoveries
	if verbose && (len(result.Secrets) > 0 || len(result.Findings) > 0) {
		styledOut.PrintSection("Integration Status")
		if len(result.Secrets) > 0 {
			styledOut.PrintIntegrationStatus("Secrets", len(result.Secrets), false)
		}
		if len(result.Findings) > 0 {
			styledOut.PrintIntegrationStatus("Findings", len(result.Findings), false)
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

func mapJSReconSeverity(findingType string, confidence float64) string {
	lowerType := strings.ToLower(findingType)

	highSeverity := []string{"secret", "apikey", "token", "password", "credential", "private_key", "aws_key", "jwt"}
	mediumSeverity := []string{"endpoint", "path", "url", "parameter", "request", "graphql", "schema"}

	for _, h := range highSeverity {
		if strings.Contains(lowerType, h) {
			return "high"
		}
	}

	for _, m := range mediumSeverity {
		if strings.Contains(lowerType, m) {
			return "medium"
		}
	}

	if confidence > 0.8 {
		return "medium"
	}

	return "low"
}

func isSecretType(findingType string) bool {
	lowerType := strings.ToLower(findingType)
	secretTypes := []string{"secret", "apikey", "token", "password", "credential", "private_key", "aws_key", "jwt", "bearer", "authorization"}

	for _, s := range secretTypes {
		if strings.Contains(lowerType, s) {
			return true
		}
	}

	return false
}
