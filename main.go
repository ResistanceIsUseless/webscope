package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/config"
	"github.com/resistanceisuseless/webscope/pkg/discovery"
	"github.com/resistanceisuseless/webscope/pkg/input"
	"github.com/resistanceisuseless/webscope/pkg/types"
)

func main() {
	var (
		inputFile   = flag.String("i", "", "Input file (nmap XML, JSON, or text file with one host per line)")
		outputFile  = flag.String("o", "", "Output file (default: stdout)")
		configFile  = flag.String("c", "", "Configuration file path (default: auto-detect)")
		workers     = flag.Int("w", 20, "Number of worker threads")
		timeout     = flag.Duration("t", 30*time.Second, "HTTP timeout")
		rateLimit   = flag.Int("r", 20, "Requests per second")
		modules     = flag.String("m", "http,robots,sitemap,paths,javascript", "Discovery modules to use (comma-separated)")
		verbose     = flag.Bool("v", false, "Verbose output")
	)
	flag.Parse()

	ctx := context.Background()

	// Load configuration
	var appConfig *config.Config
	if *configFile != "" {
		var err error
		appConfig, err = config.Load(*configFile)
		if err != nil {
			log.Fatalf("Error loading config file: %v", err)
		}
		if *verbose {
			fmt.Fprintf(os.Stderr, "Loaded config from: %s\n", *configFile)
		}
	} else {
		// Try default config paths
		for _, defaultPath := range config.GetDefaultConfigPaths() {
			if _, err := os.Stat(defaultPath); err == nil {
				appConfig, _ = config.Load(defaultPath)
				if *verbose {
					fmt.Fprintf(os.Stderr, "Loaded config from: %s\n", defaultPath)
				}
				break
			}
		}
		if appConfig == nil {
			appConfig = &config.Config{}
		}
	}

	var inputReader io.Reader
	if *inputFile != "" {
		file, err := os.Open(*inputFile)
		if err != nil {
			log.Fatalf("Error opening input file: %v", err)
		}
		defer file.Close()
		inputReader = file
	} else {
		inputReader = os.Stdin
	}

	inputHandler := input.NewHandler()
	targets, err := inputHandler.ParseInput(inputReader, *inputFile)
	if err != nil {
		log.Fatalf("Error parsing input: %v", err)
	}

	if *verbose {
		fmt.Fprintf(os.Stderr, "Loaded %d targets\n", len(targets))
	}

	if len(targets) == 0 {
		fmt.Fprintf(os.Stderr, "No targets found. Usage examples:\n")
		fmt.Fprintf(os.Stderr, "  echo 'https://example.com' | webscope\n")
		fmt.Fprintf(os.Stderr, "  echo 'example.com:443' | webscope\n")
		fmt.Fprintf(os.Stderr, "  webscope -i targets.txt\n")
		fmt.Fprintf(os.Stderr, "  webscope -i nmap_results.xml\n")
		os.Exit(1)
	}

	discoveryConfig := &discovery.Config{
		Workers:   *workers,
		Timeout:   *timeout,
		RateLimit: *rateLimit,
		Modules:   strings.Split(*modules, ","),
		Verbose:   *verbose,
		AppConfig: appConfig,
	}

	engine := discovery.NewEngine(discoveryConfig)
	results := engine.Discover(ctx, targets)

	output := &types.WebScopeResult{
		Metadata: types.Metadata{
			Timestamp: time.Now(),
			Version:   "1.0.0",
			Targets:   len(targets),
		},
		Discoveries: make(map[string]*types.Discovery),
		Statistics:  types.Statistics{},
	}

	// Simple progress counter for non-verbose mode
	processedCount := 0
	lastProgressTime := time.Now()
	
	for result := range results {
		processedCount++
		
		// Show basic progress every 10 seconds in non-verbose mode
		if !*verbose && time.Since(lastProgressTime) > 10*time.Second {
			fmt.Fprintf(os.Stderr, "[*] Processed %d targets...\n", processedCount)
			lastProgressTime = time.Now()
		}
		
		if result.Error != nil {
			if *verbose {
				fmt.Fprintf(os.Stderr, "Error processing %s: %v\n", result.Target.URL, result.Error)
			}
			continue
		}

		discovery := &types.Discovery{
			Domain:     result.Target.Domain,
			Paths:      result.Discovery.Paths,
			Endpoints:  result.Discovery.Endpoints,
			Forms:      result.Discovery.Forms,
			Parameters: result.Discovery.Parameters,
			Secrets:    result.Discovery.Secrets,
		}

		output.Discoveries[result.Target.Domain] = discovery
		output.Statistics.TotalPaths += len(result.Discovery.Paths)
		output.Statistics.TotalEndpoints += len(result.Discovery.Endpoints)
		output.Statistics.TotalSecrets += len(result.Discovery.Secrets)
		output.Statistics.TotalForms += len(result.Discovery.Forms)
	}

	var outputWriter io.Writer
	if *outputFile != "" {
		file, err := os.Create(*outputFile)
		if err != nil {
			log.Fatalf("Error creating output file: %v", err)
		}
		defer file.Close()
		outputWriter = file
	} else {
		outputWriter = os.Stdout
	}

	encoder := json.NewEncoder(outputWriter)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		log.Fatalf("Error encoding output: %v", err)
	}

	if *verbose {
		fmt.Fprintf(os.Stderr, "Discovery complete. Found %d paths, %d endpoints across %d domains\n",
			output.Statistics.TotalPaths, output.Statistics.TotalEndpoints, len(output.Discoveries))
	}
}