package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/config"
	"github.com/resistanceisuseless/webscope/pkg/discovery"
	"github.com/resistanceisuseless/webscope/pkg/input"
	"github.com/resistanceisuseless/webscope/pkg/output"
)

func main() {
	var (
		inputFile    = flag.String("i", "", "Input file (nmap XML, JSON, or text file with one host per line)")
		outputFile   = flag.String("o", "", "Output file (default: stdout)")
		outputFormat = flag.String("of", "jsonl", "Output format: jsonl (streaming JSON Lines) or json (standard JSON)")
		configFile   = flag.String("c", "", "Configuration file path (default: auto-detect)")
		workers      = flag.Int("w", 20, "Number of worker threads")
		timeout      = flag.Duration("t", 30*time.Second, "HTTP timeout")
		rateLimit    = flag.Int("r", 20, "Requests per second")
		modules      = flag.String("m", "http,robots,sitemap,paths,javascript", "Discovery modules to use (comma-separated)")
		verbose      = flag.Bool("v", false, "Verbose output")
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

	// Create streaming writer
	streamWriter, err := output.NewStreamingWriter(*outputFile, *outputFormat)
	if err != nil {
		log.Fatalf("Error creating output writer: %v", err)
	}
	defer streamWriter.Close()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	
	// Create a cancellable context
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	
	// Handle signals
	go func() {
		<-sigChan
		fmt.Fprintf(os.Stderr, "\n[!] Received interrupt signal, saving partial results...\n")
		cancel()
	}()

	engine := discovery.NewEngine(discoveryConfig)
	results := engine.Discover(ctx, targets)

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

		// Write result immediately to prevent data loss
		if err := streamWriter.WriteResult(result); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing result for %s: %v\n", result.Target.Domain, err)
		}
	}

	// Get final statistics
	stats := streamWriter.GetStatistics()
	
	if *verbose {
		fmt.Fprintf(os.Stderr, "Discovery complete. Found %d paths, %d endpoints\n",
			stats.TotalPaths, stats.TotalEndpoints)
	}
}