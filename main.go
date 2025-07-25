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

	"github.com/resistanceisuseless/webscope/pkg/discovery"
	"github.com/resistanceisuseless/webscope/pkg/input"
	"github.com/resistanceisuseless/webscope/pkg/types"
)

func main() {
	var (
		inputFile   = flag.String("i", "", "Input file (nmap XML, JSON, or text file with one host per line)")
		outputFile  = flag.String("o", "", "Output file (default: stdout)")
		workers     = flag.Int("w", 20, "Number of worker threads")
		timeout     = flag.Duration("t", 30*time.Second, "HTTP timeout")
		rateLimit   = flag.Int("r", 20, "Requests per second")
		modules     = flag.String("m", "http,robots,paths", "Discovery modules to use (comma-separated)")
		verbose     = flag.Bool("v", false, "Verbose output")
	)
	flag.Parse()

	ctx := context.Background()

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

	config := &discovery.Config{
		Workers:   *workers,
		Timeout:   *timeout,
		RateLimit: *rateLimit,
		Modules:   strings.Split(*modules, ","),
		Verbose:   *verbose,
	}

	engine := discovery.NewEngine(config)
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

	for result := range results {
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