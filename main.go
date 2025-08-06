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
		profile      = flag.String("profile", "normal", "Scanning profile (stealth, normal, aggressive, thorough)")
		workers      = flag.Int("w", 0, "Number of worker threads (0 = use profile default)")
		timeout      = flag.Duration("t", 0, "HTTP timeout (0 = use profile default)")
		rateLimit    = flag.Int("r", 0, "Requests per second (0 = use profile default)")
		modules      = flag.String("m", "httpx-lib,robots,paths", "Discovery modules to use (comma-separated)")
		listProfiles = flag.Bool("list-profiles", false, "List available profiles and exit")
		verbose      = flag.Bool("v", false, "Verbose output")
	)
	flag.Parse()

	ctx := context.Background()

	// Load configuration
	var appConfig *config.Config
	var configLoaded bool
	var configPath string

	if *configFile != "" {
		var err error
		appConfig, err = config.Load(*configFile)
		if err != nil {
			log.Fatalf("Error loading config file: %v", err)
		}
		configLoaded = true
		configPath = *configFile
	} else {
		// Try default config paths
		for _, defaultPath := range config.GetDefaultConfigPaths() {
			if _, err := os.Stat(defaultPath); err == nil {
				appConfig, _ = config.Load(defaultPath)
				if appConfig != nil {
					configLoaded = true
					configPath = defaultPath
					break
				}
			}
		}
	}

	// Always inform about config status
	if configLoaded {
		fmt.Fprintf(os.Stderr, "[*] Loaded config from: %s\n", configPath)
	} else {
		if appConfig == nil {
			appConfig = &config.Config{}
		}
		fmt.Fprintf(os.Stderr, "[*] No config file loaded, using defaults\n")
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

	// Handle profile listing
	if *listProfiles {
		fmt.Fprintf(os.Stderr, "Available Scanning Profiles:\n\n")
		
		profiles := appConfig.GetProfiles()
		if len(profiles) > 0 {
			for _, profileName := range profiles {
				if profileConfig, exists := appConfig.GetProfile(profileName); exists {
					fmt.Fprintf(os.Stderr, "  %s: %s\n", profileName, profileConfig.Description)
				}
			}
		} else {
			fmt.Fprintf(os.Stderr, "No profiles configured. Use config.example.yaml as a template.\n")
			fmt.Fprintf(os.Stderr, "Default profiles: stealth, normal, aggressive, thorough\n")
		}
		os.Exit(0)
	}

	// Always show target count
	fmt.Fprintf(os.Stderr, "[*] Loaded %d targets\n", len(targets))

	if len(targets) == 0 {
		fmt.Fprintf(os.Stderr, "No targets found. Usage examples:\n")
		fmt.Fprintf(os.Stderr, "  echo 'https://example.com' | webscope\n")
		fmt.Fprintf(os.Stderr, "  echo 'example.com:443' | webscope\n")
		fmt.Fprintf(os.Stderr, "  webscope -i targets.txt\n")
		fmt.Fprintf(os.Stderr, "  webscope -i nmap_results.xml\n")
		os.Exit(1)
	}

	// Get the selected profile configuration
	selectedProfile, profileExists := appConfig.GetProfile(*profile)
	if !profileExists && *profile != "normal" {
		fmt.Fprintf(os.Stderr, "[!] Profile '%s' not found, using defaults\n", *profile)
	}

	// Use profile settings or CLI overrides
	finalWorkers := *workers
	if finalWorkers == 0 && profileExists {
		finalWorkers = selectedProfile.GlobalLimit
	}
	if finalWorkers == 0 {
		finalWorkers = 20 // Default fallback
	}

	finalTimeout := *timeout
	if finalTimeout == 0 && profileExists {
		if selectedProfile.HTTPX.Timeout > 0 {
			finalTimeout = time.Duration(selectedProfile.HTTPX.Timeout) * time.Second
		}
	}
	if finalTimeout == 0 {
		finalTimeout = 30 * time.Second // Default fallback
	}

	finalRateLimit := *rateLimit
	if finalRateLimit == 0 && profileExists {
		finalRateLimit = selectedProfile.GlobalLimit
	}
	if finalRateLimit == 0 {
		finalRateLimit = 20 // Default fallback
	}

	discoveryConfig := &discovery.Config{
		Workers:   finalWorkers,
		Timeout:   finalTimeout,
		RateLimit: finalRateLimit,
		Modules:   strings.Split(*modules, ","),
		Verbose:   *verbose,
		AppConfig: appConfig,
		Profile:   *profile,
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

	// Show discovery start
	fmt.Fprintf(os.Stderr, "[*] Starting discovery with modules: %s\n", *modules)
	fmt.Fprintf(os.Stderr, "[*] Workers: %d, Rate limit: %d/s, Timeout: %s\n", *workers, *rateLimit, *timeout)

	engine := discovery.NewEngine(discoveryConfig)
	results := engine.Discover(ctx, targets)

	// Simple progress counter for non-verbose mode
	processedCount := 0
	lastProgressTime := time.Now()

	// Show initial progress
	fmt.Fprintf(os.Stderr, "[*] Processing targets...\n")

	for result := range results {
		processedCount++

		// Show basic progress every 10 seconds in non-verbose mode
		if !*verbose && time.Since(lastProgressTime) > 10*time.Second {
			fmt.Fprintf(os.Stderr, "[*] Progress: %d/%d targets processed...\n", processedCount, len(targets))
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

	// Always show completion status
	fmt.Fprintf(os.Stderr, "[*] Discovery complete: %d targets processed\n", processedCount)
	fmt.Fprintf(os.Stderr, "[*] Results: %d paths, %d endpoints, %d secrets, %d findings discovered\n",
		stats.TotalPaths, stats.TotalEndpoints, stats.TotalSecrets, stats.TotalFindings)
	
	// Show findings summary if we have interesting findings
	if stats.TotalFindings > 0 {
		fmt.Fprintf(os.Stderr, "[*] Interesting findings summary:\n")
		if len(stats.CriticalFindings) > 0 {
			fmt.Fprintf(os.Stderr, "  - Critical: %d findings (requires immediate attention)\n", len(stats.CriticalFindings))
		}
		if len(stats.HighPriorityFindings) > 0 {
			fmt.Fprintf(os.Stderr, "  - High priority: %d findings (review recommended)\n", len(stats.HighPriorityFindings))
		}
		if stats.FindingsByCategory != nil {
			for category, count := range stats.FindingsByCategory {
				if category == "secrets" || category == "serialization" {
					fmt.Fprintf(os.Stderr, "  - %s: %d findings\n", category, count)
				}
			}
		}
	}

	if *outputFile != "" {
		fmt.Fprintf(os.Stderr, "[*] Output saved to: %s\n", *outputFile)
	}
}
