package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/config"
	"github.com/resistanceisuseless/webscope/pkg/discovery"
	"github.com/resistanceisuseless/webscope/pkg/input"
	"github.com/resistanceisuseless/webscope/pkg/output"
	"github.com/resistanceisuseless/webscope/pkg/types"
)

const (
	appVersion = "1.0.1"
)

func showBanner() {
	fmt.Printf("WebScope - Web Content Discovery Tool v%s\n", appVersion)
	fmt.Printf("https://github.com/ResistanceIsUseless/webscope\n\n")
}

func showUsage() {
	fmt.Printf("Usage:\n")
	fmt.Printf("  webscope [flags]\n\n")
	
	fmt.Printf("FLAGS:\n")
	fmt.Printf("INPUT:\n")
	fmt.Printf("   -l, -list string[]      path to file containing a list of target URLs/hosts to scan (one per line)\n")
	fmt.Printf("   -u, -target string[]    target URLs/hosts to scan\n")
	fmt.Printf("   -resume string          resume scan using resume.cfg\n\n")
	
	fmt.Printf("INPUT-FORMAT:\n")
	fmt.Printf("   -im, -input-mode string mode of input file (list, nmap, json) (default \"list\")\n\n")
	
	fmt.Printf("OUTPUT:\n")
	fmt.Printf("   -o, -output string      output file to write results (default stdout, simple mode)\n")
	fmt.Printf("   -of, -output-format string output format (jsonl, json) (default \"jsonl\")\n")
	fmt.Printf("                          Note: simple mode outputs findings only, one per line for piping\n\n")
	
	fmt.Printf("CONFIGURATION:\n")
	fmt.Printf("   -c, -config string      path to configuration file\n")
	fmt.Printf("   -profile string         scanning profile to use (stealth, normal, aggressive, thorough) (default \"normal\")\n")
	fmt.Printf("   -lp, -list-profiles     list available scanning profiles\n\n")
	
	fmt.Printf("RATE-CONTROL:\n")
	fmt.Printf("   -t, -threads int        number of concurrent threads (default 20)\n")
	fmt.Printf("   -rl, -rate-limit int    maximum number of requests to send per second (default 20)\n")
	fmt.Printf("   -timeout int            time to wait in seconds before timeout (default 30)\n\n")
	
	fmt.Printf("MODULES:\n")
	fmt.Printf("   -m, -modules string[]   discovery modules to run (default \"robots,sitemap,paths,patterns\")\n")
	fmt.Printf("                          Available: httpx-lib,robots,sitemap,paths,katana-lib*,javascript,advanced-javascript,patterns\n")
	fmt.Printf("                          *katana-lib: can cause goroutine leaks in bulk scans, use with caution\n\n")
	
	fmt.Printf("DEBUG:\n")
	fmt.Printf("   -v, -verbose           show verbose output\n")
	fmt.Printf("   -debug                 show debug output\n")
	fmt.Printf("   -s, -silent            show only results in output\n")
	fmt.Printf("   -version               show version of the project\n")
}

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, strings.Split(value, ",")...)
	return nil
}

func main() {
	var (
		// Input flags
		targets     stringSliceFlag
		inputFiles  stringSliceFlag
		inputMode   = flag.String("input-mode", "list", "")
		
		// Output flags
		outputFile   = flag.String("o", "", "")
		outputFmt    = flag.String("of", "jsonl", "")
		
		// Configuration flags
		configFile   = flag.String("c", "", "")
		profile      = flag.String("profile", "normal", "")
		listProfiles = flag.Bool("list-profiles", false, "")
		
		// Rate control flags
		threads     = flag.Int("t", 20, "")
		rateLimit   = flag.Int("rl", 20, "")
		timeout     = flag.Int("timeout", 30, "")
		
		// Module flags
		modules     stringSliceFlag
		
		// Debug flags
		verbose     = flag.Bool("v", false, "")
		silent      = flag.Bool("s", false, "")
		version     = flag.Bool("version", false, "")
		showHelp    = flag.Bool("h", false, "")
	)
	
	// Set up aliases
	flag.StringVar(outputFile, "output", "", "")
	flag.StringVar(outputFmt, "output-format", "jsonl", "")
	flag.StringVar(configFile, "config", "", "")
	flag.IntVar(threads, "threads", 20, "")
	flag.IntVar(rateLimit, "rate-limit", 20, "")
	flag.BoolVar(verbose, "verbose", false, "")
	flag.BoolVar(silent, "silent", false, "")
	flag.BoolVar(listProfiles, "lp", false, "")
	flag.StringVar(inputMode, "im", "list", "")
	flag.Var(&targets, "u", "")
	flag.Var(&targets, "target", "")
	flag.Var(&inputFiles, "l", "")
	flag.Var(&inputFiles, "list", "")
	flag.Var(&modules, "m", "")
	flag.Var(&modules, "modules", "")
	
	// Default modules if none specified - focused on discovery
	// Note: katana-lib disabled by default due to goroutine leak issues in bulk scans
	if len(modules) == 0 {
		modules = stringSliceFlag{"robots", "sitemap", "paths", "patterns"}
	}
	
	flag.Usage = func() {
		showBanner()
		showUsage()
	}
	
	flag.Parse()
	
	if *showHelp {
		flag.Usage()
		return
	}
	
	if *version {
		fmt.Printf("webscope version %s\n", appVersion)
		return
	}

	ctx := context.Background()

	// Determine if we're using simple mode (stdout findings only)  
	// Simple mode when: no output file specified AND output format is default jsonl
	usingSimpleMode := *outputFile == "" && *outputFmt == "jsonl"

	// Load configuration
	var appConfig *config.Config
	var configLoaded bool
	var configPath string

	if *configFile != "" {
		var err error
		appConfig, err = config.Load(*configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Error loading config file: %v\n", err)
			os.Exit(1)
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

	// Always initialize config if not loaded
	if appConfig == nil {
		appConfig = &config.Config{}
	}

	// Always inform about config status unless silent or simple mode
	if !*silent && !usingSimpleMode {
		if configLoaded {
			fmt.Fprintf(os.Stderr, "[INFO] Loaded config from: %s\n", configPath)
		} else {
			fmt.Fprintf(os.Stderr, "[INFO] No config file loaded, using defaults\n")
		}
	}

	// Handle profile listing
	if *listProfiles {
		fmt.Printf("Available Scanning Profiles:\n\n")
		
		profiles := appConfig.GetProfiles()
		if len(profiles) > 0 {
			for _, profileName := range profiles {
				if profileConfig, exists := appConfig.GetProfile(profileName); exists {
					fmt.Printf("  %s: %s\n", profileName, profileConfig.Description)
				}
			}
		} else {
			fmt.Printf("No profiles configured. Use config.example.yaml as a template.\n")
			fmt.Printf("Default profiles: stealth, normal, aggressive, thorough\n")
		}
		return
	}

	// Determine input source
	var inputReader io.Reader
	var inputFile string
	
	if len(targets) > 0 {
		// Create temporary input from targets
		inputReader = strings.NewReader(strings.Join(targets, "\n"))
		inputFile = ""
	} else if len(inputFiles) > 0 {
		// Use first file from list
		file, err := os.Open(inputFiles[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Error opening input file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		inputReader = file
		inputFile = inputFiles[0]
	} else {
		// Default to stdin if no input specified
		inputReader = os.Stdin
		inputFile = ""
	}

	inputHandler := input.NewHandler()
	parsedTargets, err := inputHandler.ParseInput(inputReader, inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Error parsing input: %v\n", err)
		os.Exit(1)
	}

	// Always show target count unless silent or using simple mode
	if !*silent && !usingSimpleMode {
		fmt.Fprintf(os.Stderr, "[INFO] Loaded %d targets\n", len(parsedTargets))
	}

	if len(parsedTargets) == 0 {
		fmt.Fprintf(os.Stderr, "No targets found. Usage examples:\n")
		fmt.Fprintf(os.Stderr, "  echo 'https://example.com' | webscope\n")
		fmt.Fprintf(os.Stderr, "  echo 'example.com:443' | webscope\n")
		fmt.Fprintf(os.Stderr, "  webscope -l targets.txt\n")
		fmt.Fprintf(os.Stderr, "  webscope -u https://example.com\n")
		fmt.Fprintf(os.Stderr, "  webscope -l nmap_results.xml\n")
		return
	}

	// Get the selected profile configuration
	selectedProfile, profileExists := appConfig.GetProfile(*profile)
	if !profileExists && *profile != "normal" {
		if !*silent {
			fmt.Fprintf(os.Stderr, "[WARN] Profile '%s' not found, using defaults\n", *profile)
		}
	}

	// Use profile settings or CLI overrides
	finalWorkers := *threads
	if profileExists && finalWorkers == 20 { // default value
		if selectedProfile.GlobalLimit > 0 {
			finalWorkers = selectedProfile.GlobalLimit
		}
	}

	finalTimeout := time.Duration(*timeout) * time.Second
	if profileExists && *timeout == 30 { // default value
		if selectedProfile.HTTPX.Timeout > 0 {
			finalTimeout = time.Duration(selectedProfile.HTTPX.Timeout) * time.Second
		}
	}

	finalRateLimit := *rateLimit
	if profileExists && finalRateLimit == 20 { // default value
		if selectedProfile.GlobalLimit > 0 {
			finalRateLimit = selectedProfile.GlobalLimit
		}
	}

	discoveryConfig := &discovery.Config{
		Workers:   finalWorkers,
		Timeout:   finalTimeout,
		RateLimit: finalRateLimit,
		Modules:   []string(modules),
		Verbose:   *verbose,
		AppConfig: appConfig,
		Profile:   *profile,
	}

	// Create output writer based on mode determined earlier
	var resultWriter interface {
		WriteResult(result types.EngineResult) error
		Close() error
		GetStatistics() types.Statistics
	}

	if !usingSimpleMode {
		// Use streaming writer for file output or when JSON format explicitly requested
		streamWriter, err := output.NewStreamingWriter(*outputFile, *outputFmt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Error creating output writer: %v\n", err)
			os.Exit(1)
		}
		resultWriter = streamWriter
	} else {
		// Use simple writer for stdout with findings only
		resultWriter = output.NewSimpleWriter()
	}
	defer resultWriter.Close()

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Create a cancellable context
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Handle signals
	go func() {
		<-sigChan
		if !*silent {
			fmt.Fprintf(os.Stderr, "\n[WARN] Received interrupt signal, saving partial results...\n")
		}
		cancel()
	}()

	// Show discovery start
	if !*silent && !usingSimpleMode {
		fmt.Fprintf(os.Stderr, "[INFO] Starting discovery with modules: %s\n", strings.Join(modules, ","))
		fmt.Fprintf(os.Stderr, "[INFO] Workers: %d, Rate limit: %d/s, Timeout: %s\n", finalWorkers, finalRateLimit, finalTimeout)
	}

	engine := discovery.NewEngine(discoveryConfig)
	results := engine.Discover(ctx, parsedTargets)

	// Simple progress counter for non-verbose mode
	processedCount := 0
	lastProgressTime := time.Now()

	// Show initial progress
	if !*silent && !usingSimpleMode {
		fmt.Fprintf(os.Stderr, "[INFO] Processing targets...\n")
	}

	for result := range results {
		processedCount++

		// Show basic progress every 10 seconds in non-verbose mode
		if !*verbose && !*silent && !usingSimpleMode && time.Since(lastProgressTime) > 10*time.Second {
			fmt.Fprintf(os.Stderr, "[INFO] Progress: %d/%d targets processed...\n", processedCount, len(parsedTargets))
			lastProgressTime = time.Now()
		}

		if result.Error != nil {
			if *verbose {
				fmt.Fprintf(os.Stderr, "[ERROR] Error processing %s: %v\n", result.Target.URL, result.Error)
			}
			continue
		}

		// Write result immediately to prevent data loss
		if err := resultWriter.WriteResult(result); err != nil {
			if !usingSimpleMode {
				fmt.Fprintf(os.Stderr, "[ERROR] Error writing result for %s: %v\n", result.Target.Domain, err)
			}
		}
	}

	// Get final statistics
	stats := resultWriter.GetStatistics()

	// Show completion status and statistics unless silent or using simple mode
	if !*silent && !usingSimpleMode {
		fmt.Fprintf(os.Stderr, "[INFO] Discovery complete: %d targets processed\n", processedCount)
		fmt.Fprintf(os.Stderr, "[INFO] Results: %d paths, %d endpoints, %d secrets, %d findings discovered\n",
			stats.TotalPaths, stats.TotalEndpoints, stats.TotalSecrets, stats.TotalFindings)
		
		// Show findings summary if we have interesting findings
		if stats.TotalFindings > 0 {
			fmt.Fprintf(os.Stderr, "[INFO] Interesting findings summary:\n")
			if len(stats.CriticalFindings) > 0 {
				fmt.Fprintf(os.Stderr, "[WARN]   - Critical: %d findings (requires immediate attention)\n", len(stats.CriticalFindings))
			}
			if len(stats.HighPriorityFindings) > 0 {
				fmt.Fprintf(os.Stderr, "[INFO]   - High priority: %d findings (review recommended)\n", len(stats.HighPriorityFindings))
			}
			if stats.FindingsByCategory != nil {
				for category, count := range stats.FindingsByCategory {
					if category == "secrets" || category == "serialization" {
						fmt.Fprintf(os.Stderr, "[INFO]   - %s: %d findings\n", category, count)
					}
				}
			}
		}

		if *outputFile != "" {
			fmt.Fprintf(os.Stderr, "[INFO] Output saved to: %s\n", *outputFile)
		}
	}
}
