package output

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/resistanceisuseless/webscope/pkg/config"
	"github.com/resistanceisuseless/webscope/pkg/types"
)

// SimpleWriter outputs only successful findings, one per line to stdout
type SimpleWriter struct {
	writer          *bufio.Writer
	extendedDetails bool
	allowedStatuses map[int]bool
}

// NewSimpleWriter creates a simple writer that outputs findings to stdout
func NewSimpleWriter() *SimpleWriter {
	// Default allowed statuses for backward compatibility
	defaultStatuses := map[int]bool{200: true, 401: true}
	return &SimpleWriter{
		writer:          bufio.NewWriter(os.Stdout),
		extendedDetails: false,
		allowedStatuses: defaultStatuses,
	}
}

// NewSimpleWriterWithDetails creates a simple writer with extended details
func NewSimpleWriterWithDetails(extendedDetails bool) *SimpleWriter {
	// Default allowed statuses for backward compatibility  
	defaultStatuses := map[int]bool{200: true, 401: true}
	return &SimpleWriter{
		writer:          bufio.NewWriter(os.Stdout),
		extendedDetails: extendedDetails,
		allowedStatuses: defaultStatuses,
	}
}

// NewSimpleWriterWithConfig creates a simple writer with configuration
func NewSimpleWriterWithConfig(extendedDetails bool, appConfig *config.Config) *SimpleWriter {
	allowedStatuses := make(map[int]bool)
	
	// Get status codes from config
	if appConfig != nil {
		httpxConfig := appConfig.GetDefaultHTTPXConfig()
		if len(httpxConfig.StatusCodes) > 0 {
			for _, statusStr := range httpxConfig.StatusCodes {
				if status, err := strconv.Atoi(statusStr); err == nil {
					allowedStatuses[status] = true
				}
			}
		}
	}
	
	// If no config provided, use defaults (200, 401 only - success and auth required)
	if len(allowedStatuses) == 0 {
		allowedStatuses[200] = true
		allowedStatuses[401] = true
	}
	
	return &SimpleWriter{
		writer:          bufio.NewWriter(os.Stdout),
		extendedDetails: extendedDetails,
		allowedStatuses: allowedStatuses,
	}
}

// WriteResult processes a discovery result and outputs only successful findings
func (sw *SimpleWriter) WriteResult(result types.EngineResult) error {
	if result.Error != nil {
		return nil // Skip failed results silently
	}

	// Output only validated successful paths - from discovery modules (not path bruteforcing)
	for _, path := range result.Discovery.Paths {
		// Check if status is allowed by configuration
		if sw.allowedStatuses[path.Status] {
			// Only include actual discoveries, not bruteforce attempts
			if isDiscoverySource(path.Source) {
				if sw.extendedDetails {
					// Ensure we have a source, fallback to "unknown"
					source := path.Source
					if source == "" {
						source = "unknown"
					}
					// Format: URL [STATUS:200] [MODULE:robots]
					sw.writer.WriteString(fmt.Sprintf("%s [STATUS:%d] [MODULE:%s]\n", 
						path.URL, path.Status, source))
				} else {
					sw.writer.WriteString(path.URL + "\n")
				}
			}
		}
	}

	// Skip endpoints - these are unvalidated discovered paths
	// Only output validated paths that have been HTTP-tested above

	// Skip GraphQL endpoints - these are unvalidated discovered endpoints
	// They should be validated separately if needed

	// Skip WebSocket endpoints - these are typically unvalidated discovered endpoints

	// Skip form action URLs - these are constructed, not discovered

	// Output secrets/patterns with actionable context - only URLs that are validated
	for _, secret := range result.Discovery.Secrets {
		// Only output URL-type secrets that are actual URLs
		if secret.Type == "url" && secret.Value != "" && strings.HasPrefix(secret.Value, "http") {
			if sw.extendedDetails {
				source := secret.Source
				if source == "" {
					source = "unknown"
				}
				sw.writer.WriteString(fmt.Sprintf("%s [TYPE:Secret-%s] [MODULE:%s]\n",
					secret.Value, secret.Type, source))
			} else {
				sw.writer.WriteString(secret.Value + "\n")
			}
		}
		// Skip non-URL secrets from simple output as they're not actionable URLs
	}

	// Output critical and high priority interesting findings - only those with URLs
	for _, finding := range result.Discovery.Findings {
		if (finding.Priority == "critical" || finding.Priority == "high") && finding.URL != "" {
			if sw.extendedDetails {
				source := finding.Source
				if source == "" {
					source = "unknown"
				}
				sw.writer.WriteString(fmt.Sprintf("%s [PRIORITY:%s] [CATEGORY:%s] [MODULE:%s]\n",
					finding.URL, finding.Priority, finding.Category, source))
			} else {
				sw.writer.WriteString(finding.URL + "\n")
			}
		}
		// Skip findings without URLs from simple output
	}

	// Flush after each result to ensure output appears immediately
	return sw.writer.Flush()
}

// Close flushes any remaining data
func (sw *SimpleWriter) Close() error {
	return sw.writer.Flush()
}

// GetStatistics returns empty stats for simple mode
func (sw *SimpleWriter) GetStatistics() types.Statistics {
	return types.Statistics{}
}

// isDiscoverySource checks if the source represents actual discovery vs bruteforcing
func isDiscoverySource(source string) bool {
	// Only include sources that represent actual discoveries
	discoveryModules := []string{
		"robots",           // robots.txt discoveries
		"robots-common",    // robots.txt common paths  
		"sitemap",          // sitemap.xml discoveries
		"javascript",       // JS endpoint discoveries
		"advanced-javascript", // Advanced JS analysis
		"katana-lib",       // Crawled discoveries
		"httpx-lib",        // Direct HTTP validation (not paths module)
		"urlfinder",        // Archive-based URL discoveries
	}
	
	// Exclude path bruteforcing modules
	excludeModules := []string{
		"paths-httpx",      // Path bruteforcing
		"paths-variation",  // Path variation attempts
		"paths",            // General path bruteforcing
	}
	
	// Check if source is excluded
	for _, exclude := range excludeModules {
		if strings.Contains(source, exclude) {
			return false
		}
	}
	
	// Check if source is from discovery modules
	for _, module := range discoveryModules {
		if strings.Contains(source, module) {
			return true
		}
	}
	
	// Unknown sources are excluded by default
	return false
}