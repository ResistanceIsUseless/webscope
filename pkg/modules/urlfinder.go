package modules

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/config"
	"github.com/resistanceisuseless/webscope/pkg/types"
)

type URLFinderModule struct {
	httpx           HTTPXInterface
	timeout         time.Duration
	maxEnumTime     time.Duration
	rateLimit       int
	includeSources  []string
	excludeSources  []string
	useAllSources   bool
}

func NewURLFinderModule(timeout time.Duration) *URLFinderModule {
	return &URLFinderModule{
		httpx:         NewHTTPXLibModule(20, timeout, 10),
		timeout:       timeout,
		maxEnumTime:   2 * time.Minute, // Limit enumeration time
		rateLimit:     10,
		includeSources: nil,
		excludeSources: nil,
		useAllSources: false,
	}
}

func NewURLFinderModuleWithConfig(timeout time.Duration, appConfig *config.Config) *URLFinderModule {
	rateLimit := 10
	maxEnumTime := 2 * time.Minute
	var includeSources, excludeSources []string
	useAllSources := false

	// Get URLFinder configuration from app config
	if appConfig != nil {
		ufConfig := appConfig.GetDefaultURLFinderConfig()
		if ufConfig.RateLimit > 0 {
			rateLimit = ufConfig.RateLimit
		}
		if ufConfig.Timeout > 0 {
			maxEnumTime = time.Duration(ufConfig.Timeout) * time.Second
		}
		includeSources = ufConfig.Sources
		excludeSources = ufConfig.ExcludeSources
		useAllSources = ufConfig.UseAllSources
	}

	return &URLFinderModule{
		httpx:         NewHTTPXLibModule(20, timeout, rateLimit),
		timeout:       timeout,
		maxEnumTime:   maxEnumTime,
		rateLimit:     rateLimit,
		includeSources: includeSources,
		excludeSources: excludeSources,
		useAllSources: useAllSources,
	}
}

func (u *URLFinderModule) Name() string {
	return "urlfinder"
}

func (u *URLFinderModule) Priority() int {
	return 3 // High priority for URL discovery
}

func (u *URLFinderModule) Discover(target types.Target) (*types.DiscoveryResult, error) {
	result := &types.DiscoveryResult{
		Paths:     []types.Path{},
		Endpoints: []types.Endpoint{},
		Secrets:   []types.Secret{},
	}

	// Extract domain from target URL
	domain, err := u.extractDomain(target.URL)
	if err != nil {
		return result, fmt.Errorf("failed to extract domain from %s: %v", target.URL, err)
	}

	// Check if urlfinder CLI is available
	if _, err := exec.LookPath("urlfinder"); err != nil {
		return result, fmt.Errorf("urlfinder CLI tool not found in PATH: %v", err)
	}

	// Build urlfinder command
	args := []string{"-d", domain, "-silent"}
	
	// Add source filters if specified
	if len(u.includeSources) > 0 {
		args = append(args, "-sources", strings.Join(u.includeSources, ","))
	}
	if len(u.excludeSources) > 0 {
		args = append(args, "-exclude-sources", strings.Join(u.excludeSources, ","))
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), u.maxEnumTime)
	defer cancel()

	// Execute urlfinder command
	cmd := exec.CommandContext(ctx, "urlfinder", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return result, fmt.Errorf("failed to create urlfinder stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return result, fmt.Errorf("failed to start urlfinder: %v", err)
	}

	// Collect URLs from urlfinder output
	var urls []string
	urlSet := make(map[string]bool)
	scanner := bufio.NewScanner(stdout)

	for scanner.Scan() {
		urlStr := strings.TrimSpace(scanner.Text())
		if urlStr != "" && u.isTargetDomain(urlStr, domain) {
			if !urlSet[urlStr] {
				urlSet[urlStr] = true
				urls = append(urls, urlStr)
				
				// Limit URLs to prevent overwhelming system
				if len(urls) >= 500 {
					break
				}
			}
		}
	}

	// Wait for command to complete
	if err := cmd.Wait(); err != nil {
		// Don't fail the whole discovery if urlfinder has issues
		// Just log and continue with any URLs we collected
		if ctx.Err() != context.DeadlineExceeded {
			fmt.Fprintf(os.Stderr, "[URLFinder] Warning: urlfinder exited with error: %v\n", err)
		}
	}

	// Validate discovered URLs using httpx if we found any
	if len(urls) > 0 {
		// Process in smaller batches to avoid overwhelming httpx
		batchSize := 100
		for i := 0; i < len(urls); i += batchSize {
			end := i + batchSize
			if end > len(urls) {
				end = len(urls)
			}

			batch := urls[i:end]
			httpxResults, err := u.httpx.ProbeBulk(batch)
			if err != nil {
				// Continue with other batches even if one fails
				continue
			}

			// Process validated URLs
			for _, httpxResult := range httpxResults {
				if httpxResult.StatusCode > 0 && httpxResult.StatusCode < 500 {
					// Add as discovered path
					path := types.Path{
						URL:         httpxResult.URL,
						Status:      httpxResult.StatusCode,
						Length:      httpxResult.ContentLength,
						Method:      "GET",
						ContentType: httpxResult.ContentType,
						Title:       httpxResult.Title,
						Source:      "urlfinder",
					}
					result.Paths = append(result.Paths, path)

					// Extract path for endpoint
					pathOnly := u.extractPath(httpxResult.URL, target.URL)
					endpoint := types.Endpoint{
						Path:   pathOnly,
						Type:   "archive-discovered",
						Method: "GET",
						Source: "urlfinder",
					}
					result.Endpoints = append(result.Endpoints, endpoint)

					// Check for potentially sensitive URLs
					if u.isSensitiveURL(httpxResult.URL) {
						secret := types.Secret{
							Type:    "url",
							Value:   httpxResult.URL,
							Context: fmt.Sprintf("Potentially sensitive URL discovered via archive search"),
							Source:  "urlfinder",
						}
						result.Secrets = append(result.Secrets, secret)
					}
				}
			}
		}
	}

	return result, nil
}

// extractDomain extracts the domain from a URL
func (u *URLFinderModule) extractDomain(targetURL string) (string, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}
	
	// Return just the hostname (domain)
	return parsedURL.Hostname(), nil
}

// isTargetDomain checks if the URL belongs to the target domain or its subdomains
func (u *URLFinderModule) isTargetDomain(urlStr, targetDomain string) bool {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	urlDomain := parsedURL.Hostname()
	
	// Check exact match
	if urlDomain == targetDomain {
		return true
	}

	// Check subdomain match
	if strings.HasSuffix(urlDomain, "."+targetDomain) {
		return true
	}

	return false
}

// extractPath extracts the path portion from a full URL relative to the base URL
func (u *URLFinderModule) extractPath(fullURL, baseURL string) string {
	parsedFull, err := url.Parse(fullURL)
	if err != nil {
		return fullURL
	}

	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return fullURL
	}

	// If different hosts, return the full URL
	if parsedFull.Host != parsedBase.Host {
		return fullURL
	}

	// Return the path with query parameters if present
	path := parsedFull.Path
	if parsedFull.RawQuery != "" {
		path += "?" + parsedFull.RawQuery
	}

	if path == "" {
		return "/"
	}

	return path
}

// isSensitiveURL checks if a URL might contain sensitive information
func (u *URLFinderModule) isSensitiveURL(urlStr string) bool {
	urlStr = strings.ToLower(urlStr)
	
	sensitivePatterns := []string{
		"admin", "login", "auth", "password", "token", "key", "secret",
		"config", "settings", "env", "database", "db", "backup", "private",
		"internal", "debug", "test", "dev", "staging", "temp", "tmp",
		".git", ".env", ".config", ".bak", ".backup", ".old", ".orig",
		"swagger", "api-docs", "openapi", "graphql", "phpinfo",
		"wp-admin", "wp-config", "web.config", "application.yml",
	}

	for _, pattern := range sensitivePatterns {
		if strings.Contains(urlStr, pattern) {
			return true
		}
	}

	return false
}