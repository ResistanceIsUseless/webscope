package modules

import (
	"bufio"
	"strings"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/config"
	"github.com/resistanceisuseless/webscope/pkg/types"
)

type RobotsModule struct {
	httpx      *HTTPXModule
	fpDetector *FalsePositiveDetector
}

func NewRobotsModule(timeout time.Duration) *RobotsModule {
	return &RobotsModule{
		httpx:      NewHTTPXModule(10, timeout, 10), // Lower threads and rate limit for robots.txt
		fpDetector: NewFalsePositiveDetector(timeout, 10),
	}
}

func NewRobotsModuleWithConfig(timeout time.Duration, appConfig *config.Config) *RobotsModule {
	threads := 10
	rateLimit := 10

	if appConfig != nil {
		httpxConfig := appConfig.GetDefaultHTTPXConfig()
		if httpxConfig.Threads > 0 {
			threads = httpxConfig.Threads
		}
		if httpxConfig.RateLimit > 0 {
			rateLimit = httpxConfig.RateLimit
		}
	}

	return &RobotsModule{
		httpx:      NewHTTPXModule(threads, timeout, rateLimit),
		fpDetector: NewFalsePositiveDetector(timeout, rateLimit),
	}
}

func (r *RobotsModule) Name() string {
	return "robots"
}

func (r *RobotsModule) Priority() int {
	return 2
}

func (r *RobotsModule) Discover(target types.Target) (*types.DiscoveryResult, error) {
	result := &types.DiscoveryResult{
		Paths:     []types.Path{},
		Endpoints: []types.Endpoint{},
	}

	robotsURL := strings.TrimSuffix(target.URL, "/") + "/robots.txt"

	// Use httpx to check if robots.txt exists
	httpxResult, err := r.httpx.probeTarget(robotsURL)
	if err != nil || httpxResult == nil || httpxResult.StatusCode != 200 {
		return result, nil // No robots.txt found
	}

	// Record the robots.txt file itself
	robotsPath := types.Path{
		URL:         robotsURL,
		Status:      httpxResult.StatusCode,
		Length:      httpxResult.ContentLength,
		Method:      "GET",
		ContentType: httpxResult.ContentType,
		Source:      "robots",
	}
	result.Paths = append(result.Paths, robotsPath)

	// Since we can't get the body content from httpx directly,
	// we'll probe common disallowed paths that are typically in robots.txt
	baseURL := strings.TrimSuffix(target.URL, "/")

	// Common paths found in robots.txt files
	commonDisallowedPaths := []string{
		"/admin", "/admin/",
		"/api", "/api/",
		"/backup", "/backup/",
		"/config", "/config/",
		"/private", "/private/",
		"/test", "/test/",
		"/tmp", "/tmp/",
		"/dev", "/dev/",
		"/staging", "/staging/",
		"/.git", "/.git/",
		"/.env",
		"/wp-admin", "/wp-admin/",
		"/wp-content", "/wp-content/",
		"/wp-includes", "/wp-includes/",
		"/cgi-bin", "/cgi-bin/",
		"/scripts", "/scripts/",
		"/includes", "/includes/",
		"/lib", "/lib/",
		"/src", "/src/",
		"/vendor", "/vendor/",
		"/node_modules", "/node_modules/",
		"/cache", "/cache/",
		"/logs", "/logs/",
		"/database", "/database/",
		"/db", "/db/",
		"/sql", "/sql/",
		"/phpmyadmin", "/phpmyadmin/",
		"/phpMyAdmin", "/phpMyAdmin/",
		"/setup", "/setup/",
		"/install", "/install/",
		"/console", "/console/",
		"/status", "/status/",
		"/server-status",
		"/server-info",
	}

	// Build URLs to probe
	var urlsToProbe []string
	for _, path := range commonDisallowedPaths {
		fullURL := baseURL + path
		urlsToProbe = append(urlsToProbe, fullURL)
	}

	// Probe paths using httpx bulk
	httpxResults, err := r.httpx.ProbeBulk(urlsToProbe)
	if err == nil {
		for _, httpxRes := range httpxResults {
			// Accept various status codes as valid discoveries
			if httpxRes.StatusCode > 0 && httpxRes.StatusCode < 500 {
				discoveredPath := types.Path{
					URL:         httpxRes.URL,
					Status:      httpxRes.StatusCode,
					Length:      httpxRes.ContentLength,
					Method:      "GET",
					ContentType: httpxRes.ContentType,
					Title:       httpxRes.Title,
					Source:      "robots-common",
				}
				result.Paths = append(result.Paths, discoveredPath)

				// Extract path for endpoint
				pathOnly := strings.TrimPrefix(httpxRes.URL, baseURL)
				endpoint := types.Endpoint{
					Path:   pathOnly,
					Type:   "robots-discovered",
					Method: "GET",
					Source: "robots",
				}
				result.Endpoints = append(result.Endpoints, endpoint)
			}
		}
	}

	// Also check for common sitemap locations
	sitemapURLs := []string{
		baseURL + "/sitemap.xml",
		baseURL + "/sitemap_index.xml",
		baseURL + "/sitemap-index.xml",
		baseURL + "/sitemap.xml.gz",
		baseURL + "/sitemap1.xml",
		baseURL + "/sitemap/sitemap.xml",
		baseURL + "/sitemaps/sitemap.xml",
	}

	sitemapResults, err := r.httpx.ProbeBulk(sitemapURLs)
	if err == nil {
		for _, httpxRes := range sitemapResults {
			if httpxRes.StatusCode == 200 {
				sitemapPath := types.Path{
					URL:         httpxRes.URL,
					Status:      httpxRes.StatusCode,
					Length:      httpxRes.ContentLength,
					Method:      "GET",
					ContentType: httpxRes.ContentType,
					Source:      "robots-sitemap",
				}
				result.Paths = append(result.Paths, sitemapPath)

				// Add sitemap as endpoint
				pathOnly := strings.TrimPrefix(httpxRes.URL, baseURL)
				endpoint := types.Endpoint{
					Path:   pathOnly,
					Type:   "sitemap",
					Source: "robots",
				}
				result.Endpoints = append(result.Endpoints, endpoint)
			}
		}
	}

	// Generate baseline and filter false positives
	err = r.fpDetector.GenerateBaseline(baseURL)
	if err == nil {
		// Only apply filtering if baseline generation succeeded
		result = r.fpDetector.FilterFalsePositives(baseURL, result)
	}

	return result, nil
}

func (r *RobotsModule) parseRobots(content string) ([]string, []string) {
	var paths []string
	var sitemaps []string

	scanner := bufio.NewScanner(strings.NewReader(content))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(strings.ToLower(line), "disallow:") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "Disallow:"))
			path = strings.TrimSpace(strings.TrimPrefix(path, "disallow:"))
			if path != "" && path != "/" {
				paths = append(paths, path)
			}
		} else if strings.HasPrefix(strings.ToLower(line), "allow:") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "Allow:"))
			path = strings.TrimSpace(strings.TrimPrefix(path, "allow:"))
			if path != "" && path != "/" {
				paths = append(paths, path)
			}
		} else if strings.HasPrefix(strings.ToLower(line), "sitemap:") {
			sitemap := strings.TrimSpace(strings.TrimPrefix(line, "Sitemap:"))
			sitemap = strings.TrimSpace(strings.TrimPrefix(sitemap, "sitemap:"))
			if sitemap != "" {
				sitemaps = append(sitemaps, sitemap)
			}
		}
	}

	return r.deduplicateStrings(paths), r.deduplicateStrings(sitemaps)
}

func (r *RobotsModule) deduplicateStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string

	for _, item := range input {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}
