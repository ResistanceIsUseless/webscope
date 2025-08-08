// Package discovery implements progressive discovery flows for WebScope v2
// Flows build on each other: basic → standard → deep → analysis → crawl
package discovery

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/http"
)

// FlowType represents the type of discovery flow
type FlowType string

const (
	QuickFlow    FlowType = "quick"    // robots.txt + sitemap.xml + basic paths
	InDepthFlow  FlowType = "in-depth" // + urlfinder + katana + jsluice
	IntenseFlow  FlowType = "intense"  // + larger paths + deep katana + patterns
)

// Result represents discovery results
type Result struct {
	Target        string
	Paths         []Path
	Endpoints     []Endpoint
	Secrets       []Secret
	Findings      []Finding
	DiscoveryTime time.Duration
}

// Path represents a discovered path
type Path struct {
	URL         string
	Status      int
	Length      int
	Method      string
	ContentType string
	Title       string
	Source      string
}

// Endpoint represents a discovered endpoint
type Endpoint struct {
	Path   string
	Type   string
	Method string
	Source string
}

// Secret represents a discovered secret
type Secret struct {
	Type    string
	Value   string
	Context string
	Source  string
}

// Finding represents a pattern-based finding
type Finding struct {
	URL      string
	Type     string
	Severity string
	Details  string
}

// Flow is the interface all discovery flows must implement
type Flow interface {
	Name() string
	Execute(ctx context.Context, target string) (*Result, error)
}

// BasicDiscoveryFlow validates targets and checks common paths
type BasicDiscoveryFlow struct {
	client *http.Client
}

// NewBasicFlow creates a new basic discovery flow
func NewBasicFlow(client *http.Client) *BasicDiscoveryFlow {
	return &BasicDiscoveryFlow{
		client: client,
	}
}

func (f *BasicDiscoveryFlow) Name() string {
	return "basic"
}

func (f *BasicDiscoveryFlow) Execute(ctx context.Context, target string) (*Result, error) {
	start := time.Now()
	result := &Result{
		Target:    target,
		Paths:     []Path{},
		Endpoints: []Endpoint{},
	}

	// Step 1: Validate target is alive (2 second timeout enforced by client)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	resp, err := f.client.Get(ctx, target)
	if err != nil {
		return result, fmt.Errorf("target unreachable: %w", err)
	}

	// Add main target if successful
	if resp.StatusCode > 0 && resp.StatusCode < 500 {
		result.Paths = append(result.Paths, Path{
			URL:         resp.URL,
			Status:      resp.StatusCode,
			Method:      "GET",
			ContentType: resp.Headers.Get("Content-Type"),
			Source:      "basic",
		})
	}

	// Step 2: Check common paths (sequential, no goroutines)
	commonPaths := []string{
		"/robots.txt",
		"/sitemap.xml",
		"/.well-known/security.txt",
		"/favicon.ico",
	}

	baseURL := strings.TrimSuffix(target, "/")
	for _, path := range commonPaths {
		if ctx.Err() != nil {
			break
		}

		url := baseURL + path
		resp, err := f.client.Get(ctx, url)
		if err == nil && resp.StatusCode > 0 && resp.StatusCode < 400 {
			result.Paths = append(result.Paths, Path{
				URL:         url,
				Status:      resp.StatusCode,
				Method:      "GET",
				ContentType: resp.Headers.Get("Content-Type"),
				Source:      "basic-common",
			})

			result.Endpoints = append(result.Endpoints, Endpoint{
				Path:   path,
				Type:   "common",
				Method: "GET",
				Source: "basic",
			})
		}
	}

	result.DiscoveryTime = time.Since(start)
	return result, nil
}

// StandardDiscoveryFlow adds robots/sitemap parsing
type StandardDiscoveryFlow struct {
	basic  *BasicDiscoveryFlow
	client *http.Client
}

// NewStandardFlow creates a new standard discovery flow
func NewStandardFlow(client *http.Client) *StandardDiscoveryFlow {
	return &StandardDiscoveryFlow{
		basic:  NewBasicFlow(client),
		client: client,
	}
}

func (f *StandardDiscoveryFlow) Name() string {
	return "standard"
}

func (f *StandardDiscoveryFlow) Execute(ctx context.Context, target string) (*Result, error) {
	start := time.Now()

	// Run basic flow first
	result, err := f.basic.Execute(ctx, target)
	if err != nil {
		return result, err
	}

	baseURL := strings.TrimSuffix(target, "/")

	// Check if we found robots.txt
	for _, path := range result.Paths {
		if strings.HasSuffix(path.URL, "/robots.txt") && path.Status == 200 {
			// Get the robots.txt content
			resp, err := f.client.Get(ctx, path.URL)
			if err == nil && resp.Body != "" {
				// Parse robots.txt content
				disallowed := parseRobotsTxt(resp.Body)

				// Validate disallowed paths (with limit)
				for i, disallowedPath := range disallowed {
					if i >= 20 { // Limit to prevent explosion
						break
					}
					if ctx.Err() != nil {
						break
					}

					url := baseURL + disallowedPath
					resp, err := f.client.Get(ctx, url)
					if err == nil && resp.StatusCode > 0 && resp.StatusCode < 400 {
						result.Paths = append(result.Paths, Path{
							URL:    url,
							Status: resp.StatusCode,
							Method: "GET",
							Source: "robots",
						})
					}
				}
			}
		}

		// Check for sitemap references in robots.txt
		if strings.HasSuffix(path.URL, "/sitemap.xml") && path.Status == 200 {
			// Get the sitemap content
			resp, err := f.client.Get(ctx, path.URL)
			if err == nil && resp.Body != "" {
				// Parse sitemap content
				urls := parseSitemap(resp.Body)

				// Validate sitemap URLs (with limit)
				for i, url := range urls {
					if i >= 50 { // Limit
						break
					}
					if ctx.Err() != nil {
						break
					}

					resp, err := f.client.Get(ctx, url)
					if err == nil && resp.StatusCode > 0 && resp.StatusCode < 400 {
						result.Paths = append(result.Paths, Path{
							URL:    url,
							Status: resp.StatusCode,
							Method: "GET",
							Source: "sitemap",
						})
					}
				}
			}
		}
	}

	result.DiscoveryTime = time.Since(start)
	return result, nil
}

// DeepDiscoveryFlow adds path bruteforcing
type DeepDiscoveryFlow struct {
	standard *StandardDiscoveryFlow
	client   *http.Client
	wordlist []string
}

// NewDeepFlow creates a new deep discovery flow
func NewDeepFlow(client *http.Client, wordlist []string) *DeepDiscoveryFlow {
	if len(wordlist) == 0 {
		wordlist = getDefaultWordlist()
	}
	return &DeepDiscoveryFlow{
		standard: NewStandardFlow(client),
		client:   client,
		wordlist: wordlist,
	}
}

func (f *DeepDiscoveryFlow) Name() string {
	return "deep"
}

func (f *DeepDiscoveryFlow) Execute(ctx context.Context, target string) (*Result, error) {
	start := time.Now()

	// Run standard flow first
	result, err := f.standard.Execute(ctx, target)
	if err != nil {
		return result, err
	}

	baseURL := strings.TrimSuffix(target, "/")
	discoveredPaths := []Path{}

	// Bruteforce paths (with aggressive limits)
	for i, word := range f.wordlist {
		if i >= 100 { // Hard limit
			break
		}

		// Check context
		if ctx.Err() != nil {
			break
		}

		url := baseURL + "/" + word
		resp, err := f.client.Get(ctx, url)
		if err == nil && resp.StatusCode > 0 && resp.StatusCode < 400 {
			path := Path{
				URL:    url,
				Status: resp.StatusCode,
				Method: "GET",
				Source: "bruteforce",
			}
			result.Paths = append(result.Paths, path)
			discoveredPaths = append(discoveredPaths, path)

			result.Endpoints = append(result.Endpoints, Endpoint{
				Path:   "/" + word,
				Type:   "discovered",
				Method: "GET",
				Source: "deep",
			})
		}
	}

	// Smart permutations on discovered paths
	if len(discoveredPaths) > 0 {
		variations := generateSmartVariations(discoveredPaths, baseURL)
		
		for i, variation := range variations {
			if i >= 50 { // Limit variations
				break
			}
			if ctx.Err() != nil {
				break
			}

			resp, err := f.client.Get(ctx, variation)
			if err == nil && resp.StatusCode > 0 && resp.StatusCode < 400 {
				result.Paths = append(result.Paths, Path{
					URL:    variation,
					Status: resp.StatusCode,
					Method: "GET",
					Source: "smart-variation",
				})

				result.Endpoints = append(result.Endpoints, Endpoint{
					Path:   extractPathFromURL(variation, baseURL),
					Type:   "smart-variation",
					Method: "GET",
					Source: "deep",
				})
			}
		}
	}

	result.DiscoveryTime = time.Since(start)
	return result, nil
}

// Helper functions

func parseRobotsTxt(content string) []string {
	var disallowed []string
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Disallow:") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "Disallow:"))
			if path != "" && path != "/" {
				disallowed = append(disallowed, path)
			}
		}
	}
	return disallowed
}

func parseSitemap(content string) []string {
	var urls []string
	// Simple XML parsing for sitemap URLs
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		if strings.Contains(line, "<loc>") && strings.Contains(line, "</loc>") {
			start := strings.Index(line, "<loc>") + 5
			end := strings.Index(line, "</loc>")
			if start < end {
				url := line[start:end]
				urls = append(urls, url)
			}
		}
	}
	return urls
}

func getDefaultWordlist() []string {
	return []string{
		"admin", "api", "app", "assets", "backup", "config", "css", "dashboard",
		"data", "db", "debug", "docs", "download", "files", "home", "images",
		"img", "js", "json", "login", "logs", "manage", "media", "old", "panel",
		"private", "public", "scripts", "static", "test", "tmp", "upload",
		"uploads", "user", "users", "v1", "v2", "web", "www", "xml",
		".env", ".git", ".svn", ".htaccess", ".htpasswd", "web.config",
	}
}

// generateSmartVariations creates intelligent variations of discovered paths
func generateSmartVariations(discoveredPaths []Path, baseURL string) []string {
	var variations []string
	pathsMap := make(map[string]bool)
	
	// Extract unique paths
	for _, discoveredPath := range discoveredPaths {
		path := extractPathFromURL(discoveredPath.URL, baseURL)
		if path != "/" && path != "" {
			pathsMap[path] = true
		}
	}
	
	// Generate smart variations for each discovered path
	for path := range pathsMap {
		basePath := strings.TrimSuffix(path, "/")
		baseURL := strings.TrimSuffix(baseURL, "/")
		
		// Extension variations
		extensionVariations := []string{
			baseURL + basePath + ".json",
			baseURL + basePath + ".xml", 
			baseURL + basePath + ".txt",
			baseURL + basePath + ".html",
			baseURL + basePath + ".php",
			baseURL + basePath + ".jsp",
			baseURL + basePath + ".asp",
			baseURL + basePath + ".aspx",
		}
		variations = append(variations, extensionVariations...)
		
		// Backup variations
		backupVariations := []string{
			baseURL + basePath + ".bak",
			baseURL + basePath + ".backup", 
			baseURL + basePath + ".old",
			baseURL + basePath + ".orig",
			baseURL + basePath + "~",
			baseURL + basePath + ".save",
			baseURL + basePath + ".tmp",
		}
		variations = append(variations, backupVariations...)
		
		// Directory variations
		if !strings.HasSuffix(basePath, "/") {
			dirVariations := []string{
				baseURL + basePath + "/",
				baseURL + basePath + "/index.html",
				baseURL + basePath + "/index.php", 
				baseURL + basePath + "/default.html",
				baseURL + basePath + "/api",
				baseURL + basePath + "/admin",
				baseURL + basePath + "/config",
				baseURL + basePath + "/backup",
			}
			variations = append(variations, dirVariations...)
		}
		
		// Version variations  
		versionVariations := []string{
			baseURL + basePath + "v1",
			baseURL + basePath + "v2",
			baseURL + basePath + "/v1", 
			baseURL + basePath + "/v2",
			baseURL + basePath + "_v1",
			baseURL + basePath + "_v2",
		}
		variations = append(variations, versionVariations...)
		
		// Environment variations
		envVariations := []string{
			baseURL + basePath + "_test",
			baseURL + basePath + "_dev",
			baseURL + basePath + "_staging", 
			baseURL + basePath + "_prod",
			baseURL + basePath + "-test",
			baseURL + basePath + "-dev",
			baseURL + basePath + "-old",
			baseURL + basePath + "-new",
		}
		variations = append(variations, envVariations...)
	}
	
	return deduplicateStrings(variations)
}

// extractPathFromURL extracts the path portion from a full URL
func extractPathFromURL(fullURL, baseURL string) string {
	if strings.HasPrefix(fullURL, baseURL) {
		path := strings.TrimPrefix(fullURL, baseURL)
		if path == "" {
			return "/"
		}
		return path
	}
	return fullURL
}

// deduplicateStrings removes duplicates from a string slice
func deduplicateStrings(input []string) []string {
	seen := make(map[string]bool)
	var result []string
	
	for _, item := range input {
		if !seen[item] && item != "" {
			seen[item] = true
			result = append(result, item)
		}
	}
	
	return result
}