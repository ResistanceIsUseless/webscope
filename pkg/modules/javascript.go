package modules

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/BishopFox/jsluice"
	"github.com/resistanceisuseless/webscope/pkg/types"
)

type JavaScriptModule struct {
	client       *http.Client
	urlRegex     *regexp.Regexp
	secretRegex  *regexp.Regexp
	endpointRegex *regexp.Regexp
	analyzer     *jsluice.Analyzer
}

func NewJavaScriptModule(timeout time.Duration) *JavaScriptModule {
	return &JavaScriptModule{
		client: &http.Client{
			Timeout: timeout,
		},
		// Regex patterns for fallback analysis
		urlRegex:     regexp.MustCompile(`["'\x60](https?://[^"'\x60\s]+)["'\x60]`),
		secretRegex:  regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*["'\x60]([^"'\x60\s]{8,})["'\x60]`),
		endpointRegex: regexp.MustCompile(`["'\x60]/(api/[^"'\x60\s]+)["'\x60]`),
		analyzer:     nil, // Will be created per-analysis
	}
}

func (j *JavaScriptModule) Name() string {
	return "javascript"
}

func (j *JavaScriptModule) Priority() int {
	return 4
}

func (j *JavaScriptModule) Discover(target types.Target) (*types.DiscoveryResult, error) {
	result := &types.DiscoveryResult{
		Paths:      []types.Path{},
		Endpoints:  []types.Endpoint{},
		Secrets:    []types.Secret{},
		Parameters: []types.Parameter{},
	}

	// First, discover JavaScript files
	jsFiles := j.findJavaScriptFiles(target)
	
	// Analyze each JavaScript file
	for _, jsFile := range jsFiles {
		jsResult := j.analyzeJavaScript(jsFile)
		
		// Merge results
		result.Paths = append(result.Paths, jsResult.Paths...)
		result.Endpoints = append(result.Endpoints, jsResult.Endpoints...)
		result.Secrets = append(result.Secrets, jsResult.Secrets...)
		result.Parameters = append(result.Parameters, jsResult.Parameters...)
	}

	return result, nil
}

func (j *JavaScriptModule) findJavaScriptFiles(target types.Target) []string {
	var jsFiles []string

	// Get main page first to find script references
	req, err := http.NewRequest("GET", target.URL, nil)
	if err != nil {
		return jsFiles
	}

	req.Header.Set("User-Agent", "WebScope/1.0")
	resp, err := j.client.Do(req)
	if err != nil {
		return jsFiles
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return jsFiles
	}

	bodyStr := string(body)

	// Find script src attributes
	scriptRegex := regexp.MustCompile(`<script[^>]+src=["']([^"']+)["']`)
	matches := scriptRegex.FindAllStringSubmatch(bodyStr, -1)

	baseURL := strings.TrimSuffix(target.URL, "/")
	
	for _, match := range matches {
		if len(match) > 1 {
			scriptURL := match[1]
			
			// Convert relative URLs to absolute
			if strings.HasPrefix(scriptURL, "/") {
				scriptURL = baseURL + scriptURL
			} else if !strings.HasPrefix(scriptURL, "http") {
				scriptURL = baseURL + "/" + scriptURL
			}
			
			jsFiles = append(jsFiles, scriptURL)
		}
	}

	// Also check common JS file paths
	commonJS := []string{
		"/js/app.js",
		"/js/main.js",
		"/js/index.js",
		"/assets/js/app.js",
		"/static/js/main.js",
		"/scripts/main.js",
	}

	for _, jsPath := range commonJS {
		jsFiles = append(jsFiles, baseURL+jsPath)
	}

	return j.deduplicateStrings(jsFiles)
}

func (j *JavaScriptModule) analyzeJavaScript(jsURL string) *types.DiscoveryResult {
	result := &types.DiscoveryResult{
		Paths:      []types.Path{},
		Endpoints:  []types.Endpoint{},
		Secrets:    []types.Secret{},
		Parameters: []types.Parameter{},
	}

	// Fetch JavaScript file
	req, err := http.NewRequest("GET", jsURL, nil)
	if err != nil {
		return result
	}

	req.Header.Set("User-Agent", "WebScope/1.0")
	resp, err := j.client.Do(req)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	// Only analyze if it's actually JavaScript
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "javascript") && !strings.Contains(contentType, "application/x-javascript") {
		return result
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result
	}

	jsContent := string(body)

	// Record the JS file itself as a discovered path
	jsPath := types.Path{
		URL:         jsURL,
		Status:      resp.StatusCode,
		Length:      len(body),
		Method:      "GET",
		ContentType: contentType,
		Source:      "javascript-discovery",
	}
	result.Paths = append(result.Paths, jsPath)

	// Use jsluice for advanced analysis
	analyzer := jsluice.NewAnalyzer(body)
	
	// Extract URLs using jsluice
	jsURLs := analyzer.GetURLs()
	for _, jsURL := range jsURLs {
		endpoint := types.Endpoint{
			Path:   jsURL.URL,
			Type:   "jsluice-url",
			Source: "javascript",
		}
		result.Endpoints = append(result.Endpoints, endpoint)
	}
	
	// Extract secrets using jsluice
	jsSecrets := analyzer.GetSecrets()
	for _, jsSecret := range jsSecrets {
		context := ""
		if dataStr, ok := jsSecret.Data.(string); ok && len(dataStr) > 0 {
			context = dataStr[:min(len(dataStr), 50)] + "..."
		}
		
		secret := types.Secret{
			Type:    string(jsSecret.Kind),
			Value:   "***REDACTED***",
			Context: context,
			Source:  "javascript",
		}
		result.Secrets = append(result.Secrets, secret)
	}
	
	// Also run regex-based analysis for additional coverage
	urls := j.extractURLs(jsContent)
	for _, url := range urls {
		endpoint := types.Endpoint{
			Path:   url,
			Type:   "js-extracted",
			Source: "javascript",
		}
		result.Endpoints = append(result.Endpoints, endpoint)
	}

	endpoints := j.extractEndpoints(jsContent)
	for _, endpoint := range endpoints {
		ep := types.Endpoint{
			Path:   endpoint,
			Type:   "api",
			Source: "javascript",
		}
		result.Endpoints = append(result.Endpoints, ep)
	}

	return result
}

func (j *JavaScriptModule) extractURLs(jsContent string) []string {
	var urls []string
	matches := j.urlRegex.FindAllStringSubmatch(jsContent, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			urls = append(urls, match[1])
		}
	}
	
	return j.deduplicateStrings(urls)
}

func (j *JavaScriptModule) extractEndpoints(jsContent string) []string {
	var endpoints []string
	matches := j.endpointRegex.FindAllStringSubmatch(jsContent, -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			endpoints = append(endpoints, "/"+match[1])
		}
	}
	
	return j.deduplicateStrings(endpoints)
}

func (j *JavaScriptModule) extractSecrets(jsContent string) []types.Secret {
	var secrets []types.Secret
	matches := j.secretRegex.FindAllStringSubmatch(jsContent, -1)
	
	for _, match := range matches {
		if len(match) > 2 {
			secret := types.Secret{
				Type:   match[1],
				Value:  "***REDACTED***", // Never log actual secrets
				Context: match[0][:min(len(match[0]), 50)] + "...",
				Source: "javascript",
			}
			secrets = append(secrets, secret)
		}
	}
	
	return secrets
}

func (j *JavaScriptModule) deduplicateStrings(input []string) []string {
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// WebScope JavaScript Analysis Strategy:
// - Focus on STATIC analysis of individual JS files (not crawling)
// - Use jsluice for deep parsing of known JavaScript files
// - Extract endpoints, secrets, and parameters from JS content
// - Complement Katana's active crawling with static analysis
// - No dynamic execution or browser automation (that's Katana's job)