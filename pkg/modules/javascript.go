package modules

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/BishopFox/jsluice"
	"github.com/resistanceisuseless/webscope/pkg/config"
	"github.com/resistanceisuseless/webscope/pkg/types"
)

type JavaScriptModule struct {
	httpx         *HTTPXModule
	urlRegex      *regexp.Regexp
	secretRegex   *regexp.Regexp
	endpointRegex *regexp.Regexp
	analyzer      *jsluice.Analyzer
	config        *config.JSluiceConfig
	customRegexes map[string][]*regexp.Regexp
}

func NewJavaScriptModule(timeout time.Duration, jsConfig *config.JSluiceConfig) *JavaScriptModule {
	j := &JavaScriptModule{
		httpx: NewHTTPXModule(30, timeout, 50), // Higher threads for JS file discovery
		// Default regex patterns for fallback analysis
		urlRegex:      regexp.MustCompile(`["'\x60](https?://[^"'\x60\s]+)["'\x60]`),
		secretRegex:   regexp.MustCompile(`(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*["'\x60]([^"'\x60\s]{8,})["'\x60]`),
		endpointRegex: regexp.MustCompile(`["'\x60]/(api/[^"'\x60\s]+)["'\x60]`),
		analyzer:      nil, // Will be created per-analysis
		config:        jsConfig,
		customRegexes: make(map[string][]*regexp.Regexp),
	}

	// Compile custom regex patterns from config
	if jsConfig != nil && jsConfig.Patterns.URLs != nil {
		for _, pattern := range jsConfig.Patterns.URLs {
			if re, err := regexp.Compile(pattern); err == nil {
				j.customRegexes["urls"] = append(j.customRegexes["urls"], re)
			}
		}
	}

	if jsConfig != nil && jsConfig.Patterns.Secrets != nil {
		for _, pattern := range jsConfig.Patterns.Secrets {
			if re, err := regexp.Compile(pattern); err == nil {
				j.customRegexes["secrets"] = append(j.customRegexes["secrets"], re)
			}
		}
	}

	if jsConfig != nil && jsConfig.Patterns.Endpoints != nil {
		for _, pattern := range jsConfig.Patterns.Endpoints {
			if re, err := regexp.Compile(pattern); err == nil {
				j.customRegexes["endpoints"] = append(j.customRegexes["endpoints"], re)
			}
		}
	}

	return j
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
	
	// Use httpx to validate JavaScript files
	httpxResults, err := j.httpx.ProbeBulk(jsFiles)
	if err != nil {
		return result, err
	}
	
	// Process only valid JavaScript files
	for _, httpxResult := range httpxResults {
		if httpxResult.StatusCode == 200 {
			// Check if it's actually JavaScript
			if strings.Contains(strings.ToLower(httpxResult.ContentType), "javascript") || 
			   strings.Contains(strings.ToLower(httpxResult.ContentType), "application/x-javascript") ||
			   strings.Contains(httpxResult.URL, ".js") {
				
				// Record the JS file itself as a discovered path
				jsPath := types.Path{
					URL:         httpxResult.URL,
					Status:      httpxResult.StatusCode,
					Length:      httpxResult.ContentLength,
					Method:      "GET",
					ContentType: httpxResult.ContentType,
					Source:      "javascript-discovery",
				}
				result.Paths = append(result.Paths, jsPath)
				
				// Since httpx doesn't return body content, we'll analyze based on common patterns
				// Add the JS file URL as a potential endpoint source
				pathOnly := j.extractPath(httpxResult.URL, target.URL)
				endpoint := types.Endpoint{
					Path:   pathOnly,
					Type:   "javascript-file",
					Method: "GET",
					Source: "javascript",
				}
				result.Endpoints = append(result.Endpoints, endpoint)
			}
		}
	}

	// Discover common API endpoints and patterns based on found JS files
	if len(result.Paths) > 0 {
		apiPatterns := j.generateCommonAPIPatterns(target.URL)
		
		// Probe API patterns
		apiResults, err := j.httpx.ProbeBulk(apiPatterns)
		if err == nil {
			for _, httpxResult := range apiResults {
				if httpxResult.StatusCode > 0 && httpxResult.StatusCode < 500 {
					path := types.Path{
						URL:         httpxResult.URL,
						Status:      httpxResult.StatusCode,
						Length:      httpxResult.ContentLength,
						Method:      "GET",
						ContentType: httpxResult.ContentType,
						Title:       httpxResult.Title,
						Source:      "javascript-api-pattern",
					}
					result.Paths = append(result.Paths, path)
					
					// Extract path for endpoint
					pathOnly := j.extractPath(httpxResult.URL, target.URL)
					endpoint := types.Endpoint{
						Path:   pathOnly,
						Type:   "api",
						Method: "GET",
						Source: "javascript",
					}
					result.Endpoints = append(result.Endpoints, endpoint)
				}
			}
		}
	}

	return result, nil
}

func (j *JavaScriptModule) findJavaScriptFiles(target types.Target) []string {
	var jsFiles []string
	baseURL := strings.TrimSuffix(target.URL, "/")
	
	// Common JavaScript file locations
	commonJS := []string{
		"/js/app.js",
		"/js/main.js",
		"/js/index.js",
		"/js/bundle.js",
		"/js/vendor.js",
		"/js/script.js",
		"/js/scripts.js",
		"/js/application.js",
		"/js/functions.js",
		"/js/common.js",
		"/js/global.js",
		"/js/utils.js",
		"/js/api.js",
		"/js/config.js",
		"/js/settings.js",
		"/assets/js/app.js",
		"/assets/js/main.js",
		"/assets/js/bundle.js",
		"/assets/javascript/application.js",
		"/static/js/main.js",
		"/static/js/app.js",
		"/static/js/bundle.js",
		"/scripts/main.js",
		"/scripts/app.js",
		"/scripts/script.js",
		"/dist/js/app.js",
		"/dist/js/main.js",
		"/dist/bundle.js",
		"/build/js/app.js",
		"/build/js/main.js",
		"/build/bundle.js",
		"/public/js/app.js",
		"/public/js/main.js",
		"/public/js/bundle.js",
		"/wp-content/themes/theme/js/main.js",
		"/wp-content/themes/theme/js/scripts.js",
		"/wp-includes/js/jquery/jquery.js",
		"/wp-includes/js/jquery/jquery.min.js",
		"/app.js",
		"/main.js",
		"/bundle.js",
		"/vendor.js",
		"/index.js",
		"/script.js",
		"/scripts.js",
	}

	// Also check for common framework-specific files
	frameworkJS := []string{
		// React
		"/static/js/main.chunk.js",
		"/static/js/bundle.js",
		"/static/js/vendors~main.chunk.js",
		// Vue
		"/js/app.js",
		"/js/chunk-vendors.js",
		// Angular
		"/main.js",
		"/polyfills.js",
		"/runtime.js",
		"/vendor.js",
		"/scripts.js",
		// Webpack
		"/dist/main.js",
		"/dist/bundle.js",
		"/dist/app.js",
		"/dist/vendor.js",
	}

	// Build full URLs
	for _, jsPath := range append(commonJS, frameworkJS...) {
		jsFiles = append(jsFiles, baseURL+jsPath)
		
		// Also try minified versions
		if !strings.HasSuffix(jsPath, ".min.js") {
			minPath := strings.Replace(jsPath, ".js", ".min.js", 1)
			jsFiles = append(jsFiles, baseURL+minPath)
		}
		
		// Try with version numbers
		for v := 1; v <= 3; v++ {
			versionedPath := strings.Replace(jsPath, ".js", fmt.Sprintf(".v%d.js", v), 1)
			jsFiles = append(jsFiles, baseURL+versionedPath)
			
			versionedPath = strings.Replace(jsPath, ".js", fmt.Sprintf("-%d.js", v), 1)
			jsFiles = append(jsFiles, baseURL+versionedPath)
		}
	}

	return j.deduplicateStrings(jsFiles)
}

func (j *JavaScriptModule) generateCommonAPIPatterns(baseURL string) []string {
	var patterns []string
	baseURL = strings.TrimSuffix(baseURL, "/")
	
	// Common API endpoints
	apiPaths := []string{
		"/api",
		"/api/v1",
		"/api/v2",
		"/api/v3",
		"/v1",
		"/v2",
		"/v3",
		"/api/users",
		"/api/user",
		"/api/auth",
		"/api/login",
		"/api/logout",
		"/api/register",
		"/api/signin",
		"/api/signup",
		"/api/account",
		"/api/profile",
		"/api/settings",
		"/api/config",
		"/api/status",
		"/api/health",
		"/api/healthcheck",
		"/api/ping",
		"/api/info",
		"/api/version",
		"/api/docs",
		"/api/swagger",
		"/api/swagger.json",
		"/api/openapi.json",
		"/api/spec",
		"/api/schema",
		"/api/graphql",
		"/graphql",
		"/api/search",
		"/api/data",
		"/api/items",
		"/api/products",
		"/api/services",
		"/api/resources",
		"/api/posts",
		"/api/comments",
		"/api/messages",
		"/api/notifications",
		"/api/events",
		"/api/analytics",
		"/api/metrics",
		"/api/logs",
		"/api/admin",
		"/api/management",
		"/api/internal",
		"/api/public",
		"/api/private",
		"/rest",
		"/rest/v1",
		"/rest/v2",
		"/rest/api",
		"/services",
		"/services/api",
		"/ajax",
		"/ajax/api",
		"/json",
		"/json/api",
		"/ws",
		"/websocket",
		"/socket.io",
	}
	
	for _, apiPath := range apiPaths {
		patterns = append(patterns, baseURL+apiPath)
		patterns = append(patterns, baseURL+apiPath+"/")
		
		// Add with common suffixes
		patterns = append(patterns, baseURL+apiPath+".json")
		patterns = append(patterns, baseURL+apiPath+"/index")
		patterns = append(patterns, baseURL+apiPath+"/endpoints")
		patterns = append(patterns, baseURL+apiPath+"/routes")
	}
	
	return j.deduplicateStrings(patterns)
}

func (j *JavaScriptModule) extractPath(fullURL, baseURL string) string {
	baseURL = strings.TrimSuffix(baseURL, "/")
	if strings.HasPrefix(fullURL, baseURL) {
		path := strings.TrimPrefix(fullURL, baseURL)
		if path == "" {
			return "/"
		}
		return path
	}
	return fullURL
}

func (j *JavaScriptModule) applyCustomRegexes(regexType string, content string) []string {
	var results []string
	seen := make(map[string]bool)

	if regexes, ok := j.customRegexes[regexType]; ok {
		for _, re := range regexes {
			matches := re.FindAllStringSubmatch(content, -1)
			for _, match := range matches {
				// Use the first capture group if available, otherwise the whole match
				var value string
				if len(match) > 1 {
					value = match[1]
				} else {
					value = match[0]
				}
				
				if !seen[value] && value != "" {
					seen[value] = true
					results = append(results, value)
				}
			}
		}
	}

	return results
}

func (j *JavaScriptModule) extractCustomSecrets(content string) []types.Secret {
	var secrets []types.Secret

	if regexes, ok := j.customRegexes["secrets"]; ok {
		for _, re := range regexes {
			matches := re.FindAllStringSubmatch(content, -1)
			for _, match := range matches {
				if len(match) > 0 {
					context := match[0]
					if len(context) > 50 {
						context = context[:50] + "..."
					}
					
					secret := types.Secret{
						Type:    "custom-pattern",
						Value:   "***REDACTED***",
						Context: context,
						Source:  "javascript-custom",
					}
					secrets = append(secrets, secret)
				}
			}
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
// - Focus on discovering JavaScript files using httpx
// - Probe common API patterns based on JS file presence
// - Use custom regex patterns for enhanced discovery
// - Complement Katana's active crawling with targeted probing
// - Note: Deep JS content analysis would require downloading files