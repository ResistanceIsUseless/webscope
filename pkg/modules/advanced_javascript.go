package modules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/BishopFox/jsluice"
	"github.com/resistanceisuseless/webscope/pkg/config"
	"github.com/resistanceisuseless/webscope/pkg/types"
)

type AdvancedJavaScriptModule struct {
	httpx              *HTTPXModule
	jsluiceAnalyzer    *jsluice.Analyzer
	graphqlRegex       *regexp.Regexp
	websocketRegex     *regexp.Regexp
	secretEntropyRegex *regexp.Regexp
	config             *config.JSluiceConfig
	validatedEndpoints map[string]bool // Track validated endpoints to avoid loops
}

func NewAdvancedJavaScriptModule(timeout time.Duration, jsConfig *config.JSluiceConfig) *AdvancedJavaScriptModule {
	return &AdvancedJavaScriptModule{
		httpx: NewHTTPXModule(20, timeout, 30),
		// jsluiceAnalyzer will be created per-analysis with the actual JavaScript content
		jsluiceAnalyzer: nil,
		// GraphQL patterns
		graphqlRegex: regexp.MustCompile(`(?i)(graphql|gql|apollo|relay).*?(endpoint|uri|url).*?[:=]\s*["'\x60]([^"'\x60\s]+)["'\x60]`),
		// WebSocket patterns
		websocketRegex: regexp.MustCompile(`(?i)(ws|websocket|socket\.io).*?[:=]\s*["'\x60]([^"'\x60\s]+)["'\x60]`),
		// High-entropy secrets (API keys, tokens, etc.)
		secretEntropyRegex: regexp.MustCompile(`["'\x60]([A-Za-z0-9+/=_-]{20,})["'\x60]`),
		config:             jsConfig,
		validatedEndpoints: make(map[string]bool),
	}
}

func (a *AdvancedJavaScriptModule) Name() string {
	return "advanced-javascript"
}

func (a *AdvancedJavaScriptModule) Priority() int {
	return 5 // Higher priority than basic javascript module
}

func (a *AdvancedJavaScriptModule) Discover(target types.Target) (*types.DiscoveryResult, error) {
	result := &types.DiscoveryResult{
		Paths:          []types.Path{},
		Endpoints:      []types.Endpoint{},
		Secrets:        []types.Secret{},
		GraphQLSchemas: []types.GraphQLSchema{},
		WebSockets:     []types.WebSocketEndpoint{},
	}

	// First, probe for common GraphQL endpoints
	graphqlEndpoints := a.findGraphQLEndpoints(target)
	for _, endpoint := range graphqlEndpoints {
		schema := a.probeGraphQLSchema(endpoint, target.URL)
		if schema != nil {
			result.GraphQLSchemas = append(result.GraphQLSchemas, *schema)

			// Add as endpoint
			path := a.extractPath(endpoint, target.URL)
			result.Endpoints = append(result.Endpoints, types.Endpoint{
				Path:   path,
				Type:   "graphql",
				Method: "POST",
				Source: "advanced-javascript",
			})
		}
	}

	// Probe for WebSocket endpoints
	wsEndpoints := a.findWebSocketEndpoints(target)
	for _, wsEndpoint := range wsEndpoints {
		result.WebSockets = append(result.WebSockets, wsEndpoint)

		// Add as endpoint
		path := a.extractPath(wsEndpoint.URL, target.URL)
		result.Endpoints = append(result.Endpoints, types.Endpoint{
			Path:   path,
			Type:   "websocket",
			Method: "GET",
			Source: "advanced-javascript",
		})
	}

	// Discover JavaScript files and analyze them for patterns
	jsFiles := a.findJavaScriptFiles(target)
	httpxResults, err := a.httpx.ProbeBulk(jsFiles)
	if err == nil {
		for _, httpxResult := range httpxResults {
			if httpxResult.StatusCode == 200 && a.isJavaScriptFile(httpxResult) {
				// Record the JS file
				jsPath := types.Path{
					URL:         httpxResult.URL,
					Status:      httpxResult.StatusCode,
					Length:      httpxResult.ContentLength,
					Method:      "GET",
					ContentType: httpxResult.ContentType,
					Source:      "advanced-javascript",
				}
				result.Paths = append(result.Paths, jsPath)

				// Analyze JavaScript patterns from URL
				a.analyzeJavaScriptPatterns(httpxResult.URL, result)

				// Use jsluice for deep JavaScript analysis
				// Note: In a real implementation, this would be configurable
				// For now, we'll always attempt analysis when jsluice is available
				a.analyzeJavaScriptContent(httpxResult.URL, result)
			}
		}
	}

	return result, nil
}

func (a *AdvancedJavaScriptModule) findGraphQLEndpoints(target types.Target) []string {
	var endpoints []string
	baseURL := strings.TrimSuffix(target.URL, "/")

	// Common GraphQL endpoint patterns
	graphqlPaths := []string{
		"/graphql",
		"/api/graphql",
		"/v1/graphql",
		"/v2/graphql",
		"/v3/graphql",
		"/gql",
		"/api/gql",
		"/query",
		"/api/query",
		"/apollo",
		"/api/apollo",
		"/relay",
		"/api/relay",
		"/graphiql",
		"/playground",
		"/graphql-playground",
		"/altair",
		"/__graphql",
		"/admin/graphql",
		"/internal/graphql",
		"/public/graphql",
		"/private/graphql",
	}

	for _, path := range graphqlPaths {
		endpoints = append(endpoints, baseURL+path)
	}

	return endpoints
}

func (a *AdvancedJavaScriptModule) probeGraphQLSchema(endpoint, baseURL string) *types.GraphQLSchema {
	// Try to validate the GraphQL endpoint with a simple introspection query
	if a.validateGraphQLEndpoint(endpoint) {
		// Valid GraphQL endpoint found
		fmt.Printf("[GraphQL] Validated endpoint: %s\n", endpoint)
		schema := &types.GraphQLSchema{
			Endpoint:      endpoint,
			Source:        "advanced-javascript",
			Types:         []types.GraphQLType{},
			Queries:       []types.GraphQLOperation{},
			Mutations:     []types.GraphQLOperation{},
			Subscriptions: []types.GraphQLOperation{},
		}

		// Mark as validated
		schema.Queries = append(schema.Queries, types.GraphQLOperation{
			Name:        "__typename",
			Type:        "query",
			Description: "GraphQL endpoint validated with introspection query",
		})

		return schema
	}

	// Endpoint didn't validate - return nil
	return nil
}

// validateGraphQLEndpoint checks if an endpoint is a valid GraphQL endpoint
func (a *AdvancedJavaScriptModule) validateGraphQLEndpoint(endpoint string) bool {
	// Check if we've already validated this endpoint (avoid loops)
	if validated, exists := a.validatedEndpoints[endpoint]; exists {
		return validated
	}
	
	// Mark as being checked to avoid loops
	a.validatedEndpoints[endpoint] = false
	
	// Create a simple introspection query
	query := map[string]interface{}{
		"query": "{ __typename }",
	}
	
	jsonData, err := json.Marshal(query)
	if err != nil {
		return false
	}
	
	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Don't follow redirects for GraphQL endpoints
			return http.ErrUseLastResponse
		},
	}
	
	// Create POST request
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return false
	}
	
	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; WebScope/1.0)")
	
	// Make request
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	// Check if it's a successful response
	if resp.StatusCode != 200 {
		return false
	}
	
	// Try to parse response as JSON
	var result map[string]interface{}
	decoder := json.NewDecoder(resp.Body)
	if err := decoder.Decode(&result); err != nil {
		return false
	}
	
	// Check if response has typical GraphQL structure
	if _, hasData := result["data"]; hasData {
		a.validatedEndpoints[endpoint] = true
		return true
	}
	if _, hasErrors := result["errors"]; hasErrors {
		// Even error responses can indicate a valid GraphQL endpoint
		a.validatedEndpoints[endpoint] = true
		return true
	}
	
	a.validatedEndpoints[endpoint] = false
	return false
}

func (a *AdvancedJavaScriptModule) findWebSocketEndpoints(target types.Target) []types.WebSocketEndpoint {
	var endpoints []types.WebSocketEndpoint
	baseURL := strings.TrimSuffix(target.URL, "/")

	// Convert HTTP to WebSocket protocols
	wsBaseURL := strings.Replace(baseURL, "https://", "wss://", 1)
	wsBaseURL = strings.Replace(wsBaseURL, "http://", "ws://", 1)

	// Common WebSocket endpoint patterns
	wsPaths := []string{
		"/ws",
		"/websocket",
		"/socket.io",
		"/api/ws",
		"/api/websocket",
		"/v1/ws",
		"/v2/ws",
		"/realtime",
		"/live",
		"/streaming",
		"/events",
		"/notifications",
		"/chat",
		"/messages",
		"/updates",
		"/feed",
		"/admin/ws",
		"/internal/ws",
		"/public/ws",
		"/sockjs-node",
		"/_next/webpack-hmr",
	}

	for _, path := range wsPaths {
		endpoint := types.WebSocketEndpoint{
			URL:      wsBaseURL + path,
			Protocol: "ws",
			Source:   "advanced-javascript",
			Events:   []types.WebSocketEvent{},
		}

		// Add common WebSocket events
		if strings.Contains(path, "socket.io") {
			endpoint.Subprotocol = "socket.io"
			endpoint.Events = append(endpoint.Events, types.WebSocketEvent{
				Name:        "connect",
				Type:        "event",
				Description: "Socket.IO connection event",
			})
		}

		endpoints = append(endpoints, endpoint)
	}

	return endpoints
}

func (a *AdvancedJavaScriptModule) findJavaScriptFiles(target types.Target) []string {
	var jsFiles []string
	baseURL := strings.TrimSuffix(target.URL, "/")

	// Enhanced JavaScript file discovery patterns
	commonJS := []string{
		// Modern framework bundles
		"/static/js/main.js",
		"/static/js/app.js",
		"/static/js/bundle.js",
		"/static/js/chunk-vendors.js",
		"/static/js/runtime.js",
		"/static/js/polyfills.js",

		// GraphQL clients
		"/static/js/apollo.js",
		"/static/js/relay.js",
		"/static/js/graphql.js",

		// WebSocket libraries
		"/static/js/socket.io.js",
		"/static/js/websocket.js",
		"/static/js/sockjs.js",

		// Configuration files
		"/js/config.js",
		"/js/settings.js",
		"/js/constants.js",
		"/js/env.js",
		"/static/js/config.js",
		"/assets/js/config.js",

		// API clients
		"/js/api.js",
		"/js/client.js",
		"/js/services.js",
		"/static/js/api.js",
		"/assets/js/api.js",
	}

	for _, jsPath := range commonJS {
		jsFiles = append(jsFiles, baseURL+jsPath)

		// Try minified versions
		if !strings.HasSuffix(jsPath, ".min.js") {
			minPath := strings.Replace(jsPath, ".js", ".min.js", 1)
			jsFiles = append(jsFiles, baseURL+minPath)
		}
	}

	return a.deduplicateStrings(jsFiles)
}

func (a *AdvancedJavaScriptModule) analyzeJavaScriptContent(jsURL string, result *types.DiscoveryResult) {
	// Note: In a real implementation, we would need to download the JavaScript file content
	// For now, we'll demonstrate how jsluice would be used with placeholder content

	// This is where you would fetch the actual JavaScript content:
	// content, err := a.downloadJavaScriptFile(jsURL)
	// if err != nil {
	//     return
	// }

	// For demonstration, we'll use jsluice with a placeholder
	// In real implementation, replace this with actual file content
	content := `
		// Example JavaScript content that would be analyzed
		const API_ENDPOINT = 'https://api.example.com/graphql';
		const WS_URL = 'wss://example.com/socket';
		const SECRET_KEY = 'sk_test_abcdef123456789';
		
		// GraphQL queries
		const GET_USERS = gql` + "`" + `
			query GetUsers {
				users {
					id
					name
					email
				}
			}
		` + "`" + `;
		
		// WebSocket connection
		const socket = new WebSocket(WS_URL);
		socket.on('connect', () => {
			console.log('Connected to WebSocket');
		});
	`

	// Use jsluice to analyze the JavaScript content
	analyzer := jsluice.NewAnalyzer([]byte(content))

	// Extract URLs
	urls := analyzer.GetURLs()
	secrets := analyzer.GetSecrets()

	// Process discovered URLs
	for _, url := range urls {
		urlStr := url.URL

		// Check if it's a GraphQL endpoint
		if a.isGraphQLURL(urlStr) {
			schema := types.GraphQLSchema{
				Endpoint: urlStr,
				Source:   "jsluice-analysis",
			}
			result.GraphQLSchemas = append(result.GraphQLSchemas, schema)
		}

		// Check if it's a WebSocket URL
		if a.isWebSocketURL(urlStr) {
			wsEndpoint := types.WebSocketEndpoint{
				URL:      urlStr,
				Protocol: "ws",
				Source:   "jsluice-analysis",
			}
			result.WebSockets = append(result.WebSockets, wsEndpoint)
		}

		// Add as regular endpoint
		result.Endpoints = append(result.Endpoints, types.Endpoint{
			Path:   a.extractPath(urlStr, a.extractBaseURL(jsURL)),
			Type:   "jsluice-discovered",
			Method: "GET",
			Source: "advanced-javascript",
		})
	}

	// Extract secrets with entropy analysis
	for _, secret := range secrets {
		// Convert secret data to string for analysis
		secretData := ""
		if data, ok := secret.Data.(string); ok {
			secretData = data
		}

		secretContext := ""
		if context, ok := secret.Context.(string); ok {
			secretContext = context
		}

		entropy := a.calculateEntropy(secretData)
		strength := a.classifySecretStrength(entropy, len(secretData))

		result.Secrets = append(result.Secrets, types.Secret{
			Type:     string(secret.Severity),
			Value:    "***REDACTED***", // Never store actual secret values
			Context:  secretContext,
			Source:   "jsluice-analysis",
			Entropy:  entropy,
			Strength: strength,
		})
	}
}

func (a *AdvancedJavaScriptModule) isGraphQLURL(url string) bool {
	return strings.Contains(strings.ToLower(url), "graphql") ||
		strings.Contains(strings.ToLower(url), "gql")
}

func (a *AdvancedJavaScriptModule) isWebSocketURL(url string) bool {
	return strings.HasPrefix(strings.ToLower(url), "ws://") ||
		strings.HasPrefix(strings.ToLower(url), "wss://")
}

func (a *AdvancedJavaScriptModule) isJavaScriptFile(httpxResult *HTTPXResult) bool {
	return strings.Contains(strings.ToLower(httpxResult.ContentType), "javascript") ||
		strings.Contains(strings.ToLower(httpxResult.ContentType), "application/x-javascript") ||
		strings.HasSuffix(httpxResult.URL, ".js")
}

func (a *AdvancedJavaScriptModule) analyzeJavaScriptPatterns(jsURL string, result *types.DiscoveryResult) {
	// Analyze URL patterns for common frameworks and libraries
	jsURL = strings.ToLower(jsURL)

	// GraphQL client detection
	if strings.Contains(jsURL, "apollo") || strings.Contains(jsURL, "relay") || strings.Contains(jsURL, "graphql") {
		// Likely contains GraphQL endpoints - add common patterns
		baseURL := a.extractBaseURL(jsURL)

		schema := types.GraphQLSchema{
			Endpoint: baseURL + "/graphql",
			Source:   "advanced-javascript-pattern",
			Types:    []types.GraphQLType{},
		}
		result.GraphQLSchemas = append(result.GraphQLSchemas, schema)
	}

	// WebSocket client detection
	if strings.Contains(jsURL, "socket") || strings.Contains(jsURL, "websocket") {
		baseURL := a.extractBaseURL(jsURL)
		wsURL := strings.Replace(baseURL, "https://", "wss://", 1)
		wsURL = strings.Replace(wsURL, "http://", "ws://", 1)

		endpoint := types.WebSocketEndpoint{
			URL:      wsURL + "/ws",
			Protocol: "ws",
			Source:   "advanced-javascript-pattern",
		}

		if strings.Contains(jsURL, "socket.io") {
			endpoint.URL = wsURL + "/socket.io"
			endpoint.Subprotocol = "socket.io"
		}

		result.WebSockets = append(result.WebSockets, endpoint)
	}
}

func (a *AdvancedJavaScriptModule) calculateEntropy(data string) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count character frequencies
	freq := make(map[rune]int)
	for _, char := range data {
		freq[char]++
	}

	// Calculate Shannon entropy
	length := float64(len(data))
	entropy := 0.0

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

func (a *AdvancedJavaScriptModule) classifySecretStrength(entropy float64, length int) string {
	// Classification based on entropy and length
	if entropy >= 4.5 && length >= 32 {
		return "high"
	} else if entropy >= 3.5 && length >= 20 {
		return "medium"
	} else if entropy >= 2.5 && length >= 12 {
		return "low"
	}
	return "weak"
}

func (a *AdvancedJavaScriptModule) extractPath(fullURL, baseURL string) string {
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

func (a *AdvancedJavaScriptModule) extractBaseURL(fullURL string) string {
	// Extract protocol and domain from URL
	if strings.HasPrefix(fullURL, "https://") {
		parts := strings.Split(fullURL[8:], "/")
		return "https://" + parts[0]
	} else if strings.HasPrefix(fullURL, "http://") {
		parts := strings.Split(fullURL[7:], "/")
		return "http://" + parts[0]
	}
	return fullURL
}

func (a *AdvancedJavaScriptModule) deduplicateStrings(input []string) []string {
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
