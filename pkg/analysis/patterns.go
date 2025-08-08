// Package analysis provides pattern matching on discovered content
// No new HTTP requests - only analyzes already discovered content
package analysis

import (
	"regexp"
	"strings"

	"github.com/resistanceisuseless/webscope/pkg/discovery"
)

// PatternAnalyzer analyzes discovered content for patterns
type PatternAnalyzer struct {
	patterns map[string]*regexp.Regexp
}

// AnalysisResult contains the results of pattern analysis
type AnalysisResult struct {
	Secrets        []Secret
	SensitivePaths []string
	Endpoints      []string
	APIKeys        []APIKey
	Emails         []string
	Subdomains     []string
}

// Secret represents a discovered secret
type Secret struct {
	Type    string
	Value   string
	Context string
	URL     string
}

// APIKey represents a discovered API key
type APIKey struct {
	Provider string
	Key      string
	URL      string
}

// NewPatternAnalyzer creates a new pattern analyzer
func NewPatternAnalyzer() *PatternAnalyzer {
	return &PatternAnalyzer{
		patterns: initializePatterns(),
	}
}

// Analyze analyzes already discovered content - no new HTTP requests
func (p *PatternAnalyzer) Analyze(result *discovery.Result) *AnalysisResult {
	analysis := &AnalysisResult{
		Secrets:        []Secret{},
		SensitivePaths: []string{},
		Endpoints:      []string{},
		APIKeys:        []APIKey{},
		Emails:         []string{},
		Subdomains:     []string{},
	}

	// Analyze each discovered path's content
	for _, path := range result.Paths {
		// Check if path itself is sensitive
		if p.isSensitivePath(path.URL) {
			analysis.SensitivePaths = append(analysis.SensitivePaths, path.URL)
		}

		// If we have content from the HTTP client (which we do in v2)
		if path.Source == "basic" || path.Source == "standard" || path.Source == "deep" {
			// Note: In full implementation, we'd get body content from the HTTP response
			// For now, we're just analyzing the URL patterns
			if p.isAPIEndpoint(path.URL) {
				analysis.Endpoints = append(analysis.Endpoints, path.URL)
			}
		}
	}

	return analysis
}

// AnalyzeContent analyzes raw content for patterns
func (p *PatternAnalyzer) AnalyzeContent(content string, url string) *AnalysisResult {
	analysis := &AnalysisResult{
		Secrets:    []Secret{},
		APIKeys:    []APIKey{},
		Emails:     []string{},
		Subdomains: []string{},
		Endpoints:  []string{},
	}

	// Check for secrets
	if secrets := p.findSecrets(content, url); len(secrets) > 0 {
		analysis.Secrets = secrets
	}

	// Check for API keys
	if apiKeys := p.findAPIKeys(content, url); len(apiKeys) > 0 {
		analysis.APIKeys = apiKeys
	}

	// Extract emails
	if emails := p.findEmails(content); len(emails) > 0 {
		analysis.Emails = emails
	}

	// Extract subdomains
	if subdomains := p.findSubdomains(content); len(subdomains) > 0 {
		analysis.Subdomains = subdomains
	}

	// Extract JavaScript endpoints
	if strings.Contains(content, "api/") || strings.Contains(content, "/v1/") || strings.Contains(content, "/v2/") {
		endpoints := p.extractJSEndpoints(content)
		analysis.Endpoints = endpoints
	}

	return analysis
}

func (p *PatternAnalyzer) isSensitivePath(url string) bool {
	sensitivePaths := []string{
		".env", ".git", ".svn", "config", "backup", "admin", "debug",
		"swagger", "api-docs", "graphql", "phpmyadmin", "wp-admin",
		".htaccess", ".htpasswd", "web.config", "database", "dump",
		"private", "secret", "token", "key", "password", "passwd",
	}

	lowerURL := strings.ToLower(url)
	for _, sensitive := range sensitivePaths {
		if strings.Contains(lowerURL, sensitive) {
			return true
		}
	}
	return false
}

func (p *PatternAnalyzer) isAPIEndpoint(url string) bool {
	apiPatterns := []string{
		"/api/", "/v1/", "/v2/", "/v3/",
		"/rest/", "/graphql", "/query",
		"/oauth/", "/auth/", "/token",
		"/webhook", "/callback",
	}

	lowerURL := strings.ToLower(url)
	for _, pattern := range apiPatterns {
		if strings.Contains(lowerURL, pattern) {
			return true
		}
	}
	return false
}

func (p *PatternAnalyzer) findSecrets(content string, url string) []Secret {
	var secrets []Secret

	// AWS Keys
	if match := p.patterns["aws_access_key"].FindString(content); match != "" {
		secrets = append(secrets, Secret{
			Type:    "AWS Access Key",
			Value:   match,
			Context: extractContext(content, match),
			URL:     url,
		})
	}

	// Private Keys
	if strings.Contains(content, "-----BEGIN RSA PRIVATE KEY-----") ||
		strings.Contains(content, "-----BEGIN PRIVATE KEY-----") {
		secrets = append(secrets, Secret{
			Type:    "Private Key",
			Value:   "[REDACTED]",
			Context: "Private key found in content",
			URL:     url,
		})
	}

	// JWT Tokens
	if match := p.patterns["jwt"].FindString(content); match != "" {
		secrets = append(secrets, Secret{
			Type:    "JWT Token",
			Value:   match[:20] + "...", // Only show beginning
			Context: extractContext(content, match),
			URL:     url,
		})
	}

	return secrets
}

func (p *PatternAnalyzer) findAPIKeys(content string, url string) []APIKey {
	var apiKeys []APIKey

	apiKeyPatterns := map[string]string{
		"github":  "ghp_[a-zA-Z0-9]{36}",
		"slack":   "xox[baprs]-[0-9]{10,12}-[a-zA-Z0-9]{24}",
		"stripe":  "sk_live_[a-zA-Z0-9]{24}",
		"mailgun": "key-[a-zA-Z0-9]{32}",
	}

	for provider, pattern := range apiKeyPatterns {
		if re, err := regexp.Compile(pattern); err == nil {
			if match := re.FindString(content); match != "" {
				apiKeys = append(apiKeys, APIKey{
					Provider: provider,
					Key:      match[:10] + "...", // Redact most of the key
					URL:      url,
				})
			}
		}
	}

	return apiKeys
}

func (p *PatternAnalyzer) findEmails(content string) []string {
	var emails []string
	emailPattern := p.patterns["email"]
	matches := emailPattern.FindAllString(content, -1)

	// Deduplicate
	seen := make(map[string]bool)
	for _, email := range matches {
		if !seen[email] {
			emails = append(emails, email)
			seen[email] = true
		}
	}

	return emails
}

func (p *PatternAnalyzer) findSubdomains(content string) []string {
	var subdomains []string
	// Simple subdomain extraction - would be more sophisticated in production
	subdomainPattern := p.patterns["subdomain"]
	matches := subdomainPattern.FindAllString(content, -1)

	// Deduplicate
	seen := make(map[string]bool)
	for _, subdomain := range matches {
		if !seen[subdomain] {
			subdomains = append(subdomains, subdomain)
			seen[subdomain] = true
		}
	}

	return subdomains
}

func (p *PatternAnalyzer) extractJSEndpoints(content string) []string {
	var endpoints []string

	// Simple endpoint extraction from JavaScript
	// In production, would use jsluice or similar
	patterns := []string{
		`["'](/api/[^"']+)["']`,
		`["'](/v[0-9]/[^"']+)["']`,
		`fetch\(["']([^"']+)["']`,
		`axios\.[a-z]+\(["']([^"']+)["']`,
	}

	for _, pattern := range patterns {
		if re, err := regexp.Compile(pattern); err == nil {
			matches := re.FindAllStringSubmatch(content, -1)
			for _, match := range matches {
				if len(match) > 1 {
					endpoints = append(endpoints, match[1])
				}
			}
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, endpoint := range endpoints {
		if !seen[endpoint] {
			unique = append(unique, endpoint)
			seen[endpoint] = true
		}
	}

	return unique
}

func initializePatterns() map[string]*regexp.Regexp {
	patterns := make(map[string]*regexp.Regexp)

	// Compile common patterns
	patternDefs := map[string]string{
		"aws_access_key": "AKIA[0-9A-Z]{16}",
		"jwt":            "eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*",
		"email":          "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",
		"subdomain":      "[a-z0-9]+[.][a-z0-9.-]+[.][a-z]{2,}",
		"ip_address":     "\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b",
	}

	for name, pattern := range patternDefs {
		if re, err := regexp.Compile(pattern); err == nil {
			patterns[name] = re
		}
	}

	return patterns
}

func extractContext(content string, match string) string {
	index := strings.Index(content, match)
	if index == -1 {
		return ""
	}

	start := index - 50
	if start < 0 {
		start = 0
	}

	end := index + len(match) + 50
	if end > len(content) {
		end = len(content)
	}

	return "..." + content[start:end] + "..."
}