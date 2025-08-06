package modules

import (
	"strings"

	"github.com/resistanceisuseless/webscope/pkg/types"
)

// FindingsAggregator creates interesting findings from discovery results
type FindingsAggregator struct {
	priorityThresholds map[string][]string
}

func NewFindingsAggregator() *FindingsAggregator {
	fa := &FindingsAggregator{
		priorityThresholds: make(map[string][]string),
	}
	
	// Define which categories/patterns get which priority levels
	fa.priorityThresholds["critical"] = []string{
		"serialization", "deserialization", "java-serialized", "dotnet-serialized", "php-serialized",
		"exec-functions", "code-execution", "rce", "command-injection",
		"sql-injection", "sqli", "nosql-injection",
	}
	
	fa.priorityThresholds["high"] = []string{
		"secrets", "api-keys", "aws-keys", "google-api", "firebase",
		"passwords", "tokens", "jwt", "bearer", "access-token",
		"file-upload", "upload-param", "lfi", "rfi", "path-traversal",
		"xss", "reflected-xss", "stored-xss", "dom-xss",
		"redirect", "open-redirect", "ssrf", "server-side-request-forgery",
		"graphql", "websocket", "admin-panel", "debug-endpoint",
		"takeover", "subdomain-takeover", "cname-takeover",
	}
	
	fa.priorityThresholds["medium"] = []string{
		"disclosure", "information-disclosure", "error", "stacktrace",
		"internal-ip", "internal-hosts", "infrastructure",
		"session-id", "phpsessid", "jsessionid", "auth",
		"cors", "x-frame-options", "security-headers",
		"backup-files", "config-files", "database-files",
		"directory-listing", "index-of",
	}
	
	fa.priorityThresholds["low"] = []string{
		"versions", "server-version", "framework-version",
		"comments", "html-comments", "js-comments",
		"technology", "tech-detect", "fingerprint",
	}
	
	return fa
}

// AggregateFindings creates InterestingFinding entries from all discovery results
func (fa *FindingsAggregator) AggregateFindings(result *types.DiscoveryResult, targetURL string) []types.InterestingFinding {
	var findings []types.InterestingFinding
	
	// Process secrets as high-priority findings
	for _, secret := range result.Secrets {
		priority := fa.determinePriority(secret.Type, secret.Strength)
		
		finding := types.InterestingFinding{
			Category:    "secrets",
			Priority:    priority,
			Title:       fa.generateSecretTitle(secret),
			Description: fa.generateSecretDescription(secret),
			Evidence:    secret.Context,
			Source:      secret.Source,
			Confidence:  fa.determineConfidence(secret.Entropy, secret.Strength),
			Metadata: map[string]interface{}{
				"type":     secret.Type,
				"entropy":  secret.Entropy,
				"strength": secret.Strength,
			},
		}
		
		if secret.Context != "" {
			finding.Context = secret.Context
		}
		
		findings = append(findings, finding)
	}
	
	// Process GraphQL schemas as medium/high findings
	for _, schema := range result.GraphQLSchemas {
		finding := types.InterestingFinding{
			Category:    "graphql",
			Priority:    "high",
			Title:       "GraphQL Endpoint Discovered",
			Description: "GraphQL endpoint found with potential for introspection and schema discovery",
			URL:         schema.Endpoint,
			Source:      schema.Source,
			Confidence:  "high",
			References: []string{
				"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL",
			},
			Metadata: map[string]interface{}{
				"endpoint":      schema.Endpoint,
				"queries_count": len(schema.Queries),
				"mutations_count": len(schema.Mutations),
			},
		}
		findings = append(findings, finding)
	}
	
	// Process WebSocket endpoints
	for _, ws := range result.WebSockets {
		finding := types.InterestingFinding{
			Category:    "websocket",
			Priority:    "medium",
			Title:       "WebSocket Endpoint Discovered",
			Description: "WebSocket endpoint found - potential for real-time communication testing",
			URL:         ws.URL,
			Source:      ws.Source,
			Confidence:  "high",
			Metadata: map[string]interface{}{
				"protocol":    ws.Protocol,
				"subprotocol": ws.Subprotocol,
				"events_count": len(ws.Events),
			},
		}
		findings = append(findings, finding)
	}
	
	// Process interesting endpoints
	for _, endpoint := range result.Endpoints {
		if finding := fa.analyzeEndpoint(endpoint, targetURL); finding != nil {
			findings = append(findings, *finding)
		}
	}
	
	// Process file upload forms
	for _, form := range result.Forms {
		if fa.isFileUploadForm(form) {
			finding := types.InterestingFinding{
				Category:    "file-upload",
				Priority:    "high",
				Title:       "File Upload Form Discovered",
				Description: "Form with file upload capability found - potential for malicious file upload",
				URL:         form.Action,
				Source:      form.Source,
				Confidence:  "high",
				References: []string{
					"https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
				},
				Metadata: map[string]interface{}{
					"method": form.Method,
					"inputs": len(form.Inputs),
				},
			}
			findings = append(findings, finding)
		}
	}
	
	// Process suspicious parameters
	for _, param := range result.Parameters {
		if finding := fa.analyzeParameter(param, targetURL); finding != nil {
			findings = append(findings, *finding)
		}
	}
	
	return findings
}

func (fa *FindingsAggregator) determinePriority(secretType, strength string) string {
	// Map secret types and strengths to priorities
	secretType = strings.ToLower(secretType)
	strength = strings.ToLower(strength)
	
	// Critical secrets
	if strings.Contains(secretType, "private") || strings.Contains(secretType, "rsa") || 
	   strings.Contains(secretType, "certificate") || strength == "critical" {
		return "critical"
	}
	
	// High priority secrets
	if strength == "high" || strings.Contains(secretType, "api") || strings.Contains(secretType, "key") ||
	   strings.Contains(secretType, "token") || strings.Contains(secretType, "password") ||
	   strings.Contains(secretType, "aws") || strings.Contains(secretType, "google") {
		return "high"
	}
	
	// Medium priority
	if strength == "medium" {
		return "medium"
	}
	
	return "low"
}

func (fa *FindingsAggregator) determineConfidence(entropy float64, strength string) string {
	if entropy >= 4.5 || strength == "high" || strength == "critical" {
		return "high"
	} else if entropy >= 3.0 || strength == "medium" {
		return "medium"
	}
	return "low"
}

func (fa *FindingsAggregator) generateSecretTitle(secret types.Secret) string {
	switch strings.ToLower(secret.Type) {
	case "aws", "aws-key", "aws-access-key":
		return "AWS Access Key Detected"
	case "google", "google-api", "google-api-key":
		return "Google API Key Detected"
	case "jwt", "jwt-token":
		return "JWT Token Detected"
	case "api-key", "apikey":
		return "API Key Detected"
	case "password":
		return "Password Detected"
	case "bearer", "bearer-token":
		return "Bearer Token Detected"
	case "private-key", "rsa", "certificate":
		return "Private Key/Certificate Detected"
	default:
		return "Potential Secret Detected"
	}
}

func (fa *FindingsAggregator) generateSecretDescription(secret types.Secret) string {
	base := "Potentially sensitive information detected"
	
	if secret.Entropy > 0 {
		base += " with "
		switch {
		case secret.Entropy >= 4.5:
			base += "high entropy (likely genuine)"
		case secret.Entropy >= 3.5:
			base += "medium entropy"
		default:
			base += "low entropy"
		}
	}
	
	if secret.Strength != "" {
		base += " - " + secret.Strength + " confidence"
	}
	
	return base
}

func (fa *FindingsAggregator) analyzeEndpoint(endpoint types.Endpoint, targetURL string) *types.InterestingFinding {
	path := strings.ToLower(endpoint.Path)
	endpointType := strings.ToLower(endpoint.Type)
	
	// Admin/Debug endpoints
	if strings.Contains(path, "/admin") || strings.Contains(path, "/debug") || 
	   strings.Contains(path, "/console") || strings.Contains(path, "/management") {
		return &types.InterestingFinding{
			Category:    "admin-panel",
			Priority:    "high",
			Title:       "Administrative Endpoint Discovered",
			Description: "Potential administrative or debug endpoint found",
			URL:         endpoint.Path,
			Source:      endpoint.Source,
			Confidence:  "medium",
			Metadata: map[string]interface{}{
				"endpoint_type": endpointType,
				"method":        endpoint.Method,
			},
		}
	}
	
	// API endpoints
	if strings.Contains(path, "/api/") && (strings.Contains(path, "/v1") || 
	   strings.Contains(path, "/v2") || strings.Contains(path, "/v3")) {
		return &types.InterestingFinding{
			Category:    "api-endpoint",
			Priority:    "medium",
			Title:       "API Endpoint Discovered",
			Description: "Versioned API endpoint found - potential for further enumeration",
			URL:         endpoint.Path,
			Source:      endpoint.Source,
			Confidence:  "high",
			Metadata: map[string]interface{}{
				"endpoint_type": endpointType,
				"method":        endpoint.Method,
			},
		}
	}
	
	return nil
}

func (fa *FindingsAggregator) isFileUploadForm(form types.Form) bool {
	method := strings.ToUpper(form.Method)
	if method != "POST" {
		return false
	}
	
	for _, input := range form.Inputs {
		if strings.ToLower(input.Type) == "file" {
			return true
		}
	}
	
	// Check if action suggests file upload
	action := strings.ToLower(form.Action)
	uploadKeywords := []string{"upload", "file", "attach", "media", "document", "image", "photo"}
	for _, keyword := range uploadKeywords {
		if strings.Contains(action, keyword) {
			return true
		}
	}
	
	return false
}

func (fa *FindingsAggregator) analyzeParameter(param types.Parameter, targetURL string) *types.InterestingFinding {
	name := strings.ToLower(param.Name)
	paramType := strings.ToLower(param.Type)
	
	// SQL injection parameters
	sqlParams := []string{"id", "user", "userid", "username", "email", "name", "q", "query", "search", "filter"}
	for _, sqlParam := range sqlParams {
		if name == sqlParam {
			return &types.InterestingFinding{
				Category:    "sql-injection",
				Priority:    "high",
				Title:       "Potential SQL Injection Parameter",
				Description: "Parameter commonly vulnerable to SQL injection attacks",
				Evidence:    param.Name + "=",
				Source:      param.Source,
				Confidence:  "medium",
				References: []string{
					"https://owasp.org/www-community/attacks/SQL_Injection",
				},
				Metadata: map[string]interface{}{
					"parameter_name": param.Name,
					"parameter_type": paramType,
				},
			}
		}
	}
	
	// File inclusion parameters
	fileParams := []string{"file", "document", "doc", "path", "folder", "dir", "directory", "page", "template", "include"}
	for _, fileParam := range fileParams {
		if strings.Contains(name, fileParam) {
			return &types.InterestingFinding{
				Category:    "file-inclusion",
				Priority:    "high",
				Title:       "Potential File Inclusion Parameter",
				Description: "Parameter that may be vulnerable to local or remote file inclusion",
				Evidence:    param.Name + "=",
				Source:      param.Source,
				Confidence:  "medium",
				References: []string{
					"https://owasp.org/www-community/attacks/Path_Traversal",
				},
				Metadata: map[string]interface{}{
					"parameter_name": param.Name,
					"parameter_type": paramType,
				},
			}
		}
	}
	
	// Redirect parameters
	redirectParams := []string{"redirect", "redir", "url", "link", "goto", "next", "return", "returnto", "continue", "forward", "dest", "destination"}
	for _, redirectParam := range redirectParams {
		if strings.Contains(name, redirectParam) {
			return &types.InterestingFinding{
				Category:    "open-redirect",
				Priority:    "high",
				Title:       "Potential Open Redirect Parameter",
				Description: "Parameter that may be vulnerable to open redirect attacks",
				Evidence:    param.Name + "=",
				Source:      param.Source,
				Confidence:  "medium",
				References: []string{
					"https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet",
				},
				Metadata: map[string]interface{}{
					"parameter_name": param.Name,
					"parameter_type": paramType,
				},
			}
		}
	}
	
	return nil
}

// GetFindingsSummary creates a summary of the most important findings
func (fa *FindingsAggregator) GetFindingsSummary(findings []types.InterestingFinding) map[string]interface{} {
	summary := map[string]interface{}{
		"total_findings": len(findings),
		"by_priority":    make(map[string]int),
		"by_category":    make(map[string]int),
		"critical":       []types.InterestingFinding{},
		"high":          []types.InterestingFinding{},
	}
	
	priorityMap := summary["by_priority"].(map[string]int)
	categoryMap := summary["by_category"].(map[string]int)
	critical := summary["critical"].([]types.InterestingFinding)
	high := summary["high"].([]types.InterestingFinding)
	
	for _, finding := range findings {
		priorityMap[finding.Priority]++
		categoryMap[finding.Category]++
		
		if finding.Priority == "critical" {
			critical = append(critical, finding)
		} else if finding.Priority == "high" {
			high = append(high, finding)
		}
	}
	
	summary["critical"] = critical
	summary["high"] = high
	
	return summary
}