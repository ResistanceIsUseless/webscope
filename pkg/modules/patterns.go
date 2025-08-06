package modules

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/config"
	"github.com/resistanceisuseless/webscope/pkg/types"
)

// PatternModule detects interesting patterns in responses similar to tomnomnom's gf
type PatternModule struct {
	patterns map[string][]*CompiledPattern
	config   *config.Config
}

// CompiledPattern represents a compiled regex pattern with metadata
type CompiledPattern struct {
	Name        string
	Category    string
	Pattern     *regexp.Regexp
	Severity    string
	Description string
}

// PatternMatch represents a match found in content
type PatternMatch struct {
	Pattern     string `json:"pattern"`
	Category    string `json:"category"`
	Match       string `json:"match"`
	Context     string `json:"context"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// GfPattern represents a tomnomnom gf-style pattern file
type GfPattern struct {
	Flags    string   `json:"flags,omitempty"`
	Pattern  string   `json:"pattern,omitempty"`
	Patterns []string `json:"patterns,omitempty"`
}

func NewPatternModule(timeout time.Duration, appConfig *config.Config) *PatternModule {
	pm := &PatternModule{
		patterns: make(map[string][]*CompiledPattern),
		config:   appConfig,
	}
	
	// Load patterns from configuration
	if appConfig != nil && appConfig.Global.Patterns.CustomPatterns != nil {
		pm.loadCustomPatterns(appConfig.Global.Patterns.CustomPatterns)
	}
	
	// Load patterns from gf-style JSON files
	if appConfig != nil && appConfig.Global.Patterns.PatternsDir != "" {
		pm.loadGfPatterns(appConfig.Global.Patterns.PatternsDir)
	}
	
	// Load specific pattern files
	if appConfig != nil && appConfig.Global.Patterns.PatternsFiles != nil {
		for _, file := range appConfig.Global.Patterns.PatternsFiles {
			pm.loadGfPatternFile(file)
		}
	}
	
	// If no patterns loaded, use defaults
	if len(pm.patterns) == 0 {
		pm.loadDefaultPatterns()
	}
	
	return pm
}

func (p *PatternModule) Name() string {
	return "patterns"
}

func (p *PatternModule) Priority() int {
	return 6 // Run after other modules to analyze their findings
}

func (p *PatternModule) Discover(target types.Target) (*types.DiscoveryResult, error) {
	result := &types.DiscoveryResult{
		Secrets:    []types.Secret{},
		Parameters: []types.Parameter{},
		Endpoints:  []types.Endpoint{},
	}
	
	// Note: In a real implementation, we would analyze response bodies
	// For now, we'll analyze URLs and paths for patterns
	p.analyzeURL(target.URL, result)
	
	return result, nil
}

func (p *PatternModule) loadCustomPatterns(patterns []config.PatternRule) {
	for _, rule := range patterns {
		if rule.Enabled == false {
			continue
		}
		
		// Handle single pattern
		if rule.Pattern != "" {
			p.addPatternFromRule(rule, rule.Pattern)
		}
		
		// Handle multiple patterns
		for _, pattern := range rule.Patterns {
			p.addPatternFromRule(rule, pattern)
		}
	}
}

func (p *PatternModule) addPatternFromRule(rule config.PatternRule, pattern string) {
	compiledPattern := &CompiledPattern{
		Name:        rule.Name,
		Category:    rule.Category,
		Pattern:     regexp.MustCompile(pattern),
		Severity:    rule.Severity,
		Description: rule.Description,
	}
	
	if compiledPattern.Category == "" {
		compiledPattern.Category = "general"
	}
	if compiledPattern.Severity == "" {
		compiledPattern.Severity = "medium"
	}
	
	p.patterns[compiledPattern.Category] = append(p.patterns[compiledPattern.Category], compiledPattern)
}

func (p *PatternModule) loadGfPatterns(dir string) {
	// Expand home directory if needed
	if strings.HasPrefix(dir, "~") {
		homeDir, _ := os.UserHomeDir()
		dir = filepath.Join(homeDir, dir[1:])
	}
	
	files, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		
		p.loadGfPatternFile(filepath.Join(dir, file.Name()))
	}
}

func (p *PatternModule) loadGfPatternFile(path string) {
	// Expand home directory if needed
	if strings.HasPrefix(path, "~") {
		homeDir, _ := os.UserHomeDir()
		path = filepath.Join(homeDir, path[1:])
	}
	
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	
	var gfPattern GfPattern
	if err := json.Unmarshal(data, &gfPattern); err != nil {
		return
	}
	
	// Extract name from filename
	name := strings.TrimSuffix(filepath.Base(path), ".json")
	
	// Determine category and severity based on name
	category, severity := p.categorizePattern(name)
	
	// Handle single pattern
	if gfPattern.Pattern != "" {
		p.addPattern(name, category, gfPattern.Pattern, severity, fmt.Sprintf("Pattern from %s", name))
	}
	
	// Handle multiple patterns
	for i, pattern := range gfPattern.Patterns {
		patternName := fmt.Sprintf("%s-%d", name, i+1)
		p.addPattern(patternName, category, pattern, severity, fmt.Sprintf("Pattern from %s", name))
	}
}

func (p *PatternModule) categorizePattern(name string) (category, severity string) {
	// Default values
	category = "general"
	severity = "medium"
	
	// Categorize based on pattern name
	switch {
	case strings.Contains(name, "serializ"):
		category = "serialization"
		severity = "critical"
	case strings.Contains(name, "secret") || strings.Contains(name, "key") || strings.Contains(name, "token"):
		category = "secrets"
		severity = "high"
	case strings.Contains(name, "sql") || strings.Contains(name, "inject"):
		category = "injection"
		severity = "critical"
	case strings.Contains(name, "debug") || strings.Contains(name, "error"):
		category = "disclosure"
		severity = "medium"
	case strings.Contains(name, "upload") || strings.Contains(name, "file"):
		category = "files"
		severity = "high"
	case strings.Contains(name, "cors") || strings.Contains(name, "header"):
		category = "headers"
		severity = "medium"
	case strings.Contains(name, "takeover"):
		category = "takeover"
		severity = "high"
	case strings.Contains(name, "param"):
		category = "parameters"
		severity = "medium"
	}
	
	return category, severity
}

func (p *PatternModule) loadDefaultPatterns() {
	// AWS Keys and Secrets
	p.addPattern("aws", "secrets", `(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`, "high", "AWS Access Key ID")
	p.addPattern("aws", "secrets", `(?i)aws(.{0,20})?(?-i)['\"]?[0-9a-zA-Z\/+]{40}['\"]?`, "high", "AWS Secret Key")
	
	// API Keys
	p.addPattern("api-keys", "secrets", `(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{20,})`, "medium", "Generic API Key")
	p.addPattern("google", "secrets", `AIza[0-9A-Za-z-_]{35}`, "high", "Google API Key")
	p.addPattern("firebase", "secrets", `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`, "high", "Firebase Cloud Messaging Server Key")
	
	// Tokens
	p.addPattern("tokens", "secrets", `(?i)(access[_-]?token|auth[_-]?token)['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{20,})`, "high", "Access Token")
	p.addPattern("jwt", "secrets", `ey[A-Za-z0-9_-]{2,}\.ey[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}`, "medium", "JWT Token")
	p.addPattern("bearer", "secrets", `(?i)bearer\s+[a-zA-Z0-9_-]{20,}`, "medium", "Bearer Token")
	
	// URLs and Endpoints
	p.addPattern("urls", "endpoints", `https?://[^\s<>"{}|\\^` + "`" + `\[\]]+`, "low", "URL")
	p.addPattern("s3", "endpoints", `[a-zA-Z0-9-\.]+\.s3(?:-[a-zA-Z0-9-]+)?\.amazonaws\.com`, "medium", "S3 Bucket URL")
	p.addPattern("debug", "endpoints", `(?i)/debug|/trace|/api/debug|/console`, "medium", "Debug Endpoint")
	
	// Internal IPs and Hostnames
	p.addPattern("internal-ips", "infrastructure", `(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}`, "medium", "Internal IP Address")
	p.addPattern("internal-hosts", "infrastructure", `(?i)(?:dev|test|stage|staging|uat|internal|private)[\.-][a-zA-Z0-9-]+\.[a-zA-Z]{2,}`, "medium", "Internal Hostname")
	
	// Files and Paths
	p.addPattern("files", "files", `(?i)\.(bak|backup|old|orig|copy|tmp|temp|save|swp|swo|~)$`, "medium", "Backup File")
	p.addPattern("config", "files", `(?i)(config|conf|settings|env)\.(json|xml|yaml|yml|ini|properties)`, "high", "Configuration File")
	p.addPattern("database", "files", `(?i)\.(sql|sqlite|sqlite3|db|mdb)$`, "high", "Database File")
	
	// Interesting Parameters
	p.addPattern("sqli", "parameters", `(?i)(id|user|userid|username|email|name|q|query|search|keyword|cat|category|page|limit|offset|order|sort|filter)=`, "medium", "Potential SQL Injection Parameter")
	p.addPattern("redirect", "parameters", `(?i)(redirect|redir|url|link|goto|next|return|returnto|continue|forward|dest|destination)=`, "high", "Open Redirect Parameter")
	p.addPattern("ssrf", "parameters", `(?i)(url|uri|path|host|domain|site|fetch|proxy|load|request|callback)=`, "high", "Potential SSRF Parameter")
	p.addPattern("file", "parameters", `(?i)(file|document|doc|path|folder|dir|directory|root|include|page|template)=`, "high", "File Inclusion Parameter")
	
	// Errors and Information Disclosure
	p.addPattern("errors", "disclosure", `(?i)(exception|error|stack.?trace|traceback|debug|warning)`, "medium", "Error Message")
	p.addPattern("php-errors", "disclosure", `(?i)(Fatal error|Warning|Notice|Parse error):\s+.+\s+in\s+.+\s+on\s+line\s+\d+`, "high", "PHP Error")
	p.addPattern("sql-errors", "disclosure", `(?i)(sql|mysql|postgres|sqlite|oracle|database).{0,20}(error|exception|warning)`, "high", "SQL Error")
	
	// Version Information
	p.addPattern("versions", "disclosure", `(?i)(version|ver|v)\s*[:=]\s*['\"]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)`, "low", "Version Information")
	p.addPattern("frameworks", "disclosure", `(?i)(apache|nginx|iis|tomcat|jboss|weblogic|websphere|glassfish)\/[0-9]+\.[0-9]+`, "low", "Server Version")
	
	// Credentials
	p.addPattern("passwords", "secrets", `(?i)(password|passwd|pwd)['\"]?\s*[:=]\s*['\"]?([^'\":\s]{6,})`, "critical", "Password")
	p.addPattern("userpass", "secrets", `(?i)(user|username|email).{0,20}(pass|password)`, "high", "Username/Password Combo")
	
	// Cloud Services
	p.addPattern("azure", "cloud", `(?i)([a-z0-9]+\.blob\.core\.windows\.net|[a-z0-9]+\.file\.core\.windows\.net)`, "medium", "Azure Storage")
	p.addPattern("gcp", "cloud", `(?i)([a-z0-9-]+\.storage\.googleapis\.com|storage\.cloud\.google\.com/[a-z0-9-]+)`, "medium", "Google Cloud Storage")
	
	// Interesting Headers
	p.addPattern("cors", "headers", `(?i)access-control-allow-(origin|credentials|methods|headers)`, "medium", "CORS Header")
	p.addPattern("security", "headers", `(?i)(x-forwarded-for|x-real-ip|x-originating-ip|x-frame-options|content-security-policy)`, "low", "Security Header")
	
	// Serialized Objects - High risk for deserialization attacks
	// .NET/ASP.NET Serialized Objects
	p.addPattern("dotnet-serialized", "serialization", `AAEAAAD[/]+`, "critical", ".NET Binary Serialized Object")
	p.addPattern("dotnet-type", "serialization", `\$type\s*:\s*["'][^"']+["']`, "high", ".NET Type Hint (JSON.NET)")
	p.addPattern("dotnet-typeobject", "serialization", `TypeObject`, "high", ".NET TypeObject Reference")
	
	// Java Serialized Objects
	p.addPattern("java-serialized-hex", "serialization", `ACED0005`, "critical", "Java Serialized Object (Hex)")
	p.addPattern("java-serialized-base64", "serialization", `rO0`, "critical", "Java Serialized Object (Base64)")
	p.addPattern("java-serialized-gzip", "serialization", `H4sIA`, "critical", "Java Serialized Object (Gzipped Base64)")
	p.addPattern("java-content-type", "serialization", `application/x-java-serialized-object`, "high", "Java Serialization Content-Type")
	
	// PHP Serialized Objects
	p.addPattern("php-serialized-array", "serialization", `a:[0-9]+:\{`, "critical", "PHP Serialized Array")
	p.addPattern("php-serialized-object", "serialization", `O:[0-9]+:"[^"]+":`, "critical", "PHP Serialized Object")
	p.addPattern("php-serialized-string", "serialization", `s:[0-9]+:"`, "high", "PHP Serialized String")
	
	// Python Pickle Serialization
	p.addPattern("python-pickle", "serialization", `(c__builtin__|c__main__|cbuiltins|cmain)`, "critical", "Python Pickle Serialized Object")
	p.addPattern("python-pickle-base64", "serialization", `gASV`, "critical", "Python Pickle (Base64)")
	
	// Ruby Marshal Serialization
	p.addPattern("ruby-marshal", "serialization", `\x04\x08[\[\{IoTF]`, "critical", "Ruby Marshal Serialized Object")
	
	// Upload Fields and File Inputs
	p.addPattern("file-upload", "forms", `(?i)(type\s*=\s*["']?file["']?|multipart/form-data)`, "high", "File Upload Field")
	p.addPattern("upload-param", "parameters", `(?i)(upload|file|image|photo|attachment|document|media)=`, "high", "Upload Parameter")
	
	// Debug and Development Artifacts
	p.addPattern("debug-params", "debug", `(?i)(debug|test|testing|dev|development|stage|staging)=(true|1|on|yes)`, "high", "Debug Mode Parameter")
	p.addPattern("stacktrace", "disclosure", `(?i)(at\s+[a-zA-Z0-9_\.]+\([a-zA-Z0-9_]+\.java:[0-9]+\)|in\s+[a-zA-Z0-9_/]+\.php\s+on\s+line\s+[0-9]+)`, "high", "Stack Trace")
	
	// Authentication and Session
	p.addPattern("basic-auth", "auth", `(?i)authorization:\s*basic\s+[a-zA-Z0-9+/]+=*`, "high", "Basic Authentication Header")
	p.addPattern("session-id", "auth", `(?i)(sessionid|session_id|phpsessid|jsessionid|aspsessionid|sid)\s*=\s*[a-zA-Z0-9]+`, "medium", "Session ID")
	
	// Subdomain Takeover Indicators
	p.addPattern("cname-subdomain", "takeover", `(?i)(herokuapp\.com|github\.io|cloudfront\.net|azurewebsites\.net|blob\.core\.windows\.net)`, "high", "Potential Subdomain Takeover")
	p.addPattern("takeover-error", "takeover", `(?i)(no such app|no such bucket|bucket does not exist|there isn't a github pages site here|404 not found)`, "high", "Subdomain Takeover Error")
	
	// Interesting Functions and Sinks
	p.addPattern("exec-functions", "sinks", `(?i)(exec|system|passthru|shell_exec|eval|assert|preg_replace|create_function|include|require|include_once|require_once)\s*\(`, "critical", "Code Execution Function")
	p.addPattern("sqli-functions", "sinks", `(?i)(mysql_query|mysqli_query|pg_query|sqlite_query|odbc_exec|mssql_query|query|prepare|execute)\s*\(`, "high", "SQL Query Function")
}

func (p *PatternModule) addPattern(name, category, pattern, severity, description string) {
	compiledPattern := &CompiledPattern{
		Name:        name,
		Category:    category,
		Pattern:     regexp.MustCompile(pattern),
		Severity:    severity,
		Description: description,
	}
	
	p.patterns[category] = append(p.patterns[category], compiledPattern)
}

func (p *PatternModule) analyzeURL(url string, result *types.DiscoveryResult) {
	// Extract interesting parameters from URL
	paramRegex := regexp.MustCompile(`[?&]([^=]+)=([^&]+)`)
	matches := paramRegex.FindAllStringSubmatch(url, -1)
	
	for _, match := range matches {
		if len(match) >= 2 {
			paramName := match[1]
			paramValue := match[2]
			
			// Check if parameter name matches any interesting patterns
			for category, patterns := range p.patterns {
				if category == "parameters" {
					for _, pattern := range patterns {
						if pattern.Pattern.MatchString(paramName + "=") {
							// Add as a parameter finding
							result.Parameters = append(result.Parameters, types.Parameter{
								Name:   paramName,
								Type:   pattern.Description,
								Source: "pattern-analysis",
							})
							
							// Also add as a secret if it contains sensitive data
							if pattern.Severity == "high" || pattern.Severity == "critical" {
								result.Secrets = append(result.Secrets, types.Secret{
									Type:     pattern.Name,
									Value:    "***REDACTED***",
									Context:  paramName + "=" + maskValue(paramValue),
									Source:   "pattern-analysis",
									Strength: pattern.Severity,
								})
							}
						}
					}
				}
			}
		}
	}
	
	// Check for interesting patterns in the full URL
	for category, patterns := range p.patterns {
		for _, pattern := range patterns {
			if matches := pattern.Pattern.FindAllString(url, -1); len(matches) > 0 {
				for _, match := range matches {
					switch category {
					case "endpoints":
						// Extract just the path portion for endpoints
						if strings.Contains(match, "://") {
							result.Endpoints = append(result.Endpoints, types.Endpoint{
								Path:   extractPath(match),
								Type:   pattern.Name,
								Method: "GET",
								Source: "pattern-" + pattern.Name,
							})
						}
					case "secrets":
						result.Secrets = append(result.Secrets, types.Secret{
							Type:     pattern.Name,
							Value:    "***REDACTED***",
							Context:  getContext(url, match, 30),
							Source:   "pattern-analysis",
							Strength: pattern.Severity,
						})
					}
				}
			}
		}
	}
}

func (p *PatternModule) AnalyzeContent(content string) []PatternMatch {
	var matches []PatternMatch
	
	for category, patterns := range p.patterns {
		for _, pattern := range patterns {
			if foundMatches := pattern.Pattern.FindAllString(content, -1); len(foundMatches) > 0 {
				for _, match := range foundMatches {
					patternMatch := PatternMatch{
						Pattern:     pattern.Name,
						Category:    category,
						Match:       maskSensitiveData(match, pattern.Category),
						Context:     getContext(content, match, 50),
						Severity:    pattern.Severity,
						Description: pattern.Description,
					}
					matches = append(matches, patternMatch)
				}
			}
		}
	}
	
	return matches
}

func extractPath(url string) string {
	// Simple path extraction
	if idx := strings.Index(url, "://"); idx != -1 {
		url = url[idx+3:]
	}
	if idx := strings.Index(url, "/"); idx != -1 {
		return url[idx:]
	}
	return "/"
}

func maskValue(value string) string {
	if len(value) <= 4 {
		return "***"
	}
	return value[:2] + "***" + value[len(value)-2:]
}

func maskSensitiveData(data, category string) string {
	if category == "secrets" || category == "passwords" {
		if len(data) <= 8 {
			return "***REDACTED***"
		}
		// Show first and last few characters for reference
		return data[:4] + "***" + data[len(data)-4:]
	}
	return data
}

func getContext(content, match string, contextLen int) string {
	idx := strings.Index(content, match)
	if idx == -1 {
		return match
	}
	
	start := idx - contextLen
	if start < 0 {
		start = 0
	}
	
	end := idx + len(match) + contextLen
	if end > len(content) {
		end = len(content)
	}
	
	context := content[start:end]
	if start > 0 {
		context = "..." + context
	}
	if end < len(content) {
		context = context + "..."
	}
	
	return context
}