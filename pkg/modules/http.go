package modules

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/types"
)

type HTTPModule struct {
	client     *http.Client
	timeout    time.Duration
	formRegex  *regexp.Regexp
	inputRegex *regexp.Regexp
	paramRegex *regexp.Regexp
}

func NewHTTPModule(timeout time.Duration) *HTTPModule {
	return &HTTPModule{
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		timeout:    timeout,
		formRegex:  regexp.MustCompile(`(?i)<form[^>]*action=["']([^"']*)["'][^>]*>`),
		inputRegex: regexp.MustCompile(`(?i)<input[^>]*name=["']([^"']+)["'][^>]*>`),
		paramRegex: regexp.MustCompile(`[?&]([^=&]+)=`),
	}
}

func (h *HTTPModule) Name() string {
	return "http"
}

func (h *HTTPModule) Priority() int {
	return 1
}

func (h *HTTPModule) Discover(target types.Target) (*types.DiscoveryResult, error) {
	result := &types.DiscoveryResult{
		Paths:        []types.Path{},
		Endpoints:    []types.Endpoint{},
		Technologies: []types.Technology{},
		Forms:        []types.Form{},
		Parameters:   []types.Parameter{},
	}

	req, err := http.NewRequest("GET", target.URL, nil)
	if err != nil {
		return result, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("User-Agent", "WebScope/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := h.client.Do(req)
	if err != nil {
		return result, fmt.Errorf("error making request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, fmt.Errorf("error reading response body: %v", err)
	}

	path := types.Path{
		URL:         target.URL,
		Status:      resp.StatusCode,
		Length:      len(body),
		Method:      "GET",
		ContentType: resp.Header.Get("Content-Type"),
		Source:      "http",
	}

	if title := h.extractTitle(string(body)); title != "" {
		path.Title = title
	}

	result.Paths = append(result.Paths, path)

	techs := h.identifyTechnologies(resp, body)
	result.Technologies = append(result.Technologies, techs...)

	// Analyze security headers
	securityTechs := h.analyzeSecurityHeaders(resp)
	result.Technologies = append(result.Technologies, securityTechs...)

	// Extract forms and parameters from HTML content
	forms := h.extractForms(string(body), target.URL)
	result.Forms = append(result.Forms, forms...)

	// Extract parameters from URLs
	params := h.extractParameters(target.URL)
	result.Parameters = append(result.Parameters, params...)

	commonPaths := h.discoverCommonPaths(target)
	result.Paths = append(result.Paths, commonPaths...)

	return result, nil
}

func (h *HTTPModule) extractTitle(body string) string {
	body = strings.ToLower(body)
	start := strings.Index(body, "<title>")
	if start == -1 {
		return ""
	}
	start += 7

	end := strings.Index(body[start:], "</title>")
	if end == -1 {
		return ""
	}

	title := body[start : start+end]
	title = strings.TrimSpace(title)
	if len(title) > 100 {
		title = title[:100] + "..."
	}

	return title
}

func (h *HTTPModule) identifyTechnologies(resp *http.Response, body []byte) []types.Technology {
	var technologies []types.Technology

	server := resp.Header.Get("Server")
	if server != "" {
		technologies = append(technologies, types.Technology{
			Name:     server,
			Category: "Server",
			Source:   "http-header",
		})
	}

	xPoweredBy := resp.Header.Get("X-Powered-By")
	if xPoweredBy != "" {
		technologies = append(technologies, types.Technology{
			Name:     xPoweredBy,
			Category: "Framework",
			Source:   "http-header",
		})
	}

	bodyStr := strings.ToLower(string(body))

	if strings.Contains(bodyStr, "jquery") {
		technologies = append(technologies, types.Technology{
			Name:     "jQuery",
			Category: "JavaScript Library",
			Source:   "body-content",
		})
	}

	if strings.Contains(bodyStr, "react") {
		technologies = append(technologies, types.Technology{
			Name:     "React",
			Category: "JavaScript Framework",
			Source:   "body-content",
		})
	}

	if strings.Contains(bodyStr, "angular") {
		technologies = append(technologies, types.Technology{
			Name:     "Angular",
			Category: "JavaScript Framework",
			Source:   "body-content",
		})
	}

	if strings.Contains(bodyStr, "wordpress") || strings.Contains(bodyStr, "wp-content") {
		technologies = append(technologies, types.Technology{
			Name:     "WordPress",
			Category: "CMS",
			Source:   "body-content",
		})
	}

	return technologies
}

func (h *HTTPModule) discoverCommonPaths(target types.Target) []types.Path {
	commonPaths := []string{
		"/robots.txt",
		"/sitemap.xml",
		"/favicon.ico",
		"/.well-known/security.txt",
	}

	var paths []types.Path

	for _, path := range commonPaths {
		url := strings.TrimSuffix(target.URL, "/") + path
		
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", "WebScope/1.0")

		resp, err := h.client.Do(req)
		if err != nil {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		pathResult := types.Path{
			URL:         url,
			Status:      resp.StatusCode,
			Length:      len(body),
			Method:      "GET",
			ContentType: resp.Header.Get("Content-Type"),
			Source:      "http-common",
		}

		if resp.StatusCode < 400 {
			paths = append(paths, pathResult)
		}
	}

	return paths
}

func (h *HTTPModule) extractForms(htmlContent, baseURL string) []types.Form {
	var forms []types.Form
	
	// Find all form elements with more comprehensive regex
	formRegex := regexp.MustCompile(`(?is)<form[^>]*>.*?</form>`)
	actionRegex := regexp.MustCompile(`(?i)action=["']?([^"'\s>]+)["']?`)
	methodRegex := regexp.MustCompile(`(?i)method=["']?([^"'\s>]+)["']?`)
	
	formMatches := formRegex.FindAllString(htmlContent, -1)
	
	for _, formHTML := range formMatches {
		form := types.Form{
			Action: "",
			Method: "GET", // Default method
			Inputs: []string{},
			Source: "http-form",
		}
		
		// Extract action
		if actionMatch := actionRegex.FindStringSubmatch(formHTML); len(actionMatch) > 1 {
			form.Action = actionMatch[1]
		}
		
		// Extract method
		if methodMatch := methodRegex.FindStringSubmatch(formHTML); len(methodMatch) > 1 {
			form.Method = strings.ToUpper(methodMatch[1])
		}
		
		// Extract input names
		inputMatches := h.inputRegex.FindAllStringSubmatch(formHTML, -1)
		for _, inputMatch := range inputMatches {
			if len(inputMatch) > 1 {
				form.Inputs = append(form.Inputs, inputMatch[1])
			}
		}
		
		// Also check for textarea and select elements
		textareaRegex := regexp.MustCompile(`(?i)<textarea[^>]*name=["']([^"']+)["'][^>]*>`)
		selectRegex := regexp.MustCompile(`(?i)<select[^>]*name=["']([^"']+)["'][^>]*>`)
		
		textareaMatches := textareaRegex.FindAllStringSubmatch(formHTML, -1)
		for _, match := range textareaMatches {
			if len(match) > 1 {
				form.Inputs = append(form.Inputs, match[1])
			}
		}
		
		selectMatches := selectRegex.FindAllStringSubmatch(formHTML, -1)
		for _, match := range selectMatches {
			if len(match) > 1 {
				form.Inputs = append(form.Inputs, match[1])
			}
		}
		
		// Deduplicate inputs
		form.Inputs = h.deduplicateStrings(form.Inputs)
		
		if len(form.Inputs) > 0 || form.Action != "" {
			forms = append(forms, form)
		}
	}
	
	return forms
}

func (h *HTTPModule) extractParameters(url string) []types.Parameter {
	var parameters []types.Parameter
	
	// Extract parameters from URL query string
	paramMatches := h.paramRegex.FindAllStringSubmatch(url, -1)
	for _, match := range paramMatches {
		if len(match) > 1 {
			param := types.Parameter{
				Name:   match[1],
				Type:   "url-query",
				Source: "http-url",
			}
			parameters = append(parameters, param)
		}
	}
	
	return parameters
}

func (h *HTTPModule) deduplicateStrings(input []string) []string {
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

func (h *HTTPModule) analyzeSecurityHeaders(resp *http.Response) []types.Technology {
	var technologies []types.Technology

	securityHeaders := map[string]string{
		"Content-Security-Policy":   "CSP",
		"X-Content-Type-Options":    "Content-Type Protection",
		"X-Frame-Options":           "Clickjacking Protection", 
		"X-XSS-Protection":          "XSS Protection",
		"Strict-Transport-Security": "HSTS",
		"Referrer-Policy":           "Referrer Policy",
		"Permissions-Policy":        "Permissions Policy",
		"Cross-Origin-Embedder-Policy": "COEP",
		"Cross-Origin-Opener-Policy":   "COOP",
		"Cross-Origin-Resource-Policy": "CORP",
	}

	for header, description := range securityHeaders {
		if value := resp.Header.Get(header); value != "" {
			tech := types.Technology{
				Name:     description,
				Category: "Security Header",
				Version:  value,
				Source:   "http-security-headers",
			}
			technologies = append(technologies, tech)
		}
	}

	// Check for missing security headers (potential issues)
	missingHeaders := []string{
		"Content-Security-Policy",
		"X-Content-Type-Options", 
		"X-Frame-Options",
		"Strict-Transport-Security",
	}

	for _, header := range missingHeaders {
		if resp.Header.Get(header) == "" {
			tech := types.Technology{
				Name:     "Missing " + securityHeaders[header],
				Category: "Security Issue",
				Version:  "not-set",
				Source:   "http-security-analysis",
			}
			technologies = append(technologies, tech)
		}
	}

	// CORS analysis
	if corsOrigin := resp.Header.Get("Access-Control-Allow-Origin"); corsOrigin != "" {
		tech := types.Technology{
			Name:     "CORS",
			Category: "Security Configuration",
			Version:  corsOrigin,
			Source:   "http-cors-analysis",
		}
		technologies = append(technologies, tech)

		// Check for overly permissive CORS
		if corsOrigin == "*" {
			tech := types.Technology{
				Name:     "Permissive CORS",
				Category: "Security Issue", 
				Version:  "wildcard-origin",
				Source:   "http-cors-analysis",
			}
			technologies = append(technologies, tech)
		}
	}

	return technologies
}