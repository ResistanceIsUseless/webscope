package modules

import (
	"bufio"
	"embed"
	"os"
	"strings"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/config"
	"github.com/resistanceisuseless/webscope/pkg/types"
)

type PathsModule struct {
	httpx     *HTTPXModule
	wordlist  []string
	smartMode bool
	fpDetector *FalsePositiveDetector
}

//go:embed wordlists/common-paths.txt
var wordlistFS embed.FS

func NewPathsModule(timeout time.Duration, smartMode bool, appConfig *config.Config) *PathsModule {
	// Configure httpx settings
	threads := 50
	rateLimit := 100
	
	if appConfig != nil && appConfig.HTTPX.Threads > 0 {
		threads = appConfig.HTTPX.Threads
	}
	if appConfig != nil && appConfig.HTTPX.RateLimit > 0 {
		rateLimit = appConfig.HTTPX.RateLimit
	}
	
	return &PathsModule{
		httpx:      NewHTTPXModule(threads, timeout, rateLimit),
		wordlist:   loadWordlist(appConfig),
		smartMode:  smartMode,
		fpDetector: NewFalsePositiveDetector(timeout, rateLimit),
	}
}

func (p *PathsModule) Name() string {
	return "paths"
}

func (p *PathsModule) Priority() int {
	return 3
}

func (p *PathsModule) Discover(target types.Target) (*types.DiscoveryResult, error) {
	result := &types.DiscoveryResult{
		Paths:     []types.Path{},
		Endpoints: []types.Endpoint{},
	}

	baseURL := strings.TrimSuffix(target.URL, "/")
	
	// Generate baseline for false positive detection
	err := p.fpDetector.GenerateBaseline(baseURL)
	if err != nil {
		// Continue without false positive detection if baseline generation fails
		// This ensures the module still works even if baseline fails
	}
	
	// Build URLs for all paths
	var urls []string
	for _, path := range p.wordlist {
		fullURL := baseURL + "/" + strings.TrimPrefix(path, "/")
		urls = append(urls, fullURL)
	}

	// Use httpx bulk probing
	httpxResults, err := p.httpx.ProbeBulk(urls)
	if err != nil {
		return result, err
	}

	// Process httpx results
	for _, httpxResult := range httpxResults {
		if httpxResult.StatusCode > 0 && httpxResult.StatusCode < 400 {
			path := types.Path{
				URL:         httpxResult.URL,
				Status:      httpxResult.StatusCode,
				Length:      httpxResult.ContentLength,
				Method:      "GET",
				ContentType: httpxResult.ContentType,
				Title:       httpxResult.Title,
				Source:      "paths-httpx",
			}
			result.Paths = append(result.Paths, path)
			
			// Extract path from URL
			discoveredPath := p.extractPath(httpxResult.URL, baseURL)
			endpoint := types.Endpoint{
				Path:   discoveredPath,
				Type:   "discovered",
				Method: "GET",
				Source: "paths",
			}
			result.Endpoints = append(result.Endpoints, endpoint)
		}
	}

	// Smart mode: generate variations based on discovered paths
	if p.smartMode && len(result.Paths) > 0 {
		variations := p.generateVariations(result.Paths, baseURL)
		
		// Probe variations using httpx bulk
		varHttpxResults, err := p.httpx.ProbeBulk(variations)
		if err == nil {
			for _, httpxResult := range varHttpxResults {
				if httpxResult.StatusCode > 0 && httpxResult.StatusCode < 400 {
					path := types.Path{
						URL:         httpxResult.URL,
						Status:      httpxResult.StatusCode,
						Length:      httpxResult.ContentLength,
						Method:      "GET",
						ContentType: httpxResult.ContentType,
						Title:       httpxResult.Title,
						Source:      "paths-variation",
					}
					result.Paths = append(result.Paths, path)
					
					// Add as endpoint too
					parsedURL := p.extractPath(httpxResult.URL, baseURL)
					endpoint := types.Endpoint{
						Path:   parsedURL,
						Type:   "smart-variation",
						Method: "GET",
						Source: "paths",
					}
					result.Endpoints = append(result.Endpoints, endpoint)
				}
			}
		}
	}

	// Apply false positive filtering to the final results
	filteredResult := p.fpDetector.FilterFalsePositives(baseURL, result)
	
	return filteredResult, nil
}

func (p *PathsModule) generateVariations(discoveredPaths []types.Path, baseURL string) []string {
	var variations []string
	pathsFound := make(map[string]bool)
	
	// Collect unique paths
	for _, path := range discoveredPaths {
		cleanPath := p.extractPath(path.URL, baseURL)
		if cleanPath != "/" && cleanPath != "" {
			pathsFound[cleanPath] = true
		}
	}
	
	// Generate smart variations based on found paths
	for foundPath := range pathsFound {
		basePath := strings.TrimSuffix(foundPath, "/")
		baseURL := strings.TrimSuffix(baseURL, "/")
		
		// Extension variations
		variations = append(variations,
			baseURL+basePath+".json",
			baseURL+basePath+".xml", 
			baseURL+basePath+".txt",
			baseURL+basePath+".html",
			baseURL+basePath+".php",
			baseURL+basePath+".jsp",
			baseURL+basePath+".asp",
			baseURL+basePath+".aspx",
		)
		
		// Backup variations
		variations = append(variations,
			baseURL+basePath+".bak",
			baseURL+basePath+".backup",
			baseURL+basePath+".old",
			baseURL+basePath+".orig",
			baseURL+basePath+"~",
			baseURL+basePath+".save",
			baseURL+basePath+".tmp",
		)
		
		// Directory variations
		if !strings.HasSuffix(basePath, "/") {
			variations = append(variations,
				baseURL+basePath+"/",
				baseURL+basePath+"/index.html",
				baseURL+basePath+"/index.php",
				baseURL+basePath+"/default.html",
				baseURL+basePath+"/api",
				baseURL+basePath+"/admin",
				baseURL+basePath+"/config",
				baseURL+basePath+"/backup",
			)
		}
		
		// Version variations
		variations = append(variations,
			baseURL+basePath+"v1",
			baseURL+basePath+"v2", 
			baseURL+basePath+"/v1",
			baseURL+basePath+"/v2",
			baseURL+basePath+"_v1",
			baseURL+basePath+"_v2",
		)
		
		// Common suffixes
		variations = append(variations,
			baseURL+basePath+"_test",
			baseURL+basePath+"_dev",
			baseURL+basePath+"_staging",
			baseURL+basePath+"_prod",
			baseURL+basePath+"-test",
			baseURL+basePath+"-dev",
			baseURL+basePath+"-old",
			baseURL+basePath+"-new",
		)
	}
	
	return p.deduplicateStrings(variations)
}

func (p *PathsModule) extractPath(fullURL, baseURL string) string {
	if strings.HasPrefix(fullURL, baseURL) {
		path := strings.TrimPrefix(fullURL, baseURL)
		if path == "" {
			return "/"
		}
		return path
	}
	return fullURL
}

func (p *PathsModule) deduplicateStrings(input []string) []string {
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

func loadWordlist(appConfig *config.Config) []string {
	var wordlist []string
	
	// Try to load from custom wordlist path first
	if appConfig != nil {
		if customPath := appConfig.GetCustomWordlistPath(); customPath != "" {
			if data, err := os.ReadFile(customPath); err == nil {
				scanner := bufio.NewScanner(strings.NewReader(string(data)))
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line != "" && !strings.HasPrefix(line, "#") {
						wordlist = append(wordlist, line)
					}
				}
				if len(wordlist) > 0 {
					return wordlist
				}
			}
		}
	}
	
	// Try to load from embedded wordlist
	if data, err := wordlistFS.ReadFile("wordlists/common-paths.txt"); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				wordlist = append(wordlist, line)
			}
		}
	}
	
	// Fallback to default wordlist if file loading fails
	if len(wordlist) == 0 {
		wordlist = getDefaultWordlist()
	}
	
	return wordlist
}

func getDefaultWordlist() []string {
	return []string{
		"admin", "api", "app", "assets", "backup", "config", "css", "dashboard",
		"data", "db", "debug", "docs", "download", "files", "home", "images",
		"img", "js", "json", "login", "logs", "manage", "media", "old", "panel",
		"private", "public", "scripts", "static", "test", "tmp", "upload",
		"uploads", "user", "users", "v1", "v2", "web", "www", "xml",
		"robots.txt", "sitemap.xml", "favicon.ico", ".well-known/security.txt",
		".env", ".git", ".svn", ".htaccess", ".htpasswd", "web.config",
	}
}