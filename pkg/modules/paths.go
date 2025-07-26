package modules

import (
	"bufio"
	"embed"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/config"
	"github.com/resistanceisuseless/webscope/pkg/types"
)

type PathsModule struct {
	client    *http.Client
	wordlist  []string
	smartMode bool
}

//go:embed wordlists/common-paths.txt
var wordlistFS embed.FS

func NewPathsModule(timeout time.Duration, smartMode bool, appConfig *config.Config) *PathsModule {
	return &PathsModule{
		client: &http.Client{
			Timeout: timeout,
		},
		wordlist:  loadWordlist(appConfig),
		smartMode: smartMode,
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

	for _, path := range p.wordlist {
		fullURL := baseURL + "/" + strings.TrimPrefix(path, "/")
		
		pathResult, err := p.probePath(fullURL)
		if err != nil {
			continue
		}

		if pathResult.Status > 0 && pathResult.Status < 400 {
			result.Paths = append(result.Paths, pathResult)
			
			endpoint := types.Endpoint{
				Path:   "/" + strings.TrimPrefix(path, "/"),
				Type:   "discovered",
				Method: "GET",
				Source: "paths",
			}
			result.Endpoints = append(result.Endpoints, endpoint)
		}
	}

	if p.smartMode && len(result.Paths) > 0 {
		variations := p.generateVariations(result.Paths, baseURL)
		for _, variation := range variations {
			pathResult, err := p.probePath(variation)
			if err != nil {
				continue
			}

			if pathResult.Status > 0 && pathResult.Status < 400 {
				result.Paths = append(result.Paths, pathResult)
				
				// Add as endpoint too
				parsedURL := p.extractPath(variation, baseURL)
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

	return result, nil
}

func (p *PathsModule) probePath(url string) (types.Path, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return types.Path{}, err
	}

	req.Header.Set("User-Agent", "WebScope/1.0")

	resp, err := p.client.Do(req)
	if err != nil {
		return types.Path{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return types.Path{}, err
	}

	path := types.Path{
		URL:         url,
		Status:      resp.StatusCode,
		Length:      len(body),
		Method:      "GET",
		ContentType: resp.Header.Get("Content-Type"),
		Source:      "paths",
	}

	return path, nil
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

func (p *PathsModule) extractBasePath(url string) string {
	parts := strings.Split(url, "/")
	if len(parts) > 3 {
		return strings.Join(parts[:len(parts)-1], "/")
	}
	return url
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