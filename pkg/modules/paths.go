package modules

import (
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/types"
)

type PathsModule struct {
	client    *http.Client
	wordlist  []string
	smartMode bool
}

func NewPathsModule(timeout time.Duration, smartMode bool) *PathsModule {
	return &PathsModule{
		client: &http.Client{
			Timeout: timeout,
		},
		wordlist:  getDefaultWordlist(),
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
		variations := p.generateVariations(result.Paths)
		for _, variation := range variations {
			pathResult, err := p.probePath(variation)
			if err != nil {
				continue
			}

			if pathResult.Status > 0 && pathResult.Status < 400 {
				result.Paths = append(result.Paths, pathResult)
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

func (p *PathsModule) generateVariations(discoveredPaths []types.Path) []string {
	var variations []string
	
	for _, path := range discoveredPaths {
		basePath := p.extractBasePath(path.URL)
		
		variations = append(variations,
			basePath+".json",
			basePath+".xml",
			basePath+".txt",
			basePath+".bak",
			basePath+".old",
			basePath+"~",
			basePath+".orig",
			basePath+"/api",
			basePath+"/v1",
			basePath+"/admin",
		)
	}
	
	return p.deduplicateStrings(variations)
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

func getDefaultWordlist() []string {
	return []string{
		"admin",
		"api",
		"app",
		"assets",
		"backup",
		"config",
		"css",
		"dashboard",
		"data",
		"db",
		"debug",
		"docs",
		"download",
		"files",
		"home",
		"images",
		"img",
		"js",
		"json",
		"login",
		"logs",
		"manage",
		"media",
		"old",
		"panel",
		"private",
		"public",
		"scripts",
		"static",
		"test",
		"tmp",
		"upload",
		"uploads",
		"user",
		"users",
		"v1",
		"v2",
		"web",
		"www",
		"xml",
		"backup.zip",
		"config.json",
		"database.sql",
		"dump.sql",
		"settings.json",
		"web.config",
		"phpinfo.php",
		"info.php",
		"server-status",
		"server-info",
		".env",
		".git",
		".svn",
		".htaccess",
		".htpasswd",
		"crossdomain.xml",
		"clientaccesspolicy.xml",
	}
}