package modules

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/types"
)

type RobotsModule struct {
	client *http.Client
}

func NewRobotsModule(timeout time.Duration) *RobotsModule {
	return &RobotsModule{
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (r *RobotsModule) Name() string {
	return "robots"
}

func (r *RobotsModule) Priority() int {
	return 2
}

func (r *RobotsModule) Discover(target types.Target) (*types.DiscoveryResult, error) {
	result := &types.DiscoveryResult{
		Paths:     []types.Path{},
		Endpoints: []types.Endpoint{},
	}

	robotsURL := strings.TrimSuffix(target.URL, "/") + "/robots.txt"
	
	req, err := http.NewRequest("GET", robotsURL, nil)
	if err != nil {
		return result, fmt.Errorf("error creating robots.txt request: %v", err)
	}

	req.Header.Set("User-Agent", "WebScope/1.0")

	resp, err := r.client.Do(req)
	if err != nil {
		return result, fmt.Errorf("error fetching robots.txt: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return result, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, fmt.Errorf("error reading robots.txt: %v", err)
	}

	paths, sitemaps := r.parseRobots(string(body))

	robotsPath := types.Path{
		URL:         robotsURL,
		Status:      resp.StatusCode,
		Length:      len(body),
		Method:      "GET",
		ContentType: resp.Header.Get("Content-Type"),
		Source:      "robots",
	}
	result.Paths = append(result.Paths, robotsPath)

	for _, path := range paths {
		if path != "" && path != "/" {
			fullURL := strings.TrimSuffix(target.URL, "/") + path
			endpoint := types.Endpoint{
				Path:   path,
				Type:   "robots-disallow",
				Source: "robots",
			}
			result.Endpoints = append(result.Endpoints, endpoint)
			
			pathResult := types.Path{
				URL:    fullURL,
				Source: "robots-disallow",
			}
			result.Paths = append(result.Paths, pathResult)
		}
	}

	for _, sitemap := range sitemaps {
		if sitemap != "" {
			endpoint := types.Endpoint{
				Path:   sitemap,
				Type:   "sitemap",
				Source: "robots",
			}
			result.Endpoints = append(result.Endpoints, endpoint)
			
			if strings.HasPrefix(sitemap, "http") {
				pathResult := types.Path{
					URL:    sitemap,
					Source: "robots-sitemap",
				}
				result.Paths = append(result.Paths, pathResult)
			} else {
				fullURL := strings.TrimSuffix(target.URL, "/") + sitemap
				pathResult := types.Path{
					URL:    fullURL,
					Source: "robots-sitemap",
				}
				result.Paths = append(result.Paths, pathResult)
			}
		}
	}

	return result, nil
}

func (r *RobotsModule) parseRobots(content string) ([]string, []string) {
	var paths []string
	var sitemaps []string
	
	scanner := bufio.NewScanner(strings.NewReader(content))
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		if strings.HasPrefix(strings.ToLower(line), "disallow:") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "Disallow:"))
			path = strings.TrimSpace(strings.TrimPrefix(path, "disallow:"))
			if path != "" && path != "/" {
				paths = append(paths, path)
			}
		} else if strings.HasPrefix(strings.ToLower(line), "allow:") {
			path := strings.TrimSpace(strings.TrimPrefix(line, "Allow:"))
			path = strings.TrimSpace(strings.TrimPrefix(path, "allow:"))
			if path != "" && path != "/" {
				paths = append(paths, path)
			}
		} else if strings.HasPrefix(strings.ToLower(line), "sitemap:") {
			sitemap := strings.TrimSpace(strings.TrimPrefix(line, "Sitemap:"))
			sitemap = strings.TrimSpace(strings.TrimPrefix(sitemap, "sitemap:"))
			if sitemap != "" {
				sitemaps = append(sitemaps, sitemap)
			}
		}
	}
	
	return r.deduplicateStrings(paths), r.deduplicateStrings(sitemaps)
}

func (r *RobotsModule) deduplicateStrings(input []string) []string {
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