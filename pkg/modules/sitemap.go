package modules

import (
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/config"
	"github.com/resistanceisuseless/webscope/pkg/types"
)

type SitemapModule struct {
	httpx HTTPXInterface
}

func NewSitemapModule(timeout time.Duration) *SitemapModule {
	return &SitemapModule{
		httpx: NewHTTPXModule(20, timeout, 20), // Moderate threads for sitemap discovery
	}
}

func NewSitemapModuleWithConfig(timeout time.Duration, appConfig *config.Config) *SitemapModule {
	threads := 20
	rateLimit := 20

	if appConfig != nil {
		httpxConfig := appConfig.GetDefaultHTTPXConfig()
		if httpxConfig.Threads > 0 {
			threads = httpxConfig.Threads
		}
		if httpxConfig.RateLimit > 0 {
			rateLimit = httpxConfig.RateLimit
		}
	}

	return &SitemapModule{
		httpx: NewHTTPXModule(threads, timeout, rateLimit),
	}
}

// NewSitemapModuleWithConfigAndLibrary creates a sitemap module using httpx library
func NewSitemapModuleWithConfigAndLibrary(timeout time.Duration, appConfig *config.Config) *SitemapModule {
	threads := 20
	rateLimit := 20

	if appConfig != nil {
		httpxConfig := appConfig.GetDefaultHTTPXConfig()
		if httpxConfig.Threads > 0 {
			threads = httpxConfig.Threads
		}
		if httpxConfig.RateLimit > 0 {
			rateLimit = httpxConfig.RateLimit
		}
	}

	return &SitemapModule{
		httpx: NewHTTPXLibModule(threads, timeout, rateLimit),
	}
}

func (s *SitemapModule) Name() string {
	return "sitemap"
}

func (s *SitemapModule) Priority() int {
	return 2
}

func (s *SitemapModule) Discover(target types.Target) (*types.DiscoveryResult, error) {
	result := &types.DiscoveryResult{
		Paths:     []types.Path{},
		Endpoints: []types.Endpoint{},
	}

	baseURL := strings.TrimSuffix(target.URL, "/")

	// Try common sitemap locations
	sitemapURLs := []string{
		baseURL + "/sitemap.xml",
		baseURL + "/sitemap_index.xml",
		baseURL + "/sitemap-index.xml",
		baseURL + "/sitemaps.xml",
		baseURL + "/sitemap.xml.gz",
		baseURL + "/sitemap/sitemap.xml",
		baseURL + "/sitemaps/sitemap.xml",
		baseURL + "/sitemap1.xml",
		baseURL + "/sitemap2.xml",
		baseURL + "/sitemap-posts.xml",
		baseURL + "/sitemap-pages.xml",
		baseURL + "/sitemap-categories.xml",
		baseURL + "/sitemap-tags.xml",
		baseURL + "/sitemap-users.xml",
		baseURL + "/sitemap-images.xml",
		baseURL + "/sitemap-video.xml",
		baseURL + "/sitemap-news.xml",
		baseURL + "/sitemap-mobile.xml",
		baseURL + "/post-sitemap.xml",
		baseURL + "/page-sitemap.xml",
		baseURL + "/product-sitemap.xml",
		baseURL + "/category-sitemap.xml",
		baseURL + "/wp-sitemap.xml",
		baseURL + "/wp-sitemap-posts-post-1.xml",
		baseURL + "/wp-sitemap-posts-page-1.xml",
		baseURL + "/wp-sitemap-taxonomies-category-1.xml",
		baseURL + "/wp-sitemap-users-1.xml",
	}

	// Use httpx to bulk check sitemap URLs
	httpxResults, err := s.httpx.ProbeBulk(sitemapURLs)
	if err != nil {
		return result, err
	}

	// Process discovered sitemaps
	var foundSitemaps []string
	for _, httpxResult := range httpxResults {
		if httpxResult.StatusCode == 200 {
			// Check if it's likely an XML sitemap based on content type
			if strings.Contains(strings.ToLower(httpxResult.ContentType), "xml") ||
				strings.Contains(strings.ToLower(httpxResult.ContentType), "text/plain") ||
				strings.Contains(httpxResult.URL, ".xml") {

				// Add sitemap file itself as discovered path
				sitemapPath := types.Path{
					URL:         httpxResult.URL,
					Status:      httpxResult.StatusCode,
					Length:      httpxResult.ContentLength,
					Method:      "GET",
					ContentType: httpxResult.ContentType,
					Source:      "sitemap-file",
				}
				result.Paths = append(result.Paths, sitemapPath)

				foundSitemaps = append(foundSitemaps, httpxResult.URL)

				// Add as endpoint
				pathOnly := strings.TrimPrefix(httpxResult.URL, baseURL)
				endpoint := types.Endpoint{
					Path:   pathOnly,
					Type:   "sitemap",
					Method: "GET",
					Source: "sitemap",
				}
				result.Endpoints = append(result.Endpoints, endpoint)
			}
		}
	}

	// Download and parse each sitemap for actual URLs (up to 200 per sitemap)
	seen := make(map[string]bool)
	for _, sitemapURL := range foundSitemaps {
		xmlURLs := s.downloadAndParseXML(sitemapURL)

		var toProbe []string
		for _, u := range xmlURLs {
			if !seen[u] {
				seen[u] = true
				toProbe = append(toProbe, u)
			}
			if len(toProbe) >= 200 {
				break
			}
		}

		if len(toProbe) == 0 {
			continue
		}

		probeResults, err := s.httpx.ProbeBulk(toProbe)
		if err == nil {
			for _, httpxResult := range probeResults {
				if httpxResult.StatusCode > 0 && httpxResult.StatusCode < 400 {
					path := types.Path{
						URL:         httpxResult.URL,
						Status:      httpxResult.StatusCode,
						Length:      httpxResult.ContentLength,
						Method:      "GET",
						ContentType: httpxResult.ContentType,
						Title:       httpxResult.Title,
						Source:      "sitemap-parsed",
					}
					result.Paths = append(result.Paths, path)

					pathOnly := strings.TrimPrefix(httpxResult.URL, baseURL)
					endpoint := types.Endpoint{
						Path:   pathOnly,
						Type:   "sitemap-discovered",
						Method: "GET",
						Source: "sitemap",
					}
					result.Endpoints = append(result.Endpoints, endpoint)
				}
			}
		}
	}

	return result, nil
}

// downloadAndParseXML fetches a sitemap URL and returns all <loc> URLs found in it.
func (s *SitemapModule) downloadAndParseXML(sitemapURL string) []string {
	client := &http.Client{Timeout: 15 * time.Second}
	req, err := http.NewRequest("GET", sitemapURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; WebScope/2.0)")
	req.Header.Set("Accept", "application/xml, text/xml, */*")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil
	}

	return parseSitemapXML(string(body))
}

// parseSitemapXML extracts all <loc> values from sitemap XML content.
func parseSitemapXML(content string) []string {
	var urls []string
	seen := make(map[string]bool)

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		start := strings.Index(line, "<loc>")
		end := strings.Index(line, "</loc>")
		if start >= 0 && end > start+5 {
			u := strings.TrimSpace(line[start+5 : end])
			if u != "" && !seen[u] {
				seen[u] = true
				urls = append(urls, u)
			}
		}
	}

	return urls
}

