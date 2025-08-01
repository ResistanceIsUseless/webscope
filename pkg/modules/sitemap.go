package modules

import (
	"fmt"
	"strings"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/config"
	"github.com/resistanceisuseless/webscope/pkg/types"
)

type SitemapModule struct {
	httpx *HTTPXModule
}

func NewSitemapModule(timeout time.Duration) *SitemapModule {
	return &SitemapModule{
		httpx: NewHTTPXModule(20, timeout, 20), // Moderate threads for sitemap discovery
	}
}

func NewSitemapModuleWithConfig(timeout time.Duration, appConfig *config.Config) *SitemapModule {
	threads := 20
	rateLimit := 20
	
	if appConfig != nil && appConfig.HTTPX.Threads > 0 {
		threads = appConfig.HTTPX.Threads
	}
	if appConfig != nil && appConfig.HTTPX.RateLimit > 0 {
		rateLimit = appConfig.HTTPX.RateLimit
	}
	
	return &SitemapModule{
		httpx: NewHTTPXModule(threads, timeout, rateLimit),
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

	// Since httpx doesn't parse XML content, we'll discover common patterns
	// that might be in sitemaps and probe them
	if len(foundSitemaps) > 0 {
		// Generate common URL patterns found in sitemaps
		commonPatterns := s.generateCommonSitemapURLs(baseURL)
		
		// Probe these URLs
		patternResults, err := s.httpx.ProbeBulk(commonPatterns)
		if err == nil {
			for _, httpxResult := range patternResults {
				if httpxResult.StatusCode > 0 && httpxResult.StatusCode < 400 {
					path := types.Path{
						URL:         httpxResult.URL,
						Status:      httpxResult.StatusCode,
						Length:      httpxResult.ContentLength,
						Method:      "GET",
						ContentType: httpxResult.ContentType,
						Title:       httpxResult.Title,
						Source:      "sitemap-pattern",
					}
					result.Paths = append(result.Paths, path)
					
					// Extract path for endpoint
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

func (s *SitemapModule) generateCommonSitemapURLs(baseURL string) []string {
	var urls []string
	
	// Common patterns found in sitemaps
	patterns := []string{
		"/about", "/about-us", "/about/",
		"/contact", "/contact-us", "/contact/",
		"/services", "/services/",
		"/products", "/products/",
		"/portfolio", "/portfolio/",
		"/blog", "/blog/", "/news", "/news/",
		"/careers", "/careers/", "/jobs", "/jobs/",
		"/team", "/team/", "/our-team", "/our-team/",
		"/privacy", "/privacy-policy", "/privacy/",
		"/terms", "/terms-of-service", "/terms/",
		"/faq", "/faq/", "/help", "/help/",
		"/support", "/support/",
		"/pricing", "/pricing/", "/plans", "/plans/",
		"/features", "/features/",
		"/documentation", "/documentation/", "/docs", "/docs/",
		"/resources", "/resources/",
		"/partners", "/partners/",
		"/press", "/press/", "/media", "/media/",
		"/events", "/events/",
		"/case-studies", "/case-studies/",
		"/testimonials", "/testimonials/",
		"/gallery", "/gallery/", "/photos", "/photos/",
		"/download", "/downloads", "/download/", "/downloads/",
		"/white-papers", "/white-papers/",
		"/ebooks", "/ebooks/",
		"/webinars", "/webinars/",
		"/newsletter", "/newsletter/",
		"/subscribe", "/subscribe/",
		"/unsubscribe", "/unsubscribe/",
		"/account", "/account/", "/my-account", "/my-account/",
		"/dashboard", "/dashboard/",
		"/profile", "/profile/",
		"/settings", "/settings/",
		"/search", "/search/",
		"/categories", "/categories/",
		"/tags", "/tags/",
		"/archive", "/archive/", "/archives", "/archives/",
	}
	
	// Generate full URLs
	for _, pattern := range patterns {
		urls = append(urls, baseURL+pattern)
		
		// Also try with common date patterns for blogs
		if pattern == "/blog" || pattern == "/news" || pattern == "/archive" {
			currentYear := time.Now().Year()
			for year := currentYear; year >= currentYear-2; year-- {
				urls = append(urls, fmt.Sprintf("%s%s/%d", baseURL, pattern, year))
				urls = append(urls, fmt.Sprintf("%s%s/%d/", baseURL, pattern, year))
			}
		}
	}
	
	// Add numbered pages
	for i := 1; i <= 5; i++ {
		urls = append(urls, fmt.Sprintf("%s/page/%d", baseURL, i))
		urls = append(urls, fmt.Sprintf("%s/page/%d/", baseURL, i))
		urls = append(urls, fmt.Sprintf("%s/?page=%d", baseURL, i))
		urls = append(urls, fmt.Sprintf("%s/blog/page/%d", baseURL, i))
		urls = append(urls, fmt.Sprintf("%s/blog/page/%d/", baseURL, i))
	}
	
	return urls
}