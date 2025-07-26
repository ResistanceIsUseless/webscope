package modules

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/types"
)

type SitemapModule struct {
	client *http.Client
}

func NewSitemapModule(timeout time.Duration) *SitemapModule {
	return &SitemapModule{
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (s *SitemapModule) Name() string {
	return "sitemap"
}

func (s *SitemapModule) Priority() int {
	return 2
}

// XML structures for parsing sitemaps
type URLSet struct {
	XMLName xml.Name `xml:"urlset"`
	URLs    []URL    `xml:"url"`
}

type SitemapIndex struct {
	XMLName  xml.Name    `xml:"sitemapindex"`
	Sitemaps []SitemapRef `xml:"sitemap"`
}

type URL struct {
	Loc        string `xml:"loc"`
	LastMod    string `xml:"lastmod,omitempty"`
	ChangeFreq string `xml:"changefreq,omitempty"`
	Priority   string `xml:"priority,omitempty"`
}

type SitemapRef struct {
	Loc     string `xml:"loc"`
	LastMod string `xml:"lastmod,omitempty"`
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
		baseURL + "/sitemaps.xml",
		baseURL + "/sitemap/sitemap.xml",
	}

	for _, sitemapURL := range sitemapURLs {
		urls, err := s.parseSitemap(sitemapURL)
		if err != nil {
			continue // Try next sitemap location
		}

		// Add sitemap file itself as discovered path
		sitemapPath := types.Path{
			URL:    sitemapURL,
			Source: "sitemap-file",
		}
		result.Paths = append(result.Paths, sitemapPath)

		// Add discovered URLs
		for _, discoveredURL := range urls {
			// Validate URL
			parsedURL, err := url.Parse(discoveredURL)
			if err != nil {
				continue
			}

			// Create endpoint
			endpoint := types.Endpoint{
				Path:   parsedURL.Path,
				Type:   "sitemap-url",
				Source: "sitemap",
			}
			result.Endpoints = append(result.Endpoints, endpoint)

			// Create path
			path := types.Path{
				URL:    discoveredURL,
				Source: "sitemap-discovered",
			}
			result.Paths = append(result.Paths, path)
		}
	}

	return result, nil
}

func (s *SitemapModule) parseSitemap(sitemapURL string) ([]string, error) {
	req, err := http.NewRequest("GET", sitemapURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "WebScope/1.0")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("sitemap not found: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var urls []string

	// Try parsing as sitemap index first
	var sitemapIndex SitemapIndex
	if err := xml.Unmarshal(body, &sitemapIndex); err == nil && len(sitemapIndex.Sitemaps) > 0 {
		// This is a sitemap index, parse child sitemaps
		for _, sitemap := range sitemapIndex.Sitemaps {
			childURLs, err := s.parseSitemap(sitemap.Loc)
			if err != nil {
				continue
			}
			urls = append(urls, childURLs...)
		}
		return urls, nil
	}

	// Try parsing as regular sitemap
	var urlset URLSet
	if err := xml.Unmarshal(body, &urlset); err == nil && len(urlset.URLs) > 0 {
		for _, url := range urlset.URLs {
			if url.Loc != "" {
				urls = append(urls, url.Loc)
			}
		}
		return urls, nil
	}

	return nil, fmt.Errorf("unable to parse sitemap XML")
}