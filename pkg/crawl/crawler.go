// Package crawl provides controlled web crawling with strict limits
// No goroutine explosion, sequential processing, hard limits
package crawl

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/http"
)

// Crawler performs controlled crawling with strict limits
type Crawler struct {
	client      *http.Client
	maxDepth    int
	maxRequests int
}

// CrawlerConfig holds crawler configuration
type CrawlerConfig struct {
	MaxDepth    int
	MaxRequests int
}

// CrawlResult contains the results of crawling
type CrawlResult struct {
	Pages         []Page
	Links         []string
	Forms         []Form
	RequestsCount int
	CrawlTime     time.Duration
}

// Page represents a crawled page
type Page struct {
	URL         string
	StatusCode  int
	ContentType string
	Title       string
	Depth       int
	Links       []string
}

// Form represents an HTML form found during crawling
type Form struct {
	URL    string
	Action string
	Method string
	Inputs []FormInput
}

// FormInput represents a form input field
type FormInput struct {
	Name  string
	Type  string
	Value string
}

// NewCrawler creates a new controlled crawler
func NewCrawler(client *http.Client, config CrawlerConfig) *Crawler {
	if config.MaxDepth <= 0 {
		config.MaxDepth = 2
	}
	if config.MaxRequests <= 0 {
		config.MaxRequests = 100
	}

	return &Crawler{
		client:      client,
		maxDepth:    config.MaxDepth,
		maxRequests: config.MaxRequests,
	}
}

// Crawl performs controlled crawling with strict limits
func (c *Crawler) Crawl(ctx context.Context, target string, maxDepth int) (*CrawlResult, error) {
	start := time.Now()
	result := &CrawlResult{
		Pages: []Page{},
		Links: []string{},
		Forms: []Form{},
	}

	if maxDepth <= 0 {
		maxDepth = c.maxDepth
	}

	visited := make(map[string]bool)
	queue := []crawlItem{{url: target, depth: 0}}
	requestCount := 0

	for len(queue) > 0 && requestCount < c.maxRequests {
		// Check context
		if ctx.Err() != nil {
			break
		}

		// Get next item from queue
		item := queue[0]
		queue = queue[1:]

		// Skip if already visited
		if visited[item.url] {
			continue
		}
		visited[item.url] = true

		// Single request, no goroutine
		resp, err := c.client.Get(ctx, item.url)
		if err != nil {
			continue
		}

		requestCount++

		// Create page entry
		page := Page{
			URL:         item.url,
			StatusCode:  resp.StatusCode,
			ContentType: resp.Headers.Get("Content-Type"),
			Depth:       item.depth,
		}

		// Extract title if HTML
		if strings.Contains(page.ContentType, "text/html") && resp.Body != "" {
			page.Title = extractTitle(resp.Body)

			// Extract links (if depth allows)
			if item.depth < maxDepth {
				links := extractLinks(resp.Body, item.url)
				page.Links = links

				// Add to queue with limits
				for _, link := range links {
					if !visited[link] && len(queue) < 100 { // Queue limit
						// Only crawl same domain
						if isSameDomain(item.url, link) {
							queue = append(queue, crawlItem{
								url:   link,
								depth: item.depth + 1,
							})
						}
					}
				}
			}

			// Extract forms
			forms := extractForms(resp.Body, item.url)
			for _, form := range forms {
				result.Forms = append(result.Forms, form)
			}
		}

		result.Pages = append(result.Pages, page)
	}

	result.RequestsCount = requestCount
	result.CrawlTime = time.Since(start)

	return result, nil
}

type crawlItem struct {
	url   string
	depth int
}

func extractTitle(html string) string {
	// Simple title extraction
	start := strings.Index(html, "<title>")
	if start == -1 {
		return ""
	}
	start += 7

	end := strings.Index(html[start:], "</title>")
	if end == -1 {
		return ""
	}

	title := html[start : start+end]
	// Clean up whitespace
	title = strings.TrimSpace(title)
	title = strings.ReplaceAll(title, "\n", " ")
	title = strings.ReplaceAll(title, "\t", " ")

	if len(title) > 100 {
		title = title[:100] + "..."
	}

	return title
}

func extractLinks(html string, baseURL string) []string {
	var links []string
	seen := make(map[string]bool)

	// Parse base URL
	base, err := url.Parse(baseURL)
	if err != nil {
		return links
	}

	// Simple link extraction (href attributes)
	// In production, would use proper HTML parser
	patterns := []string{
		`href="([^"]+)"`,
		`href='([^']+)'`,
		`src="([^"]+)"`,
		`src='([^']+)'`,
	}

	for _, pattern := range patterns {
		start := 0
		for {
			idx := strings.Index(html[start:], pattern[:5])
			if idx == -1 {
				break
			}
			idx += start

			// Find the URL
			quoteStart := idx + 6
			quoteEnd := strings.IndexByte(html[quoteStart:], html[idx+5])
			if quoteEnd == -1 {
				break
			}

			rawLink := html[quoteStart : quoteStart+quoteEnd]

			// Resolve relative URLs
			if link, err := resolveURL(base, rawLink); err == nil {
				if !seen[link] {
					links = append(links, link)
					seen[link] = true
				}
			}

			start = quoteStart + quoteEnd
		}
	}

	return links
}

func extractForms(html string, baseURL string) []Form {
	var forms []Form

	// Simple form extraction
	// In production, would use proper HTML parser
	formStart := 0
	for {
		idx := strings.Index(html[formStart:], "<form")
		if idx == -1 {
			break
		}
		idx += formStart

		// Find form end
		formEndIdx := strings.Index(html[idx:], "</form>")
		if formEndIdx == -1 {
			break
		}

		formHTML := html[idx : idx+formEndIdx+7]

		// Extract form attributes
		form := Form{
			URL:    baseURL,
			Action: extractAttribute(formHTML, "action"),
			Method: extractAttribute(formHTML, "method"),
			Inputs: []FormInput{},
		}

		if form.Method == "" {
			form.Method = "GET"
		}

		// Extract inputs
		inputStart := 0
		for {
			inputIdx := strings.Index(formHTML[inputStart:], "<input")
			if inputIdx == -1 {
				break
			}
			inputIdx += inputStart

			// Find input end
			inputEnd := strings.Index(formHTML[inputIdx:], ">")
			if inputEnd == -1 {
				break
			}

			inputHTML := formHTML[inputIdx : inputIdx+inputEnd+1]

			input := FormInput{
				Name:  extractAttribute(inputHTML, "name"),
				Type:  extractAttribute(inputHTML, "type"),
				Value: extractAttribute(inputHTML, "value"),
			}

			if input.Name != "" {
				form.Inputs = append(form.Inputs, input)
			}

			inputStart = inputIdx + inputEnd
		}

		if form.Action != "" || len(form.Inputs) > 0 {
			forms = append(forms, form)
		}

		formStart = idx + formEndIdx
	}

	return forms
}

func extractAttribute(html string, attr string) string {
	// Extract attribute value from HTML
	pattern := attr + `="([^"]*)"`
	idx := strings.Index(html, pattern)
	if idx == -1 {
		pattern = attr + `='([^']*)''`
		idx = strings.Index(html, pattern)
		if idx == -1 {
			return ""
		}
	}

	start := idx + len(attr) + 2
	end := strings.IndexByte(html[start:], html[idx+len(attr)+1])
	if end == -1 {
		return ""
	}

	return html[start : start+end]
}

func resolveURL(base *url.URL, link string) (string, error) {
	// Resolve relative URLs
	parsed, err := url.Parse(link)
	if err != nil {
		return "", err
	}

	resolved := base.ResolveReference(parsed)

	// Only return HTTP/HTTPS URLs
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return "", fmt.Errorf("invalid scheme: %s", resolved.Scheme)
	}

	return resolved.String(), nil
}

func isSameDomain(url1, url2 string) bool {
	// Check if two URLs are on the same domain
	u1, err1 := url.Parse(url1)
	u2, err2 := url.Parse(url2)

	if err1 != nil || err2 != nil {
		return false
	}

	return u1.Host == u2.Host
}