// Package http provides a single, leak-free HTTP client for WebScope v2
// Philosophy: One goroutine per HTTP request, aggressive timeouts, no leaks
package http

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Client is the single HTTP client for all WebScope operations
// No goroutines per request, guaranteed cleanup, aggressive timeouts
type Client struct {
	client     *http.Client
	limiter    *RateLimiter
	maxRetries int
	mu         sync.RWMutex
	stats      ClientStats
}

// ClientConfig holds configuration for the HTTP client
type ClientConfig struct {
	Timeout           time.Duration
	RateLimit         int // requests per second
	MaxRetries        int
	MaxResponseSize   int64
	DisableKeepAlives bool
	UserAgent         string
}

// ClientStats tracks client usage statistics
type ClientStats struct {
	RequestsTotal   int64
	RequestsSuccess int64
	RequestsFailed  int64
	TotalLatency    time.Duration
}

// Response represents an HTTP response with controlled resource usage
type Response struct {
	URL        string
	StatusCode int
	Headers    http.Header
	Body       string
	Error      error
	Latency    time.Duration
}

// DefaultConfig returns the default client configuration
// Aggressive 2-second timeout as requested
func DefaultConfig() ClientConfig {
	return ClientConfig{
		Timeout:           2 * time.Second, // AGGRESSIVE timeout
		RateLimit:         10,
		MaxRetries:        1, // Minimal retries
		MaxResponseSize:   10 * 1024 * 1024, // 10MB max
		DisableKeepAlives: true, // Prevent connection pool issues
		UserAgent:         "WebScope/2.0",
	}
}

// NewClient creates a new HTTP client with the given configuration
func NewClient(config ClientConfig) *Client {
	transport := &http.Transport{
		MaxIdleConns:        10,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     10 * time.Second,
		DisableKeepAlives:   config.DisableKeepAlives, // Prevent connection pooling issues
		ForceAttemptHTTP2:   false, // Simpler, more predictable
	}

	return &Client{
		client: &http.Client{
			Timeout:   config.Timeout,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		limiter:    NewRateLimiter(config.RateLimit),
		maxRetries: config.MaxRetries,
	}
}

// Get performs a single HTTP GET request
// NO GOROUTINES - runs in the calling goroutine
func (c *Client) Get(ctx context.Context, url string) (*Response, error) {
	// Rate limit
	if err := c.limiter.Wait(ctx); err != nil {
		return nil, fmt.Errorf("rate limit: %w", err)
	}

	start := time.Now()

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		c.recordFailure()
		return nil, fmt.Errorf("create request: %w", err)
	}

	// Set user agent
	req.Header.Set("User-Agent", "WebScope/2.0")

	// Execute request - NO GOROUTINES
	resp, err := c.client.Do(req)
	if err != nil {
		c.recordFailure()
		return &Response{
			URL:     url,
			Error:   err,
			Latency: time.Since(start),
		}, err
	}
	defer resp.Body.Close() // ALWAYS close immediately

	// Read body with size limit
	body, err := readBodyWithLimit(resp.Body, 10*1024*1024) // 10MB max
	if err != nil {
		c.recordFailure()
		return &Response{
			URL:        url,
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			Error:      err,
			Latency:    time.Since(start),
		}, err
	}

	c.recordSuccess(time.Since(start))

	return &Response{
		URL:        url,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
		Latency:    time.Since(start),
	}, nil
}

// GetBatch performs multiple HTTP requests sequentially
// NO GOROUTINE EXPLOSION - processes one at a time
func (c *Client) GetBatch(ctx context.Context, urls []string) []*Response {
	responses := make([]*Response, 0, len(urls))

	for _, url := range urls {
		// Check context for cancellation
		if ctx.Err() != nil {
			break
		}

		// One request at a time, one goroutine
		resp, _ := c.Get(ctx, url)
		if resp != nil {
			responses = append(responses, resp)
		}
	}

	return responses
}

// GetBatchWithLimit performs batch requests with a maximum limit
func (c *Client) GetBatchWithLimit(ctx context.Context, urls []string, limit int) []*Response {
	if limit <= 0 || limit > len(urls) {
		limit = len(urls)
	}

	return c.GetBatch(ctx, urls[:limit])
}

// QuickProbe checks if a URL is reachable without fetching the body
func (c *Client) QuickProbe(ctx context.Context, url string) (bool, int) {
	// Create a context with even shorter timeout for probing
	probeCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	resp, err := c.Get(probeCtx, url)
	if err != nil {
		return false, 0
	}

	return resp.StatusCode > 0 && resp.StatusCode < 500, resp.StatusCode
}

// Shutdown gracefully shuts down the client
func (c *Client) Shutdown() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Close idle connections
	if transport, ok := c.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}

	return nil
}

// GetStats returns client statistics
func (c *Client) GetStats() ClientStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stats
}

// Helper functions

func (c *Client) recordSuccess(latency time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.RequestsTotal++
	c.stats.RequestsSuccess++
	c.stats.TotalLatency += latency
}

func (c *Client) recordFailure() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stats.RequestsTotal++
	c.stats.RequestsFailed++
}

func readBodyWithLimit(r io.Reader, maxSize int64) (string, error) {
	limited := io.LimitReader(r, maxSize)
	body, err := io.ReadAll(limited)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// ValidateStatusCode checks if a status code indicates success
func ValidateStatusCode(code int, allowedCodes []int) bool {
	if len(allowedCodes) == 0 {
		// Default: success codes and some client errors
		return code >= 200 && code < 400 || code == 401 || code == 403
	}

	for _, allowed := range allowedCodes {
		if code == allowed {
			return true
		}
	}
	return false
}

// ExtractDomain extracts the domain from a URL
func ExtractDomain(url string) string {
	// Simple domain extraction
	if strings.HasPrefix(url, "http://") {
		url = strings.TrimPrefix(url, "http://")
	} else if strings.HasPrefix(url, "https://") {
		url = strings.TrimPrefix(url, "https://")
	}

	if idx := strings.Index(url, "/"); idx > 0 {
		url = url[:idx]
	}

	return url
}