package modules

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/types"
)

type HTTPModule struct {
	client  *http.Client
	timeout time.Duration
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
		timeout: timeout,
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