package modules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/types"
)

type HTTPXModule struct {
	threads      int
	timeout      time.Duration
	rateLimit    int
	retries      int
	followRedirect bool
	statusCodes  []string
}

func NewHTTPXModule(threads int, timeout time.Duration, rateLimit int) *HTTPXModule {
	return &HTTPXModule{
		threads:        threads,
		timeout:        timeout,
		rateLimit:      rateLimit,
		retries:        2,
		followRedirect: true,
		statusCodes:    []string{"200,201,202,203,204,205,206,207,208,226,300,301,302,303,304,305,307,308,401,403,404,405,500,501,502,503"},
	}
}

func (h *HTTPXModule) Name() string {
	return "httpx"
}

func (h *HTTPXModule) Priority() int {
	return 1 // High priority as it's the primary HTTP prober
}

func (h *HTTPXModule) Discover(target types.Target) (*types.DiscoveryResult, error) {
	result := &types.DiscoveryResult{
		Paths:        []types.Path{},
		Endpoints:    []types.Endpoint{},
		Technologies: []types.Technology{},
	}

	// Check if httpx is installed
	if _, err := exec.LookPath("httpx"); err != nil {
		return result, fmt.Errorf("httpx not found in PATH: %w", err)
	}

	// Run httpx probe on the target
	httpxResult, err := h.probeTarget(target.URL)
	if err != nil {
		return result, err
	}

	// Convert httpx result to our types
	if httpxResult != nil {
		path := types.Path{
			URL:         httpxResult.URL,
			Status:      httpxResult.StatusCode,
			Length:      httpxResult.ContentLength,
			Method:      "GET",
			ContentType: httpxResult.ContentType,
			Title:       httpxResult.Title,
			Source:      "httpx",
		}
		result.Paths = append(result.Paths, path)

		// Extract technologies from httpx results
		for _, tech := range httpxResult.Technologies {
			technology := types.Technology{
				Name:     tech,
				Category: "Detected",
				Source:   "httpx-tech",
			}
			result.Technologies = append(result.Technologies, technology)
		}

		// Add WebServer technology if detected
		if httpxResult.WebServer != "" {
			technology := types.Technology{
				Name:     httpxResult.WebServer,
				Category: "Server",
				Source:   "httpx-header",
			}
			result.Technologies = append(result.Technologies, technology)
		}
	}

	return result, nil
}

// ProbeTarget runs httpx on a single target
func (h *HTTPXModule) probeTarget(targetURL string) (*HTTPXResult, error) {
	args := []string{
		"-u", targetURL,
		"-json",
		"-silent",
		"-timeout", fmt.Sprintf("%d", int(h.timeout.Seconds())),
		"-threads", fmt.Sprintf("%d", h.threads),
		"-rate-limit", fmt.Sprintf("%d", h.rateLimit),
		"-retries", fmt.Sprintf("%d", h.retries),
		"-status-code",
		"-content-length",
		"-content-type",
		"-title",
		"-tech-detect",
		"-web-server",
		"-method",
		"-response-time",
	}

	if h.followRedirect {
		args = append(args, "-follow-redirects")
		args = append(args, "-max-redirects", "5")
	}

	// Add status code filters
	if len(h.statusCodes) > 0 {
		args = append(args, "-mc", strings.Join(h.statusCodes, ","))
	}

	cmd := exec.Command("httpx", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("httpx error: %s", stderr.String())
		}
		return nil, fmt.Errorf("httpx execution failed: %w", err)
	}

	// Parse JSON output
	output := strings.TrimSpace(stdout.String())
	if output == "" {
		return nil, nil // No result
	}

	var httpxResult HTTPXResult
	if err := json.Unmarshal([]byte(output), &httpxResult); err != nil {
		return nil, fmt.Errorf("failed to parse httpx output: %w", err)
	}

	return &httpxResult, nil
}

// ProbeBulk runs httpx on multiple URLs efficiently
func (h *HTTPXModule) ProbeBulk(urls []string) ([]*HTTPXResult, error) {
	if len(urls) == 0 {
		return nil, nil
	}

	// Check if httpx is installed
	if _, err := exec.LookPath("httpx"); err != nil {
		return nil, fmt.Errorf("httpx not found in PATH: %w", err)
	}

	// Create input for httpx
	input := strings.Join(urls, "\n")

	args := []string{
		"-json",
		"-silent",
		"-timeout", fmt.Sprintf("%d", int(h.timeout.Seconds())),
		"-threads", fmt.Sprintf("%d", h.threads),
		"-rate-limit", fmt.Sprintf("%d", h.rateLimit),
		"-retries", fmt.Sprintf("%d", h.retries),
		"-status-code",
		"-content-length",
		"-content-type",
		"-title",
		"-tech-detect",
		"-web-server",
		"-method",
		"-response-time",
	}

	if h.followRedirect {
		args = append(args, "-follow-redirects")
		args = append(args, "-max-redirects", "5")
	}

	// Add status code filters
	if len(h.statusCodes) > 0 {
		args = append(args, "-mc", strings.Join(h.statusCodes, ","))
	}

	cmd := exec.Command("httpx", args...)
	cmd.Stdin = strings.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		if stderr.Len() > 0 {
			return nil, fmt.Errorf("httpx error: %s", stderr.String())
		}
		return nil, fmt.Errorf("httpx execution failed: %w", err)
	}

	// Parse JSON output line by line
	var results []*HTTPXResult
	lines := strings.Split(stdout.String(), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var httpxResult HTTPXResult
		if err := json.Unmarshal([]byte(line), &httpxResult); err != nil {
			continue // Skip malformed lines
		}

		results = append(results, &httpxResult)
	}

	return results, nil
}

// HTTPXResult represents httpx JSON output
type HTTPXResult struct {
	URL            string   `json:"url"`
	Input          string   `json:"input"`
	StatusCode     int      `json:"status_code"`
	ContentLength  int      `json:"content_length"`
	ContentType    string   `json:"content_type"`
	Title          string   `json:"title"`
	WebServer      string   `json:"webserver"`
	ResponseTime   string   `json:"time"`
	Technologies   []string `json:"tech"`
	Method         string   `json:"method"`
	Host           string   `json:"host"`
	Path           string   `json:"path"`
	Scheme         string   `json:"scheme"`
	ResponseHeaders map[string][]string `json:"header,omitempty"`
}