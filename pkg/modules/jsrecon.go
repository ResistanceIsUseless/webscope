package modules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type Client struct {
	jsreconPath string
	timeout     time.Duration
}

type ClientConfig struct {
	JSReconPath string
	Timeout     time.Duration
}

type Finding struct {
	Type       string  `json:"type"`
	Subtype    string  `json:"subtype"`
	Value      string  `json:"value"`
	Confidence float64 `json:"confidence"`
	Snippet    string  `json:"snippet,omitempty"`
}

type AnalysisResult struct {
	Findings []Finding `json:"findings"`
	Stats    Stats     `json:"stats"`
}

type Stats struct {
	DurationMs             int            `json:"duration_ms"`
	SourceType             string         `json:"source_type"`
	SourceSizeBytes        int            `json:"source_size_bytes"`
	ScopeVariablesResolved int            `json:"scope_variables_resolved"`
	StringsCollected       int            `json:"strings_collected"`
	TotalFindings          int            `json:"total_findings"`
	FindingsByType         map[string]int `json:"findings_by_type"`
}

func NewClient(config ClientConfig) *Client {
	path := config.JSReconPath
	if path == "" {
		path = findJSRecon()
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 60 * time.Second
	}

	return &Client{
		jsreconPath: path,
		timeout:     timeout,
	}
}

func findJSRecon() string {
	paths := []string{
		"jsrecon",
		"node",
		filepath.Join(os.Getenv("HOME"), "Projects/Code/jsRecon/src/cli.js"),
	}

	for _, p := range paths {
		if _, err := exec.LookPath(p); err == nil {
			return p
		}
	}

	// Check if Node.js can run jsRecon directly
	nodePaths := []string{
		filepath.Join(os.Getenv("HOME"), "Projects/Code/jsRecon/src/cli.js"),
		"/Users/matthew/Projects/Code/jsRecon/src/cli.js",
		"/Users/matthew/Library/Mobile Documents/com~apple~CloudDocs/Projects/Code/jsRecon/src/cli.js",
	}

	for _, p := range nodePaths {
		if _, err := os.Stat(p); err == nil {
			return "node"
		}
	}

	return "node"
}

func (c *Client) Analyze(code string, sourceURL string) (*AnalysisResult, error) {
	// Create temp file with the JS code
	tmpDir := os.TempDir()
	tmpFile := filepath.Join(tmpDir, fmt.Sprintf("jsrecon_%d.js", time.Now().UnixNano()))

	f, err := os.Create(tmpFile)
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}

	if _, err := f.WriteString(code); err != nil {
		f.Close()
		os.Remove(tmpFile)
		return nil, fmt.Errorf("write temp file: %w", err)
	}
	f.Close()

	// Clean up temp file when done
	defer os.Remove(tmpFile)

	// Build command
	var cmd *exec.Cmd
	if c.jsreconPath == "node" || strings.HasSuffix(c.jsreconPath, ".js") {
		jsreconPath := filepath.Join(os.Getenv("HOME"), "Projects/Code/jsRecon/src/cli.js")
		cmd = exec.Command("node", jsreconPath, "analyze", tmpFile, "--json")
	} else {
		cmd = exec.Command(c.jsreconPath, "analyze", tmpFile, "--json")
	}

	if sourceURL != "" {
		cmd.Env = append(os.Environ(), "JSRECON_URL="+sourceURL)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start jsrecon: %w", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			return nil, fmt.Errorf("jsrecon execution: %w - stderr: %s", err, stderr.String())
		}
	case <-time.After(c.timeout):
		cmd.Process.Kill()
		return nil, fmt.Errorf("analysis timeout after %v", c.timeout)
	}

	var result AnalysisResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("parse JSON output: %w, errOutput: %s", err, stdout.String())
	}

	return &result, nil
}

func (c *Client) AnalyzeURL(url string) (*AnalysisResult, error) {
	var cmd *exec.Cmd
	if c.jsreconPath == "node" {
		jsreconPath := filepath.Join(os.Getenv("HOME"), "Projects/Code/jsRecon/src/cli.js")
		cmd = exec.Command("node", jsreconPath, "analyze", url, "--json")
	} else {
		cmd = exec.Command(c.jsreconPath, "analyze", url, "--json")
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start jsrecon: %w", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			return nil, fmt.Errorf("jsrecon execution: %w - stderr: %s", err, stderr.String())
		}
	case <-time.After(c.timeout):
		cmd.Process.Kill()
		return nil, fmt.Errorf("analysis timeout after %v", c.timeout)
	}

	var result AnalysisResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("parse JSON output: %w", err)
	}

	return &result, nil
}
