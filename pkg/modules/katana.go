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

type KatanaModule struct {
	depth       int
	timeout     time.Duration
	rateLimit   int
	jsluice     bool
	formExtract bool
}

func NewKatanaModule(depth int, timeout time.Duration, rateLimit int) *KatanaModule {
	return &KatanaModule{
		depth:       depth,
		timeout:     timeout,
		rateLimit:   rateLimit,
		jsluice:     true,  // Enable jsluice integration by default
		formExtract: true,  // Enable form extraction by default
	}
}

func (k *KatanaModule) Name() string {
	return "katana"
}

func (k *KatanaModule) Priority() int {
	return 2 // High priority for crawling
}

func (k *KatanaModule) Discover(target types.Target) (*types.DiscoveryResult, error) {
	result := &types.DiscoveryResult{
		Paths:      []types.Path{},
		Endpoints:  []types.Endpoint{},
		Secrets:    []types.Secret{},
		Parameters: []types.Parameter{},
	}

	// Check if katana is installed
	if _, err := exec.LookPath("katana"); err != nil {
		return result, fmt.Errorf("katana not found in PATH: %w", err)
	}

	// Build katana command
	args := []string{
		"-u", target.URL,
		"-d", fmt.Sprintf("%d", k.depth),
		"-timeout", fmt.Sprintf("%d", int(k.timeout.Seconds())),
		"-rate-limit", fmt.Sprintf("%d", k.rateLimit),
		"-json",
		"-silent",
	}

	// Add jsluice integration if enabled
	if k.jsluice {
		args = append(args, "-jsluice")
	}

	// Add form extraction if enabled
	if k.formExtract {
		args = append(args, "-form-extraction")
	}

	// Execute katana
	cmd := exec.Command("katana", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Check stderr for details
		if stderr.Len() > 0 {
			return result, fmt.Errorf("katana error: %s", stderr.String())
		}
		return result, fmt.Errorf("katana execution failed: %w", err)
	}

	// Parse katana JSON output
	lines := strings.Split(stdout.String(), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		var katanaResult KatanaResult
		if err := json.Unmarshal([]byte(line), &katanaResult); err != nil {
			continue // Skip malformed lines
		}

		// Convert katana result to our types
		path := types.Path{
			URL:         katanaResult.URL,
			Status:      katanaResult.StatusCode,
			Length:      katanaResult.ContentLength,
			Method:      katanaResult.Method,
			ContentType: katanaResult.ContentType,
			Source:      "katana-crawl",
		}
		result.Paths = append(result.Paths, path)

		// Extract endpoints from katana's jsluice integration
		if katanaResult.JSluice != nil {
			for _, jsURL := range katanaResult.JSluice.URLs {
				endpoint := types.Endpoint{
					Path:   jsURL,
					Type:   "jsluice-katana",
					Source: "katana",
				}
				result.Endpoints = append(result.Endpoints, endpoint)
			}

			for _, secret := range katanaResult.JSluice.Secrets {
				sec := types.Secret{
					Type:    secret.Type,
					Value:   "***REDACTED***",
					Context: secret.Context,
					Source:  "katana-jsluice",
				}
				result.Secrets = append(result.Secrets, sec)
			}
		}

		// Extract form parameters
		if katanaResult.Forms != nil {
			for _, form := range katanaResult.Forms {
				for _, input := range form.Inputs {
					param := types.Parameter{
						Name:   input.Name,
						Type:   input.Type,
						Source: "katana-form",
					}
					result.Parameters = append(result.Parameters, param)
				}
			}
		}
	}

	return result, nil
}

// KatanaResult represents a single line of katana JSON output
type KatanaResult struct {
	URL           string `json:"url"`
	Path          string `json:"path"`
	Method        string `json:"method"`
	StatusCode    int    `json:"status_code"`
	ContentLength int    `json:"content_length"`
	ContentType   string `json:"content_type"`
	JSluice       *struct {
		URLs    []string `json:"urls"`
		Secrets []struct {
			Type    string `json:"type"`
			Value   string `json:"value"`
			Context string `json:"context"`
		} `json:"secrets"`
	} `json:"jsluice,omitempty"`
	Forms []struct {
		Action string `json:"action"`
		Method string `json:"method"`
		Inputs []struct {
			Name  string `json:"name"`
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"inputs"`
	} `json:"forms,omitempty"`
}