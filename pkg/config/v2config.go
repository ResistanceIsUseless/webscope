// Package config provides configuration management for WebScope v2
package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// V2Config represents WebScope v2 configuration
type V2Config struct {
	Discovery DiscoveryConfig `json:"discovery"`
	HTTP      HTTPConfig      `json:"http"`
	Flows     FlowConfigs     `json:"flows"`
}

// DiscoveryConfig holds discovery settings
type DiscoveryConfig struct {
	Flow      string        `json:"flow"`       // basic, standard, deep, analysis, crawl
	Timeout   time.Duration `json:"timeout"`    // Global timeout per request
	RateLimit int           `json:"rate_limit"` // Requests per second
}

// HTTPConfig holds HTTP client settings
type HTTPConfig struct {
	Timeout           time.Duration `json:"timeout"`
	Retries           int           `json:"retries"`
	DisableKeepAlives bool          `json:"disable_keepalive"`
	MaxIdleConns      int           `json:"max_idle_conns"`
	MaxResponseSize   int64         `json:"max_response_size"`
	UserAgent         string        `json:"user_agent"`
}

// FlowConfigs holds flow-specific settings
type FlowConfigs struct {
	Basic    BasicFlowConfig    `json:"basic"`
	Standard StandardFlowConfig `json:"standard"`
	Deep     DeepFlowConfig     `json:"deep"`
	Analysis AnalysisFlowConfig `json:"analysis"`
	Crawl    CrawlFlowConfig    `json:"crawl"`
}

// BasicFlowConfig holds basic flow settings
type BasicFlowConfig struct {
	CommonPaths []string `json:"common_paths"`
}

// StandardFlowConfig holds standard flow settings
type StandardFlowConfig struct {
	ParseRobots     bool `json:"parse_robots"`
	ParseSitemap    bool `json:"parse_sitemap"`
	MaxRobotsPaths  int  `json:"max_robots_paths"`
	MaxSitemapURLs  int  `json:"max_sitemap_urls"`
}

// DeepFlowConfig holds deep flow settings
type DeepFlowConfig struct {
	Wordlist string `json:"wordlist"` // "embedded" or path to file
	MaxPaths int    `json:"max_paths"`
}

// AnalysisFlowConfig holds analysis flow settings
type AnalysisFlowConfig struct {
	Patterns []string `json:"patterns"` // secrets, sensitive_paths, endpoints
}

// CrawlFlowConfig holds crawl flow settings
type CrawlFlowConfig struct {
	MaxDepth    int `json:"max_depth"`
	MaxRequests int `json:"max_requests"`
}

// DefaultV2Config returns the default configuration
func DefaultV2Config() *V2Config {
	return &V2Config{
		Discovery: DiscoveryConfig{
			Flow:      "standard",
			Timeout:   2 * time.Second,
			RateLimit: 10,
		},
		HTTP: HTTPConfig{
			Timeout:           2 * time.Second,
			Retries:           1,
			DisableKeepAlives: true,
			MaxIdleConns:      10,
			MaxResponseSize:   10 * 1024 * 1024,
			UserAgent:         "WebScope/2.0",
		},
		Flows: FlowConfigs{
			Basic: BasicFlowConfig{
				CommonPaths: []string{
					"/robots.txt",
					"/sitemap.xml",
					"/.well-known/security.txt",
					"/favicon.ico",
				},
			},
			Standard: StandardFlowConfig{
				ParseRobots:     true,
				ParseSitemap:    true,
				MaxRobotsPaths:  20,
				MaxSitemapURLs:  50,
			},
			Deep: DeepFlowConfig{
				Wordlist: "embedded",
				MaxPaths: 100,
			},
			Analysis: AnalysisFlowConfig{
				Patterns: []string{"secrets", "sensitive_paths", "endpoints"},
			},
			Crawl: CrawlFlowConfig{
				MaxDepth:    2,
				MaxRequests: 100,
			},
		},
	}
}

// LoadV2Config loads configuration from file
func LoadV2Config(path string) (*V2Config, error) {
	if path == "" {
		// Try default locations
		locations := []string{
			"./webscope-v2.json",
			"~/.config/webscope/v2config.json",
		}

		for _, loc := range locations {
			if loc[:2] == "~/" {
				home, _ := os.UserHomeDir()
				loc = filepath.Join(home, loc[2:])
			}

			if _, err := os.Stat(loc); err == nil {
				path = loc
				break
			}
		}
	}

	if path == "" {
		return DefaultV2Config(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := DefaultV2Config()
	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}

	return config, nil
}

// SaveV2Config saves configuration to file
func SaveV2Config(config *V2Config, path string) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}