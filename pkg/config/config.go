package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Profiles map[string]Profile `yaml:"profiles" json:"profiles"`
	Global   GlobalConfig       `yaml:"global" json:"global"`
}

type Profile struct {
	Description   string                 `yaml:"description" json:"description"`
	GlobalLimit   int                    `yaml:"global_limit" json:"global_limit"`
	Katana        KatanaConfig           `yaml:"katana" json:"katana"`
	HTTPX         HTTPXConfig            `yaml:"httpx" json:"httpx"`
	Paths         PathsConfig            `yaml:"paths" json:"paths"`
	JavaScript    JavaScriptConfig       `yaml:"javascript" json:"javascript"`
	FalsePositive FalsePositiveConfig    `yaml:"false_positive" json:"false_positive"`
}

type GlobalConfig struct {
	Wordlists WordlistConfig `yaml:"wordlists" json:"wordlists"`
	JSluice   JSluiceConfig  `yaml:"jsluice" json:"jsluice"`
	Patterns  PatternConfig  `yaml:"patterns" json:"patterns"`
}

type WordlistConfig struct {
	CommonPaths string `yaml:"common_paths" json:"common_paths,omitempty"`
}

type JSluiceConfig struct {
	Patterns JSluicePatterns `yaml:"patterns" json:"patterns"`
}

type JSluicePatterns struct {
	URLs      []string `yaml:"urls" json:"urls,omitempty"`
	Secrets   []string `yaml:"secrets" json:"secrets,omitempty"`
	Endpoints []string `yaml:"endpoints" json:"endpoints,omitempty"`
}

type PathsConfig struct {
	Threads     int  `yaml:"threads" json:"threads"`
	RateLimit   int  `yaml:"rate_limit" json:"rate_limit"`
	Timeout     int  `yaml:"timeout" json:"timeout"`
	SmartMode   bool `yaml:"smart_mode" json:"smart_mode"`
	MaxPaths    int  `yaml:"max_paths" json:"max_paths"`
}

type JavaScriptConfig struct {
	Enabled        bool `yaml:"enabled" json:"enabled"`
	AdvancedMode   bool `yaml:"advanced_mode" json:"advanced_mode"`
	SecretDetect   bool `yaml:"secret_detect" json:"secret_detect"`
	EndpointExtract bool `yaml:"endpoint_extract" json:"endpoint_extract"`
}

type KatanaConfig struct {
	Depth         int    `yaml:"depth" json:"depth,omitempty"`
	RateLimit     int    `yaml:"rate_limit" json:"rate_limit,omitempty"`
	Timeout       int    `yaml:"timeout" json:"timeout,omitempty"`
	Concurrency   int    `yaml:"concurrency" json:"concurrency,omitempty"`
	Parallelism   int    `yaml:"parallelism" json:"parallelism,omitempty"`
	Strategy      string `yaml:"strategy" json:"strategy,omitempty"` // "depth-first", "breadth-first"
	JSluice       bool   `yaml:"jsluice" json:"jsluice,omitempty"`
	FormExtract   bool   `yaml:"form_extract" json:"form_extract,omitempty"`
	Headless      bool   `yaml:"headless" json:"headless,omitempty"`
	BodyReadSize  int    `yaml:"body_read_size" json:"body_read_size,omitempty"`
	MaxResponses  int    `yaml:"max_responses" json:"max_responses,omitempty"`
}

type HTTPXConfig struct {
	Threads        int      `yaml:"threads" json:"threads,omitempty"`
	RateLimit      int      `yaml:"rate_limit" json:"rate_limit,omitempty"`
	Timeout        int      `yaml:"timeout" json:"timeout,omitempty"`
	Retries        int      `yaml:"retries" json:"retries,omitempty"`
	FollowRedirect bool     `yaml:"follow_redirect" json:"follow_redirect,omitempty"`
	StatusCodes    []string `yaml:"status_codes" json:"status_codes,omitempty"`
	MaxRedirects   int      `yaml:"max_redirects" json:"max_redirects,omitempty"`
	UserAgent      string   `yaml:"user_agent" json:"user_agent,omitempty"`
	CustomHeaders  []string `yaml:"custom_headers" json:"custom_headers,omitempty"`
	TechDetect     bool     `yaml:"tech_detect" json:"tech_detect,omitempty"`
	WebServer      bool     `yaml:"web_server" json:"web_server,omitempty"`
}

type FalsePositiveConfig struct {
	Enabled             bool    `yaml:"enabled" json:"enabled,omitempty"`
	MaxLengthDiff       int     `yaml:"max_length_diff" json:"max_length_diff,omitempty"`
	MinLengthRatio      float64 `yaml:"min_length_ratio" json:"min_length_ratio,omitempty"`
	SimilarityThreshold float64 `yaml:"similarity_threshold" json:"similarity_threshold,omitempty"`
	BaselineCount       int     `yaml:"baseline_count" json:"baseline_count,omitempty"`
}

type PatternConfig struct {
	PatternsDir     string            `yaml:"patterns_dir" json:"patterns_dir,omitempty"`
	PatternsFiles   []string          `yaml:"patterns_files" json:"patterns_files,omitempty"`
	CustomPatterns  []PatternRule     `yaml:"custom_patterns" json:"custom_patterns,omitempty"`
	EnabledPatterns []string          `yaml:"enabled_patterns" json:"enabled_patterns,omitempty"`
}

type PatternRule struct {
	Name        string   `yaml:"name" json:"name"`
	Category    string   `yaml:"category" json:"category"`
	Pattern     string   `yaml:"pattern" json:"pattern"`
	Patterns    []string `yaml:"patterns" json:"patterns,omitempty"` // For multiple patterns
	Severity    string   `yaml:"severity" json:"severity"`
	Description string   `yaml:"description" json:"description"`
	Enabled     bool     `yaml:"enabled" json:"enabled,omitempty"`
}

func Load(configPath string) (*Config, error) {
	config := &Config{}

	if configPath == "" {
		return config, nil
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return config, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	// Determine format by file extension
	ext := strings.ToLower(filepath.Ext(configPath))
	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, err
		}
	case ".json":
		if err := json.Unmarshal(data, config); err != nil {
			return nil, err
		}
	default:
		// Try YAML first, then JSON
		if err := yaml.Unmarshal(data, config); err != nil {
			if err2 := json.Unmarshal(data, config); err2 != nil {
				return nil, fmt.Errorf("failed to parse as YAML (%v) or JSON (%v)", err, err2)
			}
		}
	}

	return config, nil
}

func (c *Config) GetCustomWordlistPath() string {
	if c.Global.Wordlists.CommonPaths != "" {
		if filepath.IsAbs(c.Global.Wordlists.CommonPaths) {
			return c.Global.Wordlists.CommonPaths
		}

		homeDir, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(homeDir, ".webscope", c.Global.Wordlists.CommonPaths)
		}
	}

	return ""
}

func GetDefaultConfigPaths() []string {
	var paths []string

	if homeDir, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(homeDir, ".webscope", "config.yaml"))
		paths = append(paths, filepath.Join(homeDir, ".config", "webscope", "config.yaml"))
		paths = append(paths, filepath.Join(homeDir, ".webscope", "config.json"))
		paths = append(paths, filepath.Join(homeDir, ".config", "webscope", "config.json"))
	}

	paths = append(paths, "./webscope.yaml")
	paths = append(paths, "./config.yaml")
	paths = append(paths, "./webscope.json")
	paths = append(paths, "./config.json")

	return paths
}

// GetProfile returns the configuration for the specified profile
func (c *Config) GetProfile(profileName string) (Profile, bool) {
	if c.Profiles != nil {
		if profile, exists := c.Profiles[profileName]; exists {
			return profile, true
		}
	}
	return Profile{}, false
}

// GetProfiles returns all available profile names
func (c *Config) GetProfiles() []string {
	var profiles []string
	if c.Profiles != nil {
		for name := range c.Profiles {
			profiles = append(profiles, name)
		}
	}
	return profiles
}

// GetKatanaConfig returns katana configuration for the specified profile or default
func (c *Config) GetKatanaConfig(profileName string) KatanaConfig {
	if profile, exists := c.GetProfile(profileName); exists {
		return profile.Katana
	}
	return KatanaConfig{} // Return empty config if profile not found
}

// GetHTTPXConfig returns httpx configuration for the specified profile or default  
func (c *Config) GetHTTPXConfig(profileName string) HTTPXConfig {
	if profile, exists := c.GetProfile(profileName); exists {
		return profile.HTTPX
	}
	return HTTPXConfig{} // Return empty config if profile not found
}

// Legacy getters for backward compatibility during transition
func (c *Config) GetDefaultHTTPXConfig() HTTPXConfig {
	// Try to get from normal profile first, then return defaults
	if httpxConfig := c.GetHTTPXConfig("normal"); httpxConfig.Threads > 0 {
		return httpxConfig
	}
	
	// Return sensible defaults
	return HTTPXConfig{
		Threads:        20,
		RateLimit:      20,
		Timeout:        10,
		Retries:        2,
		FollowRedirect: true,
		StatusCodes:    []string{"200", "201", "202", "301", "302", "401", "403"},
		MaxRedirects:   5,
		TechDetect:     true,
		WebServer:      true,
	}
}
