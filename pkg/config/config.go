package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	Wordlists     WordlistConfig      `json:"wordlists"`
	JSluice       JSluiceConfig       `json:"jsluice"`
	Katana        KatanaConfig        `json:"katana"`
	HTTPX         HTTPXConfig         `json:"httpx"`
	FalsePositive FalsePositiveConfig `json:"false_positive"`
}

type WordlistConfig struct {
	CommonPaths string `json:"common_paths,omitempty"`
}

type JSluiceConfig struct {
	Patterns JSluicePatterns `json:"patterns"`
}

type JSluicePatterns struct {
	URLs      []string `json:"urls,omitempty"`
	Secrets   []string `json:"secrets,omitempty"`
	Endpoints []string `json:"endpoints,omitempty"`
}

type KatanaConfig struct {
	Depth       int  `json:"depth,omitempty"`
	RateLimit   int  `json:"rate_limit,omitempty"`
	Timeout     int  `json:"timeout,omitempty"`
	JSluice     bool `json:"jsluice,omitempty"`
	FormExtract bool `json:"form_extract,omitempty"`
}

type HTTPXConfig struct {
	Threads        int      `json:"threads,omitempty"`
	RateLimit      int      `json:"rate_limit,omitempty"`
	Timeout        int      `json:"timeout,omitempty"`
	Retries        int      `json:"retries,omitempty"`
	FollowRedirect bool     `json:"follow_redirect,omitempty"`
	StatusCodes    []string `json:"status_codes,omitempty"`
}

type FalsePositiveConfig struct {
	Enabled          bool    `json:"enabled,omitempty"`
	MaxLengthDiff    int     `json:"max_length_diff,omitempty"`
	MinLengthRatio   float64 `json:"min_length_ratio,omitempty"`
	SimilarityThreshold float64 `json:"similarity_threshold,omitempty"`
	BaselineCount    int     `json:"baseline_count,omitempty"`
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
	
	if err := json.Unmarshal(data, config); err != nil {
		return nil, err
	}
	
	return config, nil
}

func (c *Config) GetCustomWordlistPath() string {
	if c.Wordlists.CommonPaths != "" {
		if filepath.IsAbs(c.Wordlists.CommonPaths) {
			return c.Wordlists.CommonPaths
		}
		
		homeDir, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(homeDir, ".webscope", c.Wordlists.CommonPaths)
		}
	}
	
	return ""
}

func GetDefaultConfigPaths() []string {
	var paths []string
	
	if homeDir, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(homeDir, ".webscope", "config.json"))
		paths = append(paths, filepath.Join(homeDir, ".config", "webscope", "config.json"))
	}
	
	paths = append(paths, "./webscope.json")
	paths = append(paths, "./config.json")
	
	return paths
}