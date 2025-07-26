package config

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type Config struct {
	Wordlists WordlistConfig `json:"wordlists"`
}

type WordlistConfig struct {
	CommonPaths string `json:"common_paths,omitempty"`
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