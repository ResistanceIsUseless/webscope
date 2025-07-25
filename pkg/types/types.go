package types

import (
	"net/http"
	"time"
)

type Target struct {
	Domain      string                 `json:"domain"`
	URL         string                 `json:"url"`
	HTTPStatus  int                    `json:"http_status,omitempty"`
	Headers     map[string][]string    `json:"headers,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type DiscoveryModule interface {
	Name() string
	Discover(target Target) (*DiscoveryResult, error)
	Priority() int
}

type DiscoveryResult struct {
	Paths        []Path       `json:"paths,omitempty"`
	Endpoints    []Endpoint   `json:"endpoints,omitempty"`
	Technologies []Technology `json:"technologies,omitempty"`
	Secrets      []Secret     `json:"secrets,omitempty"`
	Forms        []Form       `json:"forms,omitempty"`
	Parameters   []Parameter  `json:"parameters,omitempty"`
}

type Path struct {
	URL         string    `json:"url"`
	Status      int       `json:"status"`
	Length      int       `json:"length"`
	Title       string    `json:"title,omitempty"`
	Technology  []string  `json:"technology,omitempty"`
	Parameters  []string  `json:"parameters,omitempty"`
	Method      string    `json:"method"`
	ContentType string    `json:"content_type,omitempty"`
	FirstSeen   time.Time `json:"first_seen,omitempty"`
	Source      string    `json:"source"`
}

type Endpoint struct {
	Path    string `json:"path"`
	Type    string `json:"type"`
	Version string `json:"version,omitempty"`
	Method  string `json:"method,omitempty"`
	Source  string `json:"source"`
}

type Technology struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Version  string `json:"version,omitempty"`
	Source   string `json:"source"`
}

type Secret struct {
	Type    string `json:"type"`
	Value   string `json:"value,omitempty"`
	Context string `json:"context,omitempty"`
	Source  string `json:"source"`
}

type Form struct {
	Action string   `json:"action"`
	Method string   `json:"method"`
	Inputs []string `json:"inputs"`
	Source string   `json:"source"`
}

type Parameter struct {
	Name   string `json:"name"`
	Type   string `json:"type,omitempty"`
	Source string `json:"source"`
}

type WebScopeResult struct {
	Metadata     Metadata               `json:"metadata"`
	Statistics   Statistics             `json:"statistics"`
	Discoveries  map[string]*Discovery  `json:"discoveries"`
	Technologies map[string][]Technology `json:"technologies,omitempty"`
}

type Discovery struct {
	Domain      string      `json:"domain"`
	Paths       []Path      `json:"paths,omitempty"`
	Endpoints   []Endpoint  `json:"endpoints,omitempty"`
	Forms       []Form      `json:"forms,omitempty"`
	Parameters  []Parameter `json:"parameters,omitempty"`
	Secrets     []Secret    `json:"secrets,omitempty"`
	Historical  []Path      `json:"historical,omitempty"`
}

type Metadata struct {
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
	Targets   int       `json:"targets"`
}

type Statistics struct {
	TotalPaths     int `json:"total_paths"`
	TotalEndpoints int `json:"total_endpoints"`
	TotalSecrets   int `json:"total_secrets"`
	TotalForms     int `json:"total_forms"`
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type RateLimiter interface {
	Wait() error
	Stop()
}

type EngineResult struct {
	Target    Target
	Discovery *DiscoveryResult
	Error     error
}