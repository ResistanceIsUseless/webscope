package types

import (
	"net/http"
	"time"
)

type Target struct {
	Domain     string                 `json:"domain"`
	URL        string                 `json:"url"`
	HTTPStatus int                    `json:"http_status,omitempty"`
	Headers    map[string][]string    `json:"headers,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

type DiscoveryModule interface {
	Name() string
	Discover(target Target) (*DiscoveryResult, error)
	Priority() int
}

type DiscoveryResult struct {
	Paths          []Path              `json:"paths,omitempty"`
	Endpoints      []Endpoint          `json:"endpoints,omitempty"`
	Technologies   []Technology        `json:"technologies,omitempty"`
	Secrets        []Secret            `json:"secrets,omitempty"`
	Forms          []Form              `json:"forms,omitempty"`
	Parameters     []Parameter         `json:"parameters,omitempty"`
	GraphQLSchemas []GraphQLSchema     `json:"graphql_schemas,omitempty"`
	WebSockets     []WebSocketEndpoint `json:"websockets,omitempty"`
	Findings       []InterestingFinding `json:"findings,omitempty"`
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
	Type     string  `json:"type"`
	Value    string  `json:"value,omitempty"`
	Context  string  `json:"context,omitempty"`
	Source   string  `json:"source"`
	Entropy  float64 `json:"entropy,omitempty"`
	Strength string  `json:"strength,omitempty"`
}

type Form struct {
	Action string      `json:"action"`
	Method string      `json:"method"`
	Inputs []FormInput `json:"inputs"`
	Source string      `json:"source"`
}

type FormInput struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
}

type Parameter struct {
	Name   string `json:"name"`
	Type   string `json:"type,omitempty"`
	Source string `json:"source"`
}

type GraphQLSchema struct {
	Endpoint      string             `json:"endpoint"`
	Schema        string             `json:"schema,omitempty"`
	Types         []GraphQLType      `json:"types,omitempty"`
	Queries       []GraphQLOperation `json:"queries,omitempty"`
	Mutations     []GraphQLOperation `json:"mutations,omitempty"`
	Subscriptions []GraphQLOperation `json:"subscriptions,omitempty"`
	Source        string             `json:"source"`
}

type GraphQLType struct {
	Name        string         `json:"name"`
	Kind        string         `json:"kind"` // OBJECT, SCALAR, ENUM, etc.
	Fields      []GraphQLField `json:"fields,omitempty"`
	Description string         `json:"description,omitempty"`
}

type GraphQLField struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	Args        []GraphQLArgument `json:"args,omitempty"`
	Description string            `json:"description,omitempty"`
}

type GraphQLArgument struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	DefaultValue string `json:"default_value,omitempty"`
	Description  string `json:"description,omitempty"`
}

type GraphQLOperation struct {
	Name        string            `json:"name"`
	Type        string            `json:"type"` // query, mutation, subscription
	Args        []GraphQLArgument `json:"args,omitempty"`
	ReturnType  string            `json:"return_type,omitempty"`
	Description string            `json:"description,omitempty"`
}

type WebSocketEndpoint struct {
	URL         string           `json:"url"`
	Protocol    string           `json:"protocol,omitempty"` // ws, wss
	Subprotocol string           `json:"subprotocol,omitempty"`
	Events      []WebSocketEvent `json:"events,omitempty"`
	Source      string           `json:"source"`
}

type WebSocketEvent struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"` // emit, on, send, receive
	Data        map[string]interface{} `json:"data,omitempty"`
	Description string                 `json:"description,omitempty"`
}

type InterestingFinding struct {
	Category    string                 `json:"category"`
	Priority    string                 `json:"priority"` // critical, high, medium, low, info
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	URL         string                 `json:"url,omitempty"`
	Evidence    string                 `json:"evidence,omitempty"`
	Context     string                 `json:"context,omitempty"`
	Source      string                 `json:"source"`
	Confidence  string                 `json:"confidence,omitempty"` // high, medium, low
	References  []string               `json:"references,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type WebScopeResult struct {
	Metadata     Metadata                `json:"metadata"`
	Statistics   Statistics              `json:"statistics"`
	Discoveries  map[string]*Discovery   `json:"discoveries"`
	Technologies map[string][]Technology `json:"technologies,omitempty"`
}

type Discovery struct {
	Domain         string                `json:"domain"`
	Paths          []Path                `json:"paths,omitempty"`
	Endpoints      []Endpoint            `json:"endpoints,omitempty"`
	Forms          []Form                `json:"forms,omitempty"`
	Parameters     []Parameter           `json:"parameters,omitempty"`
	Secrets        []Secret              `json:"secrets,omitempty"`
	Historical     []Path                `json:"historical,omitempty"`
	GraphQLSchemas []GraphQLSchema       `json:"graphql_schemas,omitempty"`
	WebSockets     []WebSocketEndpoint   `json:"websockets,omitempty"`
	Findings       []InterestingFinding  `json:"findings,omitempty"`
}

type Metadata struct {
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
	Targets   int       `json:"targets"`
}

type Statistics struct {
	TotalPaths           int                    `json:"total_paths"`
	TotalEndpoints       int                    `json:"total_endpoints"`
	TotalSecrets         int                    `json:"total_secrets"`
	TotalForms           int                    `json:"total_forms"`
	TotalFindings        int                    `json:"total_findings"`
	FindingsByPriority   map[string]int         `json:"findings_by_priority,omitempty"`
	FindingsByCategory   map[string]int         `json:"findings_by_category,omitempty"`
	CriticalFindings     []InterestingFinding   `json:"critical_findings,omitempty"`
	HighPriorityFindings []InterestingFinding   `json:"high_priority_findings,omitempty"`
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
