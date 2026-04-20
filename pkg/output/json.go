package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// JSONOutput handles structured JSON output for machine parsing
type JSONOutput struct {
	writer     io.Writer
	pretty     bool
	includeAll bool
}

// NewJSONOutput creates a new JSON output handler
func NewJSONOutput(writer io.Writer, pretty bool, includeAll bool) *JSONOutput {
	return &JSONOutput{
		writer:     writer,
		pretty:     pretty,
		includeAll: includeAll,
	}
}

// JSONResult represents the complete scan result in JSON format
type JSONResult struct {
	Target         string           `json:"target"`
	Flow           string           `json:"flow"`
	StartTime      time.Time        `json:"start_time"`
	EndTime        time.Time        `json:"end_time"`
	DiscoveryTime  string           `json:"discovery_time"`
	Stats          JSONStats        `json:"stats"`
	Paths          []JSONPath       `json:"paths,omitempty"`
	Endpoints      []JSONEndpoint   `json:"endpoints,omitempty"`
	Secrets        []JSONSecret     `json:"secrets,omitempty"`
	Findings       []JSONFinding    `json:"findings,omitempty"`
	Technologies   []JSONTechnology `json:"technologies,omitempty"`
	Forms          []JSONForm       `json:"forms,omitempty"`
	Parameters     []JSONParameter  `json:"parameters,omitempty"`
	GraphQLSchemas []JSONGraphQL    `json:"graphql_schemas,omitempty"`
	WebSockets     []JSONWebSocket  `json:"websockets,omitempty"`
}

// JSONStats represents statistics in JSON format
type JSONStats struct {
	RequestsTotal   int   `json:"requests_total"`
	RequestsSuccess int   `json:"requests_success"`
	RequestsFailed  int   `json:"requests_failed"`
	AvgLatencyMs    int64 `json:"avg_latency_ms"`
}

// JSONPath represents a discovered path in JSON format
type JSONPath struct {
	URL         string `json:"url"`
	Status      int    `json:"status"`
	Method      string `json:"method,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Title       string `json:"title,omitempty"`
	Source      string `json:"source"`
}

// JSONEndpoint represents a discovered endpoint in JSON format
type JSONEndpoint struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Method string `json:"method,omitempty"`
	Source string `json:"source"`
}

// JSONSecret represents a discovered secret in JSON format
type JSONSecret struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Context string `json:"context,omitempty"`
	Source  string `json:"source"`
}

// JSONFinding represents a security finding in JSON format
type JSONFinding struct {
	URL        string                 `json:"url"`
	Type       string                 `json:"type"`
	Severity   string                 `json:"severity"`
	Details    string                 `json:"details,omitempty"`
	Category   string                 `json:"category,omitempty"`
	Title      string                 `json:"title,omitempty"`
	Evidence   string                 `json:"evidence,omitempty"`
	Confidence string                 `json:"confidence,omitempty"`
	References []string               `json:"references,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// JSONTechnology represents a detected technology in JSON format
type JSONTechnology struct {
	Name     string `json:"name"`
	Category string `json:"category,omitempty"`
	Version  string `json:"version,omitempty"`
	Source   string `json:"source"`
}

// JSONForm represents a discovered form in JSON format
type JSONForm struct {
	Action string          `json:"action"`
	Method string          `json:"method"`
	Inputs []JSONFormInput `json:"inputs,omitempty"`
	Source string          `json:"source"`
}

// JSONFormInput represents a form input field
type JSONFormInput struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value,omitempty"`
}

// JSONParameter represents a discovered parameter in JSON format
type JSONParameter struct {
	Name   string `json:"name"`
	Type   string `json:"type,omitempty"`
	Source string `json:"source"`
}

// JSONGraphQL represents a discovered GraphQL endpoint in JSON format
type JSONGraphQL struct {
	Endpoint      string   `json:"endpoint"`
	Queries       []string `json:"queries,omitempty"`
	Mutations     []string `json:"mutations,omitempty"`
	Subscriptions []string `json:"subscriptions,omitempty"`
	Source        string   `json:"source"`
}

// JSONWebSocket represents a discovered WebSocket endpoint in JSON format
type JSONWebSocket struct {
	URL         string `json:"url"`
	Protocol    string `json:"protocol,omitempty"`
	Subprotocol string `json:"subprotocol,omitempty"`
	Source      string `json:"source"`
}

// ResultData holds all the data needed for JSON output
type ResultData struct {
	Target        string
	Flow          string
	StartTime     time.Time
	EndTime       time.Time
	DiscoveryTime time.Duration
	Stats         struct {
		RequestsTotal   int
		RequestsSuccess int
		RequestsFailed  int
		AvgLatencyMs    int64
	}
	Paths          []PathData
	Endpoints      []EndpointData
	Secrets        []SecretData
	Findings       []FindingData
	Technologies   []TechnologyData
	Forms          []FormData
	Parameters     []ParameterData
	GraphQLSchemas []GraphQLData
	WebSockets     []WebSocketData
}

// PathData represents path data for JSON output
type PathData struct {
	URL         string
	Status      int
	Method      string
	ContentType string
	Title       string
	Source      string
}

// EndpointData represents endpoint data for JSON output
type EndpointData struct {
	Path   string
	Type   string
	Method string
	Source string
}

// SecretData represents secret data for JSON output
type SecretData struct {
	Type    string
	Value   string
	Context string
	Source  string
}

// FindingData represents finding data for JSON output
type FindingData struct {
	URL        string
	Type       string
	Severity   string
	Details    string
	Category   string
	Title      string
	Evidence   string
	Confidence string
	References []string
	Metadata   map[string]interface{}
}

// TechnologyData represents technology data for JSON output
type TechnologyData struct {
	Name     string
	Category string
	Version  string
	Source   string
}

// FormData represents form data for JSON output
type FormData struct {
	Action string
	Method string
	Inputs []FormInputData
	Source string
}

// FormInputData represents form input data
type FormInputData struct {
	Name  string
	Type  string
	Value string
}

// ParameterData represents parameter data for JSON output
type ParameterData struct {
	Name   string
	Type   string
	Source string
}

// GraphQLData represents GraphQL data for JSON output
type GraphQLData struct {
	Endpoint      string
	Queries       []string
	Mutations     []string
	Subscriptions []string
	Source        string
}

// WebSocketData represents WebSocket data for JSON output
type WebSocketData struct {
	URL         string
	Protocol    string
	Subprotocol string
	Source      string
}

// OutputResult writes the complete result as JSON
func (j *JSONOutput) OutputResult(data ResultData) error {
	result := JSONResult{
		Target:        data.Target,
		Flow:          data.Flow,
		StartTime:     data.StartTime,
		EndTime:       data.EndTime,
		DiscoveryTime: data.DiscoveryTime.Round(time.Millisecond).String(),
		Stats: JSONStats{
			RequestsTotal:   data.Stats.RequestsTotal,
			RequestsSuccess: data.Stats.RequestsSuccess,
			RequestsFailed:  data.Stats.RequestsFailed,
			AvgLatencyMs:    data.Stats.AvgLatencyMs,
		},
	}

	// Always include paths
	for _, p := range data.Paths {
		result.Paths = append(result.Paths, JSONPath{
			URL:         p.URL,
			Status:      p.Status,
			Method:      p.Method,
			ContentType: p.ContentType,
			Title:       p.Title,
			Source:      p.Source,
		})
	}

	// Include endpoints if any or includeAll is true
	if len(data.Endpoints) > 0 || j.includeAll {
		for _, e := range data.Endpoints {
			result.Endpoints = append(result.Endpoints, JSONEndpoint{
				Path:   e.Path,
				Type:   e.Type,
				Method: e.Method,
				Source: e.Source,
			})
		}
	}

	// Include secrets if any or includeAll is true
	if len(data.Secrets) > 0 || j.includeAll {
		for _, s := range data.Secrets {
			result.Secrets = append(result.Secrets, JSONSecret{
				Type:    s.Type,
				Value:   s.Value,
				Context: s.Context,
				Source:  s.Source,
			})
		}
	}

	// Include findings if any or includeAll is true
	if len(data.Findings) > 0 || j.includeAll {
		for _, f := range data.Findings {
			result.Findings = append(result.Findings, JSONFinding{
				URL:        f.URL,
				Type:       f.Type,
				Severity:   f.Severity,
				Details:    f.Details,
				Category:   f.Category,
				Title:      f.Title,
				Evidence:   f.Evidence,
				Confidence: f.Confidence,
				References: f.References,
				Metadata:   f.Metadata,
			})
		}
	}

	// Include technologies
	if len(data.Technologies) > 0 || j.includeAll {
		for _, t := range data.Technologies {
			result.Technologies = append(result.Technologies, JSONTechnology{
				Name:     t.Name,
				Category: t.Category,
				Version:  t.Version,
				Source:   t.Source,
			})
		}
	}

	// Include forms
	if len(data.Forms) > 0 || j.includeAll {
		for _, f := range data.Forms {
			jf := JSONForm{
				Action: f.Action,
				Method: f.Method,
				Source: f.Source,
			}
			for _, inp := range f.Inputs {
				jf.Inputs = append(jf.Inputs, JSONFormInput{
					Name:  inp.Name,
					Type:  inp.Type,
					Value: inp.Value,
				})
			}
			result.Forms = append(result.Forms, jf)
		}
	}

	// Include parameters
	if len(data.Parameters) > 0 || j.includeAll {
		for _, p := range data.Parameters {
			result.Parameters = append(result.Parameters, JSONParameter{
				Name:   p.Name,
				Type:   p.Type,
				Source: p.Source,
			})
		}
	}

	// Include GraphQL schemas
	if len(data.GraphQLSchemas) > 0 || j.includeAll {
		for _, g := range data.GraphQLSchemas {
			result.GraphQLSchemas = append(result.GraphQLSchemas, JSONGraphQL{
				Endpoint:      g.Endpoint,
				Queries:       g.Queries,
				Mutations:     g.Mutations,
				Subscriptions: g.Subscriptions,
				Source:        g.Source,
			})
		}
	}

	// Include WebSocket endpoints
	if len(data.WebSockets) > 0 || j.includeAll {
		for _, ws := range data.WebSockets {
			result.WebSockets = append(result.WebSockets, JSONWebSocket{
				URL:         ws.URL,
				Protocol:    ws.Protocol,
				Subprotocol: ws.Subprotocol,
				Source:      ws.Source,
			})
		}
	}

	var output []byte
	if j.pretty {
		output, _ = json.MarshalIndent(result, "", "  ")
	} else {
		output, _ = json.Marshal(result)
	}

	_, err := j.writer.Write(output)
	if err != nil {
		return err
	}

	if j.pretty {
		_, err = j.writer.Write([]byte("\n"))
	}

	return err
}

// OutputPaths outputs just the paths as JSON Lines format
func (j *JSONOutput) OutputPaths(paths []PathData) error {
	for _, p := range paths {
		output, err := json.Marshal(JSONPath{
			URL:         p.URL,
			Status:      p.Status,
			Method:      p.Method,
			ContentType: p.ContentType,
			Title:       p.Title,
			Source:      p.Source,
		})
		if err != nil {
			return err
		}
		if _, err := j.writer.Write(output); err != nil {
			return err
		}
		if _, err := j.writer.Write([]byte("\n")); err != nil {
			return err
		}
	}
	return nil
}

// CreateJSONFileOutput creates a JSON output that writes to a file
func CreateJSONFileOutput(filePath string, pretty bool, includeAll bool) (*JSONOutput, error) {
	var writer io.Writer = os.Stdout

	if filePath != "" && filePath != "-" {
		f, err := os.Create(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %w", err)
		}
		writer = f
	}

	return NewJSONOutput(writer, pretty, includeAll), nil
}
