package output

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/resistanceisuseless/webscope/pkg/types"
)

// SimpleWriter outputs only successful findings, one per line to stdout
type SimpleWriter struct {
	writer          *bufio.Writer
	extendedDetails bool
}

// NewSimpleWriter creates a simple writer that outputs findings to stdout
func NewSimpleWriter() *SimpleWriter {
	return &SimpleWriter{
		writer:          bufio.NewWriter(os.Stdout),
		extendedDetails: false,
	}
}

// NewSimpleWriterWithDetails creates a simple writer with extended details
func NewSimpleWriterWithDetails(extendedDetails bool) *SimpleWriter {
	return &SimpleWriter{
		writer:          bufio.NewWriter(os.Stdout),
		extendedDetails: extendedDetails,
	}
}

// WriteResult processes a discovery result and outputs only successful findings
func (sw *SimpleWriter) WriteResult(result types.EngineResult) error {
	if result.Error != nil {
		return nil // Skip failed results silently
	}

	// Output successful paths (200 status codes) - from all discovery modules
	for _, path := range result.Discovery.Paths {
		if path.Status >= 200 && path.Status < 400 {
			if sw.extendedDetails {
				// Format: URL [STATUS:200] [MODULE:httpx-lib]
				sw.writer.WriteString(fmt.Sprintf("%s [STATUS:%d] [MODULE:%s]\n", 
					path.URL, path.Status, path.Source))
			} else {
				sw.writer.WriteString(path.URL + "\n")
			}
		}
	}

	// Output discovered endpoints - from robots, sitemap, javascript, advanced-javascript
	for _, endpoint := range result.Discovery.Endpoints {
		if endpoint.Path != "" && endpoint.Path != "/" {
			var fullURL string
			// Construct full URL if we have the target domain
			if strings.HasPrefix(endpoint.Path, "http") {
				fullURL = endpoint.Path
			} else {
				// Build URL from target + path
				baseURL := result.Target.URL
				if strings.HasSuffix(baseURL, "/") {
					baseURL = strings.TrimSuffix(baseURL, "/")
				}
				if !strings.HasPrefix(endpoint.Path, "/") {
					endpoint.Path = "/" + endpoint.Path
				}
				fullURL = baseURL + endpoint.Path
			}
			
			if sw.extendedDetails {
				// For endpoints, show type and source module
				sw.writer.WriteString(fmt.Sprintf("%s [TYPE:%s] [MODULE:%s]\n",
					fullURL, endpoint.Type, endpoint.Source))
			} else {
				sw.writer.WriteString(fullURL + "\n")
			}
		}
	}

	// Output GraphQL endpoints - from advanced-javascript module
	for _, schema := range result.Discovery.GraphQLSchemas {
		if schema.Endpoint != "" {
			var fullURL string
			// Construct full URL for GraphQL endpoint
			if strings.HasPrefix(schema.Endpoint, "http") {
				fullURL = schema.Endpoint
			} else {
				// Build URL from target + endpoint path
				baseURL := result.Target.URL
				if strings.HasSuffix(baseURL, "/") {
					baseURL = strings.TrimSuffix(baseURL, "/")
				}
				if !strings.HasPrefix(schema.Endpoint, "/") {
					schema.Endpoint = "/" + schema.Endpoint
				}
				fullURL = baseURL + schema.Endpoint
			}
			
			if sw.extendedDetails {
				sw.writer.WriteString(fmt.Sprintf("%s [TYPE:GraphQL] [MODULE:%s]\n",
					fullURL, schema.Source))
			} else {
				sw.writer.WriteString(fullURL + "\n")
			}
		}
	}

	// Output WebSocket endpoints - from advanced-javascript module
	for _, ws := range result.Discovery.WebSockets {
		if ws.URL != "" {
			if sw.extendedDetails {
				sw.writer.WriteString(fmt.Sprintf("%s [TYPE:WebSocket] [MODULE:%s]\n",
					ws.URL, ws.Source))
			} else {
				sw.writer.WriteString(ws.URL + "\n")
			}
		}
	}

	// Output form action URLs - from httpx-lib, katana-lib modules
	for _, form := range result.Discovery.Forms {
		if form.Action != "" && form.Action != "#" {
			var fullURL string
			// Construct full URL for form action
			if strings.HasPrefix(form.Action, "http") {
				fullURL = form.Action
			} else {
				// Build URL from target + action path
				baseURL := result.Target.URL
				if strings.HasSuffix(baseURL, "/") {
					baseURL = strings.TrimSuffix(baseURL, "/")
				}
				if !strings.HasPrefix(form.Action, "/") {
					form.Action = "/" + form.Action
				}
				fullURL = baseURL + form.Action
			}
			
			if sw.extendedDetails {
				sw.writer.WriteString(fmt.Sprintf("%s [TYPE:Form-%s] [MODULE:%s]\n",
					fullURL, form.Method, form.Source))
			} else {
				sw.writer.WriteString(fullURL + "\n")
			}
		}
	}

	// Output secrets/patterns with actionable context - from patterns module
	for _, secret := range result.Discovery.Secrets {
		// Output high-value secrets that might contain URLs or actionable data
		if (secret.Type == "url" || secret.Type == "endpoint") && secret.Value != "" {
			if sw.extendedDetails {
				sw.writer.WriteString(fmt.Sprintf("%s [TYPE:Secret-%s] [MODULE:%s]\n",
					secret.Value, secret.Type, secret.Source))
			} else {
				sw.writer.WriteString(secret.Value + "\n")
			}
		} else if secret.Context != "" && (secret.Strength == "high" || secret.Type == "serialization") {
			// Output pattern match context for high-value findings
			if sw.extendedDetails {
				sw.writer.WriteString(fmt.Sprintf("%s [TYPE:Pattern-%s] [MODULE:%s]\n",
					secret.Context, secret.Type, secret.Source))
			} else {
				sw.writer.WriteString(secret.Context + "\n")
			}
		}
	}

	// Output critical and high priority interesting findings - from patterns, findings modules
	for _, finding := range result.Discovery.Findings {
		if finding.Priority == "critical" || finding.Priority == "high" {
			if finding.URL != "" {
				if sw.extendedDetails {
					sw.writer.WriteString(fmt.Sprintf("%s [PRIORITY:%s] [CATEGORY:%s] [MODULE:%s]\n",
						finding.URL, finding.Priority, finding.Category, finding.Source))
				} else {
					sw.writer.WriteString(finding.URL + "\n")
				}
			} else if finding.Evidence != "" {
				// Output evidence for serialization, secrets, and other actionable patterns
				if sw.extendedDetails {
					sw.writer.WriteString(fmt.Sprintf("%s [PRIORITY:%s] [CATEGORY:%s] [MODULE:%s]\n",
						finding.Evidence, finding.Priority, finding.Category, finding.Source))
				} else {
					sw.writer.WriteString(finding.Evidence + "\n")
				}
			}
		}
	}

	// Flush after each result to ensure output appears immediately
	return sw.writer.Flush()
}

// Close flushes any remaining data
func (sw *SimpleWriter) Close() error {
	return sw.writer.Flush()
}

// GetStatistics returns empty stats for simple mode
func (sw *SimpleWriter) GetStatistics() types.Statistics {
	return types.Statistics{}
}