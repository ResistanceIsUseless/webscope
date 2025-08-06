package output

import (
	"bufio"
	"os"
	"strings"

	"github.com/resistanceisuseless/webscope/pkg/types"
)

// SimpleWriter outputs only successful findings, one per line to stdout
type SimpleWriter struct {
	writer *bufio.Writer
}

// NewSimpleWriter creates a simple writer that outputs findings to stdout
func NewSimpleWriter() *SimpleWriter {
	return &SimpleWriter{
		writer: bufio.NewWriter(os.Stdout),
	}
}

// WriteResult processes a discovery result and outputs only successful findings
func (sw *SimpleWriter) WriteResult(result types.EngineResult) error {
	if result.Error != nil {
		return nil // Skip failed results silently
	}

	// Output successful paths (200 status codes)
	for _, path := range result.Discovery.Paths {
		if path.Status >= 200 && path.Status < 400 {
			sw.writer.WriteString(path.URL + "\n")
		}
	}

	// Output discovered endpoints
	for _, endpoint := range result.Discovery.Endpoints {
		if endpoint.Path != "" && endpoint.Path != "/" {
			// Construct full URL if we have the target domain
			if strings.HasPrefix(endpoint.Path, "http") {
				sw.writer.WriteString(endpoint.Path + "\n")
			} else {
				// Build URL from target + path
				baseURL := result.Target.URL
				if strings.HasSuffix(baseURL, "/") {
					baseURL = strings.TrimSuffix(baseURL, "/")
				}
				if !strings.HasPrefix(endpoint.Path, "/") {
					endpoint.Path = "/" + endpoint.Path
				}
				sw.writer.WriteString(baseURL + endpoint.Path + "\n")
			}
		}
	}

	// Output pattern matches (from patterns module)
	for _, secret := range result.Discovery.Secrets {
		if secret.Source == "pattern-analysis" && secret.Context != "" {
			// Output the pattern match context
			sw.writer.WriteString(secret.Context + "\n")
		}
	}

	// Output interesting findings that are actionable
	for _, finding := range result.Discovery.Findings {
		if finding.Priority == "critical" || finding.Priority == "high" {
			if finding.URL != "" {
				sw.writer.WriteString(finding.URL + "\n")
			} else if finding.Evidence != "" {
				sw.writer.WriteString(finding.Evidence + "\n")
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