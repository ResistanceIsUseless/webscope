package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/modules"
	"github.com/resistanceisuseless/webscope/pkg/types"
)

// StreamingWriter handles concurrent streaming output of results
type StreamingWriter struct {
	writer        *bufio.Writer
	encoder       *json.Encoder
	mu            sync.Mutex
	file          *os.File
	metadata      types.Metadata
	statistics    types.Statistics
	statsMu       sync.RWMutex
	format        string // "jsonl" or "json"
	firstRecord   bool   // Track if this is the first record for JSON format
}

// NewStreamingWriter creates a new streaming writer
func NewStreamingWriter(outputPath string, format string) (*StreamingWriter, error) {
	var writer io.Writer
	var file *os.File

	if outputPath == "" || outputPath == "-" {
		writer = os.Stdout
	} else {
		f, err := os.Create(outputPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %w", err)
		}
		file = f
		writer = f
	}

	sw := &StreamingWriter{
		writer:      bufio.NewWriterSize(writer, 64*1024), // 64KB buffer
		file:        file,
		format:      format,
		firstRecord: true,
		metadata: types.Metadata{
			Timestamp: time.Now(),
			Version:   "1.0.0",
		},
	}

	if format == "json" {
		// For standard JSON, write opening structure
		sw.writeRaw(`{"metadata":`)
		sw.encoder = json.NewEncoder(sw.writer)
		sw.encoder.Encode(sw.metadata)
		sw.writeRaw(`,"discoveries":[`)
	}

	return sw, nil
}

// WriteResult writes a single discovery result
func (sw *StreamingWriter) WriteResult(result types.EngineResult) error {
	if result.Error != nil {
		return nil // Skip failed results
	}

	sw.mu.Lock()
	defer sw.mu.Unlock()

	// Update statistics
	sw.statsMu.Lock()
	sw.statistics.TotalPaths += len(result.Discovery.Paths)
	sw.statistics.TotalEndpoints += len(result.Discovery.Endpoints)
	sw.statistics.TotalSecrets += len(result.Discovery.Secrets)
	sw.statistics.TotalForms += len(result.Discovery.Forms)
	sw.statistics.TotalFindings += len(result.Discovery.Findings)
	
	// Update findings statistics
	if sw.statistics.FindingsByPriority == nil {
		sw.statistics.FindingsByPriority = make(map[string]int)
	}
	if sw.statistics.FindingsByCategory == nil {
		sw.statistics.FindingsByCategory = make(map[string]int)
	}
	
	for _, finding := range result.Discovery.Findings {
		sw.statistics.FindingsByPriority[finding.Priority]++
		sw.statistics.FindingsByCategory[finding.Category]++
		
		if finding.Priority == "critical" {
			sw.statistics.CriticalFindings = append(sw.statistics.CriticalFindings, finding)
		} else if finding.Priority == "high" {
			sw.statistics.HighPriorityFindings = append(sw.statistics.HighPriorityFindings, finding)
		}
	}
	sw.statsMu.Unlock()

	// Create discovery entry with all discovery data
	discovery := types.Discovery{
		Domain:         result.Target.Domain,
		Paths:          result.Discovery.Paths,
		Endpoints:      result.Discovery.Endpoints,
		Forms:          result.Discovery.Forms,
		Parameters:     result.Discovery.Parameters,
		Secrets:        result.Discovery.Secrets,
		GraphQLSchemas: result.Discovery.GraphQLSchemas,
		WebSockets:     result.Discovery.WebSockets,
		Findings:       result.Discovery.Findings,
	}

	if sw.format == "jsonl" {
		// JSON Lines format - each line is a complete record
		record := map[string]interface{}{
			"timestamp": time.Now(),
			"target":    result.Target,
			"discovery": discovery,
		}

		encoder := json.NewEncoder(sw.writer)
		if err := encoder.Encode(record); err != nil {
			return fmt.Errorf("failed to encode result: %w", err)
		}
	} else {
		// Standard JSON array format
		if !sw.firstRecord {
			sw.writeRaw(",")
		} else {
			sw.firstRecord = false
		}

		encoder := json.NewEncoder(sw.writer)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(discovery); err != nil {
			return fmt.Errorf("failed to encode result: %w", err)
		}
	}

	// Flush buffer to ensure data is written
	return sw.writer.Flush()
}

// Close finalizes the output and closes the file
func (sw *StreamingWriter) Close() error {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	if sw.format == "json" {
		// Close JSON structure with findings summary
		sw.writeRaw(`],"statistics":`)
		encoder := json.NewEncoder(sw.writer)
		encoder.SetIndent("", "  ")
		encoder.Encode(sw.statistics)
		
		// Add findings summary
		if sw.statistics.TotalFindings > 0 {
			findingsSummary := sw.generateFindingsSummary()
			sw.writeRaw(`,"findings_summary":`)
			encoder.Encode(findingsSummary)
		}
		
		sw.writeRaw("}")
	} else if sw.format == "jsonl" {
		// Write final statistics and findings summary as last lines
		summary := map[string]interface{}{
			"timestamp":  time.Now(),
			"type":       "summary",
			"statistics": sw.statistics,
			"metadata":   sw.metadata,
		}
		
		// Add findings summary if we have findings
		if sw.statistics.TotalFindings > 0 {
			findingsSummary := sw.generateFindingsSummary()
			summary["findings_summary"] = findingsSummary
		}
		
		encoder := json.NewEncoder(sw.writer)
		encoder.Encode(summary)
	}

	// Flush any remaining data
	if err := sw.writer.Flush(); err != nil {
		return err
	}

	// Close file if not stdout
	if sw.file != nil {
		return sw.file.Close()
	}

	return nil
}

// GetStatistics returns current statistics
func (sw *StreamingWriter) GetStatistics() types.Statistics {
	sw.statsMu.RLock()
	defer sw.statsMu.RUnlock()
	return sw.statistics
}

// generateFindingsSummary creates a summary of interesting findings
func (sw *StreamingWriter) generateFindingsSummary() map[string]interface{} {
	sw.statsMu.RLock()
	defer sw.statsMu.RUnlock()
	
	// Collect all findings for aggregation
	var allFindings []types.InterestingFinding
	allFindings = append(allFindings, sw.statistics.CriticalFindings...)
	allFindings = append(allFindings, sw.statistics.HighPriorityFindings...)
	
	// Use FindingsAggregator to create summary
	aggregator := modules.NewFindingsAggregator()
	summary := aggregator.GetFindingsSummary(allFindings)
	
	// Add additional summary information
	summary["total_targets"] = sw.metadata.Targets
	summary["scan_timestamp"] = sw.metadata.Timestamp
	summary["scan_version"] = sw.metadata.Version
	
	return summary
}

// writeRaw writes raw string to buffer
func (sw *StreamingWriter) writeRaw(s string) {
	sw.writer.WriteString(s)
}
