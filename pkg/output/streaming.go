package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/types"
)

// StreamingWriter handles concurrent streaming output of results
type StreamingWriter struct {
	writer     *bufio.Writer
	encoder    *json.Encoder
	mu         sync.Mutex
	file       *os.File
	metadata   types.Metadata
	statistics types.Statistics
	statsMu    sync.RWMutex
	format     string // "jsonl" or "json"
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
		writer: bufio.NewWriterSize(writer, 64*1024), // 64KB buffer
		file:   file,
		format: format,
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
	sw.statsMu.Unlock()

	// Create discovery entry
	discovery := types.Discovery{
		Domain:     result.Target.Domain,
		Paths:      result.Discovery.Paths,
		Endpoints:  result.Discovery.Endpoints,
		Forms:      result.Discovery.Forms,
		Parameters: result.Discovery.Parameters,
		Secrets:    result.Discovery.Secrets,
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
		if sw.statistics.TotalPaths > 0 || sw.statistics.TotalEndpoints > 0 {
			sw.writeRaw(",")
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
		// Close JSON structure
		sw.writeRaw(`],"statistics":`)
		encoder := json.NewEncoder(sw.writer)
		encoder.SetIndent("", "  ")
		encoder.Encode(sw.statistics)
		sw.writeRaw("}")
	} else if sw.format == "jsonl" {
		// Write final statistics as last line
		summary := map[string]interface{}{
			"timestamp":  time.Now(),
			"type":       "summary",
			"statistics": sw.statistics,
			"metadata":   sw.metadata,
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

// writeRaw writes raw string to buffer
func (sw *StreamingWriter) writeRaw(s string) {
	sw.writer.WriteString(s)
}
