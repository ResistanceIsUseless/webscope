package modules

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/resistanceisuseless/webscope/pkg/types"
)

// FalsePositiveDetector detects wildcard responses and filters false positives
type FalsePositiveDetector struct {
	httpx       *HTTPXModule
	baselines   map[string]*BaselineResponse
	thresholds  *FilterThresholds
}

// BaselineResponse stores baseline response characteristics for comparison
type BaselineResponse struct {
	StatusCode    int
	ContentLength int
	ContentType   string
	Headers       map[string]string
	Fingerprint   string
}

// FilterThresholds defines when to consider responses as false positives
type FilterThresholds struct {
	MaxLengthDiff     int     // Maximum content length difference to consider same
	MinLengthRatio    float64 // Minimum ratio for different lengths
	StatusCodeWeight  float64 // Weight for status code matching
	ContentTypeWeight float64 // Weight for content type matching
	LengthWeight      float64 // Weight for content length similarity
}

func NewFalsePositiveDetector(timeout time.Duration, rateLimit int) *FalsePositiveDetector {
	return &FalsePositiveDetector{
		httpx:     NewHTTPXModule(20, timeout, rateLimit),
		baselines: make(map[string]*BaselineResponse),
		thresholds: &FilterThresholds{
			MaxLengthDiff:     100,   // Allow 100 byte difference
			MinLengthRatio:    0.95,  // 95% similarity for length
			StatusCodeWeight:  0.4,   // 40% weight for status code
			ContentTypeWeight: 0.3,   // 30% weight for content type
			LengthWeight:      0.3,   // 30% weight for length
		},
	}
}

// GenerateBaseline probes the target with random paths to establish baseline responses
func (fp *FalsePositiveDetector) GenerateBaseline(baseURL string) error {
	baseURL = strings.TrimSuffix(baseURL, "/")
	
	// Generate multiple random paths to get baseline responses
	randomPaths := fp.generateRandomPaths(5)
	var testURLs []string
	
	for _, path := range randomPaths {
		testURLs = append(testURLs, baseURL+"/"+path)
	}
	
	// Probe random paths with httpx
	results, err := fp.httpx.ProbeBulk(testURLs)
	if err != nil {
		return fmt.Errorf("failed to generate baseline: %w", err)
	}
	
	// Analyze responses and create baselines
	fp.analyzeBaselineResponses(baseURL, results)
	
	return nil
}

// IsLikelyFalsePositive compares a result against known baselines
func (fp *FalsePositiveDetector) IsLikelyFalsePositive(baseURL string, path types.Path) bool {
	baseURL = strings.TrimSuffix(baseURL, "/")
	
	baseline, exists := fp.baselines[baseURL]
	if !exists {
		// No baseline available, assume valid
		return false
	}
	
	// Calculate similarity score
	score := fp.calculateSimilarityScore(baseline, &path)
	
	// If similarity score is too high, it's likely a false positive
	return score > 0.8
}

// FilterFalsePositives removes likely false positives from discovery results
func (fp *FalsePositiveDetector) FilterFalsePositives(baseURL string, result *types.DiscoveryResult) *types.DiscoveryResult {
	filtered := &types.DiscoveryResult{
		Paths:        []types.Path{},
		Endpoints:    []types.Endpoint{},
		Technologies: result.Technologies,
		Secrets:      result.Secrets,
		Forms:        result.Forms,
		Parameters:   result.Parameters,
	}
	
	// Filter paths
	for _, path := range result.Paths {
		if !fp.IsLikelyFalsePositive(baseURL, path) {
			filtered.Paths = append(filtered.Paths, path)
		}
	}
	
	// Filter endpoints based on remaining valid paths
	validPaths := make(map[string]bool)
	for _, path := range filtered.Paths {
		pathOnly := strings.TrimPrefix(path.URL, baseURL)
		validPaths[pathOnly] = true
	}
	
	for _, endpoint := range result.Endpoints {
		if validPaths[endpoint.Path] {
			filtered.Endpoints = append(filtered.Endpoints, endpoint)
		}
	}
	
	return filtered
}

func (fp *FalsePositiveDetector) generateRandomPaths(count int) []string {
	var paths []string
	
	for i := 0; i < count; i++ {
		// Generate random string of varying lengths
		length := 8 + (i * 2) // 8, 10, 12, 14, 16 characters
		randomBytes := make([]byte, length/2)
		rand.Read(randomBytes)
		randomPath := hex.EncodeToString(randomBytes)
		
		paths = append(paths, randomPath)
		
		// Also try with common extensions
		paths = append(paths, randomPath+".html")
		paths = append(paths, randomPath+".php")
		paths = append(paths, randomPath+".js")
	}
	
	return paths
}

func (fp *FalsePositiveDetector) analyzeBaselineResponses(baseURL string, results []*HTTPXResult) {
	// Group responses by fingerprint
	responseGroups := make(map[string][]*HTTPXResult)
	
	for _, result := range results {
		fingerprint := fp.createResponseFingerprint(result)
		responseGroups[fingerprint] = append(responseGroups[fingerprint], result)
	}
	
	// Find the most common response pattern (likely the wildcard response)
	var mostCommonFingerprint string
	var maxCount int
	
	for fingerprint, group := range responseGroups {
		if len(group) > maxCount {
			maxCount = len(group)
			mostCommonFingerprint = fingerprint
		}
	}
	
	// Create baseline from most common response pattern
	if maxCount >= 2 && len(responseGroups[mostCommonFingerprint]) > 0 {
		sample := responseGroups[mostCommonFingerprint][0]
		
		fp.baselines[baseURL] = &BaselineResponse{
			StatusCode:    sample.StatusCode,
			ContentLength: sample.ContentLength,
			ContentType:   sample.ContentType,
			Fingerprint:   mostCommonFingerprint,
		}
	}
}

func (fp *FalsePositiveDetector) createResponseFingerprint(result *HTTPXResult) string {
	// Create a fingerprint based on key response characteristics
	return fmt.Sprintf("%d:%s:%d", 
		result.StatusCode, 
		result.ContentType, 
		fp.normalizeLength(result.ContentLength))
}

func (fp *FalsePositiveDetector) normalizeLength(length int) int {
	// Group similar lengths together (within 100 bytes)
	return (length / 100) * 100
}

func (fp *FalsePositiveDetector) calculateSimilarityScore(baseline *BaselineResponse, path *types.Path) float64 {
	var score float64
	
	// Status code similarity
	if baseline.StatusCode == path.Status {
		score += fp.thresholds.StatusCodeWeight
	}
	
	// Content type similarity
	if strings.EqualFold(baseline.ContentType, path.ContentType) {
		score += fp.thresholds.ContentTypeWeight
	}
	
	// Content length similarity
	lengthDiff := abs(baseline.ContentLength - path.Length)
	if lengthDiff <= fp.thresholds.MaxLengthDiff {
		score += fp.thresholds.LengthWeight
	} else {
		// Calculate ratio-based similarity for larger differences
		minLength := min(baseline.ContentLength, path.Length)
		maxLength := max(baseline.ContentLength, path.Length)
		if minLength > 0 {
			ratio := float64(minLength) / float64(maxLength)
			if ratio >= fp.thresholds.MinLengthRatio {
				score += fp.thresholds.LengthWeight * ratio
			}
		}
	}
	
	return score
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}