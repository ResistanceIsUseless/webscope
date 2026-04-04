package output

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

// Styled output manager for modern CLI presentation
type StyledOutput struct {
	writer  io.Writer
	verbose bool

	// Color functions
	success   *color.Color
	info      *color.Color
	warning   *color.Color
	error     *color.Color
	highlight *color.Color
	muted     *color.Color
	bold      *color.Color

	// Icons
	iconCheck  string
	iconInfo   string
	iconWarn   string
	iconError  string
	iconArrow  string
	iconTarget string
}

// NewStyledOutput creates a new styled output manager
func NewStyledOutput(verbose bool) *StyledOutput {
	return &StyledOutput{
		writer:  os.Stdout,
		verbose: verbose,

		// Define color schemes
		success:   color.New(color.FgGreen, color.Bold),
		info:      color.New(color.FgCyan),
		warning:   color.New(color.FgYellow),
		error:     color.New(color.FgRed, color.Bold),
		highlight: color.New(color.FgMagenta),
		muted:     color.New(color.FgHiBlack),
		bold:      color.New(color.Bold),

		// Unicode icons for modern look
		iconCheck:  "✓",
		iconInfo:   "ℹ",
		iconWarn:   "⚠",
		iconError:  "✗",
		iconArrow:  "→",
		iconTarget: "🎯",
	}
}

// PrintBanner prints the application banner
func (s *StyledOutput) PrintBanner(version string) {
	if !s.verbose {
		return
	}

	fmt.Fprintf(os.Stderr, "\n")
	s.bold.Fprintf(os.Stderr, "╭───────────────────────────────────────────╮\n")
	s.bold.Fprintf(os.Stderr, "│ ")
	s.highlight.Fprintf(os.Stderr, "WebScope")
	s.bold.Fprintf(os.Stderr, " v%s", version)
	padding := 33 - len(version)
	fmt.Fprintf(os.Stderr, strings.Repeat(" ", padding))
	s.bold.Fprintf(os.Stderr, "│\n")
	s.bold.Fprintf(os.Stderr, "│ ")
	s.muted.Fprintf(os.Stderr, "Static Web Content Analysis")
	s.bold.Fprintf(os.Stderr, "        │\n")
	s.bold.Fprintf(os.Stderr, "╰───────────────────────────────────────────╯\n")
	fmt.Fprintf(os.Stderr, "\n")
}

// PrintFlowStart prints the flow start message
func (s *StyledOutput) PrintFlowStart(flowType, target string) {
	if !s.verbose {
		return
	}

	s.info.Fprintf(os.Stderr, "%s ", s.iconTarget)
	s.bold.Fprintf(os.Stderr, "Target: ")
	fmt.Fprintf(os.Stderr, "%s\n", target)

	s.info.Fprintf(os.Stderr, "%s ", s.iconArrow)
	s.bold.Fprintf(os.Stderr, "Flow: ")
	s.highlight.Fprintf(os.Stderr, "%s\n", flowType)
	fmt.Fprintf(os.Stderr, "\n")
}

// PrintProgress prints a progress message
func (s *StyledOutput) PrintProgress(message string) {
	if !s.verbose {
		return
	}

	s.muted.Fprintf(os.Stderr, "  %s %s\n", s.iconArrow, message)
}

// PrintPath prints a discovered path
func (s *StyledOutput) PrintPath(url string, status int, source string) {
	// Determine status color
	var statusColor *color.Color
	switch {
	case status >= 200 && status < 300:
		statusColor = s.success
	case status >= 300 && status < 400:
		statusColor = s.info
	case status >= 400 && status < 500:
		statusColor = s.warning
	default:
		statusColor = s.error
	}

	// Print URL with color
	s.highlight.Fprintf(s.writer, "%-60s ", truncateURL(url, 58))

	// Print status code with color
	statusColor.Fprintf(s.writer, "[%d]", status)

	// Print source if verbose
	if s.verbose && source != "" {
		s.muted.Fprintf(s.writer, "  [%s]", source)
	}

	fmt.Fprintf(s.writer, "\n")
}

// PrintEndpoint prints a discovered API endpoint
func (s *StyledOutput) PrintEndpoint(path, endpointType, method string) {
	if !s.verbose {
		return
	}

	// Method color
	var methodColor *color.Color
	switch method {
	case "GET":
		methodColor = s.success
	case "POST":
		methodColor = s.warning
	case "PUT", "PATCH":
		methodColor = s.info
	case "DELETE":
		methodColor = s.error
	default:
		methodColor = s.muted
	}

	s.muted.Fprintf(s.writer, "  └─ ")
	fmt.Fprintf(s.writer, "%-40s ", truncateURL(path, 38))
	methodColor.Fprintf(s.writer, "[%s]", method)
	s.muted.Fprintf(s.writer, "  %s\n", endpointType)
}

// PrintIntegrationStatus prints integration status
func (s *StyledOutput) PrintIntegrationStatus(name string, count int, success bool) {
	if !s.verbose {
		return
	}

	if success {
		s.success.Fprintf(s.writer, "  → %s: %d items sent\n", name, count)
	} else {
		s.warning.Fprintf(s.writer, "  → %s: %d items ready\n", name, count)
	}
}

// PrintSecret prints a discovered secret
func (s *StyledOutput) PrintSecret(value, secretType, source string) {
	if !s.verbose {
		return
	}

	fmt.Fprintf(s.writer, "%s ", value)
	s.warning.Fprintf(s.writer, "[SECRET]")
	s.muted.Fprintf(s.writer, " [%s]", source)
	fmt.Fprintf(s.writer, "\n")
}

// PrintFinding prints a security finding
func (s *StyledOutput) PrintFinding(url, findingType string) {
	if !s.verbose {
		return
	}

	fmt.Fprintf(s.writer, "%s ", url)
	s.error.Fprintf(s.writer, "[FINDING]")
	s.muted.Fprintf(s.writer, " [%s]", findingType)
	fmt.Fprintf(s.writer, "\n")
}

// PrintStats prints statistics summary
func (s *StyledOutput) PrintStats(requestsTotal, requestsSuccess, requestsFailed int, avgLatency, totalTime time.Duration) {
	if !s.verbose {
		return
	}

	fmt.Fprintf(os.Stderr, "\n")
	s.bold.Fprintf(os.Stderr, "╭─ Statistics ─────────────────────────────╮\n")

	// Total requests
	fmt.Fprintf(os.Stderr, "│ ")
	s.bold.Fprintf(os.Stderr, "Total Requests:")
	fmt.Fprintf(os.Stderr, " %d", requestsTotal)
	padding := 25 - len(fmt.Sprintf("%d", requestsTotal))
	fmt.Fprintf(os.Stderr, strings.Repeat(" ", padding))
	fmt.Fprintf(os.Stderr, "│\n")

	// Successful requests
	fmt.Fprintf(os.Stderr, "│ ")
	s.success.Fprintf(os.Stderr, "  %s Successful:", s.iconCheck)
	fmt.Fprintf(os.Stderr, " %d", requestsSuccess)
	padding = 23 - len(fmt.Sprintf("%d", requestsSuccess))
	fmt.Fprintf(os.Stderr, strings.Repeat(" ", padding))
	fmt.Fprintf(os.Stderr, "│\n")

	// Failed requests
	if requestsFailed > 0 {
		fmt.Fprintf(os.Stderr, "│ ")
		s.error.Fprintf(os.Stderr, "  %s Failed:", s.iconError)
		fmt.Fprintf(os.Stderr, " %d", requestsFailed)
		padding = 28 - len(fmt.Sprintf("%d", requestsFailed))
		fmt.Fprintf(os.Stderr, strings.Repeat(" ", padding))
		fmt.Fprintf(os.Stderr, "│\n")
	}

	// Average latency
	if requestsSuccess > 0 {
		fmt.Fprintf(os.Stderr, "│ ")
		s.bold.Fprintf(os.Stderr, "Avg Latency:")
		fmt.Fprintf(os.Stderr, " %v", avgLatency)
		padding = 28 - len(avgLatency.String())
		fmt.Fprintf(os.Stderr, strings.Repeat(" ", padding))
		fmt.Fprintf(os.Stderr, "│\n")
	}

	// Total time
	fmt.Fprintf(os.Stderr, "│ ")
	s.bold.Fprintf(os.Stderr, "Total Time:")
	fmt.Fprintf(os.Stderr, " %v", totalTime)
	padding = 29 - len(totalTime.String())
	fmt.Fprintf(os.Stderr, strings.Repeat(" ", padding))
	fmt.Fprintf(os.Stderr, "│\n")

	s.bold.Fprintf(os.Stderr, "╰──────────────────────────────────────────╯\n")
	fmt.Fprintf(os.Stderr, "\n")
}

// PrintCompletion prints the completion message
func (s *StyledOutput) PrintCompletion(discoveryTime time.Duration) {
	if !s.verbose {
		return
	}

	s.success.Fprintf(os.Stderr, "\n%s ", s.iconCheck)
	s.bold.Fprintf(os.Stderr, "Discovery completed in ")
	s.highlight.Fprintf(os.Stderr, "%v\n", discoveryTime)
}

// PrintError prints an error message
func (s *StyledOutput) PrintError(message string) {
	s.error.Fprintf(os.Stderr, "%s Error: ", s.iconError)
	fmt.Fprintf(os.Stderr, "%s\n", message)
}

// PrintWarning prints a warning message
func (s *StyledOutput) PrintWarning(message string) {
	if !s.verbose {
		return
	}

	s.warning.Fprintf(os.Stderr, "%s Warning: ", s.iconWarn)
	fmt.Fprintf(os.Stderr, "%s\n", message)
}

// PrintInfo prints an info message
func (s *StyledOutput) PrintInfo(message string) {
	if !s.verbose {
		return
	}

	s.info.Fprintf(os.Stderr, "%s ", s.iconInfo)
	fmt.Fprintf(os.Stderr, "%s\n", message)
}

// PrintSection prints a section header
func (s *StyledOutput) PrintSection(title string) {
	if !s.verbose {
		return
	}

	fmt.Fprintf(os.Stderr, "\n")
	s.bold.Fprintf(os.Stderr, "─── %s ", title)
	s.muted.Fprintf(os.Stderr, strings.Repeat("─", 40-len(title)))
	fmt.Fprintf(os.Stderr, "\n\n")
}

// truncateURL truncates a URL to fit within maxLen
func truncateURL(url string, maxLen int) string {
	if len(url) <= maxLen {
		return url
	}
	return "..." + url[len(url)-maxLen+3:]
}
