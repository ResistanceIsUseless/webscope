# WebScope

[![Version](https://img.shields.io/badge/version-1.2.0-blue.svg)](https://github.com/ResistanceIsUseless/webscope/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/resistanceisuseless/webscope)](https://goreportcard.com/report/github.com/resistanceisuseless/webscope)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

WebScope is a **static web content analysis tool** designed for security researchers and penetration testers. It performs deep analysis of known web targets through static techniques including path bruteforcing, JavaScript analysis, and historical data mining. WebScope complements active crawling tools like Katana by focusing on **static analysis** rather than dynamic crawling.

## Features

- **Multiple Input Formats**: Supports stdin, text files, nmap XML exports, and JSON
- **Flexible Target Parsing**: Accepts URLs, host:port pairs, IP addresses, and domain names  
- **Modular Discovery**: HTTP probing, robots.txt parsing, path bruteforcing, JavaScript analysis
- **Advanced JavaScript Analysis**: Deep static analysis using jsluice for GraphQL schemas, WebSocket endpoints, and secrets
- **Enhanced False Positive Detection**: Machine learning-based pattern recognition to filter wildcard responses
- **Entropy-Based Secret Detection**: Advanced secret classification with Shannon entropy analysis
- **Streaming Output**: Real-time result streaming with JSONL and JSON formats
- **Data Loss Prevention**: Results written immediately to prevent loss on crashes
- **Graceful Shutdown**: Signal handling to save partial results on interruption
- **Rate Limiting**: Built-in rate limiting to respect target infrastructure
- **Concurrent Processing**: Worker pools for parallel target analysis

## Installation

```bash
# Install via go install
go install github.com/resistanceisuseless/webscope@latest

# Or build from source
git clone https://github.com/resistanceisuseless/webscope
cd webscope
go build -o webscope
```

## Usage

### Basic Usage
```bash
# Single target via stdin
echo "https://example.com" | webscope

# Multiple targets from file
webscope -i targets.txt

# Nmap XML input
webscope -i nmap_results.xml

# Custom options with streaming output
webscope -i targets.txt -o results.jsonl -of jsonl -w 10 -r 50 -m http,robots,paths -v

# Standard JSON format (non-streaming)
webscope -i targets.txt -o results.json -of json -v
```

### Input Formats

**Stdin/Text Files:**
```
https://example.com
example.com:443
192.168.1.100:8080
subdomain.example.com
```

**Nmap XML:** Export nmap results with `-oX` flag
**JSON:** SubScope output or custom JSON format

### Command Line Options

- `-i`: Input file (default: stdin)
- `-o`: Output file (default: stdout)  
- `-of`: Output format: jsonl (streaming JSON Lines) or json (standard JSON) (default: jsonl)
- `-w`: Number of workers (default: 20)
- `-r`: Rate limit requests per second (default: 20)
- `-t`: HTTP timeout (default: 30s)
- `-m`: Discovery modules (default: "http,robots,sitemap,paths,javascript")
- `-v`: Verbose output

### Discovery Modules

- **http**: Basic HTTP probing and technology identification
- **robots**: robots.txt parsing for allowed/disallowed paths
- **sitemap**: XML sitemap discovery and parsing
- **paths**: Path bruteforcing with smart variations, common endpoints, and enhanced false positive detection
- **javascript**: JavaScript file analysis for endpoints and secrets
- **advanced-javascript**: Deep JavaScript analysis using jsluice for GraphQL schemas, WebSocket endpoints, and entropy-based secret detection
- **patterns**: Pattern-based detection for secrets, serialized objects, and vulnerabilities (compatible with tomnomnom's gf patterns)

## Output Formats

### JSON Lines (JSONL) - Default Streaming Format

Real-time streaming output where each line is a complete JSON record:

```jsonl
{"timestamp":"2025-01-01T12:00:00Z","target":{"domain":"example.com","url":"https://example.com"},"discovery":{"domain":"example.com","paths":[...],"endpoints":[...]}}
{"timestamp":"2025-01-01T12:00:01Z","type":"summary","statistics":{"total_paths":15,"total_endpoints":8}}
```

### Standard JSON Format 

Traditional structured JSON output:

```json
{
  "metadata": {
    "timestamp": "2025-01-01T12:00:00Z",
    "version": "1.0.0",
    "targets": 1
  },
  "discoveries": [
    {
      "domain": "example.com",
      "paths": [...],
      "endpoints": [...],
      "forms": [...],
      "secrets": [...]
    }
  ],
  "statistics": {
    "total_paths": 15,
    "total_endpoints": 8,
    "total_secrets": 2,
    "total_forms": 3
  }
}
```

## Pattern Detection

WebScope includes a powerful pattern detection system compatible with tomnomnom's gf patterns for finding interesting content in responses:

### Supported Pattern Categories
- **Serialization**: .NET, Java, PHP serialized objects (critical for deserialization attacks)
- **Secrets**: API keys, tokens, passwords, credentials
- **Injection**: SQL injection parameters, XSS sinks, command injection
- **Files**: Backup files, configuration files, sensitive documents
- **Infrastructure**: Internal IPs, debug endpoints, error messages
- **Cloud**: AWS, Azure, GCP service URLs and credentials

### Pattern Configuration
```bash
# Use existing gf pattern directory
./webscope -i targets.txt -m httpx-lib,patterns -c config.yaml

# Custom patterns in config file
patterns:
  patterns_dir: "~/.gf"
  patterns_files:
    - "~/.gf/dotnet-serialized.json"
    - "~/.gf/java-serialized.json"
  custom_patterns:
    - name: "custom-secret"
      category: "secrets"
      pattern: '(?i)(secret|token)[\"\']?\s*[:=]\s*[\"\']?([a-zA-Z0-9_-]{20,})'
      severity: "high"
      enabled: true
```

## Integration

WebScope integrates seamlessly with the security testing workflow:

```bash
# Basic reconnaissance workflow
subscope -d example.com -o subdomains.json          # Subdomain enumeration
webscope -i subdomains.json -o webscope-results.jsonl  # Deep content analysis

# Stream results in real-time for large scans
webscope -i large-targets.txt -of jsonl | while IFS= read -r line; do
  echo "$line" | jq -r '.discovery.paths[]?.url // empty' | httpx -silent
done

# Process streaming results with jq
webscope -i targets.txt -of jsonl | jq -r 'select(.discovery) | .discovery.paths[].url'

# Interrupt-safe scanning for large target lists
webscope -i 10k-targets.txt -o results.jsonl  # Ctrl+C saves partial results

# Integration with nuclei for vulnerability scanning
webscope -i targets.txt -of jsonl | jq -r 'select(.discovery.paths) | .discovery.paths[].url' | nuclei
```

### Streaming Benefits

- **Real-time Processing**: Process results as they're discovered
- **Memory Efficient**: No accumulation of results in memory  
- **Crash Resistant**: Results saved immediately, no data loss on interruption
- **Large Scale Friendly**: Handle thousands of targets without memory issues

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.