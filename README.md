# WebScope

WebScope is a **static web content analysis tool** designed for security researchers and penetration testers. It performs deep analysis of known web targets through static techniques including path bruteforcing, JavaScript analysis, and historical data mining. WebScope complements active crawling tools like Katana by focusing on **static analysis** rather than dynamic crawling.

## Features

- **Multiple Input Formats**: Supports stdin, text files, nmap XML exports, and JSON
- **Flexible Target Parsing**: Accepts URLs, host:port pairs, IP addresses, and domain names  
- **Modular Discovery**: HTTP probing, robots.txt parsing, path bruteforcing
- **Rate Limiting**: Built-in rate limiting to respect target infrastructure
- **JSON Output**: Structured output for integration with other tools
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

# Custom options
webscope -i targets.txt -w 10 -r 50 -m http,robots,paths -v
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
- `-w`: Number of workers (default: 20)
- `-r`: Rate limit requests per second (default: 20)
- `-t`: HTTP timeout (default: 30s)
- `-m`: Discovery modules (default: "http,robots,paths")
- `-v`: Verbose output

### Discovery Modules

- **http**: Basic HTTP probing and technology identification
- **robots**: robots.txt parsing and sitemap discovery
- **paths**: Path bruteforcing with smart variations

## Output Format

WebScope outputs structured JSON with discovered paths, endpoints, and metadata:

```json
{
  "metadata": {
    "timestamp": "2025-01-01T12:00:00Z",
    "version": "1.0.0",
    "targets": 1
  },
  "statistics": {
    "total_paths": 15,
    "total_endpoints": 8
  },
  "discoveries": {
    "example.com": {
      "domain": "example.com",
      "paths": [...],
      "endpoints": [...]
    }
  }
}
```

## Integration

WebScope is designed to work with the ProjectDiscovery ecosystem and other security tools:

```bash
# Comprehensive reconnaissance pipeline
subscope -d example.com -o subdomains.json          # Subdomain enumeration
cat subdomains.json | gau > historical-urls.txt     # Historical URLs from archives
cat subdomains.json | urlfinder > more-urls.txt     # Additional URL sources
katana -u https://example.com -d 3 -js-crawl -o active-crawl.txt  # Active crawling

# Deep static analysis with WebScope
webscope -i subdomains.json -o static-analysis.json  # Static analysis of targets
cat historical-urls.txt | webscope -o historical-analysis.json  # Analyze historical URLs

# Chain with validation tools
cat static-analysis.json | jq -r '.discoveries[].paths[].url' | httpx -silent
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.