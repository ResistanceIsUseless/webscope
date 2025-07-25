# WebScope

WebScope is a comprehensive web content discovery and analysis tool designed for security researchers and penetration testers. It discovers paths, endpoints, and content from web applications through multiple analysis techniques. WebScope focuses on content discovery from known targets and is designed to complement subdomain enumeration tools like SubScope.

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

WebScope is designed to complement SubScope and integrate with other security tools for content discovery:

```bash
# Integration with SubScope
subscope -d example.com -o round1.json
webscope -i round1.json -o webscope-results.json

# Chain with other tools
cat webscope-results.json | jq -r '.discoveries[].paths[].url' | httpx -silent
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.