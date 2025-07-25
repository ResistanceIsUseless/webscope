package input

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/resistanceisuseless/webscope/pkg/types"
)

type Handler struct {
	urlRegex    *regexp.Regexp
	ipPortRegex *regexp.Regexp
}

func NewHandler() *Handler {
	return &Handler{
		urlRegex:    regexp.MustCompile(`^https?://[^\s]+`),
		ipPortRegex: regexp.MustCompile(`^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$`),
	}
}

func (h *Handler) ParseInput(reader io.Reader, filename string) ([]types.Target, error) {
	if filename != "" {
		if strings.HasSuffix(strings.ToLower(filename), ".xml") {
			return h.parseNmapXML(reader)
		}
		if strings.HasSuffix(strings.ToLower(filename), ".json") {
			return h.parseJSON(reader)
		}
	}

	return h.parseTextLines(reader)
}

func (h *Handler) parseTextLines(reader io.Reader) ([]types.Target, error) {
	var targets []types.Target
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		target, err := h.parseTarget(line)
		if err != nil {
			continue
		}

		targets = append(targets, target)
	}

	return targets, scanner.Err()
}

func (h *Handler) parseTarget(input string) (types.Target, error) {
	input = strings.TrimSpace(input)

	if h.urlRegex.MatchString(input) {
		return h.parseURL(input)
	}

	if h.ipPortRegex.MatchString(input) {
		matches := h.ipPortRegex.FindStringSubmatch(input)
		ip := matches[1]
		port := matches[2]
		
		scheme := "http"
		if port == "443" || port == "8443" {
			scheme = "https"
		}
		
		url := fmt.Sprintf("%s://%s:%s", scheme, ip, port)
		return h.parseURL(url)
	}

	if strings.Contains(input, ":") {
		parts := strings.Split(input, ":")
		if len(parts) == 2 {
			host := parts[0]
			port := parts[1]
			
			scheme := "http"
			if port == "443" || port == "8443" {
				scheme = "https"
			}
			
			url := fmt.Sprintf("%s://%s:%s", scheme, host, port)
			return h.parseURL(url)
		}
	}

	if strings.Contains(input, ".") {
		url := "https://" + input
		return h.parseURL(url)
	}

	return types.Target{}, fmt.Errorf("unable to parse target: %s", input)
}

func (h *Handler) parseURL(rawURL string) (types.Target, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return types.Target{}, err
	}

	domain := parsedURL.Hostname()
	if domain == "" {
		return types.Target{}, fmt.Errorf("invalid URL: %s", rawURL)
	}

	return types.Target{
		Domain: domain,
		URL:    rawURL,
		Metadata: map[string]interface{}{
			"scheme": parsedURL.Scheme,
			"port":   parsedURL.Port(),
		},
	}, nil
}

func (h *Handler) parseJSON(reader io.Reader) ([]types.Target, error) {
	var data interface{}
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(&data); err != nil {
		return nil, fmt.Errorf("error parsing JSON: %v", err)
	}

	switch v := data.(type) {
	case []interface{}:
		return h.parseJSONArray(v)
	case map[string]interface{}:
		return h.parseJSONObject(v)
	default:
		return nil, fmt.Errorf("unsupported JSON format")
	}
}

func (h *Handler) parseJSONArray(arr []interface{}) ([]types.Target, error) {
	var targets []types.Target
	
	for _, item := range arr {
		switch v := item.(type) {
		case string:
			if target, err := h.parseTarget(v); err == nil {
				targets = append(targets, target)
			}
		case map[string]interface{}:
			if target, err := h.parseJSONObjectTarget(v); err == nil {
				targets = append(targets, target)
			}
		}
	}
	
	return targets, nil
}

func (h *Handler) parseJSONObject(obj map[string]interface{}) ([]types.Target, error) {
	if hosts, ok := obj["hosts"].([]interface{}); ok {
		return h.parseJSONArray(hosts)
	}
	
	if domains, ok := obj["domains"].([]interface{}); ok {
		return h.parseJSONArray(domains)
	}
	
	if target, err := h.parseJSONObjectTarget(obj); err == nil {
		return []types.Target{target}, nil
	}
	
	return nil, fmt.Errorf("unable to extract targets from JSON object")
}

func (h *Handler) parseJSONObjectTarget(obj map[string]interface{}) (types.Target, error) {
	var target types.Target
	
	if domain, ok := obj["domain"].(string); ok {
		target.Domain = domain
	} else if host, ok := obj["host"].(string); ok {
		target.Domain = host
	} else if url, ok := obj["url"].(string); ok {
		return h.parseURL(url)
	} else {
		return target, fmt.Errorf("no valid target found in JSON object")
	}
	
	if target.Domain != "" {
		target.URL = "https://" + target.Domain
		if port, ok := obj["port"].(float64); ok {
			target.URL = fmt.Sprintf("https://%s:%.0f", target.Domain, port)
		}
	}
	
	return target, nil
}

type NmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []NmapHost `xml:"host"`
}

type NmapHost struct {
	Status    NmapStatus    `xml:"status"`
	Addresses []NmapAddress `xml:"address"`
	Hostnames []NmapHostname `xml:"hostnames>hostname"`
	Ports     NmapPorts     `xml:"ports"`
}

type NmapStatus struct {
	State string `xml:"state,attr"`
}

type NmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type NmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type NmapPorts struct {
	Ports []NmapPort `xml:"port"`
}

type NmapPort struct {
	Protocol string         `xml:"protocol,attr"`
	PortID   string         `xml:"portid,attr"`
	State    NmapPortState  `xml:"state"`
	Service  NmapService    `xml:"service"`
}

type NmapPortState struct {
	State string `xml:"state,attr"`
}

type NmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

func (h *Handler) parseNmapXML(reader io.Reader) ([]types.Target, error) {
	var nmapRun NmapRun
	decoder := xml.NewDecoder(reader)
	if err := decoder.Decode(&nmapRun); err != nil {
		return nil, fmt.Errorf("error parsing Nmap XML: %v", err)
	}

	var targets []types.Target

	for _, host := range nmapRun.Hosts {
		if host.Status.State != "up" {
			continue
		}

		var hostIP string
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" {
				hostIP = addr.Addr
				break
			}
		}

		if hostIP == "" {
			continue
		}

		hostname := hostIP
		for _, hn := range host.Hostnames {
			if hn.Type == "PTR" || hn.Type == "user" {
				hostname = hn.Name
				break
			}
		}

		for _, port := range host.Ports.Ports {
			if port.State.State != "open" {
				continue
			}

			portNum, err := strconv.Atoi(port.PortID)
			if err != nil {
				continue
			}

			scheme := "http"
			if portNum == 443 || portNum == 8443 || port.Service.Name == "https" {
				scheme = "https"
			}

			var targetURL string
			if portNum == 80 || portNum == 443 {
				targetURL = fmt.Sprintf("%s://%s", scheme, hostname)
			} else {
				targetURL = fmt.Sprintf("%s://%s:%d", scheme, hostname, portNum)
			}

			target := types.Target{
				Domain: hostname,
				URL:    targetURL,
				Metadata: map[string]interface{}{
					"ip":       hostIP,
					"port":     portNum,
					"service":  port.Service.Name,
					"product":  port.Service.Product,
					"version":  port.Service.Version,
					"protocol": port.Protocol,
				},
			}

			targets = append(targets, target)
		}
	}

	return targets, nil
}