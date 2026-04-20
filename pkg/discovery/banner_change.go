package discovery

import (
	"context"
	"fmt"
	"strings"

	"github.com/resistanceisuseless/webscope/pkg/http"
)

// checkBannerChange makes requests to several paths on the target and compares
// the Server response header across them. If the header value changes between
// requests, it means a load balancer or reverse proxy is routing to different
// backends that leak their own Server identity.
//
// This mirrors nikto check 999962 ("Server banner changed from X to Y").
func checkBannerChange(ctx context.Context, client *http.Client, target string) []Finding {
	base := strings.TrimSuffix(target, "/")

	// Probe a handful of paths that are cheap and unlikely to be blocked.
	// Intentionally includes one 404 path — reverse proxies sometimes route
	// error responses differently from successful ones.
	probePaths := []string{
		"/",
		"/favicon.ico",
		"/robots.txt",
		"/nonexistent-" + randomSuffix(),
	}

	type bannerHit struct {
		path   string
		banner string
	}

	var hits []bannerHit
	for _, p := range probePaths {
		if ctx.Err() != nil {
			break
		}
		resp, err := client.Get(ctx, base+p)
		if err != nil || resp.StatusCode == 0 {
			continue
		}
		server := resp.Headers.Get("Server")
		if server == "" {
			continue
		}
		hits = append(hits, bannerHit{path: p, banner: server})
	}

	if len(hits) < 2 {
		return nil
	}

	// Compare all observed banners against the first one seen.
	first := hits[0]
	var findings []Finding
	seen := map[string]bool{first.banner: true}

	for _, h := range hits[1:] {
		if h.banner == first.banner {
			continue
		}
		if seen[h.banner] {
			continue // already reported this pair
		}
		seen[h.banner] = true

		// Ignore Microsoft-HTTPAPI/2.0 — it's a well-known Windows default
		// that appears on error paths and isn't meaningful.
		if h.banner == "Microsoft-HTTPAPI/2.0" || first.banner == "Microsoft-HTTPAPI/2.0" {
			continue
		}

		findings = append(findings, Finding{
			URL:      base + h.path,
			Type:     "banner-change",
			Severity: "low",
			Details: fmt.Sprintf(
				"Server banner changed from '%s' (on %s) to '%s' (on %s). "+
					"This indicates a load balancer or reverse proxy routing to different backends.",
				first.banner, first.path, h.banner, h.path,
			),
		})
	}

	return findings
}

// randomSuffix returns a short deterministic string to make the 404 probe path
// unique enough to avoid caching but doesn't need cryptographic randomness.
func randomSuffix() string {
	return "wsc9x7q"
}
