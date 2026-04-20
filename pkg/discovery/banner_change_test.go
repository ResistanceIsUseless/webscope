package discovery

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	wshttp "github.com/resistanceisuseless/webscope/pkg/http"
)

func TestCheckBannerChange_DetectsChange(t *testing.T) {
	// Simulate a load-balanced server that returns different Server headers
	// depending on the path.
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if strings.Contains(r.URL.Path, "nonexistent") {
			w.Header().Set("Server", "awselb/2.0")
		} else {
			w.Header().Set("Server", "Jetty(12.1.5)")
		}
		w.WriteHeader(200)
		fmt.Fprintln(w, "ok")
	}))
	defer ts.Close()

	client := wshttp.NewClient(wshttp.ClientConfig{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})
	defer client.Shutdown()

	findings := checkBannerChange(context.Background(), client, ts.URL)
	if len(findings) == 0 {
		t.Fatal("expected at least one banner-change finding, got none")
	}
	f := findings[0]
	if f.Type != "banner-change" {
		t.Fatalf("expected type 'banner-change', got %q", f.Type)
	}
	if !strings.Contains(f.Details, "Jetty(12.1.5)") || !strings.Contains(f.Details, "awselb/2.0") {
		t.Fatalf("finding details should mention both banners, got: %s", f.Details)
	}
	t.Logf("Finding: %s", f.Details)
}

func TestCheckBannerChange_NoBannerChange(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24")
		w.WriteHeader(200)
		fmt.Fprintln(w, "ok")
	}))
	defer ts.Close()

	client := wshttp.NewClient(wshttp.ClientConfig{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})
	defer client.Shutdown()

	findings := checkBannerChange(context.Background(), client, ts.URL)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for consistent banner, got %d", len(findings))
	}
}

func TestCheckBannerChange_IgnoresMicrosoftHTTPAPI(t *testing.T) {
	callCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if strings.Contains(r.URL.Path, "nonexistent") {
			w.Header().Set("Server", "Microsoft-HTTPAPI/2.0")
		} else {
			w.Header().Set("Server", "IIS/10.0")
		}
		w.WriteHeader(200)
		fmt.Fprintln(w, "ok")
	}))
	defer ts.Close()

	client := wshttp.NewClient(wshttp.ClientConfig{
		Timeout:   5 * time.Second,
		RateLimit: 100,
	})
	defer client.Shutdown()

	findings := checkBannerChange(context.Background(), client, ts.URL)
	if len(findings) != 0 {
		t.Fatalf("expected no findings when Microsoft-HTTPAPI/2.0 is involved, got %d: %v", len(findings), findings[0].Details)
	}
}
