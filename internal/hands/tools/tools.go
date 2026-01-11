package tools

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ToolExecutor defines the interface for executing tools
type ToolExecutor interface {
	RunTool(ctx context.Context, imageName string, cmd []string) (string, error)
}

// mapToHeaderString converts a cookie map to HTTP Cookie header format
// Example: {"PHPSESSID": "abc123", "session_id": "xyz789"} → "PHPSESSID=abc123; session_id=xyz789"
func mapToHeaderString(cookies map[string]string) string {
	if len(cookies) == 0 {
		return ""
	}

	parts := make([]string, 0, len(cookies))
	for name, value := range cookies {
		parts = append(parts, fmt.Sprintf("%s=%s", name, value))
	}
	return strings.Join(parts, "; ")
}

// lastScanResults stores the last scan results for TRT integration
var (
	lastScanResults []ScanResult
	lastScanMutex   sync.RWMutex
)

// GetLastScanResults returns the last scan results
func GetLastScanResults() []ScanResult {
	lastScanMutex.RLock()
	defer lastScanMutex.RUnlock()
	return lastScanResults
}

// ClearLastScanResults clears the last scan results
func ClearLastScanResults() {
	lastScanMutex.Lock()
	defer lastScanMutex.Unlock()
	lastScanResults = nil
}

// NmapScan 순수 Go TCP 스캐너 사용 (nmap 호환 출력)
// executor 매개변수는 호환성을 위해 유지하지만 사용하지 않음
func NmapScan(ctx context.Context, executor ToolExecutor, target string) (string, error) {
	startTime := time.Now()

	results, err := ScanNetwork(ctx, target, DefaultPorts, PortTimeout)
	if err != nil {
		return "", fmt.Errorf("scan failed: %w", err)
	}

	// Store results for TRT integration
	lastScanMutex.Lock()
	lastScanResults = results
	lastScanMutex.Unlock()

	return FormatAsNmap(results, time.Since(startTime)), nil
}

// SubfinderScan runs subfinder for subdomain enumeration
func SubfinderScan(ctx context.Context, executor ToolExecutor, domain string) (string, error) {
	cmd := []string{"-d", domain}
	return executor.RunTool(ctx, "cal-project/internal/hands/docker", cmd)
}

// HttpxProbe runs httpx to probe HTTP services
func HttpxProbe(ctx context.Context, executor ToolExecutor, target string) (string, error) {
	// Note: httpx needs stdin for targets, this is simplified
	cmd := []string{"-u", target}
	return executor.RunTool(ctx, "projectdiscovery/httpx", cmd)
}

// SimpleHTTPGet performs a basic HTTP GET using curl (without cookie)
func SimpleHTTPGet(ctx context.Context, executor ToolExecutor, urlStr string) (string, error) {
	return HTTPGetWithCookie(ctx, executor, urlStr, "")
}

// HTTPGetWithCookie performs HTTP GET with optional session cookie
// HTTPGetWithCookie performs HTTP GET with a single cookie (backward compatibility)
func HTTPGetWithCookie(ctx context.Context, executor ToolExecutor, urlStr string, cookie string) (string, error) {
	var cmd []string
	if cookie != "" {
		cmd = []string{"curl", "-s", "-L", "-i", "-H", fmt.Sprintf("Cookie: %s", cookie), urlStr}
	} else {
		cmd = []string{"curl", "-s", "-L", "-i", urlStr}
	}
	return executor.RunTool(ctx, "cal/curl:latest", cmd)
}

// HTTPGetWithCookies performs HTTP GET with multiple cookies
func HTTPGetWithCookies(ctx context.Context, executor ToolExecutor, urlStr string, cookies map[string]string) (string, error) {
	cookieHeader := mapToHeaderString(cookies)
	var cmd []string
	if cookieHeader != "" {
		cmd = []string{"curl", "-s", "-L", "-i", "-H", fmt.Sprintf("Cookie: %s", cookieHeader), urlStr}
	} else {
		cmd = []string{"curl", "-s", "-L", "-i", urlStr}
	}
	return executor.RunTool(ctx, "cal/curl:latest", cmd)
}

// HTTPPost performs HTTP POST with form data and single cookie (backward compatibility)
func HTTPPost(ctx context.Context, executor ToolExecutor, urlStr string, formData map[string]string, cookie string) (string, error) {
	// Build form data string: "field1=value1&field2=value2"
	var formParts []string
	for key, value := range formData {
		formParts = append(formParts, fmt.Sprintf("%s=%s",
			url.QueryEscape(key),
			url.QueryEscape(value)))
	}
	formDataStr := strings.Join(formParts, "&")

	// Build curl command
	cmd := []string{"curl", "-s", "-L", "-i", "-X", "POST"}

	if cookie != "" {
		cmd = append(cmd, "-H", fmt.Sprintf("Cookie: %s", cookie))
	}

	cmd = append(cmd, "-d", formDataStr, urlStr)

	return executor.RunTool(ctx, "cal/curl:latest", cmd)
}

// HTTPPostWithCookies performs HTTP POST with form data and multiple cookies
func HTTPPostWithCookies(ctx context.Context, executor ToolExecutor, urlStr string, formData map[string]string, cookies map[string]string) (string, error) {
	// Build form data string
	var formParts []string
	for key, value := range formData {
		formParts = append(formParts, fmt.Sprintf("%s=%s",
			url.QueryEscape(key),
			url.QueryEscape(value)))
	}
	formDataStr := strings.Join(formParts, "&")

	// Build curl command
	cmd := []string{"curl", "-s", "-L", "-i", "-X", "POST"}

	cookieHeader := mapToHeaderString(cookies)
	if cookieHeader != "" {
		cmd = append(cmd, "-H", fmt.Sprintf("Cookie: %s", cookieHeader))
	}

	cmd = append(cmd, "-d", formDataStr, urlStr)

	return executor.RunTool(ctx, "cal/curl:latest", cmd)
}

// ParseToolRequest interprets a natural language tool request
// This is a simple keyword matcher; in production, use LLM-based parsing
func ParseToolRequest(request string) (toolFunc func(context.Context, ToolExecutor, string) (string, error), target string, err error) {
	// Very simple pattern matching for demo
	if contains(request, "nmap") || contains(request, "port scan") {
		return func(ctx context.Context, exec ToolExecutor, t string) (string, error) {
			return NmapScan(ctx, exec, t) // Scan all ports (hardcoded in NmapScan)
		}, extractTarget(request), nil
	}

	if contains(request, "http") || contains(request, "curl") {
		return SimpleHTTPGet, extractTarget(request), nil
	}

	return nil, "", fmt.Errorf("unknown tool request: %s", request)
}

func contains(text, substr string) bool {
	for i := 0; i <= len(text)-len(substr); i++ {
		if text[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func extractTarget(request string) string {
	// Simplified: assume last word is the target
	// TODO: Use proper parsing
	words := []string{}
	current := ""
	for _, ch := range request {
		if ch == ' ' {
			if current != "" {
				words = append(words, current)
				current = ""
			}
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		words = append(words, current)
	}

	if len(words) > 0 {
		return words[len(words)-1]
	}
	return ""
}
