package tools

import (
	"context"
	"fmt"
)

// ToolExecutor defines the interface for executing tools
type ToolExecutor interface {
	RunTool(ctx context.Context, imageName string, cmd []string) (string, error)
}

// NmapScan runs a port scan
func NmapScan(ctx context.Context, executor ToolExecutor, target string) (string, error) {
	cmd := []string{"nmap", "-p", "22,80,443", target}
	return executor.RunTool(ctx, "cal/nmap", cmd)
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

// SimpleHTTPGet performs a basic HTTP GET using curl
func SimpleHTTPGet(ctx context.Context, executor ToolExecutor, url string) (string, error) {
	cmd := []string{"curl", "-s", "-L", "-i", url}
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
