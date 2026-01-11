package tools

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ============================================================================
// NativeExecutor - ToolExecutor implementation using Go's native HTTP client
// This bypasses TRT Remote Executor to avoid URL encoding issues
// ============================================================================

// NativeExecutor implements ToolExecutor using Go's native HTTP client
// Use this when direct HTTP access to target is available (e.g., Single Target Mode)
type NativeExecutor struct {
	cookie string
}

// NewNativeExecutor creates a new NativeExecutor
func NewNativeExecutor() *NativeExecutor {
	return &NativeExecutor{}
}

// NewNativeExecutorWithCookie creates a NativeExecutor with session cookie
func NewNativeExecutorWithCookie(cookie string) *NativeExecutor {
	return &NativeExecutor{cookie: cookie}
}

// RunTool implements ToolExecutor interface
// It interprets curl commands and executes them using Go's native HTTP client
func (e *NativeExecutor) RunTool(ctx context.Context, imageName string, cmd []string) (string, error) {
	// Parse curl command to extract URL and options
	if len(cmd) == 0 {
		return "", fmt.Errorf("empty command")
	}

	// Find the URL in the command (last non-option argument)
	var targetURL string
	var cookie string
	var method string = "GET"
	var postData string

	for i := 0; i < len(cmd); i++ {
		arg := cmd[i]

		switch arg {
		case "curl":
			// Skip curl command itself
			continue
		case "-s", "-L", "-i":
			// Skip common curl options
			continue
		case "-X":
			// Method follows
			if i+1 < len(cmd) {
				method = cmd[i+1]
				i++
			}
		case "-H":
			// Header follows
			if i+1 < len(cmd) {
				header := cmd[i+1]
				if strings.HasPrefix(strings.ToLower(header), "cookie:") {
					cookie = strings.TrimSpace(strings.TrimPrefix(header, "Cookie:"))
					cookie = strings.TrimSpace(strings.TrimPrefix(cookie, "cookie:"))
				}
				i++
			}
		case "-d":
			// POST data follows
			if i+1 < len(cmd) {
				postData = cmd[i+1]
				method = "POST"
				i++
			}
		default:
			// Assume it's the URL if it starts with http
			if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
				targetURL = arg
			}
		}
	}

	// Use executor's cookie if command doesn't specify one
	if cookie == "" && e.cookie != "" {
		cookie = e.cookie
	}

	if targetURL == "" {
		return "", fmt.Errorf("no URL found in command: %v", cmd)
	}

	log.Printf("[NativeExecutor] %s %s", method, targetURL)

	// Execute request
	if method == "POST" && postData != "" {
		return nativeHTTPPostRaw(ctx, targetURL, postData, cookie)
	}
	return NativeHTTPGet(ctx, targetURL, cookie)
}

// Close implements cleanup (no-op for NativeExecutor)
func (e *NativeExecutor) Close() error {
	return nil
}

// nativeHTTPPostRaw performs a POST request with raw form data
func nativeHTTPPostRaw(ctx context.Context, targetURL string, formData string, cookie string) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, HTTPRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "POST", targetURL, strings.NewReader(formData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := SharedHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Format as curl -i output
	var result strings.Builder
	result.WriteString(fmt.Sprintf("HTTP/%d.%d %d %s\r\n",
		resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, resp.Status))
	for k, v := range resp.Header {
		result.WriteString(fmt.Sprintf("%s: %s\r\n", k, strings.Join(v, ", ")))
	}
	result.WriteString("\r\n")
	result.Write(body)

	return result.String(), nil
}

// SharedHTTPClient is a global HTTP client with connection pooling
// for efficient connection reuse across multiple requests
var SharedHTTPClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		MaxConnsPerHost:     20,
		IdleConnTimeout:     60 * time.Second,
		DisableKeepAlives:   false,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	},
}

// HTTPRequestTimeout is the default timeout for individual HTTP requests
const HTTPRequestTimeout = 15 * time.Second

// NativeHTTPGet performs a GET request using the native Go HTTP client
// Returns response in curl -i compatible format (headers + body)
func NativeHTTPGet(ctx context.Context, targetURL string, cookie string) (string, error) {
	// Apply request timeout
	reqCtx, cancel := context.WithTimeout(ctx, HTTPRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "GET", targetURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := SharedHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Format as curl -i output (headers + body)
	var result strings.Builder
	result.WriteString(fmt.Sprintf("HTTP/%d.%d %d %s\r\n",
		resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, resp.Status))
	for k, v := range resp.Header {
		result.WriteString(fmt.Sprintf("%s: %s\r\n", k, strings.Join(v, ", ")))
	}
	result.WriteString("\r\n")
	result.Write(body)

	return result.String(), nil
}

// NativeHTTPPost performs a POST request using the native Go HTTP client
// Returns response in curl -i compatible format (headers + body)
func NativeHTTPPost(ctx context.Context, targetURL string, formData map[string]string, cookie string) (string, error) {
	// Apply request timeout
	reqCtx, cancel := context.WithTimeout(ctx, HTTPRequestTimeout)
	defer cancel()

	// Build form data
	form := url.Values{}
	for k, v := range formData {
		form.Set(k, v)
	}

	req, err := http.NewRequestWithContext(reqCtx, "POST", targetURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := SharedHTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Format as curl -i output (headers + body)
	var result strings.Builder
	result.WriteString(fmt.Sprintf("HTTP/%d.%d %d %s\r\n",
		resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, resp.Status))
	for k, v := range resp.Header {
		result.WriteString(fmt.Sprintf("%s: %s\r\n", k, strings.Join(v, ", ")))
	}
	result.WriteString("\r\n")
	result.Write(body)

	return result.String(), nil
}
