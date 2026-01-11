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

var xssMessageCounter atomic.Uint64

// XSSSpecialist is a specialist agent focused on XSS vulnerability detection
type XSSSpecialist struct {
	id       string
	bus      bus.Bus
	brain    llm.LLM
	ctx      context.Context
	target   string
	executor tools.ToolExecutor
}

// NewXSSSpecialist creates a new XSSSpecialist agent
func NewXSSSpecialist(ctx context.Context, id string, eventBus bus.Bus, llmClient llm.LLM, target string, executor tools.ToolExecutor) *XSSSpecialist {
	return &XSSSpecialist{
		id:       id,
		bus:      eventBus,
		brain:    llmClient,
		ctx:      ctx,
		target:   target,
		executor: executor,
	}
}

func (x *XSSSpecialist) ID() string {
	return x.id
}

func (x *XSSSpecialist) Type() agent.AgentType {
	return agent.Specialist
}

func (x *XSSSpecialist) Run() error {
	log.Printf("[%s] Online. Hunting for XSS vulnerabilities on: %s\n", x.id, x.target)
	return nil
}

func (x *XSSSpecialist) OnEvent(event bus.Event) {
	// Only process commands directed to this agent
	if event.Type == bus.Command && event.ToAgent == x.id {
		log.Printf("[%s] Received command: %v\n", x.id, event.Payload)
		go func() {
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("[%s] PANIC in executeTask: %v\n%s\n", x.id, rec, debug.Stack())
					x.reportError(event.FromAgent, fmt.Errorf("task panicked: %v", rec))
				}
			}()
			x.executeTask(event)
		}()
	}
}

// executeTask performs XSS vulnerability scanning
func (x *XSSSpecialist) executeTask(cmdEvent bus.Event) {
	taskDesc, ok := cmdEvent.Payload.(string)
	if !ok {
		log.Printf("[%s] Invalid task payload\n", x.id)
		return
	}

	log.Printf("[%s] Executing: %s\n", x.id, taskDesc)

	if x.executor == nil {
		x.reportObservation(cmdEvent.FromAgent, "XSS scan skipped (Docker executor unavailable)")
		return
	}

	// Phase 1: Analyze Main Page
	targetURL := x.replaceLocalhostForDocker(x.target)
	log.Printf("[%s] Fetching HTTP response from: %s\n", x.id, targetURL)
	httpOutput, err := tools.SimpleHTTPGet(x.ctx, x.executor, targetURL)
	if err != nil {
		log.Printf("[%s] HTTP request failed: %v\n", x.id, err)
		x.reportError(cmdEvent.FromAgent, err)
		return
	}

	// Use LLM to analyze for XSS vulnerabilities with ENHANCED PROMPT
	log.Printf("[%s] Analyzing for XSS vulnerabilities...\n", x.id)
	analysis := x.analyzeForXSS(httpOutput)

	// Phase 2: If forms or links found, try to follow them (Basic Logic)
	// For now, we relay the findings

	log.Printf("[%s] Analysis complete\n", x.id)

	// Report candidate to Reporter if found
	x.reportCandidateIfFound(analysis)

	// Generate report
	report := x.generateReport(httpOutput, analysis)

	x.reportObservation(cmdEvent.FromAgent, report)
}

func (x *XSSSpecialist) replaceLocalhostForDocker(targetURL string) string {
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

func (x *XSSSpecialist) analyzeForXSS(httpResponse string) string {
	// OPTIMIZATION: Pattern matching first (skip LLM if clear patterns found)
	if patternResult := x.patternMatchXSS(httpResponse); patternResult != "" {
		log.Printf("[%s] Pattern match found XSS indicators, skipping LLM\n", x.id)
		return patternResult
	}

	// Limit response size for LLM
	responseToAnalyze := httpResponse
	if len(httpResponse) > 4000 {
		responseToAnalyze = httpResponse[:4000]
	}

	// ENHANCED PROMPT for finding specific locations (only when pattern matching fails)
	prompt := prompts.GetXSSAnalysis(responseToAnalyze)

	analysis, err := x.brain.Generate(x.ctx, prompt)
	if err != nil {
		log.Printf("[%s] LLM analysis failed: %v\n", x.id, err)
		return "❌ Unable to analyze (LLM error)"
	}

	return analysis
}

// patternMatchXSS performs fast pattern matching for XSS indicators
func (x *XSSSpecialist) patternMatchXSS(httpResponse string) string {
	// Common patterns indicating XSS vulnerability
	formPatterns := []*regexp.Regexp{
		regexp.MustCompile(`<form[^>]*>`),
		regexp.MustCompile(`<input[^>]*type=["']?(text|search|hidden)["']?[^>]*>`),
		regexp.MustCompile(`<textarea[^>]*>`),
	}

	// Script/event handler patterns that might indicate reflection
	reflectionPatterns := []*regexp.Regexp{
		regexp.MustCompile(`value=["'][^"']*<[^"']*["']`), // Value containing HTML
		regexp.MustCompile(`<script[^>]*>[^<]*</script>`), // Inline scripts
	}

	// Extract parameters from forms
	paramPattern := regexp.MustCompile(`name=["']([^"']+)["']`)
	params := paramPattern.FindAllStringSubmatch(httpResponse, -1)

	foundForms := false
	for _, p := range formPatterns {
		if p.MatchString(httpResponse) {
			foundForms = true
			break
		}
	}

	// If no forms found, no XSS vulnerability likely
	if !foundForms || len(params) == 0 {
		return "" // Return empty to trigger LLM analysis
	}

	// Check for obvious reflection indicators
	hasReflection := false
	for _, p := range reflectionPatterns {
		if p.MatchString(httpResponse) {
			hasReflection = true
			break
		}
	}

	// Build parameter list
	var paramList []string
	for _, p := range params {
		if len(p) > 1 {
			paramList = append(paramList, p[1])
		}
	}

	// If clear XSS indicators found, return pattern-based analysis
	if foundForms && len(paramList) > 0 {
		result := "VULNERABILITY FOUND: Yes\n"
		result += fmt.Sprintf("- LOCATION: %s\n", x.target)
		result += fmt.Sprintf("- VULNERABLE PARAMETER: %s\n", paramList[0])
		result += "- CONFIDENCE: Medium (Pattern-based detection)\n"
		if hasReflection {
			result += "- EVIDENCE: Input form found with potential reflection\n"
		} else {
			result += "- EVIDENCE: Input form detected, requires payload testing\n"
		}
		result += fmt.Sprintf("- SUGGESTED PAYLOAD: <script>alert('XSS')</script>\n")
		return result
	}

	return "" // Fallback to LLM
}

func (x *XSSSpecialist) generateReport(httpResponse string, analysis string) string {
	report := "=== XSS VULNERABILITY SCAN REPORT ===\n\n"
	report += fmt.Sprintf("Target: %s\n\n", x.target)

	// XSS Analysis
	report += "\n--- XSS Vulnerability Analysis ---\n"
	report += analysis + "\n"

	return report
}

// reportCandidateIfFound parses LLM analysis and reports vulnerability candidate to Reporter
func (x *XSSSpecialist) reportCandidateIfFound(analysis string) {
	// Check if vulnerability was found
	if !strings.Contains(analysis, "VULNERABILITY FOUND: Yes") {
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
		} else if strings.HasPrefix(line, "- EVIDENCE:") {
			reasoning = strings.TrimSpace(strings.TrimPrefix(line, "- EVIDENCE:"))
		}
	}

	// Build full URL if location is relative
	fullURL := x.target
	if location != "" && !strings.HasPrefix(location, "http") {
		if strings.HasPrefix(location, "/") {
			// Parse base URL
			if parsedURL, err := url.Parse(x.target); err == nil {
				fullURL = fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, location)
			}
		}
	} else if location != "" {
		fullURL = location
	}

	// Attempt exploitation before reporting
	if parameter != "" && fullURL != "" {
		log.Printf("[%s] Attempting XSS exploitation on parameter: %s\n", x.id, parameter)
		if x.exploitXSS(fullURL, parameter) {
			// Exploitation successful - report as Finding (verified)
			x.reportFinding(fullURL, parameter, reasoning)
			return
		}
	}

	// Exploitation failed - report as Candidate (unverified)
	candidate := reporter.VulnerabilityCandidate{
		Type:      "XSS",
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
		ID:        fmt.Sprintf("%s-candidate-%d", x.id, xssMessageCounter.Add(1)),
		FromAgent: x.id,
		ToAgent:   "Reporter-01",
		Type:      bus.Candidate,
		Payload:   string(candidateJSON),
	}
	x.bus.Publish("Reporter-01", event)
}

// XSSResult holds the result of a single payload test
type XSSResult struct {
	Payload  string
	Verified bool
}

// exploitXSS attempts to exploit an XSS vulnerability by injecting payloads (PARALLEL)
func (x *XSSSpecialist) exploitXSS(targetURL, parameter string) bool {
	// Common XSS payloads for reflection testing
	payloads := []string{
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert('XSS')>",
		"<svg onload=alert('XSS')>",
		"'\"><script>alert('XSS')</script>",
		"javascript:alert('XSS')",
	}

	// Parallel testing with early termination
	results := make(chan XSSResult, len(payloads))
	var wg sync.WaitGroup

	for _, payload := range payloads {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			verified := x.testSingleXSSPayload(targetURL, parameter, p)
			results <- XSSResult{Payload: p, Verified: verified}
		}(payload)
	}

	// Close results channel when all goroutines complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Check results - return true on first success
	for result := range results {
		if result.Verified {
			log.Printf("[%s] ✅ XSS VERIFIED: Payload reflected unescaped: %s\n", x.id, result.Payload)
			return true
		}
	}

	log.Printf("[%s] ❌ XSS exploitation failed: No payload reflected\n", x.id)
	return false
}

// testSingleXSSPayload tests a single XSS payload
func (x *XSSSpecialist) testSingleXSSPayload(targetURL, parameter, payload string) bool {
	// Construct test URL with payload
	testURL, err := x.injectPayload(targetURL, parameter, payload)
	if err != nil {
		log.Printf("[%s] Failed to construct test URL: %v\n", x.id, err)
		return false
	}

	// Replace localhost for Docker
	dockerURL := x.replaceLocalhostForDocker(testURL)

	// Send HTTP request
	response, err := tools.SimpleHTTPGet(x.ctx, x.executor, dockerURL)
	if err != nil {
		log.Printf("[%s] HTTP request failed for payload test: %v\n", x.id, err)
		return false
	}

	// Check if payload is reflected in response (unescaped)
	return strings.Contains(response, payload)
}

// injectPayload injects the XSS payload into the target URL parameter
func (x *XSSSpecialist) injectPayload(targetURL, parameter, payload string) (string, error) {
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}

	// Get existing query parameters
	query := parsedURL.Query()

	// If parameter exists, replace it; otherwise add it
	query.Set(parameter, payload)

	parsedURL.RawQuery = query.Encode()
	return parsedURL.String(), nil
}

// reportFinding reports a verified XSS vulnerability
func (x *XSSSpecialist) reportFinding(targetURL, parameter, evidence string) {
	finding := reporter.VulnerabilityFinding{
		Type:        "XSS",
		Severity:    "High",
		URL:         targetURL,
		Payload:     parameter,
		Description: fmt.Sprintf("XSS vulnerability verified on parameter '%s'. Evidence: %s. Recommendation: Implement proper input sanitization and output encoding. Use Content Security Policy (CSP) headers.", parameter, evidence),
		Timestamp:   time.Now().Format(time.RFC1123),
	}

	findingJSON, _ := json.Marshal(finding)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-finding-%d", x.id, xssMessageCounter.Add(1)),
		FromAgent: x.id,
		ToAgent:   "Reporter-01",
		Type:      bus.Finding,
		Payload:   string(findingJSON),
	}
	x.bus.Publish("Reporter-01", event)
	log.Printf("[%s] 🎯 Reported verified XSS finding: %s (param: %s)\n", x.id, targetURL, parameter)
}

func (x *XSSSpecialist) reportObservation(toAgent string, observation string) {
	msgID := xssMessageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-obs-%d", x.id, msgID),
		FromAgent: x.id,
		ToAgent:   toAgent,
		Type:      bus.Observation,
		Payload:   observation,
	}
	x.bus.Publish(toAgent, event)
}

func (x *XSSSpecialist) reportError(toAgent string, err error) {
	msgID := xssMessageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-err-%d", x.id, msgID),
		FromAgent: x.id,
		ToAgent:   toAgent,
		Type:      bus.Error,
		Payload:   err.Error(),
	}
	x.bus.Publish(toAgent, event)
}
