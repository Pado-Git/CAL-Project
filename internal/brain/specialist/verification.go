package specialist

import (
	"cal-project/internal/brain/llm"
	"cal-project/internal/brain/prompts"
	"cal-project/internal/core/agent"
	"cal-project/internal/core/bus"
	"cal-project/internal/hands/docker"
	"cal-project/internal/hands/tools"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync/atomic"
)

var verifyMessageCounter atomic.Uint64

// VerificationResult represents the result from headless browser verification
type VerificationResult struct {
	URL          string `json:"url"`
	Payload      string `json:"payload"`
	Verified     bool   `json:"verified"`
	AlertMessage string `json:"alertMessage,omitempty"`
	Error        string `json:"error,omitempty"`
	Timestamp    string `json:"timestamp,omitempty"`
}

// VulnInfo represents the extracted vulnerability details from the reporter
type VulnInfo struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Payload   string `json:"payload"`
	Method    string `json:"method,omitempty"`
	Parameter string `json:"parameter,omitempty"` // Input field name
}

// VerificationSpecialist validates discovered vulnerabilities
type VerificationSpecialist struct {
	id       string
	bus      bus.Bus
	brain    llm.LLM
	ctx      context.Context
	target   string
	executor *docker.Executor
}

// NewVerificationSpecialist creates a new VerificationSpecialist agent
func NewVerificationSpecialist(ctx context.Context, id string, eventBus bus.Bus, llmClient llm.LLM, target string) *VerificationSpecialist {
	exec, err := docker.NewExecutor(id)
	if err != nil {
		log.Printf("[%s] Warning: Failed to create Docker executor: %v\n", id, err)
	}

	return &VerificationSpecialist{
		id:       id,
		bus:      eventBus,
		brain:    llmClient,
		ctx:      ctx,
		target:   target,
		executor: exec,
	}
}

func (v *VerificationSpecialist) ID() string {
	return v.id
}

func (v *VerificationSpecialist) Type() agent.AgentType {
	return agent.Specialist
}

func (v *VerificationSpecialist) Run() error {
	log.Printf("[%s] Online. Ready to verify vulnerabilities for: %s\n", v.id, v.target)
	return nil
}

func (v *VerificationSpecialist) OnEvent(event bus.Event) {
	if event.Type == bus.Command && event.ToAgent == v.id {
		log.Printf("[%s] Received verification request\n", v.id)
		go v.executeVerification(event)
	}
}

// executeVerification validates a reported vulnerability using headless browser
func (v *VerificationSpecialist) executeVerification(cmdEvent bus.Event) {
	report, ok := cmdEvent.Payload.(string)
	if !ok {
		log.Printf("[%s] Invalid task payload\n", v.id)
		return
	}

	log.Printf("[%s] Analyzing vulnerability report\n", v.id)

	if v.executor == nil {
		v.reportObservation(cmdEvent.FromAgent, "Verification skipped (Docker executor unavailable)")
		return
	}

	// Extract vulnerability information from the report using LLM
	vulnInfoList := v.extractVulnerabilityInfo(report)

	if len(vulnInfoList) == 0 {
		v.reportObservation(cmdEvent.FromAgent, "No specific vulnerabilities extracted to verify")
		return
	}

	var combinedReport strings.Builder
	combinedReport.WriteString(fmt.Sprintf("=== VERIFICATION REPORT (%d items) ===\n", len(vulnInfoList)))

	for i, info := range vulnInfoList {
		vulnInfo := info // copy for reference
		log.Printf("[%s] Extracted vulnerability info [%d]: Type=%s URL=%s Payload=%s\n", v.id, i+1, vulnInfo.Type, vulnInfo.URL, vulnInfo.Payload)

		// Construct test URL
		testURL := v.constructTestURL(&vulnInfo)

		log.Printf("[%s] Testing URL: %s\n", v.id, testURL)

		var result *VerificationResult

		if strings.Contains(strings.ToUpper(vulnInfo.Type), "SQL") {
			result = v.verifySQLi(testURL, vulnInfo.Payload)
		} else if strings.Contains(strings.ToUpper(vulnInfo.Type), "TRAVERSAL") ||
			strings.Contains(strings.ToUpper(vulnInfo.Type), "FILE") ||
			strings.Contains(strings.ToUpper(vulnInfo.Type), "LFI") {
			result = v.verifyPathTraversal(testURL, vulnInfo.Payload)
		} else {
			// Default to XSS/Browser verification
			// If payload is empty, use a default XSS payload for testing
			payload := vulnInfo.Payload
			if payload == "" {
				payload = "<script>alert('XSS')</script>"
			}
			// Ensure payload is updated in info for consistency if we set a default
			vulnInfo.Payload = payload
			result = v.verifyWithBrowser(testURL, &vulnInfo)
		}

		// Generate verification report entry
		status := "❌ FAILED"
		if result.Verified {
			status = "✅ CONFIRMED"
			// If verified, publish a formal Finding event
			v.publishFinding(result, vulnInfo.Type)
		}

		reportEntry := fmt.Sprintf(
			"--- Item %d ---\n"+
				"Target: %s\n"+
				"Payload: %s\n"+
				"Status: %s\n"+
				"Error: %s\n",
			i+1, result.URL, result.Payload, status, result.Error,
		)
		combinedReport.WriteString(reportEntry)
	}

	v.reportObservation(cmdEvent.FromAgent, combinedReport.String())
}

func (v *VerificationSpecialist) extractVulnerabilityInfo(report string) []VulnInfo {
	prompt := prompts.GetVerifyExtract(report[:min(1000, len(report))])

	infoRaw, err := v.brain.Generate(v.ctx, prompt)
	if err != nil {
		log.Printf("[%s] Failed to extract info: %v\n", v.id, err)
		return nil
	}

	// Parse JSON result from LLM
	// Clean up potential markdown code blocks
	infoData := strings.TrimSpace(infoRaw)
	infoData = strings.ReplaceAll(infoData, "```json", "")
	infoData = strings.ReplaceAll(infoData, "```", "")

	// Try unmarshalling as an array first (preferred)
	var infoList []VulnInfo
	if err := json.Unmarshal([]byte(infoData), &infoList); err == nil {
		return infoList
	}

	// If that fails, try unmarshalling as a single object and wrap it
	var info VulnInfo
	if err := json.Unmarshal([]byte(infoData), &info); err == nil {
		return []VulnInfo{info}
	}

	log.Printf("[%s] Failed to parse vulnerability info. Raw Data: %s\n", v.id, infoData)
	return nil
}

func (v *VerificationSpecialist) constructTestURL(info *VulnInfo) string {
	target := info.URL
	if !strings.HasPrefix(target, "http") {
		// Append to base target if it's a relative path
		if strings.HasPrefix(target, "/") {
			target = strings.TrimRight(v.target, "/") + target
		} else {
			target = strings.TrimRight(v.target, "/") + "/" + target
		}
	}
	return target
}

func (v *VerificationSpecialist) verifyWithBrowser(targetURL string, info *VulnInfo) *VerificationResult {
	log.Printf("[%s] Running headless browser verification\n", v.id)

	// Replace localhost for Docker
	dockerURL := strings.Replace(targetURL, "localhost", "host.docker.internal", 1)
	dockerURL = strings.Replace(dockerURL, "127.0.0.1", "host.docker.internal", 1)

	// Run Playwright verification
	// Arguments: URL, Payload, Method (optional), Parameter (optional)
	cmd := []string{dockerURL, info.Payload}
	if info.Method != "" {
		cmd = append(cmd, info.Method)
		if info.Parameter != "" {
			cmd = append(cmd, info.Parameter)
		}
	}
	output, err := v.executor.RunTool(v.ctx, "cal/xss-verifier:latest", cmd)

	if err != nil {
		log.Printf("[%s] Verification failed: %v. Is cal/xss-verifier built?\n", v.id, err)
		log.Printf("[%s] Browser verification failed: %v\n", v.id, err)
		return &VerificationResult{
			URL:      targetURL,
			Payload:  info.Payload,
			Verified: false,
			Error:    err.Error(),
		}
	}

	log.Printf("[%s] Browser output: %s\n", v.id, output)

	// Parse JSON result - find the last occurring JSON object
	lines := strings.Split(output, "\n")
	var jsonLine string
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
			jsonLine = line
			break
		}
	}

	var result VerificationResult
	if jsonLine == "" {
		log.Printf("[%s] No JSON found in output\n", v.id)
		return &VerificationResult{
			URL:      targetURL,
			Payload:  info.Payload,
			Verified: false,
			Error:    "Invalid output from verifier",
		}
	}

	if err := json.Unmarshal([]byte(jsonLine), &result); err != nil {
		log.Printf("[%s] Failed to parse verification result: %v\n", v.id, err)
		// Look for XSS indicators in output
		verified := strings.Contains(output, "XSS TRIGGERED") || strings.Contains(output, "Alert detected")
		return &VerificationResult{
			URL:      targetURL,
			Payload:  info.Payload,
			Verified: verified,
		}
	}

	return &result
}

func (v *VerificationSpecialist) verifySQLi(targetURL, payload string) *VerificationResult {
	log.Printf("[%s] Verifying SQL Injection via HTTP Request\n", v.id)

	verifyURL := targetURL
	if !strings.Contains(verifyURL, payload) {
		if strings.Contains(verifyURL, "?") {
			verifyURL += payload
		} else {
			log.Printf("[%s] Warning: complex SQLi injection not fully supported yet for POST/path.\n", v.id)
		}
	}

	// Replace localhost for Docker
	dockerURL := strings.Replace(verifyURL, "localhost", "host.docker.internal", 1)
	dockerURL = strings.Replace(dockerURL, "127.0.0.1", "host.docker.internal", 1)

	// Use simple curl to check response
	output, err := tools.SimpleHTTPGet(v.ctx, v.executor, dockerURL)
	verified := false
	if err != nil {
		log.Printf("[%s] HTTP check failed: %v\n", v.id, err)
	} else {
		// Basic check: if we get significant content back, assume executed.
		if len(output) > 500 {
			verified = true
		}
	}

	return &VerificationResult{
		URL:      verifyURL,
		Payload:  payload,
		Verified: verified,
	}
}

func (v *VerificationSpecialist) verifyPathTraversal(targetURL, payload string) *VerificationResult {
	log.Printf("[%s] Verifying Path Traversal via HTTP Request\n", v.id)

	verifyURL := targetURL
	if !strings.Contains(verifyURL, payload) {
		if strings.Contains(verifyURL, "?") {
			verifyURL += payload
		} else {
			if strings.HasSuffix(verifyURL, "=") {
				verifyURL += payload
			}
		}
	}

	// Replace localhost for Docker
	dockerURL := strings.Replace(verifyURL, "localhost", "host.docker.internal", 1)
	dockerURL = strings.Replace(dockerURL, "127.0.0.1", "host.docker.internal", 1)

	output, err := tools.SimpleHTTPGet(v.ctx, v.executor, dockerURL)
	verified := false
	if err != nil {
		log.Printf("[%s] HTTP check failed: %v\n", v.id, err)
	} else {
		// Check for common indicators
		// Unix: root:x:0:0
		// Windows: [boot loader] or [extensions]
		// PHP Error: failed to open stream
		if strings.Contains(output, "root:x:0:0") ||
			strings.Contains(output, "[boot loader]") ||
			strings.Contains(output, "daemon:") ||
			(strings.Contains(output, "Warning") && strings.Contains(output, "failed to open stream")) {
			verified = true
		}
	}

	return &VerificationResult{
		URL:      verifyURL,
		Payload:  payload,
		Verified: verified,
	}
}

func (v *VerificationSpecialist) generateVerificationReport(result *VerificationResult) string {
	status := "❌ FAILED"
	if result.Verified {
		status = "✅ CONFIRMED"
	}

	return fmt.Sprintf(
		"=== VERIFICATION REPORT ===\n"+
			"Target: %s\n"+
			"Payload: %s\n"+
			"Status: %s\n"+
			"Error: %s\n",
		result.URL, result.Payload, status, result.Error,
	)
}

func (v *VerificationSpecialist) publishFinding(result *VerificationResult, vulnType string) {
	finding := map[string]interface{}{
		"type":        vulnType,
		"url":         result.URL,
		"payload":     result.Payload,
		"severity":    "High", // Default to High for verified XSS/SQLi
		"description": fmt.Sprintf("Verified %s vulnerability. \nError/Output: %s", vulnType, result.Error+result.AlertMessage),
		"timestamp":   result.Timestamp,
	}

	msgID := verifyMessageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-finding-%d", v.id, msgID),
		FromAgent: v.id,
		ToAgent:   "BROADCAST", // Broadcast key findings
		Type:      bus.Finding,
		Payload:   finding,
	}
	v.bus.Publish("Reporter-01", event) // Send directly to Reporter
}

func (v *VerificationSpecialist) reportObservation(toAgent string, observation string) {
	msgID := verifyMessageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-obs-%d", v.id, msgID),
		FromAgent: v.id,
		ToAgent:   toAgent,
		Type:      bus.Observation,
		Payload:   observation,
	}
	v.bus.Publish(toAgent, event)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
