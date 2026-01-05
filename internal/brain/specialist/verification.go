package specialist

import (
	"cal-project/internal/brain/llm"
	"cal-project/internal/core/agent"
	"cal-project/internal/core/bus"
	"cal-project/internal/hands/docker"
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
	exec, err := docker.NewExecutor()
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
	vulnInfo := v.extractVulnerabilityInfo(report)

	if vulnInfo == "" {
		v.reportObservation(cmdEvent.FromAgent, "No specific vulnerabilities to verify")
		return
	}

	log.Printf("[%s] Extracted vulnerability info: %s\n", v.id, vulnInfo)

	// Construct test URL - use LLM to help build the payload URL
	testURL := v.constructTestURL(vulnInfo)

	if testURL == "" {
		v.reportObservation(cmdEvent.FromAgent, "Unable to construct verification URL")
		return
	}

	log.Printf("[%s] Testing URL: %s\n", v.id, testURL)

	// Run headless browser verification
	result := v.verifyWithBrowser(testURL, "<script>alert('XSS')</script>")

	// Generate verification report
	verificationReport := v.generateVerificationReport(result)

	v.reportObservation(cmdEvent.FromAgent, verificationReport)
}

func (v *VerificationSpecialist) extractVulnerabilityInfo(report string) string {
	prompt := fmt.Sprintf(
		"Extract XSS vulnerability details from this report:\n\n%s\n\n"+
			"Reply with ONLY the vulnerable URL or form location. "+
			"Example: 'http://192.168.50.10:8082/comment.php' or 'Form at /comment.php'",
		report[:min(1000, len(report))],
	)

	info, err := v.brain.Generate(v.ctx, prompt)
	if err != nil {
		log.Printf("[%s] Failed to extract info: %v\n", v.id, err)
		return ""
	}

	return strings.TrimSpace(info)
}

func (v *VerificationSpecialist) constructTestURL(vulnInfo string) string {
	// Simple URL construction - if it contains http, use it
	if strings.Contains(vulnInfo, "http") {
		// Extract URL
		parts := strings.Fields(vulnInfo)
		for _, part := range parts {
			if strings.HasPrefix(part, "http") {
				return strings.Trim(part, "',\"")
			}
		}
	}

	// Otherwise, construct from target
	if strings.Contains(vulnInfo, "/") {
		path := vulnInfo
		if strings.Contains(path, " ") {
			parts := strings.Fields(path)
			for _, p := range parts {
				if strings.HasPrefix(p, "/") {
					path = p
					break
				}
			}
		}
		return v.target + path
	}

	return v.target
}

func (v *VerificationSpecialist) verifyWithBrowser(targetURL, payload string) *VerificationResult {
	log.Printf("[%s] Running headless browser verification\n", v.id)

	// Replace localhost for Docker
	dockerURL := strings.Replace(targetURL, "localhost", "host.docker.internal", 1)
	dockerURL = strings.Replace(dockerURL, "127.0.0.1", "host.docker.internal", 1)

	// Run Playwright verification
	cmd := []string{dockerURL, payload}
	output, err := v.executor.RunTool(v.ctx, "cal/xss-verifier:latest", cmd)

	if err != nil {
		log.Printf("[%s] Verification failed: %v. Is cal/xss-verifier built?\n", v.id, err)
		log.Printf("[%s] Browser verification failed: %v\n", v.id, err)
		return &VerificationResult{
			URL:      targetURL,
			Payload:  payload,
			Verified: false,
			Error:    err.Error(),
		}
	}

	log.Printf("[%s] Browser output: %s\n", v.id, output)

	// Parse JSON result
	var result VerificationResult
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		log.Printf("[%s] Failed to parse verification result: %v\n", v.id, err)
		// Look for XSS indicators in output
		verified := strings.Contains(output, "XSS TRIGGERED") || strings.Contains(output, "Alert detected")
		return &VerificationResult{
			URL:      targetURL,
			Payload:  payload,
			Verified: verified,
		}
	}

	return &result
}

func (v *VerificationSpecialist) generateVerificationReport(result *VerificationResult) string {
	report := "=== VULNERABILITY VERIFICATION REPORT ===\n\n"
	report += fmt.Sprintf("Target URL: %s\n", result.URL)
	report += fmt.Sprintf("Payload: %s\n\n", result.Payload)

	if result.Verified {
		report += "🚨 VERIFICATION: SUCCESS ✅\n\n"
		report += "The XSS vulnerability is CONFIRMED!\n"
		report += "The payload successfully executed in a real browser.\n"
		if result.AlertMessage != "" {
			report += fmt.Sprintf("Alert message: %s\n", result.AlertMessage)
		}
		report += "\n⚠️ CRITICAL: Immediate remediation required.\n"
	} else {
		report += "⚠️ VERIFICATION: FAILED ❌\n\n"
		report += "Could not confirm XSS execution in browser.\n"
		if result.Error != "" {
			report += fmt.Sprintf("Error: %s\n", result.Error)
		}
		report += "\nPossible reasons:\n"
		report += "- WAF/XSS filter blocking\n"
		report += "- Different context needed\n"
		report += "- False positive from initial scan\n"
	}

	return report
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
