package reporter

import (
	"cal-project/internal/core/agent"
	"cal-project/internal/core/bus"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// VulnerabilityFinding represents a confirmed security issue
type VulnerabilityFinding struct {
	Type        string `json:"type"`
	URL         string `json:"url"`
	Payload     string `json:"payload"`
	Severity    string `json:"severity"` // High, Medium, Low
	Description string `json:"description"`
	Timestamp   string `json:"timestamp"`
}

// Reporter collects findings and generates reports
type Reporter struct {
	id       string
	bus      bus.Bus
	findings []VulnerabilityFinding
	mu       sync.RWMutex
}

// NewReporter creates a new Reporter agent
func NewReporter(eventBus bus.Bus) *Reporter {
	return &Reporter{
		id:       "Reporter-01",
		bus:      eventBus,
		findings: make([]VulnerabilityFinding, 0),
	}
}

func (r *Reporter) ID() string {
	return r.id
}

func (r *Reporter) Type() agent.AgentType {
	return agent.Specialist
}

func (r *Reporter) Run() error {
	log.Printf("[%s] Online. Listening for findings...\n", r.id)
	// Generate initial empty report
	r.generateMarkdownReport()
	return nil
}

func (r *Reporter) OnEvent(event bus.Event) {
	if event.Type == bus.Finding {
		r.processFinding(event)
	}
}

func (r *Reporter) processFinding(event bus.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Try to parse the payload as a finding
	// It might come as a map or struct depending on how it was sent
	// For now, let's assume it's sent as a VulnerabilityFinding struct or JSON string

	var finding VulnerabilityFinding

	switch payload := event.Payload.(type) {
	case string:
		if err := json.Unmarshal([]byte(payload), &finding); err != nil {
			log.Printf("[%s] Error parsing finding JSON: %v. Raw: %s\n", r.id, err, payload)
			return
		}
	case VulnerabilityFinding:
		finding = payload
	default:
		// Attempt manual mapping if it's a generic map
		if payloadMap, ok := event.Payload.(map[string]interface{}); ok {
			jsonBytes, _ := json.Marshal(payloadMap)
			json.Unmarshal(jsonBytes, &finding)
		} else {
			log.Printf("[%s] Unknown payload type for finding: %T\n", r.id, event.Payload)
			return
		}
	}

	// De-duplicate: check if we already have this finding (URL + Type + Payload)
	for _, f := range r.findings {
		if f.URL == finding.URL && f.Type == finding.Type && f.Payload == finding.Payload {
			return // Duplicate
		}
	}

	r.findings = append(r.findings, finding)
	log.Printf("[%s] 📝 New Vulnerability Recorded: %s at %s\n", r.id, finding.Type, finding.URL)

	// Auto-save report on every new finding
	r.generateMarkdownReport()
}

func (r *Reporter) generateMarkdownReport() {
	filename := "security_report.md"

	content := "# CAL Security Assessment Report\n\n"
	content += fmt.Sprintf("**Generated:** %s\n", time.Now().Format(time.RFC1123))
	content += fmt.Sprintf("**Total Findings:** %d\n\n", len(r.findings))

	content += "## Executive Summary\n"
	if len(r.findings) == 0 {
		content += "No confirmed vulnerabilities were found during this scan.\n"
	} else {
		content += "The following security issues were identified and confirmed:\n\n"
		content += "| Severity | Type | URL | Payload |\n"
		content += "|---|---|---|---|\n"
		for _, f := range r.findings {
			content += fmt.Sprintf("| **%s** | %s | `%s` | `%s` |\n", f.Severity, f.Type, f.URL, f.Payload)
		}
	}

	content += "\n## Detailed Findings\n"
	for i, f := range r.findings {
		content += fmt.Sprintf("### %d. %s\n", i+1, f.Type)
		content += fmt.Sprintf("- **Severity:** %s\n", f.Severity)
		content += fmt.Sprintf("- **URL:** `%s`\n", f.URL)
		content += fmt.Sprintf("- **Payload:** `%s`\n", f.Payload)
		content += fmt.Sprintf("- **Timestamp:** %s\n", f.Timestamp)
		content += fmt.Sprintf("- **Description:**\n%s\n\n", f.Description)
	}

	if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
		log.Printf("[%s] Failed to write report file: %v\n", r.id, err)
	} else {
		log.Printf("[%s] Report updated: %s\n", r.id, filename)
	}
}
