package reporter

import (
	"cal-project/internal/core/agent"
	"cal-project/internal/core/bus"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
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

// VulnerabilityCandidate represents a potential security issue pending verification
type VulnerabilityCandidate struct {
	Type        string `json:"type"`
	URL         string `json:"url"`
	Parameter   string `json:"parameter"`
	Evidence    string `json:"evidence"`
	Reasoning   string `json:"reasoning"`
	Timestamp   string `json:"timestamp"`
	Status      string `json:"status"` // "pending", "verifying", "verified", "false_positive"
}

// CompromisedTarget represents a target where shell access was obtained and agent deployed
type CompromisedTarget struct {
	URL       string `json:"url"`       // Target URL where RCE was exploited
	AgentPAW  string `json:"agent_paw"` // Deployed agent's PAW identifier
	Platform  string `json:"platform"`  // linux, windows
	Host      string `json:"host"`      // Hostname of compromised system
	Username  string `json:"username"`  // User context (e.g., root, SYSTEM)
	Privilege string `json:"privilege"` // Elevated, User
	Timestamp string `json:"timestamp"`
}

// Reporter collects findings and generates reports
type Reporter struct {
	id                 string
	bus                bus.Bus
	target             string
	engagedTargets     []string
	compromisedTargets []CompromisedTarget
	findings           []VulnerabilityFinding
	candidates         []VulnerabilityCandidate
	mu                 sync.RWMutex
}

// NewReporter creates a new Reporter agent
func NewReporter(eventBus bus.Bus, target string) *Reporter {
	return &Reporter{
		id:                 "Reporter-01",
		bus:                eventBus,
		target:             target,
		engagedTargets:     make([]string, 0),
		compromisedTargets: make([]CompromisedTarget, 0),
		findings:           make([]VulnerabilityFinding, 0),
		candidates:         make([]VulnerabilityCandidate, 0),
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
	if event.Type == bus.Candidate {
		r.processCandidate(event)
	}
	if event.Type == bus.Engagement {
		r.processEngagement(event)
	}
	if event.Type == bus.Compromised {
		r.processCompromised(event)
	}
}

func (r *Reporter) processEngagement(event bus.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	target, ok := event.Payload.(string)
	if !ok {
		return
	}

	// De-duplicate
	for _, t := range r.engagedTargets {
		if t == target {
			return
		}
	}

	r.engagedTargets = append(r.engagedTargets, target)
	log.Printf("[%s] 🎯 Engagement Recorded: %s\n", r.id, target)
	r.generateMarkdownReport()
}

func (r *Reporter) processCompromised(event bus.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var compromised CompromisedTarget

	switch payload := event.Payload.(type) {
	case string:
		if err := json.Unmarshal([]byte(payload), &compromised); err != nil {
			log.Printf("[%s] Error parsing compromised JSON: %v. Raw: %s\n", r.id, err, payload)
			return
		}
	case CompromisedTarget:
		compromised = payload
	default:
		// Attempt manual mapping if it's a generic map
		if payloadMap, ok := event.Payload.(map[string]interface{}); ok {
			jsonBytes, _ := json.Marshal(payloadMap)
			json.Unmarshal(jsonBytes, &compromised)
		} else {
			log.Printf("[%s] Unknown payload type for compromised: %T\n", r.id, event.Payload)
			return
		}
	}

	// De-duplicate by AgentPAW
	for _, c := range r.compromisedTargets {
		if c.AgentPAW == compromised.AgentPAW {
			return // Already recorded
		}
	}

	r.compromisedTargets = append(r.compromisedTargets, compromised)
	log.Printf("[%s] 💀 COMPROMISED TARGET: %s (Agent: %s, Platform: %s, User: %s)\n",
		r.id, compromised.URL, compromised.AgentPAW, compromised.Platform, compromised.Username)
	r.generateMarkdownReport()
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

func (r *Reporter) processCandidate(event bus.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var candidate VulnerabilityCandidate

	switch payload := event.Payload.(type) {
	case string:
		if err := json.Unmarshal([]byte(payload), &candidate); err != nil {
			log.Printf("[%s] Error parsing candidate JSON: %v. Raw: %s\n", r.id, err, payload)
			return
		}
	case VulnerabilityCandidate:
		candidate = payload
	default:
		// Attempt manual mapping if it's a generic map
		if payloadMap, ok := event.Payload.(map[string]interface{}); ok {
			jsonBytes, _ := json.Marshal(payloadMap)
			json.Unmarshal(jsonBytes, &candidate)
		} else {
			log.Printf("[%s] Unknown payload type for candidate: %T\n", r.id, event.Payload)
			return
		}
	}

	// Normalize before de-duplication
	normalizedURL := normalizeURL(candidate.URL)
	normalizedParam := normalizeParameter(candidate.Parameter)

	// De-duplicate: check if we already have this candidate with normalized values
	for _, c := range r.candidates {
		if normalizeURL(c.URL) == normalizedURL &&
			c.Type == candidate.Type &&
			normalizeParameter(c.Parameter) == normalizedParam {
			log.Printf("[%s] ⏭️ Skipping duplicate candidate: %s at %s (param: %s)\n",
				r.id, candidate.Type, normalizedURL, normalizedParam)
			return // Duplicate
		}
	}

	r.candidates = append(r.candidates, candidate)
	log.Printf("[%s] 🔍 New Vulnerability Candidate: %s at %s (param: %s)\n", r.id, candidate.Type, candidate.URL, candidate.Parameter)

	// Auto-save report on every new candidate
	r.generateMarkdownReport()
}

func (r *Reporter) generateMarkdownReport() {
	filename := "security_report.md"

	content := "# CAL Security Assessment Report\n\n"
	content += fmt.Sprintf("**Target:** %s\n", r.target)
	content += fmt.Sprintf("**Generated:** %s\n", time.Now().Format(time.RFC1123))
	content += fmt.Sprintf("**Engaged Targets:** %d\n", len(r.engagedTargets))
	content += fmt.Sprintf("**Compromised Targets:** %d\n", len(r.compromisedTargets))
	content += fmt.Sprintf("**Vulnerability Candidates:** %d\n", len(r.candidates))
	content += fmt.Sprintf("**Verified Vulnerabilities:** %d\n\n", len(r.findings))

	content += "## Attack Targets\n"
	if len(r.engagedTargets) == 0 {
		content += "No targets have been actively engaged yet.\n"
	} else {
		content += "The following targets were identified and subjected to active security testing:\n"
		for _, t := range r.engagedTargets {
			content += fmt.Sprintf("- `%s`\n", t)
		}
		content += "\n"
	}

	// Compromised Targets - Systems where shell access was obtained
	content += "## 💀 Compromised Targets (Shell Obtained)\n"
	if len(r.compromisedTargets) == 0 {
		content += "No targets have been fully compromised yet.\n\n"
	} else {
		content += "The following targets have been fully compromised with agent deployment:\n\n"
		content += "| Target URL | Agent PAW | Platform | Host | User | Privilege |\n"
		content += "|---|---|---|---|---|---|\n"
		for _, c := range r.compromisedTargets {
			content += fmt.Sprintf("| `%s` | `%s` | %s | %s | %s | **%s** |\n",
				c.URL, c.AgentPAW, c.Platform, c.Host, c.Username, c.Privilege)
		}
		content += "\n"
	}

	content += "## Executive Summary\n"
	if len(r.candidates) == 0 && len(r.findings) == 0 {
		content += "No vulnerabilities were found during this scan.\n\n"
	} else {
		if len(r.candidates) > 0 {
			content += fmt.Sprintf("**Found %d vulnerability candidate(s)** pending verification:\n\n", len(r.candidates))
			// Count by type
			typeCount := make(map[string]int)
			for _, c := range r.candidates {
				typeCount[c.Type]++
			}
			for vulnType, count := range typeCount {
				content += fmt.Sprintf("- %s: %d candidate(s)\n", vulnType, count)
			}
			content += "\n"
		}

		if len(r.findings) > 0 {
			content += fmt.Sprintf("**Confirmed %d verified vulnerabilit(ies)**:\n\n", len(r.findings))
			content += "| Severity | Type | URL | Payload |\n"
			content += "|---|---|---|---|\n"
			for _, f := range r.findings {
				content += fmt.Sprintf("| **%s** | %s | `%s` | `%s` |\n", f.Severity, f.Type, f.URL, f.Payload)
			}
			content += "\n"
		}
	}

	content += "## Vulnerability Candidates (Pending Verification)\n"
	if len(r.candidates) == 0 {
		content += "No vulnerability candidates detected.\n\n"
	} else {
		content += "The following potential vulnerabilities were identified and are awaiting active verification:\n\n"
		content += "| Type | URL | Parameter | Status |\n"
		content += "|---|---|---|---|\n"
		for _, c := range r.candidates {
			content += fmt.Sprintf("| %s | `%s` | `%s` | %s |\n", c.Type, c.URL, c.Parameter, c.Status)
		}
		content += "\n"
	}

	content += "## Verified Vulnerabilities (Exploited)\n"
	if len(r.findings) == 0 {
		content += "No vulnerabilities have been successfully exploited yet.\n\n"
	} else {
		for i, f := range r.findings {
			content += fmt.Sprintf("### %d. %s\n", i+1, f.Type)
			content += fmt.Sprintf("- **Severity:** %s\n", f.Severity)
			content += fmt.Sprintf("- **URL:** `%s`\n", f.URL)
			content += fmt.Sprintf("- **Payload:** `%s`\n", f.Payload)
			content += fmt.Sprintf("- **Timestamp:** %s\n", f.Timestamp)
			content += fmt.Sprintf("- **Description:**\n%s\n\n", f.Description)
		}
	}

	if err := os.WriteFile(filename, []byte(content), 0644); err != nil {
		log.Printf("[%s] Failed to write report file: %v\n", r.id, err)
	} else {
		log.Printf("[%s] Report updated: %s\n", r.id, filename)
	}
}

// normalizeURL converts relative/absolute paths to canonical form
// This removes ./, ../, redundant slashes, and ensures consistent URL format
func normalizeURL(rawURL string) string {
	// 1. Trim whitespace
	rawURL = strings.TrimSpace(rawURL)

	// 2. Parse URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return rawURL // Return as-is if parsing fails
	}

	// 3. Clean path (removes ./, ../, redundant slashes)
	parsedURL.Path = path.Clean(parsedURL.Path)

	// 4. Convert to absolute URL string
	return parsedURL.String()
}

// normalizeParameter removes backticks, sorts, and standardizes format
// This ensures parameters like "`email` and `password`" and "password, email" are treated as equal
func normalizeParameter(param string) string {
	// 1. Remove backticks
	param = strings.ReplaceAll(param, "`", "")

	// 2. Remove "and" connectors
	param = strings.ReplaceAll(param, " and ", ",")

	// 3. Split by comma, trim, sort
	parts := strings.Split(param, ",")
	var cleaned []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			cleaned = append(cleaned, p)
		}
	}
	sort.Strings(cleaned)

	// 4. Join with comma-space
	return strings.Join(cleaned, ", ")
}
