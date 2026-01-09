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
	"strings"
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
		go p.executeTask(event)
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

	// Create candidate
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
