package specialist

import (
	"cal-project/internal/brain/llm"
	"cal-project/internal/brain/prompts"
	"cal-project/internal/core/agent"
	"cal-project/internal/core/bus"
	"cal-project/internal/hands/tools"
	"context"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync/atomic"
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
		go x.executeTask(event)
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
	// Limit response size for LLM
	responseToAnalyze := httpResponse
	if len(httpResponse) > 4000 {
		responseToAnalyze = httpResponse[:4000]
	}

	// ENHANCED PROMPT for finding specific locations
	prompt := prompts.GetXSSAnalysis(responseToAnalyze)

	analysis, err := x.brain.Generate(x.ctx, prompt)
	if err != nil {
		log.Printf("[%s] LLM analysis failed: %v\n", x.id, err)
		return "❌ Unable to analyze (LLM error)"
	}

	return analysis
}

func (x *XSSSpecialist) generateReport(httpResponse string, analysis string) string {
	report := "=== XSS VULNERABILITY SCAN REPORT ===\n\n"
	report += fmt.Sprintf("Target: %s\n\n", x.target)

	// XSS Analysis
	report += "\n--- XSS Vulnerability Analysis ---\n"
	report += analysis + "\n"

	return report
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
