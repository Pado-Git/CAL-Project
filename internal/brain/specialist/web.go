package specialist

import (
	"cal-project/internal/brain/llm"
	"cal-project/internal/core/agent"
	"cal-project/internal/core/bus"
	"cal-project/internal/hands/docker"
	"cal-project/internal/hands/tools"
	"context"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync/atomic"
)

var webMessageCounter atomic.Uint64

// WebSpecialist is a specialist agent focused on web/HTTP reconnaissance
type WebSpecialist struct {
	id       string
	bus      bus.Bus
	brain    llm.LLM
	ctx      context.Context
	target   string
	executor *docker.Executor
}

// NewWebSpecialist creates a new WebSpecialist agent
func NewWebSpecialist(ctx context.Context, id string, eventBus bus.Bus, llmClient llm.LLM, target string) *WebSpecialist {
	exec, err := docker.NewExecutor()
	if err != nil {
		log.Printf("[%s] Warning: Failed to create Docker executor: %v. Tools will not run.\n", id, err)
	}

	return &WebSpecialist{
		id:       id,
		bus:      eventBus,
		brain:    llmClient,
		ctx:      ctx,
		target:   target,
		executor: exec,
	}
}

func (w *WebSpecialist) ID() string {
	return w.id
}

func (w *WebSpecialist) Type() agent.AgentType {
	return agent.Specialist
}

func (w *WebSpecialist) Run() error {
	log.Printf("[%s] Online. Awaiting web reconnaissance tasks for: %s\n", w.id, w.target)
	return nil
}

func (w *WebSpecialist) OnEvent(event bus.Event) {
	// Only process commands directed to this agent
	if event.Type == bus.Command && event.ToAgent == w.id {
		log.Printf("[%s] Received command: %v\n", w.id, event.Payload)
		go w.executeTask(event)
	}
}

// executeTask performs the web reconnaissance task
func (w *WebSpecialist) executeTask(cmdEvent bus.Event) {
	taskDesc, ok := cmdEvent.Payload.(string)
	if !ok {
		log.Printf("[%s] Invalid task payload\n", w.id)
		return
	}

	log.Printf("[%s] Executing: %s\n", w.id, taskDesc)

	if w.executor == nil {
		w.reportObservation(cmdEvent.FromAgent, "Web reconnaissance skipped (Docker executor unavailable)")
		return
	}

	// Fetch HTTP response
	targetURL := w.replaceLocalhostForDocker(w.target)

	log.Printf("[%s] Fetching HTTP response from: %s\n", w.id, targetURL)
	httpOutput, err := tools.SimpleHTTPGet(w.ctx, w.executor, targetURL)
	if err != nil {
		log.Printf("[%s] HTTP request failed: %v\n", w.id, err)
		w.reportError(cmdEvent.FromAgent, err)
		return
	}

	log.Printf("[%s] HTTP response received (%d bytes)\n", w.id, len(httpOutput))

	// Use LLM to analyze for vulnerabilities
	log.Printf("[%s] Analyzing response for vulnerabilities...\n", w.id)
	analysis := w.analyzeForVulnerabilities(httpOutput)

	log.Printf("[%s] Analysis complete\n", w.id)

	// Generate report
	report := w.generateReport(httpOutput, analysis)

	log.Printf("[%s] Sending report to %s\n", w.id, cmdEvent.FromAgent)
	w.reportObservation(cmdEvent.FromAgent, report)
	log.Printf("[%s] Task completed\n", w.id)
}

func (w *WebSpecialist) replaceLocalhostForDocker(targetURL string) string {
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

func (w *WebSpecialist) analyzeForVulnerabilities(httpResponse string) string {
	// Limit response size for LLM
	responseToAnalyze := httpResponse
	if len(httpResponse) > 3000 {
		responseToAnalyze = httpResponse[:3000]
	}

	// Use LLM to analyze HTTP response for security issues
	prompt := fmt.Sprintf(
		"Analyze this HTTP response for XSS and security vulnerabilities.\n\n"+
			"HTTP Response:\n%s\n\n"+
			"TASK:\n"+
			"1. Check for input forms - are they vulnerable to XSS?\n"+
			"2. Look for reflected user input in the response\n"+
			"3. Check security headers (X-Frame-Options, CSP, etc.)\n"+
			"4. Identify exposed sensitive information\n\n"+
			"Reply with findings in 3-4 sentences. Be specific about vulnerabilities found.",
		responseToAnalyze,
	)

	analysis, err := w.brain.Generate(w.ctx, prompt)
	if err != nil {
		log.Printf("[%s] LLM analysis failed: %v\n", w.id, err)
		return "❌ Unable to analyze (LLM error)"
	}

	return analysis
}

func (w *WebSpecialist) generateReport(httpResponse string, analysis string) string {
	report := "=== WEB RECONNAISSANCE REPORT ===\n\n"
	report += fmt.Sprintf("Target: %s\n\n", w.target)

	// HTTP Response headers
	report += "--- HTTP Response Headers ---\n"
	lines := strings.Split(httpResponse, "\n")
	headerCount := 0
	for _, line := range lines {
		if line == "" || line == "\r" {
			break
		}
		report += line + "\n"
		headerCount++
		if headerCount > 15 {
			break
		}
	}

	// LLM Security Analysis
	report += "\n--- Security Analysis ---\n"
	report += analysis + "\n"

	return report
}

func (w *WebSpecialist) reportObservation(toAgent string, observation string) {
	msgID := webMessageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-obs-%d", w.id, msgID),
		FromAgent: w.id,
		ToAgent:   toAgent,
		Type:      bus.Observation,
		Payload:   observation,
	}
	w.bus.Publish(toAgent, event)
}

func (w *WebSpecialist) reportError(toAgent string, err error) {
	msgID := webMessageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-err-%d", w.id, msgID),
		FromAgent: w.id,
		ToAgent:   toAgent,
		Type:      bus.Error,
		Payload:   err.Error(),
	}
	w.bus.Publish(toAgent, event)
}
