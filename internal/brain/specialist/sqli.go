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
		go s.executeTask(event)
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

func (s *SQLInjectionSpecialist) generateReport(httpResponse string, analysis string) string {
	report := "=== SQL INJECTION SCAN REPORT ===\n\n"
	report += fmt.Sprintf("Target: %s\n\n", s.target)

	// SQL Injection Analysis
	report += "\n--- SQL Injection Vulnerability Analysis ---\n"
	report += analysis + "\n"

	return report
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
