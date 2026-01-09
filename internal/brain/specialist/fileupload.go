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

var fileUploadMessageCounter atomic.Uint64

// FileUploadSpecialist is a specialist agent focused on File Upload vulnerability detection
type FileUploadSpecialist struct {
	id       string
	bus      bus.Bus
	brain    llm.LLM
	ctx      context.Context
	target   string
	executor tools.ToolExecutor
}

// NewFileUploadSpecialist creates a new FileUploadSpecialist agent
func NewFileUploadSpecialist(ctx context.Context, id string, eventBus bus.Bus, llmClient llm.LLM, target string, executor tools.ToolExecutor) *FileUploadSpecialist {
	return &FileUploadSpecialist{
		id:       id,
		bus:      eventBus,
		brain:    llmClient,
		ctx:      ctx,
		target:   target,
		executor: executor,
	}
}

func (f *FileUploadSpecialist) ID() string {
	return f.id
}

func (f *FileUploadSpecialist) Type() agent.AgentType {
	return agent.Specialist
}

func (f *FileUploadSpecialist) Run() error {
	log.Printf("[%s] Online. Hunting for File Upload vulnerabilities on: %s\n", f.id, f.target)
	return nil
}

func (f *FileUploadSpecialist) OnEvent(event bus.Event) {
	// Only process commands directed to this agent
	if event.Type == bus.Command && event.ToAgent == f.id {
		log.Printf("[%s] Received command: %v\n", f.id, event.Payload)
		go f.executeTask(event)
	}
}

// executeTask performs File Upload vulnerability scanning
func (f *FileUploadSpecialist) executeTask(cmdEvent bus.Event) {
	taskDesc, ok := cmdEvent.Payload.(string)
	if !ok {
		log.Printf("[%s] Invalid task payload\n", f.id)
		return
	}

	log.Printf("[%s] Executing: %s\n", f.id, taskDesc)

	if f.executor == nil {
		f.reportObservation(cmdEvent.FromAgent, "File Upload scan skipped (Docker executor unavailable)")
		return
	}

	// Fetch HTTP response
	targetURL := f.replaceLocalhostForDocker(f.target)

	log.Printf("[%s] Fetching HTTP response from: %s\n", f.id, targetURL)
	httpOutput, err := tools.SimpleHTTPGet(f.ctx, f.executor, targetURL)
	if err != nil {
		log.Printf("[%s] HTTP request failed: %v\n", f.id, err)
		f.reportError(cmdEvent.FromAgent, err)
		return
	}

	// Use LLM to analyze for File Upload vulnerabilities
	log.Printf("[%s] Analyzing for File Upload vulnerabilities...\n", f.id)
	analysis := f.analyzeForFileUpload(httpOutput)

	log.Printf("[%s] File Upload analysis complete\n", f.id)

	// Report candidate to Reporter if found
	f.reportCandidateIfFound(analysis)

	// Generate report
	report := f.generateReport(httpOutput, analysis)

	f.reportObservation(cmdEvent.FromAgent, report)
}

func (f *FileUploadSpecialist) replaceLocalhostForDocker(targetURL string) string {
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

func (f *FileUploadSpecialist) analyzeForFileUpload(httpResponse string) string {
	// Limit response size for LLM
	responseToAnalyze := httpResponse
	if len(httpResponse) > 4000 {
		responseToAnalyze = httpResponse[:4000]
	}

	prompt := prompts.GetFileUploadAnalysis(responseToAnalyze)

	analysis, err := f.brain.Generate(f.ctx, prompt)
	if err != nil {
		log.Printf("[%s] LLM analysis failed: %v\n", f.id, err)
		return "❌ Unable to analyze (LLM error)"
	}

	return analysis
}

// reportCandidateIfFound parses LLM analysis and reports vulnerability candidate to Reporter
func (f *FileUploadSpecialist) reportCandidateIfFound(analysis string) {
	// Check if vulnerability was found
	if !strings.Contains(analysis, "VULNERABILITY CANDIDATE FOUND: Yes") {
		return
	}

	// Extract details from the analysis
	var location, parameter, reasoning, uploadEndpoint string

	lines := strings.Split(analysis, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "- LOCATION:") {
			location = strings.TrimSpace(strings.TrimPrefix(line, "- LOCATION:"))
		} else if strings.HasPrefix(line, "- FILE INPUT NAME:") {
			parameter = strings.TrimSpace(strings.TrimPrefix(line, "- FILE INPUT NAME:"))
		} else if strings.HasPrefix(line, "- REASONING:") {
			reasoning = strings.TrimSpace(strings.TrimPrefix(line, "- REASONING:"))
		} else if strings.HasPrefix(line, "- UPLOAD ENDPOINT:") {
			uploadEndpoint = strings.TrimSpace(strings.TrimPrefix(line, "- UPLOAD ENDPOINT:"))
		}
	}

	// Build full URL if location is relative
	fullURL := f.target
	if location != "" && !strings.HasPrefix(location, "http") {
		if strings.HasPrefix(location, "/") {
			// Parse base URL
			if parsedURL, err := url.Parse(f.target); err == nil {
				fullURL = fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, location)
			}
		}
	} else if location != "" {
		fullURL = location
	}

	// Use upload endpoint if available
	if uploadEndpoint != "" && !strings.HasPrefix(uploadEndpoint, "http") {
		if parsedURL, err := url.Parse(f.target); err == nil {
			baseURL := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
			if strings.HasPrefix(uploadEndpoint, "/") {
				fullURL = baseURL + uploadEndpoint
			} else {
				fullURL = baseURL + "/" + uploadEndpoint
			}
		}
	}

	// Create candidate
	candidate := reporter.VulnerabilityCandidate{
		Type:      "FileUpload",
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
		ID:        fmt.Sprintf("%s-candidate-%d", f.id, fileUploadMessageCounter.Add(1)),
		FromAgent: f.id,
		ToAgent:   "Reporter-01",
		Type:      bus.Candidate,
		Payload:   string(candidateJSON),
	}
	f.bus.Publish("Reporter-01", event)
}

func (f *FileUploadSpecialist) generateReport(httpResponse string, analysis string) string {
	report := "=== FILE UPLOAD VULNERABILITY SCAN REPORT ===\n\n"
	report += fmt.Sprintf("Target: %s\n\n", f.target)

	// File Upload Analysis
	report += "\n--- File Upload Vulnerability Analysis ---\n"
	report += analysis + "\n"

	return report
}

func (f *FileUploadSpecialist) reportObservation(toAgent string, observation string) {
	msgID := fileUploadMessageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-obs-%d", f.id, msgID),
		FromAgent: f.id,
		ToAgent:   toAgent,
		Type:      bus.Observation,
		Payload:   observation,
	}
	f.bus.Publish(toAgent, event)
}

func (f *FileUploadSpecialist) reportError(toAgent string, err error) {
	msgID := fileUploadMessageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-err-%d", f.id, msgID),
		FromAgent: f.id,
		ToAgent:   toAgent,
		Type:      bus.Error,
		Payload:   err.Error(),
	}
	f.bus.Publish(toAgent, event)
}
