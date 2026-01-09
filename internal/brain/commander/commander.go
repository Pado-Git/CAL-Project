package commander

import (
	"cal-project/internal/brain/llm"
	"cal-project/internal/brain/prompts"
	"cal-project/internal/brain/specialist"
	"cal-project/internal/core/agent"
	"cal-project/internal/core/bus"
	"cal-project/internal/hands/docker"
	"cal-project/internal/hands/tools"
	"cal-project/internal/hands/trt"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

// VulnerabilityReport represents JSON output from WebSpecialist
type VulnerabilityReport struct {
	Vulnerabilities []VulnerabilityCandidate `json:"vulnerabilities"`
}

// VulnerabilityCandidate represents a single vulnerability candidate
type VulnerabilityCandidate struct {
	Type       string `json:"type"`
	Location   string `json:"location"`
	Parameter  string `json:"parameter"`
	Confidence string `json:"confidence"`
	Reason     string `json:"reason"`
}

// Commander is the strategic leader agent
type Commander struct {
	id          string
	bus         bus.Bus
	brain       llm.LLM
	ctx         context.Context
	target      string
	trtClient   *trt.Client
	specialists map[string]agent.Agent
	counters    map[string]int
	mu          sync.RWMutex
}

// NewCommander creates a new Commander agent
func NewCommander(ctx context.Context, eventBus bus.Bus, llmClient llm.LLM, targetURL string, trtClient *trt.Client) *Commander {
	return &Commander{
		id:          "Commander-01",
		bus:         eventBus,
		brain:       llmClient,
		ctx:         ctx,
		target:      targetURL,
		trtClient:   trtClient,
		specialists: make(map[string]agent.Agent),
		counters:    make(map[string]int),
	}
}

func (c *Commander) ID() string {
	return c.id
}

func (c *Commander) Type() agent.AgentType {
	return agent.Commander
}

func (c *Commander) Run() error {
	log.Printf("[%s] Online. Target: %s\n", c.id, c.target)

	// TRT Initialization
	if c.trtClient != nil {
		log.Printf("[%s] TRT: Authenticating...\n", c.id)
		if err := c.trtClient.Authenticate(); err != nil {
			log.Printf("[%s] TRT Auth Failed: %v. Stopping Brain.\n", c.id, err)
			return fmt.Errorf("failed to authenticate with TRT: %w", err)
		} else {
			log.Printf("[%s] TRT Auth Success\n", c.id)
			agents, err := c.trtClient.GetAliveAgents()
			if err != nil {
				log.Printf("[%s] Failed to get agents: %v\n", c.id, err)
			} else {
				log.Printf("[%s] Discovered %d alive agents\n", c.id, len(agents))
				if len(agents) > 0 {
					log.Printf("[%s] Primary Agent: %s (%s)\n", c.id, agents[0].Paw, agents[0].Host)
				}
			}
		}
	}

	// Initial thought with authorized testing context
	initialPrompt := prompts.GetCommanderInitial(c.target)
	go c.think(initialPrompt)

	return nil
}

func (c *Commander) OnEvent(event bus.Event) {
	// Commander reacts to observations and errors
	switch event.Type {
	case bus.Observation:
		observation, ok := event.Payload.(string)
		if !ok {
			return
		}

		log.Printf("[%s] ✅ Observation from %s: %v\n", c.id, event.FromAgent, truncateLog(observation, 300))

		// Analyze observation with LLM to find vulnerabilities
		go c.analyzeObservation(event.FromAgent, observation)

		// Check for vulnerabilities to trigger verification
		// Match various formats from different specialists
		lowerObs := strings.ToLower(observation)
		isVuln := false

		if strings.Contains(lowerObs, "vulnerabilities found:") && !strings.Contains(lowerObs, "vulnerabilities found: 0") {
			isVuln = true
		}
		if strings.Contains(observation, "VULNERABILITY FOUND: Yes") {
			isVuln = true
		}
		if strings.Contains(observation, "VULNERABILITY CANDIDATE FOUND: Yes") {
			isVuln = true
		}

		// Check for open ports to trigger WebSpecialist
		if strings.Contains(observation, "Discovered Open Port:") {
			// Legacy check removed or updated to use specific parsing if standard nmap output was reliable here.
			// Since we rely on LLM Analysis now, we can remove this or make it robust.
			// Use LLM analysis trigger instead.
		}

		// Direct triggers from specific agents finding issues
		if isVuln {
			log.Printf("[%s] 🚨 Vulnerabilities detected! Spawning VerificationSpecialist\n", c.id)
			go c.spawnVerificationSpecialist(observation)
		}

	case bus.Error:
		log.Printf("[%s] ❌ Error received from %s: %v\n", c.id, event.FromAgent, event.Payload)
	}
}

func (c *Commander) analyzeObservation(fromAgent string, observation string) {
	// First, check if observation contains JSON vulnerability report from WebSpecialist
	if strings.Contains(observation, "VULN_JSON_START") {
		c.parseVulnerabilityJSON(fromAgent, observation)
		return
	}

	prompt := prompts.GetCommanderAnalyze(fromAgent, c.target, observation)

	analysis, err := c.brain.Generate(c.ctx, prompt)
	if err != nil {
		log.Printf("[%s] Failed to analyze observation: %v\n", c.id, err)
		return
	}

	log.Printf("[%s] 🔍 ANALYSIS: %s\n", c.id, analysis)

	// Check for "Recommended: Spawn WebSpecialist for <IP>"
	lines := strings.Split(analysis, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Recommended: Spawn WebSpecialist for") {
			parts := strings.Split(line, "for")
			if len(parts) > 1 {
				ip := strings.TrimSpace(parts[1])
				// Clean up IP (remove punctuation if any)
				ip = strings.TrimRight(ip, ".")

				targetURL := fmt.Sprintf("http://%s", ip)
				log.Printf("[%s] 🚀 Triggering WebSpecialist for discovered target: %s\n", c.id, targetURL)

				// Spawn ONLY WebSpecialist initially. It will scout and recommend others.
				go func(t string) {
					c.spawnWebSpecialist(t)
				}(targetURL)
			}
		}
	}
}

// parseVulnerabilityJSON extracts and parses JSON from WebSpecialist report
func (c *Commander) parseVulnerabilityJSON(fromAgent string, observation string) {
	// Extract JSON between markers
	startMarker := "VULN_JSON_START"
	endMarker := "VULN_JSON_END"

	startIdx := strings.Index(observation, startMarker)
	endIdx := strings.Index(observation, endMarker)

	if startIdx == -1 || endIdx == -1 || endIdx <= startIdx {
		log.Printf("[%s] Failed to find JSON markers in observation\n", c.id)
		return
	}

	jsonStr := strings.TrimSpace(observation[startIdx+len(startMarker) : endIdx])
	log.Printf("[%s] 📋 Parsing vulnerability JSON from %s\n", c.id, fromAgent)

	var report VulnerabilityReport
	if err := json.Unmarshal([]byte(jsonStr), &report); err != nil {
		log.Printf("[%s] Failed to parse vulnerability JSON: %v\n", c.id, err)
		log.Printf("[%s] Raw JSON: %s\n", c.id, jsonStr)
		return
	}

	if len(report.Vulnerabilities) == 0 {
		log.Printf("[%s] No vulnerabilities found by %s\n", c.id, fromAgent)
		return
	}

	log.Printf("[%s] 🎯 Found %d vulnerability candidates from %s\n", c.id, len(report.Vulnerabilities), fromAgent)

	// Extract base URL from the report's target (need to get it from WebSpecialist's observation)
	baseURL := c.extractBaseURL(observation)

	// Spawn appropriate specialists based on vulnerability types
	for _, vuln := range report.Vulnerabilities {
		targetURL := c.buildTargetURL(baseURL, vuln.Location)

		log.Printf("[%s] Vulnerability: type=%s, location=%s, param=%s, confidence=%s\n",
			c.id, vuln.Type, vuln.Location, vuln.Parameter, vuln.Confidence)

		switch strings.ToUpper(vuln.Type) {
		case "XSS":
			log.Printf("[%s] ⚔️ Spawning XSSSpecialist for: %s (param: %s)\n", c.id, targetURL, vuln.Parameter)
			go c.spawnXSSSpecialist(targetURL)

		case "SQLI":
			log.Printf("[%s] 💉 Spawning SQLiSpecialist for: %s (param: %s)\n", c.id, targetURL, vuln.Parameter)
			go c.spawnSQLiSpecialist(targetURL)

		case "PATHTRAVERSAL":
			log.Printf("[%s] 📂 Spawning PathTraversalSpecialist for: %s (param: %s)\n", c.id, targetURL, vuln.Parameter)
			go c.spawnPathTraversalSpecialist(targetURL)

		case "COMMANDINJECTION":
			log.Printf("[%s] ⚡ Spawning CommandInjectionSpecialist for: %s (param: %s)\n", c.id, targetURL, vuln.Parameter)
			go c.spawnCommandInjectionSpecialist(targetURL, vuln.Parameter)

		default:
			log.Printf("[%s] Unknown vulnerability type: %s\n", c.id, vuln.Type)
		}
	}
}

// extractBaseURL extracts the target URL from WebSpecialist's report
func (c *Commander) extractBaseURL(observation string) string {
	// Look for "Target: http://..." in the report
	lines := strings.Split(observation, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "Target:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) > 1 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	// Fallback to commander's target
	return c.target
}

// buildTargetURL constructs full URL from base and location
func (c *Commander) buildTargetURL(baseURL, location string) string {
	// If location is already a full URL, use it
	if strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		return location
	}

	// Combine base URL with location path
	baseURL = strings.TrimSuffix(baseURL, "/")
	if !strings.HasPrefix(location, "/") {
		location = "/" + location
	}
	return baseURL + location
}

func truncateLog(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// think uses the LLM to generate a thought process and potentially issue commands
func (c *Commander) think(prompt string) {
	log.Printf("[%s] Thinking...\n", c.id)

	resp, err := c.brain.Generate(c.ctx, prompt)
	if err != nil {
		log.Printf("[%s] Brain freeze (LLM Error): %v\n", c.id, err)

		// FALLBACK PROTOCOL
		log.Printf("[%s] ⚠️ LLM Unavailable. Switching to MANUAL OVERRIDE protocol.\n", c.id)
		resp = "Perform reconnaissance and web scanning on the target." // Synthetic thought to trigger standard flow
	}

	log.Printf("[%s] Thought: %s\n", c.id, resp)

	log.Printf("[%s] Thought: %s\n", c.id, resp)

	// Always spawn Recon Specialist to start
	c.spawnReconSpecialist()

	// Logic for WebSpecialist is now event-driven based on Recon results.
	// We do NOT spawn it immediately to avoid "curl before open port" issues.
	/*
		if strings.HasPrefix(c.target, "http") || c.shouldSpawnWebSpecialist(resp) {
			log.Printf("[%s] Target is web-based or requested: Spawning Web Specialists\n", c.id)
			c.spawnWebSpecialist()           // Coordinator
			c.spawnXSSSpecialist()           // Worker
			c.spawnSQLiSpecialist()          // Worker
			c.spawnPathTraversalSpecialist() // Worker
		}
	*/
}

// shouldSpawnReconSpecialist checks if the LLM response suggests spawning a recon agent
func (c *Commander) shouldSpawnReconSpecialist(response string) bool {
	// Convert to lowercase for case-insensitive matching
	lowerResponse := strings.ToLower(response)

	// Expanded keyword list
	keywords := []string{
		"reconnaissance", "recon", "scan", "discover", "enumerate",
		"nmap", "port", "service", "fingerprint", "identify",
		"information gathering", "enumeration",
	}

	for _, kw := range keywords {
		if strings.Contains(lowerResponse, kw) {
			return true
		}
	}
	return false
}

// shouldSpawnWebSpecialist checks if the LLM response suggests spawning a web specialist
func (c *Commander) shouldSpawnWebSpecialist(response string) bool {
	lowerResponse := strings.ToLower(response)

	keywords := []string{
		"web", "http", "https", "curl", "webpage", "website",
		"header", "response", "request", "url",
		"path", "traversal", "file", "directory",
	}

	for _, kw := range keywords {
		if strings.Contains(lowerResponse, kw) {
			return true
		}
	}
	return false
}

// spawnReconSpecialist creates and registers a new ReconSpecialist
func (c *Commander) spawnReconSpecialist() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we already have a recon specialist
	reconID := "ReconAgent-01"
	if _, exists := c.specialists[reconID]; exists {
		log.Printf("[%s] ReconSpecialist already exists, sending task instead\n", c.id)
		c.sendTaskToSpecialist(reconID, "Perform initial reconnaissance on "+c.target)
		return
	}

	// Determine Executor
	var executor tools.ToolExecutor
	var err error

	if c.trtClient != nil {
		agents, trtErr := c.trtClient.GetAliveAgents()
		if trtErr == nil && len(agents) > 0 {
			agent := agents[0]
			log.Printf("[%s] Using TRT Agent %s (%s) for ReconSpecialist\n", c.id, agent.Paw, agent.Platform)
			executor = trt.NewRemoteExecutor(c.trtClient, agent.Paw, agent.Platform)
		}
	}

	if executor == nil {
		log.Printf("[%s] TRT unavailable, falling back to Docker Executor for ReconSpecialist\n", c.id)
		executor, err = docker.NewExecutor(reconID)
		if err != nil {
			log.Printf("[%s] Failed to create Docker executor: %v\n", c.id, err)
		}
	}

	// Create new specialist
	log.Printf("[%s] Spawning ReconSpecialist...\n", c.id)
	reconAgent := specialist.NewReconSpecialist(c.ctx, reconID, c.bus, c.brain, c.target, executor)

	// Register specialist
	c.specialists[reconID] = reconAgent

	// Subscribe to Event Bus (crucial for receiving commands!)
	c.bus.Subscribe(reconID, func(e bus.Event) {
		reconAgent.OnEvent(e)
	})

	log.Printf("[%s] Subscribed %s to Event Bus\n", c.id, reconID)

	// Start the specialist
	go func() {
		if err := reconAgent.Run(); err != nil {
			log.Printf("[%s] Specialist %s crashed: %v\n", c.id, reconID, err)
		}
	}()

	// Send initial task
	c.sendTaskToSpecialist(reconID, "Perform initial reconnaissance on "+c.target)
}

// spawnWebSpecialist creates and registers a new WebSpecialist
func (c *Commander) spawnWebSpecialist(targetURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Generate unique ID based on target
	c.counters["WebAgent"]++
	count := c.counters["WebAgent"]
	webID := fmt.Sprintf("WebAgent-%02d", count)

	// Check if this specific target is already being handled (optional, simple de-dupe)
	// For now, allow multiple agents or rely on manual management

	// Determine Executor

	var executor tools.ToolExecutor
	var err error

	// Try TRT first if client exists
	if c.trtClient != nil {
		// Need to find a paw. In Run() we logged it, but didn't store it?
		// Let's call GetAliveAgents again or reuse result if cached (not cached currently)
		agents, trtErr := c.trtClient.GetAliveAgents()
		if trtErr == nil && len(agents) > 0 {
			agent := agents[0] // Pick first for now
			log.Printf("[%s] Using TRT Agent %s (%s) for WebSpecialist\n", c.id, agent.Paw, agent.Platform)
			executor = trt.NewRemoteExecutor(c.trtClient, agent.Paw, agent.Platform)
		}
	}

	// Fallback to Docker if TRT not available or failed
	if executor == nil {
		log.Printf("[%s] TRT unavailable, falling back to Docker Executor for WebSpecialist\n", c.id)
		executor, err = docker.NewExecutor(webID)
		if err != nil {
			log.Printf("[%s] Failed to create Docker executor: %v\n", c.id, err)
		}
	}

	// Create new specialist
	log.Printf("[%s] Spawning WebSpecialist for %s...\n", c.id, targetURL)
	webAgent := specialist.NewWebSpecialist(c.ctx, webID, c.bus, c.brain, targetURL, executor)

	// Register specialist
	c.specialists[webID] = webAgent

	// Report engagement to Reporter
	c.reportEngagement(targetURL)

	// Subscribe to Event Bus
	c.bus.Subscribe(webID, func(e bus.Event) {
		webAgent.OnEvent(e)
	})

	log.Printf("[%s] Subscribed %s to Event Bus\n", c.id, webID)

	// Start the specialist
	go func() {
		if err := webAgent.Run(); err != nil {
			log.Printf("[%s] Specialist %s crashed: %v\n", c.id, webID, err)
		}
	}()

	// Send initial task
	c.sendTaskToSpecialist(webID, "Perform web reconnaissance on "+targetURL)
}

// spawnVerificationSpecialist creates and registers a new VerificationSpecialist
func (c *Commander) spawnVerificationSpecialist(vulnReport string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Generate unique ID for parallel verification
	c.counters["VerifyAgent"]++
	count := c.counters["VerifyAgent"]
	verifyID := fmt.Sprintf("VerifyAgent-%02d", count)

	// Previously we checked for existence, now we allow parallels
	// But valid to check if SPECIFIC ID exists (unlikely with counter)
	if _, exists := c.specialists[verifyID]; exists {
		log.Printf("[%s] %s already exists, sending task\n", c.id, verifyID)
		c.sendTaskToSpecialist(verifyID, vulnReport)
		return
	}

	// Verification always uses Docker for now (needs browser)
	log.Printf("[%s] Spawning VerificationSpecialist (Force Docker)...\n", c.id)
	dockerExec, err := docker.NewExecutor(verifyID)
	if err != nil {
		log.Printf("[%s] Failed to create Docker executor for Verify: %v\n", c.id, err)
	}

	// Create new specialist
	verifyAgent := specialist.NewVerificationSpecialist(c.ctx, verifyID, c.bus, c.brain, c.target, dockerExec)

	// Register specialist
	c.specialists[verifyID] = verifyAgent

	// Subscribe to Event Bus
	c.bus.Subscribe(verifyID, func(e bus.Event) {
		verifyAgent.OnEvent(e)
	})

	log.Printf("[%s] Subscribed %s to Event Bus\n", c.id, verifyID)

	// Start the specialist
	go func() {
		if err := verifyAgent.Run(); err != nil {
			log.Printf("[%s] Specialist %s crashed: %v\n", c.id, verifyID, err)
		}
	}()

	// Send verification task
	c.sendTaskToSpecialist(verifyID, vulnReport)
}

// sendTaskToSpecialist sends a command to a specialist agent
func (c *Commander) sendTaskToSpecialist(specialistID string, task string) {
	cmd := bus.Event{
		ID:        fmt.Sprintf("%s-cmd-%s", c.id, specialistID),
		FromAgent: c.id,
		ToAgent:   specialistID,
		Type:      bus.Command,
		Payload:   task,
	}
	c.bus.Publish(specialistID, cmd)
	log.Printf("[%s] Sent task to %s: %s\n", c.id, specialistID, task)
}

// Helper function
func contains(text, substr string) bool {
	return len(text) >= len(substr) && (text == substr || containsHelper(text, substr))
}

func containsHelper(text, substr string) bool {
	for i := 0; i <= len(text)-len(substr); i++ {
		if text[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func (c *Commander) reportEngagement(target string) {
	event := bus.Event{
		ID:        fmt.Sprintf("%s-engage-%d", c.id, time.Now().UnixNano()),
		FromAgent: c.id,
		ToAgent:   "Reporter-01",
		Type:      bus.Engagement,
		Payload:   target,
	}
	c.bus.Publish("Reporter-01", event)
}

// spawnXSSSpecialist creates and registers XSS specialist
func (c *Commander) spawnXSSSpecialist(targetURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Generate unique ID
	c.counters["XSSAgent"]++
	count := c.counters["XSSAgent"]
	xssID := fmt.Sprintf("XSSAgent-%02d", count)

	// Since ID is unique with counter, we don't strictly need exists check unless re-using IDs
	// But good practice.
	if _, exists := c.specialists[xssID]; exists {
		return
	}

	executor, _ := c.selectExecutor(xssID)
	log.Printf("[%s] Spawning XSSSpecialist for %s...\n", c.id, targetURL)
	xssAgent := specialist.NewXSSSpecialist(c.ctx, xssID, c.bus, c.brain, targetURL, executor)
	c.specialists[xssID] = xssAgent

	c.bus.Subscribe(xssID, func(e bus.Event) {
		xssAgent.OnEvent(e)
	})

	log.Printf("[%s] Subscribed %s to Event Bus\n", c.id, xssID)

	go func() {
		if err := xssAgent.Run(); err != nil {
			log.Printf("[%s] XSSSpecialist crashed: %v\n", c.id, err)
		}
	}()

	c.sendTaskToSpecialist(xssID, "Hunt for XSS vulnerabilities on "+targetURL)
}

// spawnSQLiSpecialist creates and registers SQLi specialist
func (c *Commander) spawnSQLiSpecialist(targetURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Generate unique ID
	c.counters["SQLiAgent"]++
	count := c.counters["SQLiAgent"]
	sqliID := fmt.Sprintf("SQLiAgent-%02d", count)

	if _, exists := c.specialists[sqliID]; exists {
		return
	}

	executor, _ := c.selectExecutor(sqliID)
	log.Printf("[%s] Spawning SQLiSpecialist for %s...\n", c.id, targetURL)
	sqliAgent := specialist.NewSQLInjectionSpecialist(c.ctx, sqliID, c.bus, c.brain, targetURL, executor)
	c.specialists[sqliID] = sqliAgent

	c.bus.Subscribe(sqliID, func(e bus.Event) {
		sqliAgent.OnEvent(e)
	})

	log.Printf("[%s] Subscribed %s to Event Bus\n", c.id, sqliID)

	go func() {
		if err := sqliAgent.Run(); err != nil {
			log.Printf("[%s] SQLiSpecialist crashed: %v\n", c.id, err)
		}
	}()

	c.sendTaskToSpecialist(sqliID, "Hunt for SQL injection on "+targetURL)
}

// spawnPathTraversalSpecialist creates and registers Path Traversal specialist
func (c *Commander) spawnPathTraversalSpecialist(targetURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Generate unique ID
	c.counters["PathTraversalAgent"]++
	count := c.counters["PathTraversalAgent"]
	ptID := fmt.Sprintf("PathTraversalAgent-%02d", count)

	if _, exists := c.specialists[ptID]; exists {
		return
	}

	executor, _ := c.selectExecutor(ptID)
	log.Printf("[%s] Spawning PathTraversalSpecialist for %s...\n", c.id, targetURL)
	ptAgent := specialist.NewPathTraversalSpecialist(c.ctx, ptID, c.bus, c.brain, targetURL, executor)
	c.specialists[ptID] = ptAgent

	c.bus.Subscribe(ptID, func(e bus.Event) {
		ptAgent.OnEvent(e)
	})

	log.Printf("[%s] Subscribed %s to Event Bus\n", c.id, ptID)

	go func() {
		if err := ptAgent.Run(); err != nil {
			log.Printf("[%s] PathTraversalSpecialist crashed: %v\n", c.id, err)
		}
	}()

	c.sendTaskToSpecialist(ptID, "Hunt for Path Traversal vulnerabilities on "+targetURL)
}

// Helper: Select Executor
func (c *Commander) selectExecutor(agentID string) (tools.ToolExecutor, error) {
	var executor tools.ToolExecutor
	var err error

	// Try TRT
	if c.trtClient != nil {
		agents, trtErr := c.trtClient.GetAliveAgents()
		if trtErr == nil && len(agents) > 0 {
			agent := agents[0]
			// log.Printf("[%s] Using TRT Agent %s for %s\n", c.id, agent.Paw, agentID)
			executor = trt.NewRemoteExecutor(c.trtClient, agent.Paw, agent.Platform)
		}
	}

	// Fallback
	if executor == nil {
		// log.Printf("[%s] Using Docker Executor for %s\n", c.id, agentID)
		executor, err = docker.NewExecutor(agentID)
	}
	return executor, err
}

// spawnCommandInjectionSpecialist creates and registers Command Injection specialist
// This now uses TRT API to deploy agents through existing agents
func (c *Commander) spawnCommandInjectionSpecialist(targetURL string, parameter string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Generate unique ID
	c.counters["CmdIAgent"]++
	count := c.counters["CmdIAgent"]
	cmdiID := fmt.Sprintf("CmdIAgent-%02d", count)

	if _, exists := c.specialists[cmdiID]; exists {
		return
	}

	// TRT Client is required for the new approach
	if c.trtClient == nil {
		log.Printf("[%s] Cannot spawn CommandInjectionSpecialist: TRT Client not available\n", c.id)
		return
	}

	// Get an available agent to use for deployment
	agents, err := c.trtClient.GetAliveAgents()
	if err != nil || len(agents) == 0 {
		log.Printf("[%s] Cannot spawn CommandInjectionSpecialist: No agents available (err: %v)\n", c.id, err)
		return
	}

	// Use the first available agent
	agent := agents[0]
	log.Printf("[%s] Spawning CommandInjectionSpecialist using agent %s (%s)...\n", c.id, agent.Paw, agent.Platform)

	cmdiAgent := specialist.NewCommandInjectionSpecialist(c.ctx, cmdiID, c.bus, c.brain, c.trtClient, agent.Paw, agent.Platform)
	c.specialists[cmdiID] = cmdiAgent

	c.bus.Subscribe(cmdiID, func(e bus.Event) {
		cmdiAgent.OnEvent(e)
	})

	log.Printf("[%s] Subscribed %s to Event Bus\n", c.id, cmdiID)

	go func() {
		if err := cmdiAgent.Run(); err != nil {
			log.Printf("[%s] CommandInjectionSpecialist crashed: %v\n", c.id, err)
		}
	}()

	c.sendTaskToSpecialist(cmdiID, fmt.Sprintf("Deploy CallistoAgent via agent %s (target context: %s)", agent.Paw, targetURL))
}

// spawnAgentDeploymentSpecialist creates a specialist specifically for deploying agents
// This is an alias/shortcut for deployment tasks
func (c *Commander) spawnAgentDeploymentSpecialist(agentPaw string, platform string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Generate unique ID
	c.counters["CmdIAgent"]++
	count := c.counters["CmdIAgent"]
	cmdiID := fmt.Sprintf("DeployAgent-%02d", count)

	if _, exists := c.specialists[cmdiID]; exists {
		return
	}

	if c.trtClient == nil {
		log.Printf("[%s] Cannot spawn AgentDeploymentSpecialist: TRT Client not available\n", c.id)
		return
	}

	log.Printf("[%s] Spawning AgentDeploymentSpecialist using agent %s (%s)...\n", c.id, agentPaw, platform)

	cmdiAgent := specialist.NewCommandInjectionSpecialist(c.ctx, cmdiID, c.bus, c.brain, c.trtClient, agentPaw, platform)
	c.specialists[cmdiID] = cmdiAgent

	c.bus.Subscribe(cmdiID, func(e bus.Event) {
		cmdiAgent.OnEvent(e)
	})

	log.Printf("[%s] Subscribed %s to Event Bus\n", c.id, cmdiID)

	go func() {
		if err := cmdiAgent.Run(); err != nil {
			log.Printf("[%s] AgentDeploymentSpecialist crashed: %v\n", c.id, err)
		}
	}()

	c.sendTaskToSpecialist(cmdiID, fmt.Sprintf("Deploy CallistoAgent via agent %s", agentPaw))
}
