package commander

import (
	"cal-project/internal/brain/llm"
	"cal-project/internal/brain/prompts"
	"cal-project/internal/brain/specialist"
	"cal-project/internal/core/agent"
	"cal-project/internal/core/bus"
	"cal-project/internal/core/utils"
	"cal-project/internal/hands/docker"
	"cal-project/internal/hands/tools"
	"cal-project/internal/hands/trt"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
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
	id            string
	bus           bus.Bus
	brain         llm.LLM
	ctx           context.Context

	// Target configuration
	target        string
	mode          string // "single" or "network"
	email         string // Login credentials
	password      string // Login credentials

	trtClient     *trt.Client
	specialists   map[string]agent.Agent
	counters      map[string]int
	sessionCookie string          // Session cookie for authenticated requests
	crawledURLs   map[string]bool // Base URLs that have been crawled
	mu            sync.RWMutex
}

// NewCommander creates a new Commander agent
func NewCommander(ctx context.Context, eventBus bus.Bus, llmClient llm.LLM, targetURL string, mode string, email string, password string, trtClient *trt.Client) *Commander {
	return &Commander{
		id:          "Commander-01",
		bus:         eventBus,
		brain:       llmClient,
		ctx:         ctx,
		target:      targetURL,
		mode:        mode,
		email:       email,
		password:    password,
		trtClient:   trtClient,
		specialists: make(map[string]agent.Agent),
		counters:    make(map[string]int),
		crawledURLs: make(map[string]bool),
	}
}

func (c *Commander) ID() string {
	return c.id
}

func (c *Commander) Type() agent.AgentType {
	return agent.Commander
}

func (c *Commander) Run() error {
	log.Printf("[%s] Online. Target: %s | Mode: %s\n", c.id, c.target, c.mode)

	// TRT Initialization (optional, only warn on failure in single mode)
	if c.trtClient != nil {
		log.Printf("[%s] TRT: Authenticating...\n", c.id)
		if err := c.trtClient.Authenticate(); err != nil {
			if c.mode == "single" {
				log.Printf("[%s] ⚠️ TRT Auth Failed (Single Mode): %v. Continuing without TRT.\n", c.id, err)
			} else {
				log.Printf("[%s] TRT Auth Failed: %v. Stopping Brain.\n", c.id, err)
				return fmt.Errorf("failed to authenticate with TRT: %w", err)
			}
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

	// Execute mode-specific logic
	switch c.mode {
	case "single":
		return c.runSingleTargetMode()
	case "network":
		return c.runNetworkMode()
	default:
		return fmt.Errorf("unknown mode: %s", c.mode)
	}
}

// runSingleTargetMode directly spawns WebSpecialist (skip ReconSpecialist)
func (c *Commander) runSingleTargetMode() error {
	log.Printf("[%s] SINGLE TARGET MODE: Directly attacking %s\n", c.id, c.target)

	// Spawn WebSpecialist directly for the target URL
	c.spawnWebSpecialistDirect(c.target)

	return nil
}

// runNetworkMode uses existing ReconSpecialist flow
func (c *Commander) runNetworkMode() error {
	log.Printf("[%s] NETWORK MODE: Starting reconnaissance on %s\n", c.id, c.target)

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

	// Check for session cookie from LoginSpecialist
	if strings.Contains(observation, "SESSION_COOKIE_START") {
		c.handleSessionCookie(observation)
		return
	}

	// Check for crawler results
	if strings.Contains(observation, "CRAWLER_JSON_START") {
		c.handleCrawlerResults(observation)
		return
	}

	// Check for login form detection
	if strings.Contains(observation, "LOGIN_FORM_FOUND:") {
		loginURL := c.extractLoginURL(observation)
		if loginURL != "" {
			log.Printf("[%s] 🔐 Login form detected, spawning LoginSpecialist\n", c.id)

			// Use credentials from Commander (set via CLI or .env)
			email := c.email
			if email == "" {
				email = "test@test.net" // Backward compatibility
				log.Printf("[%s] ⚠️ No credentials configured, using default\n", c.id)
			}

			password := c.password
			if password == "" {
				password = "1234" // Backward compatibility
			}

			credentials := map[string]string{
				"email":    email,
				"password": password,
			}
			go c.spawnLoginSpecialist(loginURL, credentials)
		}
		return
	}

	// Second, check if observation contains nmap scan results - parse directly without LLM
	if strings.Contains(observation, "Nmap scan report for") {
		httpHosts := c.parseNmapForHTTPPorts(observation)
		for _, host := range httpHosts {
			targetURL := fmt.Sprintf("http://%s", host)
			log.Printf("[%s] 🚀 Auto-spawning WebSpecialist for discovered HTTP host: %s\n", c.id, host)
			go c.spawnWebSpecialist(targetURL)
		}

		// If we found HTTP hosts, we can skip LLM analysis (already handled)
		if len(httpHosts) > 0 {
			return
		}
	}

	// Third, use LLM analysis as fallback
	prompt := prompts.GetCommanderAnalyze(fromAgent, c.target, observation)

	analysis, err := c.brain.Generate(c.ctx, prompt)
	if err != nil {
		log.Printf("[%s] ⚠️ LLM analysis failed: %v (continuing with rule-based logic)\n", c.id, err)
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
	if err := utils.ParseLLMJSON(jsonStr, &report); err != nil {
		log.Printf("[%s] ❌ Failed to parse JSON: %v\n", c.id, err)
		log.Printf("[%s] Raw (first 300 chars): %s\n", c.id, truncate(jsonStr, 300))

		// Try parsing entire observation as fallback
		log.Printf("[%s] Attempting fallback: parsing full observation\n", c.id)
		if err2 := utils.ParseLLMJSON(observation, &report); err2 != nil {
			log.Printf("[%s] ❌ Complete parsing failure\n", c.id)
			return
		}
	}

	// Extract base URL from the report's target (need to get it from WebSpecialist's observation)
	baseURL := c.extractBaseURL(observation)

	// Auto-spawn CrawlerSpecialist to discover all pages (check for duplicates)
	c.mu.Lock()
	alreadyCrawled := c.crawledURLs[baseURL]
	if !alreadyCrawled {
		c.crawledURLs[baseURL] = true
		c.mu.Unlock()
		log.Printf("[%s] 🕷️ Auto-spawning CrawlerSpecialist for: %s\n", c.id, baseURL)
		go c.spawnCrawlerSpecialist(baseURL)
	} else {
		c.mu.Unlock()
		log.Printf("[%s] ⏭️ Skipping duplicate crawl for: %s\n", c.id, baseURL)
	}

	if len(report.Vulnerabilities) == 0 {
		log.Printf("[%s] No vulnerabilities found by %s\n", c.id, fromAgent)
		return
	}

	log.Printf("[%s] 🎯 Found %d vulnerability candidates from %s\n", c.id, len(report.Vulnerabilities), fromAgent)

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

		case "FILEUPLOAD":
			log.Printf("[%s] 📤 Spawning FileUploadSpecialist for: %s (param: %s)\n", c.id, targetURL, vuln.Parameter)
			go c.spawnFileUploadSpecialist(targetURL)

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
	var agentPaw string

	if c.trtClient != nil {
		agents, trtErr := c.trtClient.GetAliveAgents()
		if trtErr == nil && len(agents) > 0 {
			agent := agents[0]
			agentPaw = agent.Paw
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
	reconAgent := specialist.NewReconSpecialist(c.ctx, reconID, c.bus, c.brain, c.target, executor, c.trtClient, agentPaw)

	// Register specialist
	c.specialists[reconID] = reconAgent

	// Subscribe to Event Bus (crucial for receiving commands!)
	c.bus.Subscribe(reconID, func(e bus.Event) {
		reconAgent.OnEvent(e)
	})

	log.Printf("[%s] Subscribed %s to Event Bus\n", c.id, reconID)

	// Start the specialist
	utils.SafeGo(reconID, func() {
		if err := reconAgent.Run(); err != nil {
			log.Printf("[%s] Specialist %s crashed: %v\n", c.id, reconID, err)
		}
	})

	// Send initial task
	c.sendTaskToSpecialist(reconID, "Perform initial reconnaissance on "+c.target)
}

// spawnWebSpecialist creates and registers a new WebSpecialist
// spawnWebSpecialistDirect creates WebSpecialist for a specific URL (single target mode)
// This bypasses ReconSpecialist and directly attacks the target URL
func (c *Commander) spawnWebSpecialistDirect(targetURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Generate unique ID
	c.counters["WebAgent"]++
	count := c.counters["WebAgent"]
	webID := fmt.Sprintf("WebAgent-%02d", count)

	log.Printf("[%s] Spawning WebSpecialist for direct URL attack: %s\n", c.id, targetURL)

	// Determine Executor (same logic as spawnWebSpecialist)
	var executor tools.ToolExecutor
	var err error

	// Try TRT first if client exists
	if c.trtClient != nil {
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
	webAgent := specialist.NewWebSpecialist(c.ctx, webID, c.bus, c.brain, targetURL, executor)

	// Register specialist
	c.specialists[webID] = webAgent

	// Report engagement to Reporter
	c.reportEngagement(targetURL)

	// Subscribe to Event Bus
	c.bus.Subscribe(webID, webAgent.OnEvent)

	// Start agent
	utils.SafeGo(webID, func() {
		if err := webAgent.Run(); err != nil {
			log.Printf("[%s] Specialist %s crashed: %v\n", c.id, webID, err)
		}
	})

	// Send initial command
	task := fmt.Sprintf("Perform web reconnaissance on %s", targetURL)
	c.sendTaskToSpecialist(webID, task)
}

func (c *Commander) spawnWebSpecialist(targetURL string) {
	// Pre-check: Verify target is reachable before spawning
	if !c.isTargetReachable(targetURL) {
		log.Printf("[%s] ⏭️ Skipping unreachable target: %s\n", c.id, targetURL)
		return
	}

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
	utils.SafeGo(webID, func() {
		if err := webAgent.Run(); err != nil {
			log.Printf("[%s] Specialist %s crashed: %v\n", c.id, webID, err)
		}
	})

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
	utils.SafeGo(verifyID, func() {
		if err := verifyAgent.Run(); err != nil {
			log.Printf("[%s] Specialist %s crashed: %v\n", c.id, verifyID, err)
		}
	})

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

	utils.SafeGo(xssID, func() {
		if err := xssAgent.Run(); err != nil {
			log.Printf("[%s] XSSSpecialist crashed: %v\n", c.id, err)
		}
	})

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

	utils.SafeGo(sqliID, func() {
		if err := sqliAgent.Run(); err != nil {
			log.Printf("[%s] SQLiSpecialist crashed: %v\n", c.id, err)
		}
	})

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

	utils.SafeGo(ptID, func() {
		if err := ptAgent.Run(); err != nil {
			log.Printf("[%s] PathTraversalSpecialist crashed: %v\n", c.id, err)
		}
	})

	c.sendTaskToSpecialist(ptID, "Hunt for Path Traversal vulnerabilities on "+targetURL)
}

// spawnFileUploadSpecialist creates and registers File Upload specialist
func (c *Commander) spawnFileUploadSpecialist(targetURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Generate unique ID
	c.counters["FileUploadAgent"]++
	count := c.counters["FileUploadAgent"]
	fuID := fmt.Sprintf("FileUploadAgent-%02d", count)

	if _, exists := c.specialists[fuID]; exists {
		return
	}

	executor, _ := c.selectExecutor(fuID)
	log.Printf("[%s] Spawning FileUploadSpecialist for %s...\n", c.id, targetURL)
	fuAgent := specialist.NewFileUploadSpecialist(c.ctx, fuID, c.bus, c.brain, targetURL, executor)
	c.specialists[fuID] = fuAgent

	c.bus.Subscribe(fuID, func(e bus.Event) {
		fuAgent.OnEvent(e)
	})

	log.Printf("[%s] Subscribed %s to Event Bus\n", c.id, fuID)

	utils.SafeGo(fuID, func() {
		if err := fuAgent.Run(); err != nil {
			log.Printf("[%s] FileUploadSpecialist crashed: %v\n", c.id, err)
		}
	})

	c.sendTaskToSpecialist(fuID, "Hunt for File Upload vulnerabilities on "+targetURL)
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

	utils.SafeGo(cmdiID, func() {
		if err := cmdiAgent.Run(); err != nil {
			log.Printf("[%s] CommandInjectionSpecialist crashed: %v\n", c.id, err)
		}
	})

	// P1: Include parameter in task description for RCE verification
	taskDesc := fmt.Sprintf("Deploy CallistoAgent via agent %s (target context: %s?%s=test)", agent.Paw, targetURL, parameter)
	c.sendTaskToSpecialist(cmdiID, taskDesc)
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

	utils.SafeGo(cmdiID, func() {
		if err := cmdiAgent.Run(); err != nil {
			log.Printf("[%s] AgentDeploymentSpecialist crashed: %v\n", c.id, err)
		}
	})

	c.sendTaskToSpecialist(cmdiID, fmt.Sprintf("Deploy CallistoAgent via agent %s", agentPaw))
}

// parseNmapForHTTPPorts parses nmap output and extracts hosts with HTTP ports
func (c *Commander) parseNmapForHTTPPorts(nmapOutput string) []string {
	var httpHosts []string

	// Regular expression patterns
	// Match: "Nmap scan report for 192.168.127.128"
	hostPattern := regexp.MustCompile(`Nmap scan report for ([\d\.]+)`)
	// Match: "80/tcp   open  http" or "443/tcp   open  https"
	portPattern := regexp.MustCompile(`(?m)^(80|443|8080|8443)/tcp\s+open`)

	// Split by host sections
	hostSections := strings.Split(nmapOutput, "Nmap scan report for")

	for _, section := range hostSections[1:] { // Skip first empty split
		// Extract IP
		hostMatch := hostPattern.FindStringSubmatch("Nmap scan report for" + section)
		if len(hostMatch) < 2 {
			continue
		}
		ip := hostMatch[1]

		// Check for HTTP ports
		if portPattern.MatchString(section) {
			httpHosts = append(httpHosts, ip)
			log.Printf("[%s] 🌐 Detected HTTP service on: %s\n", c.id, ip)
		}
	}

	return httpHosts
}

// handleSessionCookie processes session cookie from LoginSpecialist
func (c *Commander) handleSessionCookie(observation string) {
	// Extract content between markers
	startMarker := "SESSION_COOKIE_START"
	endMarker := "SESSION_COOKIE_END"

	startIdx := strings.Index(observation, startMarker)
	endIdx := strings.Index(observation, endMarker)

	if startIdx == -1 || endIdx == -1 || endIdx <= startIdx {
		log.Printf("[%s] Failed to find session cookie markers\n", c.id)
		return
	}

	content := strings.TrimSpace(observation[startIdx+len(startMarker) : endIdx])

	// Parse url and cookie from content
	// Format: "url: http://...\ncookie: PHPSESSID=..."
	var baseURL, cookie string
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "url:") {
			baseURL = strings.TrimSpace(strings.TrimPrefix(line, "url:"))
		} else if strings.HasPrefix(line, "cookie:") {
			cookie = strings.TrimSpace(strings.TrimPrefix(line, "cookie:"))
		}
	}

	if cookie == "" {
		log.Printf("[%s] No cookie found in session cookie event\n", c.id)
		return
	}

	c.mu.Lock()
	c.sessionCookie = cookie
	c.mu.Unlock()

	// Mask cookie for logging
	maskedCookie := maskCookie(cookie)

	log.Printf("[%s] 🍪 Session Cookie Acquired: %s\n", c.id, maskedCookie)

	// Re-crawl the target with authentication to discover authenticated pages
	if baseURL == "" {
		log.Printf("[%s] ⚠️ No base URL provided in session cookie event, skipping re-crawl\n", c.id)
		return
	}

	log.Printf("[%s] 🔄 Re-spawning CrawlerSpecialist with authentication for: %s\n", c.id, baseURL)
	go c.spawnCrawlerSpecialist(baseURL)
}

// getBaseURLFromLogin extracts base URL from login URL
func (c *Commander) getBaseURLFromLogin(loginURL string) string {
	// If login URL is like http://example.com/login.php
	// return http://example.com
	if parsedURL, err := url.Parse(c.target); err == nil {
		return fmt.Sprintf("%s://%s", parsedURL.Scheme, parsedURL.Host)
	}
	return c.target
}

// handleCrawlerResults processes discovered URLs from CrawlerSpecialist
func (c *Commander) handleCrawlerResults(observation string) {
	// Extract JSON between markers
	startMarker := "CRAWLER_JSON_START"
	endMarker := "CRAWLER_JSON_END"

	startIdx := strings.Index(observation, startMarker)
	endIdx := strings.Index(observation, endMarker)

	if startIdx == -1 || endIdx == -1 || endIdx <= startIdx {
		log.Printf("[%s] Failed to find crawler JSON markers\n", c.id)
		return
	}

	jsonStr := strings.TrimSpace(observation[startIdx+len(startMarker) : endIdx])

	var result struct {
		DiscoveredURLs []string `json:"discovered_urls"`
		TotalCount     int      `json:"total_count"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &result); err != nil {
		log.Printf("[%s] Failed to parse crawler JSON: %v\n", c.id, err)
		return
	}

	log.Printf("[%s] 📋 Crawler discovered %d URLs\n", c.id, result.TotalCount)

	// Spawn WebSpecialist for each discovered URL
	for _, url := range result.DiscoveredURLs {
		log.Printf("[%s] 🔍 Analyzing discovered URL: %s\n", c.id, url)
		go c.spawnWebSpecialist(url)
	}
}

// extractLoginURL extracts URL from LOGIN_FORM_FOUND message
func (c *Commander) extractLoginURL(observation string) string {
	// Format: "LOGIN_FORM_FOUND: http://..."
	parts := strings.SplitN(observation, "LOGIN_FORM_FOUND:", 2)
	if len(parts) < 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

// spawnCrawlerSpecialist creates and registers a new CrawlerSpecialist
func (c *Commander) spawnCrawlerSpecialist(baseURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.counters["CrawlerAgent"]++
	count := c.counters["CrawlerAgent"]
	crawlerID := fmt.Sprintf("CrawlerAgent-%02d", count)

	executor, _ := c.selectExecutor(crawlerID)

	log.Printf("[%s] Spawning CrawlerSpecialist for %s...\n", c.id, baseURL)
	crawlerAgent := specialist.NewCrawlerSpecialist(c.ctx, crawlerID, c.bus, c.brain, baseURL, executor, c.sessionCookie)

	c.specialists[crawlerID] = crawlerAgent

	c.bus.Subscribe(crawlerID, func(e bus.Event) {
		crawlerAgent.OnEvent(e)
	})

	log.Printf("[%s] Subscribed %s to Event Bus\n", c.id, crawlerID)

	utils.SafeGo(crawlerID, func() {
		if err := crawlerAgent.Run(); err != nil {
			log.Printf("[%s] CrawlerSpecialist crashed: %v\n", c.id, err)
		}
	})

	c.sendTaskToSpecialist(crawlerID, "Crawl entire website starting from "+baseURL)
}

// spawnLoginSpecialist creates and registers a new LoginSpecialist
func (c *Commander) spawnLoginSpecialist(loginURL string, credentials map[string]string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.counters["LoginAgent"]++
	count := c.counters["LoginAgent"]
	loginID := fmt.Sprintf("LoginAgent-%02d", count)

	executor, _ := c.selectExecutor(loginID)

	log.Printf("[%s] Spawning LoginSpecialist for %s...\n", c.id, loginURL)
	loginAgent := specialist.NewLoginSpecialist(c.ctx, loginID, c.bus, c.brain, loginURL, executor, credentials)

	c.specialists[loginID] = loginAgent

	c.bus.Subscribe(loginID, func(e bus.Event) {
		loginAgent.OnEvent(e)
	})

	log.Printf("[%s] Subscribed %s to Event Bus\n", c.id, loginID)

	utils.SafeGo(loginID, func() {
		if err := loginAgent.Run(); err != nil {
			log.Printf("[%s] LoginSpecialist crashed: %v\n", c.id, err)
		}
	})

	c.sendTaskToSpecialist(loginID, "Attempt login on "+loginURL)
}

// maskCookie masks sensitive cookie data for secure logging
// Exposes only first 4 chars + last 4 chars for debugging
func maskCookie(cookie string) string {
	const (
		prefixLen = 4
		suffixLen = 4
		minLen    = prefixLen + suffixLen + 3 // 3 for "***"
	)

	if len(cookie) <= minLen {
		if len(cookie) > 1 {
			return cookie[:1] + "***"
		}
		return "***"
	}

	return cookie[:prefixLen] + "***" + cookie[len(cookie)-suffixLen:]
}

// truncate limits string length for logging
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// isTargetReachable performs a quick HTTP HEAD request to verify target is reachable
// This prevents adding non-existent hosts to the engagement list
func (c *Commander) isTargetReachable(targetURL string) bool {
	// Quick timeout for reachability check
	ctx, cancel := context.WithTimeout(c.ctx, 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "HEAD", targetURL, nil)
	if err != nil {
		return false
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")

	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow redirects, just checking if host responds
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		// Connection refused, timeout, etc.
		return false
	}
	defer resp.Body.Close()

	// Any response (even 4xx/5xx) means the host is reachable
	return true
}
