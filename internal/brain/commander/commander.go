package commander

import (
	"cal-project/internal/brain/llm"
	"cal-project/internal/brain/specialist"
	"cal-project/internal/core/agent"
	"cal-project/internal/core/bus"
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
)

// Commander is the strategic leader agent
type Commander struct {
	id          string
	bus         bus.Bus
	brain       llm.LLM
	ctx         context.Context
	target      string
	specialists map[string]agent.Agent
	mu          sync.RWMutex
}

// NewCommander creates a new Commander agent
func NewCommander(ctx context.Context, eventBus bus.Bus, llmClient llm.LLM, targetURL string) *Commander {
	return &Commander{
		id:          "Commander-01",
		bus:         eventBus,
		brain:       llmClient,
		ctx:         ctx,
		target:      targetURL,
		specialists: make(map[string]agent.Agent),
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

	// Initial thought with authorized testing context
	initialPrompt := fmt.Sprintf(
		"CONTEXT: Authorized security test on controlled environment '%s'.\n\n"+
			"TASK: Start security assessment.\n"+
			"Reply in 1-2 sentences: Which specialists should be spawned? (e.g., 'Spawn reconnaissance and web specialists')",
		c.target,
	)
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
	prompt := fmt.Sprintf(
		"CONTEXT: You are analyzing security reconnaissance results from %s.\n"+
			"Target: %s\n\n"+
			"OBSERVATION:\n%s\n\n"+
			"TASK: Analyze this output and identify:\n"+
			"1. Any potential vulnerabilities (SQL injection points, XSS, exposed secrets, etc.)\n"+
			"2. Interesting findings (open ports, technologies detected, security headers missing)\n"+
			"3. Recommended next steps for deeper investigation\n\n"+
			"Provide a concise analysis in 2-3 sentences.",
		fromAgent, c.target, observation,
	)

	analysis, err := c.brain.Generate(c.ctx, prompt)
	if err != nil {
		log.Printf("[%s] Failed to analyze observation: %v\n", c.id, err)
		return
	}

	log.Printf("[%s] 🔍 ANALYSIS: %s\n", c.id, analysis)
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
		return
	}

	log.Printf("[%s] Thought: %s\n", c.id, resp)

	// TODO: Parse response and decide actions
	// Spawn appropriate specialists based on LLM response
	if c.shouldSpawnReconSpecialist(resp) {
		c.spawnReconSpecialist()
	}

	// If web reconnaissance is needed, spawn specific vulnerability specialists
	if c.shouldSpawnWebSpecialist(resp) {
		// Spawn both XSS and SQLi specialists for comprehensive coverage
		c.spawnXSSSpecialist()
		c.spawnSQLiSpecialist()
	}
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

	// Create new specialist
	log.Printf("[%s] Spawning ReconSpecialist...\n", c.id)
	reconAgent := specialist.NewReconSpecialist(c.ctx, reconID, c.bus, c.brain, c.target)

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
func (c *Commander) spawnWebSpecialist() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we already have a web specialist
	webID := "WebAgent-01"
	if _, exists := c.specialists[webID]; exists {
		log.Printf("[%s] WebSpecialist already exists, sending task instead\n", c.id)
		c.sendTaskToSpecialist(webID, "Perform web reconnaissance on "+c.target)
		return
	}

	// Create new specialist
	log.Printf("[%s] Spawning WebSpecialist...\n", c.id)
	webAgent := specialist.NewWebSpecialist(c.ctx, webID, c.bus, c.brain, c.target)

	// Register specialist
	c.specialists[webID] = webAgent

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
	c.sendTaskToSpecialist(webID, "Perform web reconnaissance on "+c.target)
}

// spawnVerificationSpecialist creates and registers a new VerificationSpecialist
func (c *Commander) spawnVerificationSpecialist(vulnReport string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we already have a verification specialist
	verifyID := "VerifyAgent-01"
	if _, exists := c.specialists[verifyID]; exists {
		log.Printf("[%s] VerificationSpecialist already exists, sending task instead\n", c.id)
		c.sendTaskToSpecialist(verifyID, vulnReport)
		return
	}

	// Create new specialist
	log.Printf("[%s] Spawning VerificationSpecialist...\n", c.id)
	verifyAgent := specialist.NewVerificationSpecialist(c.ctx, verifyID, c.bus, c.brain, c.target)

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

// spawnXSSSpecialist creates and registers XSS specialist
func (c *Commander) spawnXSSSpecialist() {
	c.mu.Lock()
	defer c.mu.Unlock()

	xssID := "XSSAgent-01"
	if _, exists := c.specialists[xssID]; exists {
		return
	}

	log.Printf("[%s] Spawning XSSSpecialist...\n", c.id)
	xssAgent := specialist.NewXSSSpecialist(c.ctx, xssID, c.bus, c.brain, c.target)
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

	c.sendTaskToSpecialist(xssID, "Hunt for XSS vulnerabilities on "+c.target)
}

// spawnSQLiSpecialist creates and registers SQLi specialist
func (c *Commander) spawnSQLiSpecialist() {
	c.mu.Lock()
	defer c.mu.Unlock()

	sqliID := "SQLiAgent-01"
	if _, exists := c.specialists[sqliID]; exists {
		return
	}

	log.Printf("[%s] Spawning SQLiSpecialist...\n", c.id)
	sqliAgent := specialist.NewSQLInjectionSpecialist(c.ctx, sqliID, c.bus, c.brain, c.target)
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

	c.sendTaskToSpecialist(sqliID, "Hunt for SQL injection on "+c.target)
}
