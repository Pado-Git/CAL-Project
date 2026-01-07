package commander

import (
	"cal-project/internal/brain/llm"
	"cal-project/internal/brain/prompts"
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
	counters    map[string]int
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
	prompt := prompts.GetCommanderAnalyze(fromAgent, c.target, observation)

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

	log.Printf("[%s] Thought: %s\n", c.id, resp)

	// Always spawn Recon Specialist to start
	c.spawnReconSpecialist()

	// If target is HTTP/HTTPS, automatically spawn Web Specialists
	if strings.HasPrefix(c.target, "http") || c.shouldSpawnWebSpecialist(resp) {
		log.Printf("[%s] Target is web-based or requested: Spawning Web Specialists\n", c.id)
		c.spawnWebSpecialist()           // Coordinator
		c.spawnXSSSpecialist()           // Worker
		c.spawnSQLiSpecialist()          // Worker
		c.spawnPathTraversalSpecialist() // Worker
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

	// Generate unique ID
	c.counters["XSSAgent"]++
	count := c.counters["XSSAgent"]
	xssID := fmt.Sprintf("XSSAgent-%02d", count)

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

	// Generate unique ID
	c.counters["SQLiAgent"]++
	count := c.counters["SQLiAgent"]
	sqliID := fmt.Sprintf("SQLiAgent-%02d", count)

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

// spawnPathTraversalSpecialist creates and registers Path Traversal specialist
func (c *Commander) spawnPathTraversalSpecialist() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Generate unique ID
	c.counters["PathTraversalAgent"]++
	count := c.counters["PathTraversalAgent"]
	ptID := fmt.Sprintf("PathTraversalAgent-%02d", count)

	if _, exists := c.specialists[ptID]; exists {
		return
	}

	log.Printf("[%s] Spawning PathTraversalSpecialist...\n", c.id)
	ptAgent := specialist.NewPathTraversalSpecialist(c.ctx, ptID, c.bus, c.brain, c.target)
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

	c.sendTaskToSpecialist(ptID, "Hunt for Path Traversal vulnerabilities on "+c.target)
}
