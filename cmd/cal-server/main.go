package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cal-project/internal/brain/commander"
	"cal-project/internal/brain/llm"
	"cal-project/internal/brain/prompts"
	"cal-project/internal/core/bus"
	"cal-project/internal/core/orchestrator"
	"cal-project/internal/core/reporter"
	"cal-project/internal/hands/trt"

	"github.com/joho/godotenv"
)

func main() {
	// CLI Flags for targeting
	var (
		enableRAG = flag.Bool("enable-rag", false, "Enable RAG mode for prompt management")
		ragShort  = flag.Bool("rag", false, "Enable RAG mode (short flag)")

		// Targeting flags
		targetMode = flag.String("mode", "network", "Execution mode: 'single' or 'network'")
		targetURL  = flag.String("url", "", "Target URL (overrides .env TARGET_URL)")
		loginEmail = flag.String("email", "", "Login email (overrides .env LOGIN_EMAIL)")
		loginPass  = flag.String("password", "", "Login password (overrides .env LOGIN_PASSWORD)")

		// Deep Dive flags (network exploration after compromising targets)
		// Single Mode: deep-dive OFF by default, use --deep-dive to enable
		// Network Mode: deep-dive ON by default, use --no-deep-dive to disable
		deepDive   = flag.Bool("deep-dive", false, "Enable deep network exploration after compromising targets (Single Mode)")
		deepDiveD  = flag.Bool("d", false, "Short for --deep-dive")
		noDeepDive = flag.Bool("no-deep-dive", false, "Disable deep network exploration (Network Mode)")
		maxDepth   = flag.Int("max-depth", 3, "Maximum exploration depth (1-5), requires deep-dive enabled")
	)

	flag.Parse()

	// Validate Deep Dive flags
	effectiveDeepDive := *deepDive || *deepDiveD

	// --deep-dive and --no-deep-dive cannot be used together
	if effectiveDeepDive && *noDeepDive {
		log.Fatal("Error: --deep-dive and --no-deep-dive cannot be used together")
	}

	// Validate max-depth range
	if *maxDepth < 1 || *maxDepth > 5 {
		log.Fatal("Error: --max-depth must be between 1 and 5")
	}

	// Setup Multi-writer logging (Console + File)
	logFile, err := os.OpenFile("cal-debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()

	mw := io.MultiWriter(os.Stdout, logFile)
	log.SetOutput(mw)

	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	fmt.Println("CAL-like Autonomous Security Platform Starting...")
	fmt.Println("mode: Distributed Multi-Agent System (Go)")

	// Global context with timeout (5 minutes)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Determine RAG mode (CLI > ENV > config.yaml)
	ragEnabled := *enableRAG || *ragShort
	if !ragEnabled {
		if os.Getenv("PROMPT_RAG_ENABLED") == "true" {
			ragEnabled = true
		}
	}

	// Initialize Prompt Management System
	if err := prompts.Initialize(ctx, ragEnabled); err != nil {
		log.Printf("Warning: Prompt system initialization failed: %v", err)
		log.Printf("Falling back to legacy prompt mode")
	} else {
		if ragEnabled {
			log.Printf("[Prompts] RAG mode enabled")
		} else {
			log.Printf("[Prompts] Direct file loading mode (default)")
		}
	}
	defer prompts.Close()

	// 1. Initialize Event Bus
	eventBus := bus.NewMemoryBus(100)

	// 2. Initialize Orchestrator
	orch := orchestrator.NewOrchestrator(eventBus)

	// 3. Initialize LLM Client (Gemini)
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		log.Fatal("GEMINI_API_KEY environment variable not set")
	}

	modelName := os.Getenv("GEMINI_MODEL")
	if modelName == "" {
		modelName = "gemini-2.0-flash-exp" // Default model
	}

	llmClient, err := llm.NewGeminiClient(ctx, apiKey, modelName)
	if err != nil {
		log.Fatalf("Failed to create LLM client: %v", err)
	}
	defer llmClient.Close()

	// 4. Initialize TRT Client
	trtClient := trt.NewClient()

	// 5. Initialize Commander Agent
	// Load target config (CLI > .env > default)
	finalURL := *targetURL
	if finalURL == "" {
		finalURL = os.Getenv("TARGET_URL")
		if finalURL == "" {
			finalURL = "http://example.com" // Default fallback
		}
	}

	finalEmail := *loginEmail
	if finalEmail == "" {
		finalEmail = os.Getenv("LOGIN_EMAIL")
	}

	finalPassword := *loginPass
	if finalPassword == "" {
		finalPassword = os.Getenv("LOGIN_PASSWORD")
	}

	finalMode := *targetMode
	if finalMode != "single" && finalMode != "network" {
		log.Fatalf("Invalid mode: %s (must be 'single' or 'network')", finalMode)
	}

	// Calculate final deep-dive setting based on mode
	// Single Mode: default OFF, --deep-dive enables
	// Network Mode: default ON, --no-deep-dive disables
	finalDeepDive := effectiveDeepDive
	if finalMode == "network" {
		finalDeepDive = !*noDeepDive // Network mode: ON by default unless --no-deep-dive
	}

	// Validate: --max-depth requires deep-dive enabled (only if changed from default)
	if *maxDepth != 3 && !finalDeepDive {
		log.Fatal("Error: --max-depth requires --deep-dive (single mode) or enabled deep-dive (network mode)")
	}

	log.Printf("========================================")
	log.Printf("Execution Mode: %s", finalMode)
	log.Printf("Target URL: %s", finalURL)
	if finalEmail != "" {
		log.Printf("Credentials: %s / ********", finalEmail)
	}
	log.Printf("Deep Dive: %v (max-depth: %d)", finalDeepDive, *maxDepth)
	log.Printf("========================================")

	cmdr := commander.NewCommander(ctx, eventBus, llmClient, finalURL, finalMode, finalEmail, finalPassword, trtClient, finalDeepDive, *maxDepth)
	orch.RegisterAgent(cmdr)

	// 6. Initialize Reporter Agent
	reporterAgent := reporter.NewReporter(eventBus, finalURL)
	orch.RegisterAgent(reporterAgent)

	// 7. Start System
	orch.Start()

	// 8. Wait for tasks to complete or user interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Give agents time to work (60 seconds) or wait for manual interrupt
	select {
	case <-sigChan:
		log.Println("User interrupt received")
	case <-time.After(300 * time.Second):
		log.Println("Timeout reached (300s)")
	}

	orch.Stop()
	log.Println("System halted.")
}
