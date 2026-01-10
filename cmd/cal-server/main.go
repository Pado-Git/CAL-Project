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
	// CLI Flags
	enableRAG := flag.Bool("enable-rag", false, "Enable RAG mode for prompt management")
	ragShort := flag.Bool("rag", false, "Enable RAG mode (short flag)")
	flag.Parse()

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

	ctx := context.Background()

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
	targetURL := os.Getenv("TARGET_URL")
	if targetURL == "" {
		targetURL = "http://example.com" // Default fallback
	}
	// Now passing trtClient to Commander
	cmdr := commander.NewCommander(ctx, eventBus, llmClient, targetURL, trtClient)
	orch.RegisterAgent(cmdr)

	// 6. Initialize Reporter Agent
	reporterAgent := reporter.NewReporter(eventBus, targetURL)
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
