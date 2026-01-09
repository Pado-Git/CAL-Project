package main

import (
	"cal-project/internal/hands/trt"
	"context"
	"fmt"
	"log"
	"time"

	"github.com/joho/godotenv"
)

func main() {
	// Load .env
	_ = godotenv.Load()

	log.Println("Verifying TRT Environment & Adapter...")

	client := trt.NewClient()

	// Auth
	if err := client.Authenticate(); err != nil {
		log.Fatalf("Auth failed: %v", err)
	}

	// Agents
	agents, err := client.GetAliveAgents()
	if err != nil {
		log.Fatalf("Get agents failed: %v", err)
	}

	if len(agents) == 0 {
		log.Fatal("No agents found.")
	}

	agent := agents[0]
	log.Printf("Using Agent: %s (%s)\n", agent.Paw, agent.Host)

	// Executor
	exec := trt.NewRemoteExecutor(client, agent.Paw, agent.Platform)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	log.Println("--- Testing Nmap Adapter (PowerShell via cmd) ---")
	// Use localhost
	target := "127.0.0.1"

	cmdNmap := []string{"nmap", "-p-", "--min-rate", "1000", "-T4", target}

	log.Printf("Requesting 'cal/nmap' on target %s...\n", target)
	outScan, err := exec.RunTool(ctx, "cal/nmap", cmdNmap)
	if err != nil {
		log.Printf("Scan failed: %v\n", err)
	} else {
		fmt.Println("Scan Output:")
		fmt.Println(outScan)
	}

	log.Println("-------------------")
}
