package orchestrator

import (
	"cal-project/internal/core/agent"
	"cal-project/internal/core/bus"
	"fmt"
	"log"
	"runtime/debug"
	"sync"
)

// Orchestrator manages the lifecycle of the system
type Orchestrator struct {
	Bus    bus.Bus
	Agents map[string]agent.Agent
	mu     sync.RWMutex
}

// NewOrchestrator creates a new Orchestrator instance
func NewOrchestrator(eventBus bus.Bus) *Orchestrator {
	return &Orchestrator{
		Bus:    eventBus,
		Agents: make(map[string]agent.Agent),
	}
}

// RegisterAgent adds an agent to the system and subscribes it to the bus
func (o *Orchestrator) RegisterAgent(a agent.Agent) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.Agents[a.ID()] = a
	fmt.Printf("[Orchestrator] Registered Agent: %s (%s)\n", a.ID(), a.Type())

	// Subscribe the agent to messages directed to it or broadcast
	// Note: In a real system, agents might subscribe to specific topics.
	// For now, let's assume valid topics are "BROADCAST" or the AgentID.

	// Convention: Agents listen to their own ID as a topic
	o.Bus.Subscribe(a.ID(), func(e bus.Event) {
		a.OnEvent(e)
	})

	// Convention: Agents listen to "BROADCAST"
	o.Bus.Subscribe("BROADCAST", func(e bus.Event) {
		// Prevent echo if needed, or handle in agent
		if e.FromAgent != a.ID() {
			a.OnEvent(e)
		}
	})
}

// Start boots up the bus and all agents
func (o *Orchestrator) Start() {
	fmt.Println("[Orchestrator] Starting System...")
	o.Bus.Start()

	o.mu.RLock()
	defer o.mu.RUnlock()

	for _, a := range o.Agents {
		agent := a // capture for closure
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("[Orchestrator] PANIC in agent %s: %v\n%s\n", agent.ID(), r, debug.Stack())
				}
			}()
			if err := agent.Run(); err != nil {
				fmt.Printf("[Orchestrator] Agent %s crashed: %v\n", agent.ID(), err)
			}
		}()
	}
}

// Stop shuts down the system
func (o *Orchestrator) Stop() {
	fmt.Println("[Orchestrator] Stopping System...")
	o.Bus.Stop()
}
