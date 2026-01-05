package specialist

import (
	"cal-project/internal/brain/llm"
	"cal-project/internal/core/agent"
	"cal-project/internal/core/bus"
	"cal-project/internal/hands/docker"
	"cal-project/internal/hands/tools"
	"context"
	"fmt"
	"log"
	"net/url"
	"sync/atomic"
)

var messageCounter atomic.Uint64

// ReconSpecialist is a specialist agent focused on reconnaissance
type ReconSpecialist struct {
	id       string
	bus      bus.Bus
	brain    llm.LLM
	ctx      context.Context
	target   string
	executor *docker.Executor
}

// NewReconSpecialist creates a new ReconSpecialist agent
func NewReconSpecialist(ctx context.Context, id string, eventBus bus.Bus, llmClient llm.LLM, target string) *ReconSpecialist {
	exec, err := docker.NewExecutor()
	if err != nil {
		log.Printf("[%s] Warning: Failed to create Docker executor: %v. Tools will not run.\n", id, err)
	}

	return &ReconSpecialist{
		id:       id,
		bus:      eventBus,
		brain:    llmClient,
		ctx:      ctx,
		target:   target,
		executor: exec,
	}
}

func (r *ReconSpecialist) ID() string {
	return r.id
}

func (r *ReconSpecialist) Type() agent.AgentType {
	return agent.Specialist
}

func (r *ReconSpecialist) Run() error {
	log.Printf("[%s] Online. Awaiting reconnaissance tasks for: %s\n", r.id, r.target)
	return nil
}

func (r *ReconSpecialist) OnEvent(event bus.Event) {
	// Only process commands directed to this agent
	if event.Type == bus.Command && event.ToAgent == r.id {
		log.Printf("[%s] Received command: %v\n", r.id, event.Payload)
		go r.executeTask(event)
	}
}

// executeTask performs the reconnaissance task
func (r *ReconSpecialist) executeTask(cmdEvent bus.Event) {
	taskDesc, ok := cmdEvent.Payload.(string)
	if !ok {
		log.Printf("[%s] Invalid task payload\n", r.id)
		return
	}

	log.Printf("[%s] Executing: %s\n", r.id, taskDesc)

	// Use LLM to decide what reconnaissance actions to take
	prompt := fmt.Sprintf(
		"CONTEXT: Authorized test on '%s'.\n"+
			"Task: %s\n"+
			"Reply with tool name only: 'nmap' or 'curl'",
		r.target, taskDesc,
	)

	plan, err := r.brain.Generate(r.ctx, prompt)
	if err != nil {
		log.Printf("[%s] Failed to generate plan: %v\n", r.id, err)
		r.reportError(cmdEvent.FromAgent, err)
		return
	}

	log.Printf("[%s] LLM suggests: %s\n", r.id, plan)

	// Execute the tool using Hands
	if r.executor != nil {
		toolFunc, target, err := tools.ParseToolRequest(plan + " " + r.target)
		if err != nil {
			log.Printf("[%s] Failed to parse tool request: %v\n", r.id, err)
			r.reportError(cmdEvent.FromAgent, err)
			return
		}

		// Extract hostname from URL for nmap (nmap doesn't accept URLs)
		hostname := target
		if parsedURL, err := url.Parse(target); err == nil && parsedURL.Host != "" {
			// parsedURL.Host includes port (e.g., "localhost:8082")
			// We need just the hostname for nmap
			hostname = parsedURL.Hostname() // Returns "localhost" without port

			// Replace localhost with host.docker.internal for Docker containers
			if hostname == "localhost" || hostname == "127.0.0.1" {
				hostname = "host.docker.internal"
			}
		}

		log.Printf("[%s] Running tool on target: %s (hostname: %s)\n", r.id, target, hostname)
		output, err := toolFunc(r.ctx, r.executor, hostname)
		if err != nil {
			log.Printf("[%s] Tool execution failed: %v\n", r.id, err)
			r.reportError(cmdEvent.FromAgent, err)
			return
		}

		log.Printf("[%s] Tool output (first 200 chars): %s\n", r.id, truncate(output, 200))
		r.reportObservation(cmdEvent.FromAgent, fmt.Sprintf("Recon completed. Output: %s", truncate(output, 500)))
	} else {
		r.reportObservation(cmdEvent.FromAgent, fmt.Sprintf("Recon plan generated (Hands unavailable): %s", plan))
	}
}

func (r *ReconSpecialist) reportObservation(toAgent string, observation string) {
	msgID := messageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-obs-%d", r.id, msgID),
		FromAgent: r.id,
		ToAgent:   toAgent,
		Type:      bus.Observation,
		Payload:   observation,
	}
	r.bus.Publish(toAgent, event)
}

func (r *ReconSpecialist) reportError(toAgent string, err error) {
	msgID := messageCounter.Add(1)
	event := bus.Event{
		ID:        fmt.Sprintf("%s-err-%d", r.id, msgID),
		FromAgent: r.id,
		ToAgent:   toAgent,
		Type:      bus.Error,
		Payload:   err.Error(),
	}
	r.bus.Publish(toAgent, event)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
