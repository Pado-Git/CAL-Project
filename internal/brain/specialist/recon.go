package specialist

import (
	"cal-project/internal/brain/llm"
	"cal-project/internal/brain/prompts"
	"cal-project/internal/core/agent"
	"cal-project/internal/core/bus"
	"cal-project/internal/hands/tools"
	"cal-project/internal/hands/trt"
	"context"
	"fmt"
	"log"
	"net/url"
	"runtime/debug"
	"strings"
	"sync/atomic"
)

var messageCounter atomic.Uint64

// ReconSpecialist is a specialist agent focused on reconnaissance
type ReconSpecialist struct {
	id         string
	bus        bus.Bus
	brain      llm.LLM
	ctx        context.Context
	target     string
	executor   tools.ToolExecutor
	trtClient  *trt.Client
	agentPaw   string // PAW of the agent performing the scan
	singleHost bool   // If true, scan only the single host (no CIDR expansion)
}

// NewReconSpecialist creates a new ReconSpecialist agent
func NewReconSpecialist(ctx context.Context, id string, eventBus bus.Bus, llmClient llm.LLM, target string, executor tools.ToolExecutor, trtClient *trt.Client, agentPaw string) *ReconSpecialist {
	return &ReconSpecialist{
		id:         id,
		bus:        eventBus,
		brain:      llmClient,
		ctx:        ctx,
		target:     target,
		executor:   executor,
		trtClient:  trtClient,
		agentPaw:   agentPaw,
		singleHost: false,
	}
}

// NewReconSpecialistSingleHost creates a ReconSpecialist for single host scanning (no CIDR)
func NewReconSpecialistSingleHost(ctx context.Context, id string, eventBus bus.Bus, llmClient llm.LLM, target string, executor tools.ToolExecutor, trtClient *trt.Client, agentPaw string) *ReconSpecialist {
	return &ReconSpecialist{
		id:         id,
		bus:        eventBus,
		brain:      llmClient,
		ctx:        ctx,
		target:     target,
		executor:   executor,
		trtClient:  trtClient,
		agentPaw:   agentPaw,
		singleHost: true,
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
		go func() {
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("[%s] PANIC in executeTask: %v\n%s\n", r.id, rec, debug.Stack())
					r.reportError(event.FromAgent, fmt.Errorf("task panicked: %v", rec))
				}
			}()
			r.executeTask(event)
		}()
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
	// Use different prompt for single host mode (no CIDR expansion)
	var prompt string
	if r.singleHost {
		log.Printf("[%s] Single host mode: scanning only %s (no CIDR expansion)\n", r.id, r.target)
		prompt = prompts.GetReconDecisionSingleHost(r.target, taskDesc)
	} else {
		prompt = prompts.GetReconDecision(r.target, taskDesc)
	}

	plan, err := r.brain.Generate(r.ctx, prompt)
	if err != nil {
		log.Printf("[%s] Failed to generate plan: %v\n", r.id, err)
		r.reportError(cmdEvent.FromAgent, err)
		return
	}

	log.Printf("[%s] LLM suggests: %s\n", r.id, plan)

	// Execute the tool using Hands
	if r.executor != nil {
		// Construct tool request. Prefer LLM plan if it has arguments (e.g., 'nmap <subnet>').
		// Only append default target if plan is just a single word (e.g., 'nmap').
		toolRequest := plan
		if !strings.Contains(strings.TrimSpace(plan), " ") {
			toolRequest = plan + " " + r.target
		}

		toolFunc, target, err := tools.ParseToolRequest(toolRequest)
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

		// If TRT Client is available and this is a scan result, send to TRT
		if r.trtClient != nil && r.agentPaw != "" && strings.Contains(output, "Starting Nmap") {
			log.Printf("[%s] Sending scan results to TRT...\n", r.id)

			// Get last scan results
			scanResults := tools.GetLastScanResults()
			if len(scanResults) > 0 {
				// Convert to TRT format
				var trtHosts []trt.ScanResultHost
				for _, result := range scanResults {
					var trtPorts []trt.ScanResultPort
					for _, port := range result.OpenPorts {
						trtPorts = append(trtPorts, trt.ScanResultPort{
							Port:     port.Port,
							Protocol: port.Protocol,
							State:    port.State,
							Service:  port.Service,
						})
					}
					trtHosts = append(trtHosts, trt.ScanResultHost{
						IP:    result.Host,
						Ports: trtPorts,
					})
				}

				// Send to TRT
				if err := r.trtClient.SaveScanResult(r.agentPaw, trtHosts); err != nil {
					log.Printf("[%s] Failed to save scan results to TRT: %v\n", r.id, err)
				} else {
					log.Printf("[%s] Successfully saved %d hosts to TRT\n", r.id, len(trtHosts))
				}

				// Clear last scan results
				tools.ClearLastScanResults()
			}
		}

		r.reportObservation(cmdEvent.FromAgent, fmt.Sprintf("Recon completed. Output: %s", truncate(output, 5000)))
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
