package agent

import "cal-project/internal/core/bus"

// AgentType defines the role of an agent
type AgentType string

const (
	Commander  AgentType = "COMMANDER"
	Specialist AgentType = "SPECIALIST"
)

// Agent defines the interface that all agents must implement
type Agent interface {
	// ID returns the unique identifier of the agent
	ID() string

	// Type returns the role of the agent
	Type() AgentType

	// Run starts the agent's main loop or setup logic
	Run() error

	// OnEvent is called by the bus when a subscribed event arrives
	OnEvent(event bus.Event)
}
