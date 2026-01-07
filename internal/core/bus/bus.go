package bus

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// EventType defines the type of the event/message
type EventType string

const (
	TaskResult  EventType = "TASK_RESULT"
	Observation EventType = "OBSERVATION"
	Finding     EventType = "FINDING"
	Error       EventType = "ERROR"
	Command     EventType = "COMMAND"
)

// Event (AgentMessage) represents the standardized message exchanged between agents
type Event struct {
	ID        string      `json:"id"`
	Timestamp time.Time   `json:"timestamp"`
	FromAgent string      `json:"from_agent"`
	ToAgent   string      `json:"to_agent"` // "BROADCAST" or specific AgentID
	Type      EventType   `json:"type"`
	Payload   interface{} `json:"payload"`
}

// Handler is a function that processes an event
type Handler func(Event)

// Bus defines the interface for the event system
type Bus interface {
	Publish(topic string, event Event) error
	Subscribe(topic string, handler Handler)
	Start()
	Stop()
}

// MemoryBus is a simple in-memory implementation of Bus
type MemoryBus struct {
	subscribers map[string][]Handler // topic -> handlers
	mu          sync.RWMutex
	eventChan   chan struct {
		topic string
		event Event
	}
	done chan struct{}
}

// NewMemoryBus creates a new instance of MemoryBus
func NewMemoryBus(bufferSize int) *MemoryBus {
	return &MemoryBus{
		subscribers: make(map[string][]Handler),
		eventChan: make(chan struct {
			topic string
			event Event
		}, bufferSize),
		done: make(chan struct{}),
	}
}

// Subscribe adds a handler for a specific topic
func (b *MemoryBus) Subscribe(topic string, handler Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subscribers[topic] = append(b.subscribers[topic], handler)
}

// Publish sends an event to the bus asynchronously
func (b *MemoryBus) Publish(topic string, event Event) error {
	select {
	case b.eventChan <- struct {
		topic string
		event Event
	}{topic: topic, event: event}:
		return nil
	case <-time.After(50 * time.Millisecond):
		return errors.New("event bus full, dropped message")
	}
}

// Start begins the event processing loop
func (b *MemoryBus) Start() {
	go func() {
		for {
			select {
			case msg := <-b.eventChan:
				b.dispatch(msg.topic, msg.event)
			case <-b.done:
				return
			}
		}
	}()
	fmt.Println("[Bus] Event Loop Started")
}

// Stop halts the event loop
func (b *MemoryBus) Stop() {
	close(b.done)
	fmt.Println("[Bus] Event Loop Stopped")
}

func (b *MemoryBus) dispatch(topic string, event Event) {
	b.mu.RLock()
	handlers := b.subscribers[topic]
	// Also dispatch to wildcard "*" subscribers if we implement that,
	// for now just exact match
	b.mu.RUnlock()

	for _, h := range handlers {
		// Run handlers in their own goroutine to prevent blocking the bus?
		// For safety in this architecture, yes.
		go h(event)
	}
}
