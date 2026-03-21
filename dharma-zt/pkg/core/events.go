package core

import (
	"context"
	"sync"
	"time"
)

// EventType represents the category of an event.
type EventType string

const (
	EventPeerDiscovered EventType = "PeerDiscovered"
	EventPeerLost       EventType = "PeerLost"
	EventPolicyUpdated  EventType = "PolicyUpdated"
	EventTamperDetected EventType = "TamperDetected"
	EventPacketBlocked  EventType = "PacketBlocked"
	EventKeyRotated     EventType = "KeyRotated"
	EventLockdown       EventType = "Lockdown"
)

// Event defines the standard message passed on the EventBus.
type Event struct {
	ID        string    `json:"id"`
	Type      EventType `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Payload   any       `json:"payload"`
}

// EventHandler processes an event.
type EventHandler func(context.Context, Event)

// EventBus provides publish-subscribe mechanisms for internal components.
type EventBus struct {
	mu          sync.RWMutex
	subscribers map[EventType][]EventHandler
}

// NewEventBus creates a new EventBus.
func NewEventBus() *EventBus {
	return &EventBus{
		subscribers: make(map[EventType][]EventHandler),
	}
}

// Subscribe registers a handler for a specific event type.
func (b *EventBus) Subscribe(eventType EventType, handler EventHandler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subscribers[eventType] = append(b.subscribers[eventType], handler)
}

// Publish broadcasts an event to all subscribers in separate goroutines.
// The context should be used by the EventHandler implementation to manage its lifecycle.
func (b *EventBus) Publish(ctx context.Context, event Event) {
	b.mu.RLock()
	handlers := b.subscribers[event.Type]
	b.mu.RUnlock()

	for _, handler := range handlers {
		// The handler itself is responsible for selecting on ctx.Done()
		go handler(ctx, event)
	}
}
