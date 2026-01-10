package prompts

import (
	"sync"
	"time"
)

// Cache provides in-memory caching for prompts with TTL support
type Cache struct {
	items   map[string]*cacheItem
	mu      sync.RWMutex
	ttl     time.Duration
	maxSize int
}

// cacheItem represents a cached prompt with expiration
type cacheItem struct {
	prompt    *Prompt
	expiresAt time.Time
}

// NewCache creates a new Cache instance
func NewCache(config CacheConfig) *Cache {
	ttl := 1 * time.Hour // default
	if config.TTL != "" {
		if parsed, err := time.ParseDuration(config.TTL); err == nil {
			ttl = parsed
		}
	}

	maxSize := config.MaxSize
	if maxSize <= 0 {
		maxSize = 100 // default
	}

	return &Cache{
		items:   make(map[string]*cacheItem),
		ttl:     ttl,
		maxSize: maxSize,
	}
}

// Get retrieves a prompt from cache
// Returns nil if not found or expired
func (c *Cache) Get(promptID string) *Prompt {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, exists := c.items[promptID]
	if !exists {
		return nil
	}

	// Check expiration
	if time.Now().After(item.expiresAt) {
		// Expired, will be cleaned up later
		return nil
	}

	return item.prompt
}

// Set stores a prompt in cache with TTL
func (c *Cache) Set(promptID string, prompt *Prompt) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if cache is full
	if len(c.items) >= c.maxSize {
		// Simple eviction: remove expired items first
		c.evictExpired()

		// If still full, remove oldest item
		if len(c.items) >= c.maxSize {
			c.evictOldest()
		}
	}

	c.items[promptID] = &cacheItem{
		prompt:    prompt,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Invalidate removes a specific prompt from cache
func (c *Cache) Invalidate(promptID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.items, promptID)
}

// Clear removes all items from cache
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*cacheItem)
}

// evictExpired removes all expired items (must be called with lock held)
func (c *Cache) evictExpired() {
	now := time.Now()
	for id, item := range c.items {
		if now.After(item.expiresAt) {
			delete(c.items, id)
		}
	}
}

// evictOldest removes the oldest item by expiration time (must be called with lock held)
func (c *Cache) evictOldest() {
	if len(c.items) == 0 {
		return
	}

	var oldestID string
	var oldestTime time.Time

	for id, item := range c.items {
		if oldestTime.IsZero() || item.expiresAt.Before(oldestTime) {
			oldestID = id
			oldestTime = item.expiresAt
		}
	}

	if oldestID != "" {
		delete(c.items, oldestID)
	}
}

// Size returns the current number of items in cache
func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.items)
}

// StartCleanupWorker starts a background goroutine that periodically cleans expired items
func (c *Cache) StartCleanupWorker(interval time.Duration) chan struct{} {
	stopChan := make(chan struct{})

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				c.mu.Lock()
				c.evictExpired()
				c.mu.Unlock()
			case <-stopChan:
				return
			}
		}
	}()

	return stopChan
}
