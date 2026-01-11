package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"sync"
	"time"
)

// CachedResponse represents a cached LLM response with timestamp
type CachedResponse struct {
	Response  string
	Timestamp time.Time
}

// LLMCache provides thread-safe caching for LLM responses
type LLMCache struct {
	cache map[string]CachedResponse
	mu    sync.RWMutex
	ttl   time.Duration
}

// DefaultCacheTTL is the default time-to-live for cached responses (30 minutes)
const DefaultCacheTTL = 30 * time.Minute

// NewLLMCache creates a new LLM cache with the specified TTL
func NewLLMCache(ttl time.Duration) *LLMCache {
	if ttl <= 0 {
		ttl = DefaultCacheTTL
	}
	return &LLMCache{
		cache: make(map[string]CachedResponse),
		ttl:   ttl,
	}
}

// Get retrieves a cached response if it exists and hasn't expired
func (c *LLMCache) Get(prompt string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := hashPrompt(prompt)
	if cached, ok := c.cache[key]; ok {
		if time.Since(cached.Timestamp) < c.ttl {
			return cached.Response, true
		}
		// Entry expired, will be cleaned up on next Set
	}
	return "", false
}

// Set stores a response in the cache
func (c *LLMCache) Set(prompt, response string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := hashPrompt(prompt)
	c.cache[key] = CachedResponse{
		Response:  response,
		Timestamp: time.Now(),
	}
}

// Size returns the current number of cached entries
func (c *LLMCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

// Clear removes all entries from the cache
func (c *LLMCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]CachedResponse)
	log.Println("[LLMCache] Cache cleared")
}

// Cleanup removes expired entries from the cache
func (c *LLMCache) Cleanup() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	removed := 0
	now := time.Now()
	for key, cached := range c.cache {
		if now.Sub(cached.Timestamp) >= c.ttl {
			delete(c.cache, key)
			removed++
		}
	}

	if removed > 0 {
		log.Printf("[LLMCache] Cleaned up %d expired entries\n", removed)
	}
	return removed
}

// hashPrompt creates a SHA-256 hash of the prompt for use as a cache key
func hashPrompt(prompt string) string {
	h := sha256.Sum256([]byte(prompt))
	return hex.EncodeToString(h[:16]) // Use first 16 bytes (32 hex chars)
}

// GlobalLLMCache is the singleton LLM cache instance
var GlobalLLMCache = NewLLMCache(DefaultCacheTTL)
