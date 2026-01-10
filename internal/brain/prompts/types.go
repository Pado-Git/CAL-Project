package prompts

import (
	"time"
)

// Prompt represents a single prompt template
type Prompt struct {
	ID           string            // Unique identifier (e.g., "xss_analysis")
	Content      string            // The actual prompt text with {{variable}} placeholders
	Variables    []string          // Required variables for this prompt
	OutputFormat string            // "text" or "json"
	Tags         []string          // Categorization tags
	Version      string            // Semantic version (e.g., "1.0.0")
	LoadedAt     time.Time         // Timestamp when loaded
	Metadata     map[string]string // Additional metadata
}

// PromptMetadata represents metadata for a prompt stored in metadata.json
type PromptMetadata struct {
	File         string   `json:"file"`          // Relative path to prompt file
	Version      string   `json:"version"`       // Semantic version
	Variables    []string `json:"variables"`     // Required variables
	OutputFormat string   `json:"output_format"` // Output format
	Tags         []string `json:"tags"`          // Tags for categorization
}

// Config represents the overall prompt system configuration
type Config struct {
	PromptSystem PromptSystemConfig `yaml:"prompt_system"`
}

type PromptSystemConfig struct {
	Version        string           `yaml:"version"`
	CurrentVersion string           `yaml:"current_version"`
	BasePath       string           `yaml:"base_path"`
	HotReload      HotReloadConfig  `yaml:"hot_reload"`
	Cache          CacheConfig      `yaml:"cache"`
	Validation     ValidationConfig `yaml:"validation"`
	RAG            RAGConfig        `yaml:"rag"`
	Logging        LoggingConfig    `yaml:"logging"`
}

// HotReloadConfig configures file watching and hot reloading
type HotReloadConfig struct {
	Enabled       bool   `yaml:"enabled"`
	WatchInterval string `yaml:"watch_interval"` // e.g., "2s"
	Debounce      string `yaml:"debounce"`       // e.g., "500ms"
}

// CacheConfig configures in-memory caching
type CacheConfig struct {
	Enabled bool   `yaml:"enabled"`
	TTL     string `yaml:"ttl"`      // e.g., "1h"
	MaxSize int    `yaml:"max_size"` // Maximum number of cached prompts
}

// ValidationConfig configures prompt validation
type ValidationConfig struct {
	Enabled        bool `yaml:"enabled"`
	StrictMode     bool `yaml:"strict_mode"`
	CheckVariables bool `yaml:"check_variables"`
}

// RAGConfig configures RAG (Retrieval-Augmented Generation) mode
type RAGConfig struct {
	Enabled          bool        `yaml:"enabled"`
	FallbackToDirect bool        `yaml:"fallback_to_direct"`
	VectorDB         VectorDB    `yaml:"vector_db"`
	Embedding        EmbeddingConfig `yaml:"embedding"`
}

// VectorDB configures the vector database (Qdrant)
type VectorDB struct {
	Type       string `yaml:"type"`       // "qdrant"
	Host       string `yaml:"host"`       // e.g., "localhost"
	Port       int    `yaml:"port"`       // e.g., 6333
	Collection string `yaml:"collection"` // e.g., "cai_prompts"
}

// EmbeddingConfig configures the embedding provider
type EmbeddingConfig struct {
	Provider  string `yaml:"provider"`  // e.g., "gemini"
	Model     string `yaml:"model"`     // e.g., "models/text-embedding-004"
	Dimension int    `yaml:"dimension"` // e.g., 768
}

// LoggingConfig configures prompt system logging
type LoggingConfig struct {
	Level           string `yaml:"level"`              // "info", "debug", "warn", "error"
	LogPromptAccess bool   `yaml:"log_prompt_access"` // Log each prompt access
}

// FileEvent represents a file system event (for hot reload)
type FileEvent struct {
	Path      string    // Full path to the file
	Type      string    // "write", "create", "remove"
	Timestamp time.Time // When the event occurred
}
