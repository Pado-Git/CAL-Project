package prompts

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PromptManager is the central manager for the prompt system
type PromptManager struct {
	config        *Config
	loader        *FileLoader
	validator     *Validator
	watcher       *FileWatcher
	cache         *Cache
	rag           *RAGEngine // Phase 3: Optional RAG engine
	cleanupStopCh chan struct{}
}

// NewPromptManager creates a new PromptManager instance
func NewPromptManager(ctx context.Context, config *Config) (*PromptManager, error) {
	loader := NewFileLoader(config.PromptSystem.BasePath)
	validator := NewValidator(config.PromptSystem.Validation)
	cache := NewCache(config.PromptSystem.Cache)

	pm := &PromptManager{
		config:    config,
		loader:    loader,
		validator: validator,
		cache:     cache,
	}

	// Load metadata
	if err := loader.LoadMetadata(ctx); err != nil {
		log.Printf("[PromptManager] Warning: Failed to load metadata: %v", err)
	}

	// Phase 3: Initialize RAG engine if enabled
	if config.PromptSystem.RAG.Enabled {
		log.Printf("[PromptManager] RAG mode enabled, initializing RAG engine...")

		// Get Gemini API key from environment
		apiKey := os.Getenv("GEMINI_API_KEY")
		if apiKey == "" {
			log.Printf("[PromptManager] Warning: GEMINI_API_KEY not set, RAG disabled")
		} else {
			rag, err := NewRAGEngine(ctx, apiKey, config.PromptSystem.RAG)
			if err != nil {
				log.Printf("[PromptManager] Warning: Failed to initialize RAG engine: %v", err)
				if config.PromptSystem.RAG.FallbackToDirect {
					log.Printf("[PromptManager] Continuing with direct file loading (fallback)")
				} else {
					return nil, fmt.Errorf("RAG initialization failed and fallback disabled: %w", err)
				}
			} else {
				pm.rag = rag
				log.Printf("[PromptManager] RAG engine initialized successfully")
			}
		}
	}

	// Start cache cleanup worker
	if config.PromptSystem.Cache.Enabled {
		pm.cleanupStopCh = cache.StartCleanupWorker(5 * time.Minute)
	}

	// Setup hot reload if enabled
	if config.PromptSystem.HotReload.Enabled {
		watcher, err := NewFileWatcher(config.PromptSystem.BasePath, config.PromptSystem.HotReload)
		if err != nil {
			log.Printf("[PromptManager] Warning: Failed to start file watcher: %v", err)
			log.Printf("[PromptManager] Hot reload disabled")
		} else {
			pm.watcher = watcher
			go pm.handleFileChanges(ctx, watcher.Events())
		}
	}

	log.Printf("[PromptManager] Initialized successfully")

	return pm, nil
}

// Get retrieves a prompt by ID
func (pm *PromptManager) Get(ctx context.Context, promptID string) (*Prompt, error) {
	// 1. Check cache first
	if pm.config.PromptSystem.Cache.Enabled {
		if cached := pm.cache.Get(promptID); cached != nil {
			if pm.config.PromptSystem.Logging.LogPromptAccess {
				log.Printf("[PromptManager] Cache hit: %s", promptID)
			}
			return cached, nil
		}
	}

	// 2. Try RAG if enabled (Phase 3)
	var prompt *Prompt
	var err error

	if pm.rag != nil {
		prompt, err = pm.rag.Search(ctx, promptID)
		if err == nil && prompt != nil {
			// RAG success
			if pm.config.PromptSystem.Logging.LogPromptAccess {
				log.Printf("[PromptManager] Loaded: %s (from RAG)", promptID)
			}

			// Cache and return
			if pm.config.PromptSystem.Cache.Enabled {
				pm.cache.Set(promptID, prompt)
			}
			return prompt, nil
		}

		// RAG failed, fallback to direct loading
		if pm.config.PromptSystem.RAG.FallbackToDirect {
			log.Printf("[PromptManager] RAG search failed for %s: %v, using direct loading", promptID, err)
		} else {
			return nil, fmt.Errorf("RAG search failed and fallback disabled: %w", err)
		}
	}

	// 3. Load from file system (direct loading)
	prompt, err = pm.loader.Load(ctx, promptID)
	if err != nil {
		return nil, err
	}

	// 4. Validate
	if pm.config.PromptSystem.Validation.Enabled {
		if err := pm.validator.Validate(prompt); err != nil {
			log.Printf("[PromptManager] Validation failed for %s: %v", promptID, err)

			// Show suggestions if available
			if suggestions := pm.validator.SuggestFixes(prompt); len(suggestions) > 0 {
				log.Printf("[PromptManager] Suggestions for %s:", promptID)
				for _, suggestion := range suggestions {
					log.Printf("  - %s", suggestion)
				}
			}

			// In strict mode, fail on validation error
			if pm.config.PromptSystem.Validation.StrictMode {
				return nil, err
			}
			// Otherwise, log and continue
		}
	}

	// 5. Cache the prompt
	if pm.config.PromptSystem.Cache.Enabled {
		pm.cache.Set(promptID, prompt)
	}

	if pm.config.PromptSystem.Logging.LogPromptAccess {
		log.Printf("[PromptManager] Loaded: %s (from file)", promptID)
	}

	return prompt, nil
}

// handleFileChanges handles file system events and invalidates cache
func (pm *PromptManager) handleFileChanges(ctx context.Context, events <-chan FileEvent) {
	for event := range events {
		log.Printf("[PromptManager] File changed: %s (type: %s)", event.Path, event.Type)

		// Determine which prompt(s) to invalidate
		ext := filepath.Ext(event.Path)

		if ext == ".txt" {
			// Individual prompt file changed
			promptID := extractPromptIDFromPath(event.Path)
			if promptID != "" {
				pm.cache.Invalidate(promptID)
				log.Printf("[PromptManager] Invalidated cache for: %s", promptID)
			}
		} else if ext == ".json" {
			// Metadata file changed - reload all metadata and clear cache
			log.Printf("[PromptManager] Metadata changed, reloading...")

			if err := pm.loader.LoadMetadata(ctx); err != nil {
				log.Printf("[PromptManager] Failed to reload metadata: %v", err)
			} else {
				pm.cache.Clear()
				log.Printf("[PromptManager] Cache cleared, metadata reloaded")
			}
		}
	}
}

// extractPromptIDFromPath extracts the prompt ID from a file path
// Examples:
//   - "assets/prompts/v1/specialist/xss_analysis.txt" -> "xss_analysis"
//   - "E:\business\Cai\cal-project\assets\prompts\v1\commander\initial.txt" -> "initial"
func extractPromptIDFromPath(path string) string {
	// Normalize path separators
	path = filepath.ToSlash(path)

	// Get base name without extension
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	nameWithoutExt := strings.TrimSuffix(base, ext)

	// The filename is the prompt ID (e.g., "xss_analysis", "initial")
	return nameWithoutExt
}

// Close cleans up resources
func (pm *PromptManager) Close() {
	if pm.watcher != nil {
		pm.watcher.Stop()
	}

	if pm.rag != nil {
		if err := pm.rag.Close(); err != nil {
			log.Printf("[PromptManager] Error closing RAG engine: %v", err)
		}
	}

	if pm.cleanupStopCh != nil {
		close(pm.cleanupStopCh)
	}

	log.Printf("[PromptManager] Closed")
}

// GetCacheStats returns cache statistics
func (pm *PromptManager) GetCacheStats() map[string]interface{} {
	return map[string]interface{}{
		"size":    pm.cache.Size(),
		"enabled": pm.config.PromptSystem.Cache.Enabled,
	}
}

// ReloadMetadata manually reloads all metadata
func (pm *PromptManager) ReloadMetadata(ctx context.Context) error {
	if err := pm.loader.LoadMetadata(ctx); err != nil {
		return err
	}

	pm.cache.Clear()
	log.Printf("[PromptManager] Metadata reloaded manually")

	return nil
}
