package prompts

import (
	"log"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// FileWatcher watches prompt files for changes and triggers reloads
type FileWatcher struct {
	watcher      *fsnotify.Watcher
	events       chan FileEvent
	debounceTime time.Duration
	basePath     string
	stopChan     chan struct{}
}

// NewFileWatcher creates a new FileWatcher instance
func NewFileWatcher(basePath string, config HotReloadConfig) (*FileWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	// Parse debounce duration
	debounce := 500 * time.Millisecond // default
	if config.Debounce != "" {
		if parsed, err := time.ParseDuration(config.Debounce); err == nil {
			debounce = parsed
		}
	}

	fw := &FileWatcher{
		watcher:      watcher,
		events:       make(chan FileEvent, 100),
		debounceTime: debounce,
		basePath:     basePath,
		stopChan:     make(chan struct{}),
	}

	// Add watch on the base path recursively
	if err := fw.addRecursive(basePath); err != nil {
		watcher.Close()
		return nil, err
	}

	// Start event processing
	go fw.processEvents()

	log.Printf("[FileWatcher] Started watching: %s (debounce: %v)", basePath, debounce)

	return fw, nil
}

// addRecursive adds watches on all subdirectories
func (fw *FileWatcher) addRecursive(path string) error {
	// Add watch on the directory itself
	if err := fw.watcher.Add(path); err != nil {
		return err
	}

	// In Phase 2, we'll keep it simple and just watch the known directories
	// Phase 3 can add recursive directory traversal if needed
	subdirs := []string{"v1/commander", "v1/specialist", "v1/recon", "v1/verification"}
	for _, subdir := range subdirs {
		fullPath := filepath.Join(path, subdir)
		if err := fw.watcher.Add(fullPath); err != nil {
			// Log error but don't fail - directory might not exist yet
			log.Printf("[FileWatcher] Warning: Could not watch %s: %v", fullPath, err)
		}
	}

	return nil
}

// processEvents processes file system events with debouncing
func (fw *FileWatcher) processEvents() {
	// Debouncing: collect events and only process after debounce period
	pendingEvents := make(map[string]FileEvent)
	var debounceTimer *time.Timer

	for {
		select {
		case event, ok := <-fw.watcher.Events:
			if !ok {
				return
			}

			// Only process .txt and .json files
			ext := filepath.Ext(event.Name)
			if ext != ".txt" && ext != ".json" {
				continue
			}

			// Only process Write and Create events
			if !event.Has(fsnotify.Write) && !event.Has(fsnotify.Create) {
				continue
			}

			// Determine event type
			eventType := "write"
			if event.Has(fsnotify.Create) {
				eventType = "create"
			}

			// Add to pending events
			pendingEvents[event.Name] = FileEvent{
				Path:      event.Name,
				Type:      eventType,
				Timestamp: time.Now(),
			}

			// Reset debounce timer
			if debounceTimer != nil {
				debounceTimer.Stop()
			}

			debounceTimer = time.AfterFunc(fw.debounceTime, func() {
				// Process all pending events
				for _, evt := range pendingEvents {
					fw.events <- evt
				}
				// Clear pending events
				pendingEvents = make(map[string]FileEvent)
			})

		case err, ok := <-fw.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("[FileWatcher] Error: %v", err)

		case <-fw.stopChan:
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			return
		}
	}
}

// Events returns the channel for file change events
func (fw *FileWatcher) Events() <-chan FileEvent {
	return fw.events
}

// Stop stops the file watcher
func (fw *FileWatcher) Stop() {
	close(fw.stopChan)
	fw.watcher.Close()
	close(fw.events)
	log.Printf("[FileWatcher] Stopped")
}

// extractPromptID extracts the prompt ID from a file path
// e.g., "assets/prompts/v1/specialist/xss_analysis.txt" -> "xss_analysis"
func extractPromptID(filePath string) string {
	// Get base name without extension
	base := filepath.Base(filePath)
	ext := filepath.Ext(base)
	nameWithoutExt := strings.TrimSuffix(base, ext)

	// Remove common suffixes
	nameWithoutExt = strings.TrimSuffix(nameWithoutExt, "_analysis")
	nameWithoutExt = strings.TrimSuffix(nameWithoutExt, "_detect")

	return nameWithoutExt
}
