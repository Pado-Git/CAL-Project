package prompts

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// FileLoader loads prompts from the file system
type FileLoader struct {
	basePath string
	metadata map[string]map[string]PromptMetadata // category -> promptID -> metadata
}

// NewFileLoader creates a new FileLoader instance
func NewFileLoader(basePath string) *FileLoader {
	return &FileLoader{
		basePath: basePath,
		metadata: make(map[string]map[string]PromptMetadata),
	}
}

// LoadMetadata loads all metadata.json files from the prompt directories
func (fl *FileLoader) LoadMetadata(ctx context.Context) error {
	categories := []string{"commander", "specialist", "recon", "verification"}
	currentVersion := "v1" // TODO: Read from config

	for _, category := range categories {
		metadataPath := filepath.Join(fl.basePath, currentVersion, category, "metadata.json")

		// Check if metadata file exists
		if _, err := os.Stat(metadataPath); os.IsNotExist(err) {
			// Skip if metadata doesn't exist yet
			continue
		}

		// Read metadata file
		data, err := os.ReadFile(metadataPath)
		if err != nil {
			return fmt.Errorf("failed to read metadata %s: %w", metadataPath, err)
		}

		// Parse metadata
		var categoryMetadata map[string]PromptMetadata
		if err := json.Unmarshal(data, &categoryMetadata); err != nil {
			return fmt.Errorf("failed to parse metadata %s: %w", metadataPath, err)
		}

		fl.metadata[category] = categoryMetadata
	}

	return nil
}

// Load loads a prompt by its ID from the file system
func (fl *FileLoader) Load(ctx context.Context, promptID string) (*Prompt, error) {
	// Find the prompt metadata
	var meta PromptMetadata
	var found bool
	var category string

	for cat, catMeta := range fl.metadata {
		if m, ok := catMeta[promptID]; ok {
			meta = m
			category = cat
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("prompt not found: %s", promptID)
	}

	// Build file path
	currentVersion := "v1" // TODO: Read from config
	filePath := filepath.Join(fl.basePath, currentVersion, category, filepath.Base(meta.File))

	// Read prompt file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read prompt file %s: %w", filePath, err)
	}

	// Create Prompt object
	prompt := &Prompt{
		ID:           promptID,
		Content:      string(content),
		Variables:    meta.Variables,
		OutputFormat: meta.OutputFormat,
		Tags:         meta.Tags,
		Version:      meta.Version,
		LoadedAt:     time.Now(),
		Metadata:     make(map[string]string),
	}

	// Add additional metadata
	prompt.Metadata["category"] = category
	prompt.Metadata["file_path"] = filePath

	return prompt, nil
}

// Format formats a prompt by replacing {{variable}} placeholders with actual values
func Format(prompt *Prompt, vars map[string]interface{}) (string, error) {
	result := prompt.Content

	// Replace each variable placeholder
	for key, value := range vars {
		placeholder := fmt.Sprintf("{{%s}}", key)
		var strValue string

		switch v := value.(type) {
		case string:
			strValue = v
		case int, int32, int64:
			strValue = fmt.Sprintf("%d", v)
		case float32, float64:
			strValue = fmt.Sprintf("%f", v)
		case bool:
			strValue = fmt.Sprintf("%t", v)
		default:
			strValue = fmt.Sprintf("%v", v)
		}

		result = strings.ReplaceAll(result, placeholder, strValue)
	}

	// Check if any placeholders remain (indicates missing variables)
	if strings.Contains(result, "{{") && strings.Contains(result, "}}") {
		// Extract remaining placeholders for error message
		var remaining []string
		parts := strings.Split(result, "{{")
		for _, part := range parts[1:] {
			if idx := strings.Index(part, "}}"); idx != -1 {
				remaining = append(remaining, part[:idx])
			}
		}
		return "", fmt.Errorf("missing variables: %v", remaining)
	}

	return result, nil
}

// LoadConfigFromFile loads the prompt system configuration from config.yaml
func LoadConfigFromFile(configPath string) (*Config, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Phase 2: Parse YAML properly
	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config YAML: %w", err)
	}

	// Set defaults for any missing fields
	if config.PromptSystem.Version == "" {
		config.PromptSystem.Version = "1.0.0"
	}
	if config.PromptSystem.CurrentVersion == "" {
		config.PromptSystem.CurrentVersion = "v1"
	}
	if config.PromptSystem.BasePath == "" {
		config.PromptSystem.BasePath = "assets/prompts"
	}

	// Validation defaults
	if config.PromptSystem.Validation.Enabled && config.PromptSystem.Cache.MaxSize == 0 {
		config.PromptSystem.Cache.MaxSize = 100
	}

	return &config, nil
}
