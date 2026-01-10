package prompts

import (
	"fmt"
	"strings"
)

// Validator validates prompt structure and content
type Validator struct {
	config ValidationConfig
}

// NewValidator creates a new Validator instance
func NewValidator(config ValidationConfig) *Validator {
	return &Validator{
		config: config,
	}
}

// Validate checks if a prompt is valid
func (v *Validator) Validate(prompt *Prompt) error {
	if !v.config.Enabled {
		return nil // Validation disabled
	}

	// 1. Check content is not empty
	if len(strings.TrimSpace(prompt.Content)) < 10 {
		if v.config.StrictMode {
			return fmt.Errorf("prompt content too short (must be at least 10 characters)")
		}
		// In non-strict mode, just warn
		return nil
	}

	// 2. Check required variables exist in content
	if v.config.CheckVariables {
		for _, varName := range prompt.Variables {
			placeholder := fmt.Sprintf("{{%s}}", varName)
			if !strings.Contains(prompt.Content, placeholder) {
				if v.config.StrictMode {
					return fmt.Errorf("required variable not found in prompt: %s", varName)
				}
				// In non-strict mode, warn but don't fail
			}
		}
	}

	// 3. Check for unclosed placeholders
	if v.hasUnmatchedBraces(prompt.Content) {
		if v.config.StrictMode {
			return fmt.Errorf("prompt has unmatched {{ or }} braces")
		}
	}

	return nil
}

// hasUnmatchedBraces checks if the content has unmatched {{ or }} braces
func (v *Validator) hasUnmatchedBraces(content string) bool {
	// Count opening and closing braces
	openCount := strings.Count(content, "{{")
	closeCount := strings.Count(content, "}}")

	return openCount != closeCount
}

// ValidateMetadata validates prompt metadata
func (v *Validator) ValidateMetadata(meta PromptMetadata) error {
	if !v.config.Enabled {
		return nil
	}

	// Check required fields
	if meta.File == "" {
		return fmt.Errorf("metadata missing 'file' field")
	}

	if meta.Version == "" {
		return fmt.Errorf("metadata missing 'version' field")
	}

	// Validate output format
	if meta.OutputFormat != "" && meta.OutputFormat != "text" && meta.OutputFormat != "json" {
		return fmt.Errorf("invalid output_format: %s (must be 'text' or 'json')", meta.OutputFormat)
	}

	return nil
}

// SuggestFixes analyzes a prompt and suggests potential fixes
func (v *Validator) SuggestFixes(prompt *Prompt) []string {
	var suggestions []string

	// Check for common issues
	content := prompt.Content

	// 1. Check for single braces (should be double)
	if strings.Contains(content, "{") && !strings.Contains(content, "{{") {
		suggestions = append(suggestions, "Found single '{' - did you mean '{{' for variable placeholder?")
	}

	// 2. Check for variables in metadata but not in content
	for _, varName := range prompt.Variables {
		placeholder := fmt.Sprintf("{{%s}}", varName)
		if !strings.Contains(content, placeholder) {
			suggestions = append(suggestions, fmt.Sprintf("Variable '%s' declared in metadata but not used in content", varName))
		}
	}

	// 3. Check for potential undeclared variables
	// Find all {{...}} patterns
	start := 0
	for {
		startIdx := strings.Index(content[start:], "{{")
		if startIdx == -1 {
			break
		}
		startIdx += start

		endIdx := strings.Index(content[startIdx:], "}}")
		if endIdx == -1 {
			break
		}
		endIdx += startIdx

		// Extract variable name
		varName := strings.TrimSpace(content[startIdx+2 : endIdx])

		// Check if it's in the declared variables
		found := false
		for _, declaredVar := range prompt.Variables {
			if declaredVar == varName {
				found = true
				break
			}
		}

		if !found && varName != "" {
			suggestions = append(suggestions, fmt.Sprintf("Undeclared variable in content: '%s'", varName))
		}

		start = endIdx + 2
	}

	return suggestions
}
