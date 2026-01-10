package utils

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// CleanLLMJSON removes markdown code blocks and artifacts
func CleanLLMJSON(raw string) string {
	cleaned := strings.TrimSpace(raw)

	// Remove markdown code blocks
	if strings.HasPrefix(cleaned, "```json") {
		cleaned = strings.TrimPrefix(cleaned, "```json")
		cleaned = strings.TrimSuffix(cleaned, "```")
		cleaned = strings.TrimSpace(cleaned)
	} else if strings.HasPrefix(cleaned, "```") {
		cleaned = strings.TrimPrefix(cleaned, "```")
		cleaned = strings.TrimSuffix(cleaned, "```")
		cleaned = strings.TrimSpace(cleaned)
	}

	// Extract JSON: first { to last }
	startIdx := strings.Index(cleaned, "{")
	endIdx := strings.LastIndex(cleaned, "}")
	if startIdx != -1 && endIdx != -1 && endIdx > startIdx {
		cleaned = cleaned[startIdx : endIdx+1]
	}

	// Handle JSON arrays
	if strings.HasPrefix(cleaned, "[") {
		endIdx := strings.LastIndex(cleaned, "]")
		if endIdx != -1 {
			cleaned = cleaned[:endIdx+1]
		}
	}

	return cleaned
}

// ParseLLMJSON attempts to parse LLM output with multiple strategies
func ParseLLMJSON(raw string, target interface{}) error {
	// Strategy 1: Direct parse
	cleaned := CleanLLMJSON(raw)
	if err := json.Unmarshal([]byte(cleaned), target); err == nil {
		return nil
	}

	// Strategy 2: Fix trailing commas
	fixedJSON := regexp.MustCompile(`,(\s*[}\]])`).ReplaceAllString(cleaned, "$1")
	if err := json.Unmarshal([]byte(fixedJSON), target); err == nil {
		return nil
	}

	// Strategy 3: Regex extraction
	jsonPattern := regexp.MustCompile(`(?s)(\{.*\}|\[.*\])`)
	matches := jsonPattern.FindStringSubmatch(raw)
	if len(matches) > 1 {
		if err := json.Unmarshal([]byte(matches[1]), target); err == nil {
			return nil
		}
	}

	return fmt.Errorf("failed to parse LLM JSON after 3 strategies")
}
