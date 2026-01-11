package llm

import (
	"cal-project/internal/core/cache"
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"google.golang.org/genai"
)

// LLM call timeout constant
const LLMTimeout = 60 * time.Second

// LLM defines the interface for Large Language Model interactions
type LLM interface {
	Generate(ctx context.Context, prompt string) (string, error)
	Close()
}

// GeminiClient implements the LLM interface using Google's Gemini
type GeminiClient struct {
	client *genai.Client
	model  string
	cache  *cache.LLMCache
}

// NewGeminiClient creates a new instance of GeminiClient
func NewGeminiClient(ctx context.Context, apiKey string, modelName string) (*GeminiClient, error) {
	// Using google.golang.org/genai (googleapis/go-genai)
	client, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey:  apiKey,
		Backend: genai.BackendGeminiAPI, // Use Gemini Developer API (AI Studio)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create gemini client: %w", err)
	}

	return &GeminiClient{
		client: client,
		model:  modelName,
		cache:  cache.GlobalLLMCache,
	}, nil
}

// Generate sends a prompt to the model and returns the text response
// Includes caching and a 60-second timeout to prevent indefinite hangs
func (g *GeminiClient) Generate(ctx context.Context, prompt string) (string, error) {
	// Check cache first
	if g.cache != nil {
		if cached, ok := g.cache.Get(prompt); ok {
			log.Printf("[LLM] Cache hit (len=%d)\n", len(cached))
			return cached, nil
		}
	}

	// Apply LLM timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, LLMTimeout)
	defer cancel()

	resp, err := g.client.Models.GenerateContent(timeoutCtx, g.model, genai.Text(prompt), nil)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			log.Printf("[LLM] Timeout after %v\n", LLMTimeout)
			return "", fmt.Errorf("LLM timeout after %v", LLMTimeout)
		}
		return "", err
	}

	if len(resp.Candidates) == 0 {
		return "", fmt.Errorf("no candidates returned")
	}

	// Simple text extraction
	var sb strings.Builder
	for _, part := range resp.Candidates[0].Content.Parts {
		sb.WriteString(part.Text)
	}

	result := sb.String()

	// Cache the result
	if g.cache != nil {
		g.cache.Set(prompt, result)
	}

	return result, nil
}

// Close cleans up resources
func (g *GeminiClient) Close() {
	// The http-based client typically doesn't need explicit closing
}
