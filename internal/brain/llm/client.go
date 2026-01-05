package llm

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/genai"
)

// LLM defines the interface for Large Language Model interactions
type LLM interface {
	Generate(ctx context.Context, prompt string) (string, error)
	Close()
}

// GeminiClient implements the LLM interface using Google's Gemini
type GeminiClient struct {
	client *genai.Client
	model  string
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
	}, nil
}

// Generate sends a prompt to the model and returns the text response
func (g *GeminiClient) Generate(ctx context.Context, prompt string) (string, error) {
	resp, err := g.client.Models.GenerateContent(ctx, g.model, genai.Text(prompt), nil)
	if err != nil {
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

	return sb.String(), nil
}

// Close cleans up resources
func (g *GeminiClient) Close() {
	// The http-based client typically doesn't need explicit closing
}
