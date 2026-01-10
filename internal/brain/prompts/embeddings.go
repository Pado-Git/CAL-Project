package prompts

import (
	"context"
	"fmt"
	"log"

	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

// Embedder is an interface for generating text embeddings
type Embedder interface {
	Embed(ctx context.Context, text string) ([]float32, error)
	Dimension() int
	Close() error
}

// GeminiEmbedder uses Google Gemini API for generating embeddings
type GeminiEmbedder struct {
	client *genai.Client
	model  string
	dim    int
}

// NewGeminiEmbedder creates a new Gemini embedder
func NewGeminiEmbedder(ctx context.Context, apiKey string, config EmbeddingConfig) (*GeminiEmbedder, error) {
	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create Gemini client: %w", err)
	}

	model := config.Model
	if model == "" {
		model = "models/text-embedding-004" // Default Gemini embedding model
	}

	dimension := config.Dimension
	if dimension <= 0 {
		dimension = 768 // Default dimension for text-embedding-004
	}

	log.Printf("[GeminiEmbedder] Initialized with model: %s (dimension: %d)", model, dimension)

	return &GeminiEmbedder{
		client: client,
		model:  model,
		dim:    dimension,
	}, nil
}

// Embed generates an embedding vector for the given text
func (g *GeminiEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	// Use the embedding model
	em := g.client.EmbeddingModel(g.model)

	// Generate embedding
	res, err := em.EmbedContent(ctx, genai.Text(text))
	if err != nil {
		return nil, fmt.Errorf("failed to generate embedding: %w", err)
	}

	// Check if embedding was generated
	if res == nil || res.Embedding == nil || len(res.Embedding.Values) == 0 {
		return nil, fmt.Errorf("empty embedding response")
	}

	// Convert to []float32
	embedding := make([]float32, len(res.Embedding.Values))
	for i, v := range res.Embedding.Values {
		embedding[i] = v
	}

	// Verify dimension
	if len(embedding) != g.dim {
		log.Printf("[GeminiEmbedder] Warning: Expected dimension %d, got %d", g.dim, len(embedding))
	}

	return embedding, nil
}

// Dimension returns the embedding dimension
func (g *GeminiEmbedder) Dimension() int {
	return g.dim
}

// Close closes the Gemini client
func (g *GeminiEmbedder) Close() error {
	if g.client != nil {
		return g.client.Close()
	}
	return nil
}

// EmbedBatch generates embeddings for multiple texts at once
// This is more efficient than calling Embed() multiple times
func (g *GeminiEmbedder) EmbedBatch(ctx context.Context, texts []string) ([][]float32, error) {
	if len(texts) == 0 {
		return nil, nil
	}

	embeddings := make([][]float32, len(texts))

	// Gemini API doesn't support batch embeddings yet,
	// so we'll call Embed() for each text sequentially
	// In the future, this could be optimized with concurrent requests
	for i, text := range texts {
		embedding, err := g.Embed(ctx, text)
		if err != nil {
			return nil, fmt.Errorf("failed to embed text %d: %w", i, err)
		}
		embeddings[i] = embedding
	}

	return embeddings, nil
}
