package prompts

import (
	"context"
	"fmt"
	"log"

	"github.com/google/uuid"
	"github.com/qdrant/go-client/qdrant"
)

// RAGEngine provides vector-based prompt retrieval using Qdrant
type RAGEngine struct {
	client     *qdrant.Client
	embedder   Embedder
	config     RAGConfig
	collection string
}

// NewRAGEngine creates a new RAG engine instance
func NewRAGEngine(ctx context.Context, apiKey string, config RAGConfig) (*RAGEngine, error) {
	// Create Qdrant client
	// Note: Qdrant Go client expects just the host without the port
	// Port 6334 is the default gRPC port for Qdrant
	client, err := qdrant.NewClient(&qdrant.Config{
		Host: config.VectorDB.Host,
		Port: config.VectorDB.Port,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Qdrant client: %w", err)
	}

	// Create embedder
	embedder, err := NewGeminiEmbedder(ctx, apiKey, config.Embedding)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to create embedder: %w", err)
	}

	collection := config.VectorDB.Collection
	if collection == "" {
		collection = "cai_prompts"
	}

	engine := &RAGEngine{
		client:     client,
		embedder:   embedder,
		config:     config,
		collection: collection,
	}

	// Ensure collection exists
	if err := engine.ensureCollection(ctx); err != nil {
		client.Close()
		embedder.Close()
		return nil, fmt.Errorf("failed to ensure collection: %w", err)
	}

	log.Printf("[RAGEngine] Initialized successfully (collection: %s)", collection)

	return engine, nil
}

// ensureCollection creates the collection if it doesn't exist
func (r *RAGEngine) ensureCollection(ctx context.Context) error {
	// Check if collection exists
	exists, err := r.client.CollectionExists(ctx, r.collection)
	if err != nil {
		return fmt.Errorf("failed to check collection: %w", err)
	}

	if exists {
		log.Printf("[RAGEngine] Collection '%s' already exists", r.collection)
		return nil
	}

	// Create collection
	log.Printf("[RAGEngine] Creating collection '%s' with dimension %d", r.collection, r.embedder.Dimension())

	err = r.client.CreateCollection(ctx, &qdrant.CreateCollection{
		CollectionName: r.collection,
		VectorsConfig: qdrant.NewVectorsConfig(&qdrant.VectorParams{
			Size:     uint64(r.embedder.Dimension()),
			Distance: qdrant.Distance_Cosine,
		}),
	})

	if err != nil {
		return fmt.Errorf("failed to create collection: %w", err)
	}

	log.Printf("[RAGEngine] Collection '%s' created successfully", r.collection)
	return nil
}

// Search searches for a prompt by exact ID match using payload filter
func (r *RAGEngine) Search(ctx context.Context, promptID string) (*Prompt, error) {
	// Use Scroll API with payload filter for exact ID matching
	// This is more efficient than semantic search for ID lookups
	scrollResult, err := r.client.Scroll(ctx, &qdrant.ScrollPoints{
		CollectionName: r.collection,
		Filter: &qdrant.Filter{
			Must: []*qdrant.Condition{
				{
					ConditionOneOf: &qdrant.Condition_Field{
						Field: &qdrant.FieldCondition{
							Key: "id",
							Match: &qdrant.Match{
								MatchValue: &qdrant.Match_Keyword{
									Keyword: promptID,
								},
							},
						},
					},
				},
			},
		},
		Limit:       qdrant.PtrOf(uint32(1)),
		WithPayload: qdrant.NewWithPayload(true),
	})

	if err != nil {
		return nil, fmt.Errorf("failed to search in Qdrant: %w", err)
	}

	// Check if we got results
	if scrollResult == nil || len(scrollResult) == 0 {
		return nil, fmt.Errorf("no prompt found with ID: %s", promptID)
	}

	// Reconstruct Prompt from the result
	point := scrollResult[0]
	return r.reconstructPromptFromPoint(point)
}

// Index indexes a prompt into the vector database
func (r *RAGEngine) Index(ctx context.Context, prompt *Prompt) error {
	// Generate embedding for the prompt content
	embedding, err := r.embedder.Embed(ctx, prompt.Content)
	if err != nil {
		return fmt.Errorf("failed to generate embedding: %w", err)
	}

	// Create point ID from prompt ID
	pointID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(prompt.ID))

	// Prepare payload with proper types
	payload := make(map[string]*qdrant.Value)
	payload["id"] = qdrant.NewValueString(prompt.ID)
	payload["content"] = qdrant.NewValueString(prompt.Content)
	payload["output_format"] = qdrant.NewValueString(prompt.OutputFormat)
	payload["version"] = qdrant.NewValueString(prompt.Version)

	// Convert string slices to Qdrant list values
	if len(prompt.Variables) > 0 {
		varValues := make([]*qdrant.Value, len(prompt.Variables))
		for i, v := range prompt.Variables {
			varValues[i] = qdrant.NewValueString(v)
		}
		payload["variables"] = qdrant.NewValueList(&qdrant.ListValue{Values: varValues})
	}

	if len(prompt.Tags) > 0 {
		tagValues := make([]*qdrant.Value, len(prompt.Tags))
		for i, t := range prompt.Tags {
			tagValues[i] = qdrant.NewValueString(t)
		}
		payload["tags"] = qdrant.NewValueList(&qdrant.ListValue{Values: tagValues})
	}

	// Add metadata
	for k, v := range prompt.Metadata {
		payload["meta_"+k] = qdrant.NewValueString(v)
	}

	// Upsert point
	_, err = r.client.Upsert(ctx, &qdrant.UpsertPoints{
		CollectionName: r.collection,
		Points: []*qdrant.PointStruct{
			{
				Id:      qdrant.NewIDUUID(pointID.String()),
				Vectors: qdrant.NewVectors(embedding...),
				Payload: payload,
			},
		},
	})

	if err != nil {
		return fmt.Errorf("failed to upsert point: %w", err)
	}

	log.Printf("[RAGEngine] Indexed prompt: %s", prompt.ID)
	return nil
}

// IndexBatch indexes multiple prompts at once
func (r *RAGEngine) IndexBatch(ctx context.Context, prompts []*Prompt) error {
	if len(prompts) == 0 {
		return nil
	}

	log.Printf("[RAGEngine] Indexing %d prompts...", len(prompts))

	points := make([]*qdrant.PointStruct, 0, len(prompts))

	for _, prompt := range prompts {
		// Generate embedding
		embedding, err := r.embedder.Embed(ctx, prompt.Content)
		if err != nil {
			return fmt.Errorf("failed to embed prompt %s: %w", prompt.ID, err)
		}

		// Create point
		pointID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(prompt.ID))

		// Prepare payload with proper types
		payload := make(map[string]*qdrant.Value)
		payload["id"] = qdrant.NewValueString(prompt.ID)
		payload["content"] = qdrant.NewValueString(prompt.Content)
		payload["output_format"] = qdrant.NewValueString(prompt.OutputFormat)
		payload["version"] = qdrant.NewValueString(prompt.Version)

		// Convert string slices to Qdrant list values
		if len(prompt.Variables) > 0 {
			varValues := make([]*qdrant.Value, len(prompt.Variables))
			for i, v := range prompt.Variables {
				varValues[i] = qdrant.NewValueString(v)
			}
			payload["variables"] = qdrant.NewValueList(&qdrant.ListValue{Values: varValues})
		}

		if len(prompt.Tags) > 0 {
			tagValues := make([]*qdrant.Value, len(prompt.Tags))
			for i, t := range prompt.Tags {
				tagValues[i] = qdrant.NewValueString(t)
			}
			payload["tags"] = qdrant.NewValueList(&qdrant.ListValue{Values: tagValues})
		}

		// Add metadata
		for k, v := range prompt.Metadata {
			payload["meta_"+k] = qdrant.NewValueString(v)
		}

		points = append(points, &qdrant.PointStruct{
			Id:      qdrant.NewIDUUID(pointID.String()),
			Vectors: qdrant.NewVectors(embedding...),
			Payload: payload,
		})
	}

	// Batch upsert
	_, err := r.client.Upsert(ctx, &qdrant.UpsertPoints{
		CollectionName: r.collection,
		Points:         points,
	})

	if err != nil {
		return fmt.Errorf("failed to batch upsert: %w", err)
	}

	log.Printf("[RAGEngine] Successfully indexed %d prompts", len(prompts))
	return nil
}

// reconstructPrompt reconstructs a Prompt object from a Qdrant point
func (r *RAGEngine) reconstructPrompt(point *qdrant.ScoredPoint) (*Prompt, error) {
	payload := point.GetPayload()

	// Helper function to extract string value
	getString := func(v *qdrant.Value) string {
		if v == nil {
			return ""
		}
		if str := v.GetStringValue(); str != "" {
			return str
		}
		return ""
	}

	// Helper function to extract list of strings
	getStringList := func(v *qdrant.Value) []string {
		if v == nil {
			return nil
		}

		var result []string
		if listVal := v.GetListValue(); listVal != nil {
			for _, item := range listVal.GetValues() {
				if str := item.GetStringValue(); str != "" {
					result = append(result, str)
				}
			}
		}
		return result
	}

	// Extract fields
	id := getString(payload["id"])
	content := getString(payload["content"])
	version := getString(payload["version"])
	outputFormat := getString(payload["output_format"])

	// Extract arrays
	variables := getStringList(payload["variables"])
	tags := getStringList(payload["tags"])

	// Extract metadata
	metadata := make(map[string]string)
	for key, value := range payload {
		if len(key) > 5 && key[:5] == "meta_" {
			if s := getString(value); s != "" {
				metadata[key[5:]] = s
			}
		}
	}

	return &Prompt{
		ID:           id,
		Content:      content,
		Variables:    variables,
		OutputFormat: outputFormat,
		Tags:         tags,
		Version:      version,
		Metadata:     metadata,
	}, nil
}

// reconstructPromptFromPoint reconstructs a Prompt from a RetrievedPoint (used by Scroll API)
func (r *RAGEngine) reconstructPromptFromPoint(point *qdrant.RetrievedPoint) (*Prompt, error) {
	payload := point.GetPayload()

	// Helper function to extract string value
	getString := func(v *qdrant.Value) string {
		if v == nil {
			return ""
		}
		if str := v.GetStringValue(); str != "" {
			return str
		}
		return ""
	}

	// Helper function to extract list of strings
	getStringList := func(v *qdrant.Value) []string {
		if v == nil {
			return nil
		}

		var result []string
		if listVal := v.GetListValue(); listVal != nil {
			for _, item := range listVal.GetValues() {
				if str := item.GetStringValue(); str != "" {
					result = append(result, str)
				}
			}
		}
		return result
	}

	// Extract fields
	id := getString(payload["id"])
	content := getString(payload["content"])
	version := getString(payload["version"])
	outputFormat := getString(payload["output_format"])

	// Extract arrays
	variables := getStringList(payload["variables"])
	tags := getStringList(payload["tags"])

	// Extract metadata
	metadata := make(map[string]string)
	for key, value := range payload {
		if len(key) > 5 && key[:5] == "meta_" {
			if s := getString(value); s != "" {
				metadata[key[5:]] = s
			}
		}
	}

	return &Prompt{
		ID:           id,
		Content:      content,
		Variables:    variables,
		OutputFormat: outputFormat,
		Tags:         tags,
		Version:      version,
		Metadata:     metadata,
	}, nil
}

// DeleteCollection deletes the entire collection
func (r *RAGEngine) DeleteCollection(ctx context.Context) error {
	err := r.client.DeleteCollection(ctx, r.collection)
	if err != nil {
		return fmt.Errorf("failed to delete collection: %w", err)
	}

	log.Printf("[RAGEngine] Deleted collection: %s", r.collection)
	return nil
}

// Close closes the RAG engine and its resources
func (r *RAGEngine) Close() error {
	if r.embedder != nil {
		if err := r.embedder.Close(); err != nil {
			log.Printf("[RAGEngine] Error closing embedder: %v", err)
		}
	}

	if r.client != nil {
		if err := r.client.Close(); err != nil {
			return fmt.Errorf("failed to close Qdrant client: %w", err)
		}
	}

	log.Printf("[RAGEngine] Closed")
	return nil
}
