package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"cal-project/internal/brain/prompts"

	"github.com/joho/godotenv"
)

func main() {
	// Parse flags
	deleteFirst := flag.Bool("delete", false, "Delete existing collection before indexing")
	flag.Parse()

	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using system environment variables")
	}

	fmt.Println("=== Prompt Indexing Tool ===")
	fmt.Println("Indexing prompts into Qdrant vector database")

	ctx := context.Background()

	// Load configuration
	configPath := "assets/prompts/config.yaml"
	config, err := prompts.LoadConfigFromFile(configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Force enable RAG
	config.PromptSystem.RAG.Enabled = true

	// Get API key
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		log.Fatal("GEMINI_API_KEY environment variable not set")
	}

	// Create RAG engine
	fmt.Println("\n1. Initializing RAG engine...")
	rag, err := prompts.NewRAGEngine(ctx, apiKey, config.PromptSystem.RAG)
	if err != nil {
		log.Fatalf("Failed to create RAG engine: %v", err)
	}
	defer rag.Close()

	// Optionally delete existing collection
	if *deleteFirst {
		fmt.Println("\n2. Deleting existing collection...")
		if err := rag.DeleteCollection(ctx); err != nil {
			log.Printf("Warning: Failed to delete collection: %v", err)
		} else {
			fmt.Println("   Collection deleted successfully")
		}

		// Recreate the engine to recreate collection
		rag.Close()
		rag, err = prompts.NewRAGEngine(ctx, apiKey, config.PromptSystem.RAG)
		if err != nil {
			log.Fatalf("Failed to recreate RAG engine: %v", err)
		}
		defer rag.Close()
	}

	// Load all prompts
	fmt.Println("\n3. Loading all prompts...")
	loader := prompts.NewFileLoader(config.PromptSystem.BasePath)
	if err := loader.LoadMetadata(ctx); err != nil {
		log.Fatalf("Failed to load metadata: %v", err)
	}

	// Define all prompt IDs (manually for now)
	allPromptIDs := []string{
		// Commander
		"initial",
		"analyze",

		// Recon
		"decision",

		// Specialist
		"web_analysis",
		"xss_analysis",
		"sqli_analysis",
		"cmdi_analysis",
		"path_traversal",
		"file_upload",
		"crawler",
		"login_form",

		// Verification
		"extract",
		"platform_detect",
	}

	fmt.Printf("   Found %d prompts to index\n", len(allPromptIDs))

	// Load all prompts
	var promptsToIndex []*prompts.Prompt
	for _, promptID := range allPromptIDs {
		prompt, err := loader.Load(ctx, promptID)
		if err != nil {
			log.Printf("Warning: Failed to load prompt %s: %v", promptID, err)
			continue
		}
		promptsToIndex = append(promptsToIndex, prompt)
	}

	fmt.Printf("   Successfully loaded %d prompts\n", len(promptsToIndex))

	// Index all prompts
	fmt.Println("\n4. Indexing prompts into Qdrant...")
	if err := rag.IndexBatch(ctx, promptsToIndex); err != nil {
		log.Fatalf("Failed to index prompts: %v", err)
	}

	fmt.Printf("\n✅ Successfully indexed %d prompts!\n", len(promptsToIndex))
	fmt.Println("\nYou can now run cal-server with --enable-rag flag to use RAG mode.")
}
