// Package main demonstrates batch encryption and decryption operations.
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jasoet/gopki/bao/transit"
)

func main() {
	address := os.Getenv("OPENBAO_ADDR")
	if address == "" {
		address = "http://localhost:8200"
	}

	token := os.Getenv("OPENBAO_TOKEN")
	if token == "" {
		log.Fatal("OPENBAO_TOKEN environment variable must be set")
	}

	client, err := transit.NewClient(&transit.Config{
		Address: address,
		Token:   token,
		Mount:   "transit",
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Create encryption key
	keyName := "batch-demo-key"
	fmt.Println("Creating encryption key...")
	_, err = client.CreateAES256Key(ctx, keyName, nil)
	if err != nil {
		log.Fatalf("Failed to create key: %v", err)
	}
	fmt.Printf("✓ Key '%s' created\n\n", keyName)

	// Prepare batch data
	messages := []string{
		"User 1 data",
		"User 2 data",
		"User 3 data",
		"User 4 data",
		"User 5 data",
	}

	fmt.Printf("Preparing %d messages for batch encryption...\n", len(messages))
	items := make([]transit.BatchEncryptItem, len(messages))
	for i, msg := range messages {
		items[i] = transit.BatchEncryptItem{
			Plaintext: base64.StdEncoding.EncodeToString([]byte(msg)),
		}
	}

	// Batch encrypt
	fmt.Println("\nBatch encrypting...")
	start := time.Now()
	encResult, err := client.EncryptBatch(ctx, keyName, items)
	if err != nil {
		log.Fatalf("Batch encryption failed: %v", err)
	}
	elapsed := time.Since(start)

	fmt.Printf("✓ Encrypted %d items in %v\n", len(encResult.Results), elapsed)
	for i, result := range encResult.Results {
		if encResult.Errors[i] != nil {
			fmt.Printf("  [%d] ERROR: %v\n", i, encResult.Errors[i])
		} else {
			fmt.Printf("  [%d] %s... (v%d)\n", i, result.Ciphertext[:30], result.KeyVersion)
		}
	}

	// Batch decrypt
	fmt.Println("\nBatch decrypting...")
	decItems := make([]transit.BatchDecryptItem, len(encResult.Results))
	for i, result := range encResult.Results {
		decItems[i] = transit.BatchDecryptItem{
			Ciphertext: result.Ciphertext,
		}
	}

	start = time.Now()
	decResult, err := client.DecryptBatch(ctx, keyName, decItems)
	if err != nil {
		log.Fatalf("Batch decryption failed: %v", err)
	}
	elapsed = time.Since(start)

	fmt.Printf("✓ Decrypted %d items in %v\n", len(decResult.Results), elapsed)
	for i, result := range decResult.Results {
		if decResult.Errors[i] != nil {
			fmt.Printf("  [%d] ERROR: %v\n", i, decResult.Errors[i])
		} else {
			decoded, _ := base64.StdEncoding.DecodeString(result.Plaintext)
			fmt.Printf("  [%d] %s\n", i, string(decoded))
		}
	}

	// Demonstrate large batch with auto-chunking
	fmt.Println("\n--- Large Batch with Auto-Chunking ---")
	largeCount := 300
	fmt.Printf("Preparing %d messages (will be auto-chunked)...\n", largeCount)

	largeItems := make([]transit.BatchEncryptItem, largeCount)
	for i := 0; i < largeCount; i++ {
		largeItems[i] = transit.BatchEncryptItem{
			Plaintext: base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("Message %d", i))),
		}
	}

	start = time.Now()
	largeResult, err := client.EncryptBatch(ctx, keyName, largeItems)
	if err != nil {
		log.Fatalf("Large batch encryption failed: %v", err)
	}
	elapsed = time.Since(start)

	successCount := 0
	for _, err := range largeResult.Errors {
		if err == nil {
			successCount++
		}
	}

	fmt.Printf("✓ Encrypted %d/%d items in %v\n", successCount, largeCount, elapsed)
	fmt.Printf("  Average: %.2f ms/item\n", float64(elapsed.Milliseconds())/float64(largeCount))

	// Clean up
	fmt.Println("\nCleaning up...")
	keyClient, _ := client.GetKey(ctx, keyName)
	keyClient.Update(ctx, &transit.UpdateKeyOptions{
		DeletionAllowed: func() *bool { b := true; return &b }(),
	})
	keyClient.Delete(ctx)
	fmt.Printf("✓ Key '%s' deleted\n", keyName)

	fmt.Println("\n✓ Batch operations example completed!")
}
