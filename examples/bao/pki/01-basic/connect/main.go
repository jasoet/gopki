//go:build example

// Package main demonstrates how to connect to an OpenBao server.
//
// This example shows how to:
// - Create a client connection to OpenBao
// - Verify connectivity
// - Check server health
// - List available mounts
//
// Prerequisites:
// - OpenBao server running
// - Valid authentication token
//
// Usage:
//
//	BAO_ADDR=http://localhost:8200 BAO_TOKEN=your-token go run main.go
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jasoet/gopki/bao/pki"
)

func main() {
	// Get connection details from environment variables
	address := getEnv("BAO_ADDR", "http://127.0.0.1:8200")
	token := getEnv("BAO_TOKEN", "")
	mount := getEnv("BAO_MOUNT", "pki")

	if token == "" {
		log.Fatal("BAO_TOKEN environment variable must be set")
	}

	// Create client connection
	fmt.Printf("Connecting to OpenBao at %s...\n", address)
	client, err := pki.NewClient(&pki.Config{
		Address: address,
		Token:   token,
		Mount:   mount,
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	fmt.Println("✓ Client created successfully")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Check server health
	fmt.Println("\nChecking server health...")
	err = client.Health(ctx)
	if err != nil {
		log.Fatalf("Failed to check health: %v", err)
	}

	fmt.Println("✓ Server is healthy")

	// List keys to verify PKI mount access
	fmt.Println("\nVerifying PKI mount access...")
	keys, err := client.ListKeys(ctx)
	if err != nil {
		log.Printf("Warning: Could not list keys: %v", err)
		log.Println("Make sure the PKI secrets engine is enabled at the specified mount point")
	} else {
		fmt.Printf("✓ PKI mount accessible (found %d keys)\n", len(keys))
	}

	// Connection successful
	fmt.Println("\n✓ Connection test successful!")
	fmt.Println("\nNext steps:")
	fmt.Println("  - Generate a root CA: see examples/bao/01-basic/root-ca")
	fmt.Println("  - Generate keys: see examples/bao/01-basic/generate-key")
	fmt.Println("  - Issue certificates: see examples/bao/02-certificates")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
