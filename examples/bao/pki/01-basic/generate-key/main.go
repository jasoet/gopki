//go:build example

// Package main demonstrates how to generate cryptographic keys in OpenBao.
//
// This example shows how to:
// - Generate RSA keys with different sizes
// - Generate ECDSA keys with different curves
// - Generate Ed25519 keys
// - Store keys internally vs export key material
// - List and retrieve keys
//
// Prerequisites:
// - OpenBao server running
//
// Usage:
//
//	go run main.go
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
	client, err := pki.NewClient(&pki.Config{
		Address: getEnv("BAO_ADDR", "http://127.0.0.1:8200"),
		Token:   getEnv("BAO_TOKEN", ""),
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Example 1: Generate RSA key (internal - key stays in OpenBao)
	fmt.Println("=== Example 1: RSA Key (Internal) ===")
	fmt.Println("Generating 2048-bit RSA key (stored in OpenBao)...")

	rsaKeyInternal, err := client.CreateRSAKey(ctx, &pki.GenerateKeyOptions{
		KeyName: "example-rsa-internal",
		KeyBits: 2048,
	})
	if err != nil {
		log.Fatalf("Failed to generate internal RSA key: %v", err)
	}

	fmt.Printf("✓ RSA key created: %s\n", rsaKeyInternal.KeyInfo().KeyID)
	fmt.Printf("  Key Name: %s\n", rsaKeyInternal.KeyInfo().KeyName)
	fmt.Printf("  Key Type: %s\n", rsaKeyInternal.KeyInfo().KeyType)
	fmt.Println("  Private key is securely stored in OpenBao")

	// Example 2: Generate RSA key (exported - returns key material)
	fmt.Println("\n=== Example 2: RSA Key (Exported) ===")
	fmt.Println("Generating 2048-bit RSA key (exported)...")

	rsaKeyExported, err := client.GenerateRSAKey(ctx, &pki.GenerateKeyOptions{
		KeyName: "example-rsa-exported",
		KeyBits: 2048,
	})
	if err != nil {
		log.Fatalf("Failed to generate exported RSA key: %v", err)
	}

	keyPair, err := rsaKeyExported.KeyPair()
	if err != nil {
		log.Fatalf("Failed to get key pair: %v", err)
	}

	fmt.Printf("✓ RSA key generated and exported: %s\n", rsaKeyExported.KeyInfo().KeyID)
	fmt.Printf("  Key available for local use: %v\n", keyPair != nil)

	// Example 3: Generate ECDSA key
	fmt.Println("\n=== Example 3: ECDSA Key (P-256) ===")
	fmt.Println("Generating ECDSA P-256 key...")

	ecdsaKey, err := client.CreateECDSAKey(ctx, &pki.GenerateKeyOptions{
		KeyName: "example-ecdsa-p256",
		KeyBits: 256, // P-256 curve
	})
	if err != nil {
		log.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	fmt.Printf("✓ ECDSA key created: %s\n", ecdsaKey.KeyInfo().KeyID)
	fmt.Printf("  Curve: P-256\n")

	// Example 4: Generate Ed25519 key
	fmt.Println("\n=== Example 4: Ed25519 Key ===")
	fmt.Println("Generating Ed25519 key...")

	ed25519Key, err := client.CreateEd25519Key(ctx, &pki.GenerateKeyOptions{
		KeyName: "example-ed25519",
	})
	if err != nil {
		log.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	fmt.Printf("✓ Ed25519 key created: %s\n", ed25519Key.KeyInfo().KeyID)
	fmt.Println("  Modern, fast, and secure signature algorithm")

	// List all keys
	fmt.Println("\n=== Listing All Keys ===")
	keys, err := client.ListKeys(ctx)
	if err != nil {
		log.Fatalf("Failed to list keys: %v", err)
	}

	fmt.Printf("Found %d key(s):\n", len(keys))
	for i, keyID := range keys {
		keyInfo, err := client.GetKey(ctx, keyID)
		if err != nil {
			log.Printf("  Warning: Could not get info for key %s: %v", keyID, err)
			continue
		}
		fmt.Printf("  %d. %s (ID: %s, Type: %s)\n", i+1, keyInfo.KeyName, keyInfo.KeyID, keyInfo.KeyType)
	}

	// Cleanup
	fmt.Println("\n=== Cleanup ===")
	fmt.Println("Deleting example keys...")

	_ = rsaKeyInternal.Delete(ctx)
	_ = rsaKeyExported.Delete(ctx)
	_ = ecdsaKey.Delete(ctx)
	_ = ed25519Key.Delete(ctx)

	fmt.Println("✓ Cleanup completed")

	fmt.Println("\n✓ Key generation examples completed!")

	fmt.Println("\nKey Types Summary:")
	fmt.Println("  • RSA 2048/4096: Traditional, widely supported")
	fmt.Println("  • ECDSA P-256/P-384: Modern, smaller keys")
	fmt.Println("  • Ed25519: Fast, secure, recommended for new systems")

	fmt.Println("\nStorage Options:")
	fmt.Println("  • Internal: Private key stays in OpenBao (more secure)")
	fmt.Println("  • Exported: Private key available for local use")

	fmt.Println("\nNext steps:")
	fmt.Println("  - Use keys for CA creation: examples/bao/01-basic/root-ca")
	fmt.Println("  - Import existing keys: examples/bao/03-key-management/import-key")
	fmt.Println("  - Issue certificates: examples/bao/02-certificates")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
