//go:build example

// Package main demonstrates how to export cryptographic keys from OpenBao.
//
// This example shows how to:
// - Generate keys with export capability
// - Export RSA key material
// - Export ECDSA key material
// - Export Ed25519 key material
// - Use exported keys locally
//
// Key export is useful for:
// - Backup and disaster recovery
// - Migrating keys to other systems
// - Local cryptographic operations
// - Integration with external systems
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

	// Example 1: Export RSA key
	fmt.Println("=== Example 1: Export RSA Key ===")
	fmt.Println("Generating RSA key with export capability...")

	rsaKeyClient, err := client.GenerateRSAKey(ctx, &pki.GenerateKeyOptions{
		KeyName: "exportable-rsa-key",
		KeyBits: 2048,
	})
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}

	fmt.Printf("✓ RSA key generated: %s\n", rsaKeyClient.KeyInfo().KeyID)

	// Export the key pair
	rsaKeyPair, err := rsaKeyClient.KeyPair()
	if err != nil {
		log.Fatalf("Failed to export RSA key: %v", err)
	}

	fmt.Println("✓ RSA key exported successfully")
	fmt.Printf("  Key available for local use: %v\n", rsaKeyPair != nil)
	fmt.Printf("  Private key exported: %v\n", rsaKeyPair.PrivateKey != nil)
	fmt.Printf("  Public key exported: %v\n", rsaKeyPair.PublicKey != nil)

	// Example 2: Export ECDSA key
	fmt.Println("\n=== Example 2: Export ECDSA Key ===")
	fmt.Println("Generating ECDSA P-256 key with export capability...")

	ecdsaKeyClient, err := client.GenerateECDSAKey(ctx, &pki.GenerateKeyOptions{
		KeyName: "exportable-ecdsa-key",
		KeyBits: 256, // P-256
	})
	if err != nil {
		log.Fatalf("Failed to generate ECDSA key: %v", err)
	}

	fmt.Printf("✓ ECDSA key generated: %s\n", ecdsaKeyClient.KeyInfo().KeyID)

	// Export the key pair
	ecdsaKeyPair, err := ecdsaKeyClient.KeyPair()
	if err != nil {
		log.Fatalf("Failed to export ECDSA key: %v", err)
	}

	fmt.Println("✓ ECDSA key exported successfully")
	fmt.Printf("  Curve: P-256\n")
	fmt.Printf("  Key available for local use: %v\n", ecdsaKeyPair != nil)

	// Example 3: Export Ed25519 key
	fmt.Println("\n=== Example 3: Export Ed25519 Key ===")
	fmt.Println("Generating Ed25519 key with export capability...")

	ed25519KeyClient, err := client.GenerateEd25519Key(ctx, &pki.GenerateKeyOptions{
		KeyName: "exportable-ed25519-key",
	})
	if err != nil {
		log.Fatalf("Failed to generate Ed25519 key: %v", err)
	}

	fmt.Printf("✓ Ed25519 key generated: %s\n", ed25519KeyClient.KeyInfo().KeyID)

	// Export the key pair
	ed25519KeyPair, err := ed25519KeyClient.KeyPair()
	if err != nil {
		log.Fatalf("Failed to export Ed25519 key: %v", err)
	}

	fmt.Println("✓ Ed25519 key exported successfully")
	fmt.Printf("  Key available for local use: %v\n", ed25519KeyPair != nil)

	// Example 4: Use exported key locally
	fmt.Println("\n=== Example 4: Using Exported Key Locally ===")
	fmt.Println("Using exported RSA key for local signing...")

	// The key pair is now available for local cryptographic operations
	// For example: signing, encryption, etc.
	fmt.Println("✓ Exported key can be used for:")
	fmt.Println("  • Local signing operations")
	fmt.Println("  • Encryption/Decryption")
	fmt.Println("  • Integration with other libraries")
	fmt.Println("  • Backup and disaster recovery")

	// Cleanup
	fmt.Println("\n=== Cleanup ===")
	_ = rsaKeyClient.Delete(ctx)
	_ = ecdsaKeyClient.Delete(ctx)
	_ = ed25519KeyClient.Delete(ctx)

	fmt.Println("✓ Key export examples completed!")

	fmt.Println("\nExport vs Internal Keys:")
	fmt.Println("  Exported Keys:")
	fmt.Println("    ✓ Private key material available locally")
	fmt.Println("    ✓ Can be used without OpenBao")
	fmt.Println("    ✓ Useful for backup and migration")
	fmt.Println("    ⚠ Higher security risk (key leaves OpenBao)")

	fmt.Println("\n  Internal Keys:")
	fmt.Println("    ✓ Private key never leaves OpenBao")
	fmt.Println("    ✓ Higher security")
	fmt.Println("    ✓ Better for production CAs")
	fmt.Println("    ⚠ Requires OpenBao for all operations")

	fmt.Println("\nSecurity Best Practices:")
	fmt.Println("  ⚠ Only export keys when necessary")
	fmt.Println("  ⚠ Use secure channels for key transmission")
	fmt.Println("  ⚠ Encrypt exported keys at rest")
	fmt.Println("  ⚠ Audit all key export operations")
	fmt.Println("  ⚠ Consider using internal keys for sensitive operations")
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
