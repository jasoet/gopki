// Package main demonstrates how to import gopki keypairs directly into OpenBao Transit
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/jasoet/gopki/bao/transit"
	"github.com/jasoet/gopki/keypair/algo"
)

func main() {
	// Initialize Transit client
	client, err := transit.NewClient(&transit.Config{
		Address: "https://openbao.example.com",
		Token:   "your-token",
		Mount:   "transit",
	})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	ctx := context.Background()

	// ============================================
	// Example 1: Import RSA Key from gopki
	// ============================================
	fmt.Println("=== Example 1: Import RSA Key ===")

	// Generate RSA keypair using gopki
	rsaKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Fatal(err)
	}

	// Import directly into Transit - NO manual conversion needed!
	err = client.ImportRSAKeyPair(ctx, "my-rsa-signing-key", rsaKeyPair, &transit.ImportKeyOptions{
		Exportable: true, // Allow export/backup
	})
	if err != nil {
		log.Fatal(err)
	}

	// Use the imported key for signing
	message := []byte("Hello, World!")
	signature, err := client.Sign(ctx, "my-rsa-signing-key", message, &transit.SignOptions{
		HashAlgorithm: "sha2-256",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("RSA Signature: %s\n", signature.Signature[:50]+"...")

	// Verify signature
	verified, err := client.VerifySignature(ctx, "my-rsa-signing-key", message, signature.Signature, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Signature verified: %v\n\n", verified.Valid)

	// ============================================
	// Example 2: Import ECDSA Key from gopki
	// ============================================
	fmt.Println("=== Example 2: Import ECDSA Key ===")

	// Generate ECDSA keypair using gopki
	ecdsaKeyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		log.Fatal(err)
	}

	// Import directly - curve type auto-detected!
	err = client.ImportECDSAKeyPair(ctx, "my-ecdsa-signing-key", ecdsaKeyPair, &transit.ImportKeyOptions{
		Exportable: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Use for signing
	ecdsaSignature, err := client.Sign(ctx, "my-ecdsa-signing-key", message, &transit.SignOptions{
		HashAlgorithm:  "sha2-256",
		SignatureAlgorithm: "ecdsa",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("ECDSA Signature: %s\n", ecdsaSignature.Signature[:50]+"...")

	// ============================================
	// Example 3: Import Ed25519 Key from gopki
	// ============================================
	fmt.Println("\n=== Example 3: Import Ed25519 Key ===")

	// Generate Ed25519 keypair using gopki
	ed25519KeyPair, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		log.Fatal(err)
	}

	// Import directly - type auto-detected!
	err = client.ImportEd25519KeyPair(ctx, "my-ed25519-signing-key", ed25519KeyPair, &transit.ImportKeyOptions{
		Exportable: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Use for signing
	ed25519Signature, err := client.Sign(ctx, "my-ed25519-signing-key", message, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Ed25519 Signature: %s\n", ed25519Signature.Signature[:50]+"...")

	// ============================================
	// Example 4: Import AES Encryption Key
	// ============================================
	fmt.Println("\n=== Example 4: Import AES Key ===")

	// Generate AES key (can use any method)
	aesKey := make([]byte, 32) // AES-256
	// In production, use: rand.Read(aesKey)

	// Import directly - size auto-detected (AES-256)
	err = client.ImportAESKey(ctx, "my-aes-key", aesKey, &transit.ImportKeyOptions{
		Exportable: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Use for encryption
	plaintext := base64.StdEncoding.EncodeToString([]byte("Secret data"))
	encrypted, err := client.Encrypt(ctx, "my-aes-key", plaintext, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Encrypted: %s\n", encrypted.Ciphertext[:50]+"...")

	// ============================================
	// Comparison: Before vs After
	// ============================================
	fmt.Println("\n=== Before vs After Comparison ===")

	fmt.Println("\nBEFORE (Manual conversion):")
	fmt.Println(`
  rsaKeyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

  // Manual conversion required!
  keyBytes, err := x509.MarshalPKCS8PrivateKey(rsaKeyPair.PrivateKey)
  if err != nil {
      log.Fatal(err)
  }
  defer secureZero(keyBytes)

  err = client.ImportKey(ctx, "my-key", keyBytes, &transit.ImportKeyOptions{
      Type:         transit.KeyTypeRSA2048, // Manual type specification
      HashFunction: "SHA256",
      Exportable:   true,
  })
`)

	fmt.Println("AFTER (With gopki integration):")
	fmt.Println(`
  rsaKeyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)

  // Direct import - no conversion needed!
  err = client.ImportRSAKeyPair(ctx, "my-key", rsaKeyPair, &transit.ImportKeyOptions{
      Exportable: true, // Type auto-detected from key!
  })
`)

	fmt.Println("\n✅ All examples completed successfully!")
}
