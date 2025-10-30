// Package main demonstrates basic encryption and decryption using the Transit client.
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/jasoet/gopki/bao/transit"
)

func main() {
	// Get OpenBao configuration from environment
	address := os.Getenv("OPENBAO_ADDR")
	if address == "" {
		address = "http://localhost:8200"
	}

	token := os.Getenv("OPENBAO_TOKEN")
	if token == "" {
		log.Fatal("OPENBAO_TOKEN environment variable must be set")
	}

	// Initialize Transit client
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

	// Step 1: Create encryption key
	fmt.Println("Creating AES-256 encryption key...")
	keyName := "demo-key"
	keyClient, err := client.CreateAES256Key(ctx, keyName, nil)
	if err != nil {
		log.Fatalf("Failed to create key: %v", err)
	}
	fmt.Printf("✓ Key '%s' created\n\n", keyName)

	// Step 2: Encrypt data
	plaintext := "Hello, OpenBao Transit!"
	fmt.Printf("Plaintext: %s\n", plaintext)

	// Transit expects base64-encoded input
	encoded := base64.StdEncoding.EncodeToString([]byte(plaintext))

	encrypted, err := client.Encrypt(ctx, keyName, encoded, nil)
	if err != nil {
		log.Fatalf("Failed to encrypt: %v", err)
	}
	fmt.Printf("✓ Encrypted (version %d): %s\n\n", encrypted.KeyVersion, encrypted.Ciphertext)

	// Step 3: Decrypt data
	decrypted, err := client.Decrypt(ctx, keyName, encrypted.Ciphertext, nil)
	if err != nil {
		log.Fatalf("Failed to decrypt: %v", err)
	}

	// Decode base64 result
	decoded, err := base64.StdEncoding.DecodeString(decrypted.Plaintext)
	if err != nil {
		log.Fatalf("Failed to decode: %v", err)
	}
	fmt.Printf("✓ Decrypted: %s\n\n", string(decoded))

	// Step 4: Rotate key
	fmt.Println("Rotating key...")
	err = keyClient.Rotate(ctx)
	if err != nil {
		log.Fatalf("Failed to rotate key: %v", err)
	}

	keyInfo, _ := keyClient.GetInfo(ctx)
	fmt.Printf("✓ Key rotated to version %d\n\n", keyInfo.LatestVersion)

	// Step 5: Re-encrypt with new version
	fmt.Println("Re-encrypting with new key version...")
	reencrypted, err := client.ReEncrypt(ctx, keyName, encrypted.Ciphertext, nil)
	if err != nil {
		log.Fatalf("Failed to re-encrypt: %v", err)
	}
	fmt.Printf("✓ Re-encrypted (version %d): %s\n\n", reencrypted.KeyVersion, reencrypted.Ciphertext)

	// Step 6: Verify decryption still works
	decrypted2, err := client.Decrypt(ctx, keyName, reencrypted.Ciphertext, nil)
	if err != nil {
		log.Fatalf("Failed to decrypt re-encrypted data: %v", err)
	}

	decoded2, _ := base64.StdEncoding.DecodeString(decrypted2.Plaintext)
	fmt.Printf("✓ Decrypted re-encrypted data: %s\n\n", string(decoded2))

	// Step 7: Clean up
	fmt.Println("Cleaning up...")
	err = keyClient.Update(ctx, &transit.UpdateKeyOptions{
		DeletionAllowed: func() *bool { b := true; return &b }(),
	})
	if err != nil {
		log.Fatalf("Failed to enable deletion: %v", err)
	}

	err = keyClient.Delete(ctx)
	if err != nil {
		log.Fatalf("Failed to delete key: %v", err)
	}
	fmt.Printf("✓ Key '%s' deleted\n", keyName)

	fmt.Println("\n✓ Example completed successfully!")
}
