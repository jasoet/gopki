// Package main demonstrates digital signature operations.
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

	// Demonstrate RSA signing
	fmt.Println("=== RSA-2048 Signing ===")
	rsaKeyName := "rsa-sign-key"
	_, err = client.CreateRSA2048Key(ctx, rsaKeyName, nil)
	if err != nil {
		log.Fatalf("Failed to create RSA key: %v", err)
	}
	fmt.Printf("✓ Created RSA-2048 key '%s'\n", rsaKeyName)

	document := "Important contract document"
	data := base64.StdEncoding.EncodeToString([]byte(document))

	// Sign with RSA-PSS
	rsaSig, err := client.Sign(ctx, rsaKeyName, data, &transit.SignOptions{
		HashAlgorithm:      transit.HashSHA2_256,
		SignatureAlgorithm: transit.SignatureAlgPSS,
	})
	if err != nil {
		log.Fatalf("Failed to sign with RSA: %v", err)
	}
	fmt.Printf("✓ Signed with RSA-PSS (version %d)\n", rsaSig.KeyVersion)
	fmt.Printf("  Signature: %s...\n", rsaSig.Signature[:40])

	// Verify RSA signature
	rsaVerified, err := client.Verify(ctx, rsaKeyName, data, rsaSig.Signature, &transit.VerifyOptions{
		HashAlgorithm:      transit.HashSHA2_256,
		SignatureAlgorithm: transit.SignatureAlgPSS,
	})
	if err != nil {
		log.Fatalf("Failed to verify RSA signature: %v", err)
	}
	fmt.Printf("✓ RSA signature valid: %v\n\n", rsaVerified.Valid)

	// Demonstrate ECDSA signing
	fmt.Println("=== ECDSA P-256 Signing ===")
	ecdsaKeyName := "ecdsa-sign-key"
	_, err = client.CreateECDSAP256Key(ctx, ecdsaKeyName, nil)
	if err != nil {
		log.Fatalf("Failed to create ECDSA key: %v", err)
	}
	fmt.Printf("✓ Created ECDSA P-256 key '%s'\n", ecdsaKeyName)

	// Sign with ECDSA
	ecdsaSig, err := client.Sign(ctx, ecdsaKeyName, data, &transit.SignOptions{
		HashAlgorithm:       transit.HashSHA2_256,
		MarshalingAlgorithm: transit.MarshalingASN1,
	})
	if err != nil {
		log.Fatalf("Failed to sign with ECDSA: %v", err)
	}
	fmt.Printf("✓ Signed with ECDSA-P256 (version %d)\n", ecdsaSig.KeyVersion)
	fmt.Printf("  Signature: %s...\n", ecdsaSig.Signature[:40])

	// Verify ECDSA signature
	ecdsaVerified, err := client.Verify(ctx, ecdsaKeyName, data, ecdsaSig.Signature, &transit.VerifyOptions{
		HashAlgorithm:       transit.HashSHA2_256,
		MarshalingAlgorithm: transit.MarshalingASN1,
	})
	if err != nil {
		log.Fatalf("Failed to verify ECDSA signature: %v", err)
	}
	fmt.Printf("✓ ECDSA signature valid: %v\n\n", ecdsaVerified.Valid)

	// Demonstrate Ed25519 signing
	fmt.Println("=== Ed25519 Signing ===")
	ed25519KeyName := "ed25519-sign-key"
	_, err = client.CreateEd25519Key(ctx, ed25519KeyName, nil)
	if err != nil {
		log.Fatalf("Failed to create Ed25519 key: %v", err)
	}
	fmt.Printf("✓ Created Ed25519 key '%s'\n", ed25519KeyName)

	// Sign with Ed25519
	edSig, err := client.Sign(ctx, ed25519KeyName, data, nil)
	if err != nil {
		log.Fatalf("Failed to sign with Ed25519: %v", err)
	}
	fmt.Printf("✓ Signed with Ed25519 (version %d)\n", edSig.KeyVersion)
	fmt.Printf("  Signature: %s...\n", edSig.Signature[:40])

	// Verify Ed25519 signature
	edVerified, err := client.Verify(ctx, ed25519KeyName, data, edSig.Signature, nil)
	if err != nil {
		log.Fatalf("Failed to verify Ed25519 signature: %v", err)
	}
	fmt.Printf("✓ Ed25519 signature valid: %v\n\n", edVerified.Valid)

	// Demonstrate tampering detection
	fmt.Println("=== Tampering Detection ===")
	tamperedData := base64.StdEncoding.EncodeToString([]byte("Modified contract document"))

	tamperedVerify, err := client.Verify(ctx, rsaKeyName, tamperedData, rsaSig.Signature, &transit.VerifyOptions{
		HashAlgorithm:      transit.HashSHA2_256,
		SignatureAlgorithm: transit.SignatureAlgPSS,
	})
	if err != nil {
		log.Fatalf("Failed to verify tampered data: %v", err)
	}
	fmt.Printf("✓ Tampered data signature valid: %v (expected false)\n\n", tamperedVerify.Valid)

	// Demonstrate HMAC
	fmt.Println("=== HMAC Authentication ===")
	hmacKeyName := "hmac-key"
	_, err = client.CreateAES256Key(ctx, hmacKeyName, nil)
	if err != nil {
		log.Fatalf("Failed to create HMAC key: %v", err)
	}
	fmt.Printf("✓ Created HMAC key '%s'\n", hmacKeyName)

	message := base64.StdEncoding.EncodeToString([]byte("Message to authenticate"))

	// Generate HMAC
	hmac, err := client.HMAC(ctx, hmacKeyName, message, &transit.HMACOptions{
		Algorithm: transit.HashSHA2_256,
	})
	if err != nil {
		log.Fatalf("Failed to generate HMAC: %v", err)
	}
	fmt.Printf("✓ Generated HMAC: %s...\n", hmac.HMAC[:40])

	// Verify HMAC
	hmacVerified, err := client.VerifyHMAC(ctx, hmacKeyName, message, hmac.HMAC, &transit.HMACOptions{
		Algorithm: transit.HashSHA2_256,
	})
	if err != nil {
		log.Fatalf("Failed to verify HMAC: %v", err)
	}
	fmt.Printf("✓ HMAC valid: %v\n\n", hmacVerified.Valid)

	// Clean up
	fmt.Println("Cleaning up...")
	for _, name := range []string{rsaKeyName, ecdsaKeyName, ed25519KeyName, hmacKeyName} {
		client.UpdateKeyConfig(ctx, name, &transit.UpdateKeyOptions{
			DeletionAllowed: func() *bool { b := true; return &b }(),
		})
		client.DeleteKey(ctx, name)
	}
	fmt.Println("✓ All keys deleted")

	fmt.Println("\n✓ Signing example completed!")
}
