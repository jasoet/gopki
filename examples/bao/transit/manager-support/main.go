// Package main demonstrates using gopki Manager API with Transit
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"

	"github.com/jasoet/gopki/bao/transit"
	"github.com/jasoet/gopki/keypair"
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

	fmt.Println("=== Manager Support Examples ===")
	fmt.Println()

	// ============================================
	// Example 1: Generate with Manager, Import to Transit
	// ============================================
	fmt.Println("Example 1: Generate → Import → Sign")

	// Generate key using Manager API
	rsaManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		log.Fatal(err)
	}

	// Get key info from Manager
	info, _ := rsaManager.GetInfo()
	fmt.Printf("Generated: %s %d-bit key\n", info.Algorithm, info.KeySize)

	// Import from Manager (auto-detects type!)
	err = client.ImportFromManager(ctx, "managed-rsa-key", rsaManager, &transit.ImportKeyOptions{
		Exportable: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Use in Transit
	message := []byte("Important document")
	messageB64 := base64.StdEncoding.EncodeToString(message)
	signature, err := client.Sign(ctx, "managed-rsa-key", messageB64, &transit.SignOptions{
		HashAlgorithm: "sha2-256",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Signature: %s\n\n", signature.Signature[:50]+"...")

	// ============================================
	// Example 2: Export from Transit to Manager
	// ============================================
	fmt.Println("Example 2: Export → Manager → File")

	// Export key back to Manager
	exportedManager, err := client.ExportToRSAManager(ctx, "managed-rsa-key", 1)
	if err != nil {
		log.Fatal(err)
	}

	// Validate the exported key
	err = exportedManager.Validate()
	if err != nil {
		log.Printf("⚠️  Key validation failed: %v", err)
	} else {
		fmt.Println("✅ Key validation passed")
	}

	// Get metadata
	exportedInfo, _ := exportedManager.GetInfo()
	fmt.Printf("Exported: %s %d-bit key\n", exportedInfo.Algorithm, exportedInfo.KeySize)

	// Convert to PEM
	privatePEM, publicPEM, _ := exportedManager.ToPEM()
	fmt.Printf("Private PEM: %d bytes\n", len(privatePEM))
	fmt.Printf("Public PEM: %d bytes\n", len(publicPEM))

	// Save to files (commented out - would write to disk)
	// err = exportedManager.SaveToPEM("private.pem", "public.pem")

	// Compare original and exported
	if rsaManager.ComparePrivateKeys(exportedManager) {
		fmt.Println("✅ Round-trip successful - keys match!")
	} else {
		fmt.Println("⚠️  Keys don't match after round-trip")
	}
	fmt.Println()

	// ============================================
	// Example 3: ECDSA Manager Support
	// ============================================
	fmt.Println("Example 3: ECDSA Manager")

	// Generate ECDSA manager
	ecdsaManager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
	if err != nil {
		log.Fatal(err)
	}

	ecdsaInfo, _ := ecdsaManager.GetInfo()
	fmt.Printf("Generated: %s %s (%d-bit)\n", ecdsaInfo.Algorithm, ecdsaInfo.Curve, ecdsaInfo.KeySize)

	// Import via Manager
	err = client.ImportFromManager(ctx, "managed-ecdsa-key", ecdsaManager, &transit.ImportKeyOptions{
		Exportable: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Sign
	ecdsaSignature, err := client.Sign(ctx, "managed-ecdsa-key", messageB64, &transit.SignOptions{
		HashAlgorithm:      "sha2-256",
		SignatureAlgorithm: "ecdsa",
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("ECDSA Signature: %s\n\n", ecdsaSignature.Signature[:50]+"...")

	// Export back to Manager
	exportedECDSA, err := client.ExportToECDSAManager(ctx, "managed-ecdsa-key", 1)
	if err != nil {
		log.Fatal(err)
	}

	// Convert to SSH format
	privateSSH, publicSSH, _ := exportedECDSA.ToSSH("user@host", "")
	fmt.Printf("SSH Private: %d bytes\n", len(privateSSH))
	fmt.Printf("SSH Public: %d bytes\n\n", len(publicSSH))

	// ============================================
	// Example 4: Ed25519 Manager Support
	// ============================================
	fmt.Println("Example 4: Ed25519 Manager")

	// Generate Ed25519 manager
	ed25519Manager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey]("")
	if err != nil {
		log.Fatal(err)
	}

	ed25519Info, _ := ed25519Manager.GetInfo()
	fmt.Printf("Generated: %s %d-bit key\n", ed25519Info.Algorithm, ed25519Info.KeySize)

	// Import via Manager
	err = client.ImportFromManager(ctx, "managed-ed25519-key", ed25519Manager, &transit.ImportKeyOptions{
		Exportable: true,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Sign
	ed25519Signature, err := client.Sign(ctx, "managed-ed25519-key", messageB64, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Ed25519 Signature: %s\n\n", ed25519Signature.Signature[:50]+"...")

	// ============================================
	// Summary
	// ============================================
	fmt.Println("=== Summary ===")
	fmt.Println("✅ Manager API provides:")
	fmt.Println("  - Automatic type detection")
	fmt.Println("  - Format conversion (PEM/DER/SSH)")
	fmt.Println("  - Key validation and comparison")
	fmt.Println("  - Metadata extraction")
	fmt.Println("  - Secure file I/O")
	fmt.Println("\n✅ Transit integration is seamless!")
}
