package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"log"
	"os"

	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

func main() {
	fmt.Println("=== GoPKI Example Usage (Unified Wrapper) ===")

	// Generate RSA key pair using new generic function
	fmt.Println("1. Generating RSA 2048-bit key pair...")
	rsaKeyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key pair:", err)
	}

	rsaPrivatePEM, _ := keypair.PrivateKeyToPEM(rsaKeyPair.PrivateKey)
	rsaPublicPEM, _ := keypair.PublicKeyToPEM(rsaKeyPair.PublicKey)

	fmt.Printf("RSA Private Key (first 100 chars): %s...\n", string(rsaPrivatePEM)[:100])
	fmt.Printf("RSA Public Key (first 100 chars): %s...\n\n", string(rsaPublicPEM)[:100])

	// Save RSA keys to files
	os.WriteFile("rsa_private.pem", rsaPrivatePEM, 0600)
	os.WriteFile("rsa_public.pem", rsaPublicPEM, 0600)
	fmt.Println("RSA keys saved to rsa_private.pem and rsa_public.pem")

	// Generate ECDSA key pair using new generic function
	fmt.Println("\n2. Generating ECDSA P-256 key pair...")
	ecdsaKeyPair, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
	if err != nil {
		log.Fatal("Failed to generate ECDSA key pair:", err)
	}

	ecdsaPrivatePEM, _ := keypair.PrivateKeyToPEM(ecdsaKeyPair.PrivateKey)
	ecdsaPublicPEM, _ := keypair.PublicKeyToPEM(ecdsaKeyPair.PublicKey)

	fmt.Printf("ECDSA Private Key (first 100 chars): %s...\n", string(ecdsaPrivatePEM)[:100])
	fmt.Printf("ECDSA Public Key (first 100 chars): %s...\n\n", string(ecdsaPublicPEM)[:100])

	// Save ECDSA keys to files
	os.WriteFile("ecdsa_private.pem", ecdsaPrivatePEM, 0600)
	os.WriteFile("ecdsa_public.pem", ecdsaPublicPEM, 0600)
	fmt.Println("ECDSA keys saved to ecdsa_private.pem and ecdsa_public.pem")

	// Generate Ed25519 key pair using new generic function
	fmt.Println("\n3. Generating Ed25519 key pair...")
	ed25519KeyPair, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
	if err != nil {
		log.Fatal("Failed to generate Ed25519 key pair:", err)
	}

	ed25519PrivatePEM, _ := keypair.PrivateKeyToPEM(ed25519KeyPair.PrivateKey)
	ed25519PublicPEM, _ := keypair.PublicKeyToPEM(ed25519KeyPair.PublicKey)

	fmt.Printf("Ed25519 Private Key (first 100 chars): %s...\n", string(ed25519PrivatePEM)[:100])
	fmt.Printf("Ed25519 Public Key (first 100 chars): %s...\n\n", string(ed25519PublicPEM)[:100])

	// Save Ed25519 keys to files
	os.WriteFile("ed25519_private.pem", ed25519PrivatePEM, 0600)
	os.WriteFile("ed25519_public.pem", ed25519PublicPEM, 0600)
	fmt.Println("Ed25519 keys saved to ed25519_private.pem and ed25519_public.pem")

	// Demonstrate loading keys from PEM with auto-detection
	fmt.Println("\n4. Loading RSA key from PEM with auto-detection...")
	loadedRSAPEM, err := os.ReadFile("rsa_private.pem")
	if err != nil {
		log.Fatal("Failed to load RSA private key:", err)
	}

	// Load using generics with type safety
	loadedRSAPrivateKey, err := keypair.ParsePrivateKeyFromPEM[*rsa.PrivateKey](loadedRSAPEM)
	if err != nil {
		log.Fatal("Failed to parse RSA key from PEM:", err)
	}

	fmt.Printf("Successfully loaded RSA key pair. Key size: %d bits\n", loadedRSAPrivateKey.Size()*8)

	// Demonstrate that we can load any algorithm without specifying it using new detection function
	fmt.Println("\n5. Demonstrating auto-detection for all algorithms...")

	testFiles := map[string]string{
		"RSA":     "rsa_private.pem",
		"ECDSA":   "ecdsa_private.pem", 
		"Ed25519": "ed25519_private.pem",
	}

	for expectedAlgo, filename := range testFiles {
		pemData, err := os.ReadFile(filename)
		if err != nil {
			log.Printf("Failed to load %s: %v", filename, err)
			continue
		}

		// Try to detect algorithm by attempting to parse with different types
		var detectedAlgorithm string
		if _, algorithm, err := keypair.PrivateKeyFromPEM[*rsa.PrivateKey](pemData); err == nil {
			detectedAlgorithm = algorithm
		} else if _, algorithm, err := keypair.PrivateKeyFromPEM[*ecdsa.PrivateKey](pemData); err == nil {
			detectedAlgorithm = algorithm
		} else if _, algorithm, err := keypair.PrivateKeyFromPEM[ed25519.PrivateKey](pemData); err == nil {
			detectedAlgorithm = algorithm
		} else {
			log.Printf("Failed to detect algorithm for %s", filename)
			continue
		}

		fmt.Printf("   %s: Auto-detected as %s ✓\n", filename, detectedAlgorithm)

		if detectedAlgorithm == expectedAlgo {
			fmt.Printf("   Algorithm detection correct! ✓\n")
		} else {
			fmt.Printf("   ❌ Expected %s but got %s\n", expectedAlgo, detectedAlgorithm)
		}
	}

	fmt.Println("\n=== Example completed successfully ===")
}