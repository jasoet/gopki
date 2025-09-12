package main

import (
	"fmt"
	"github.com/jasoet/gopki/keypair/algo"
	"log"
	"os"
)

func main() {
	fmt.Println("=== GoPKI Example Usage ===")

	// Generate RSA key pair
	fmt.Println("1. Generating RSA 2048-bit key pair...")
	rsaKeyPair, err := algo.GenerateRSAKeyPair(2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key pair:", err)
	}

	rsaPrivatePEM, _ := rsaKeyPair.PrivateKeyToPEM()
	rsaPublicPEM, _ := rsaKeyPair.PublicKeyToPEM()

	fmt.Printf("RSA Private Key (first 100 chars): %s...\n", string(rsaPrivatePEM)[:100])
	fmt.Printf("RSA Public Key (first 100 chars): %s...\n\n", string(rsaPublicPEM)[:100])

	// Save RSA keys to files
	os.WriteFile("rsa_private.pem", rsaPrivatePEM, 0600)
	os.WriteFile("rsa_public.pem", rsaPublicPEM, 0600)
	fmt.Println("RSA keys saved to rsa_private.pem and rsa_public.pem")

	// Generate ECDSA key pair with P256 curve
	fmt.Println("\n2. Generating ECDSA P-256 key pair...")
	ecdsaKeyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		log.Fatal("Failed to generate ECDSA key pair:", err)
	}

	ecdsaPrivatePEM, _ := ecdsaKeyPair.PrivateKeyToPEM()
	ecdsaPublicPEM, _ := ecdsaKeyPair.PublicKeyToPEM()

	fmt.Printf("ECDSA Private Key (first 100 chars): %s...\n", string(ecdsaPrivatePEM)[:100])
	fmt.Printf("ECDSA Public Key (first 100 chars): %s...\n\n", string(ecdsaPublicPEM)[:100])

	// Save ECDSA keys to files
	os.WriteFile("ecdsa_private.pem", ecdsaPrivatePEM, 0600)
	os.WriteFile("ecdsa_public.pem", ecdsaPublicPEM, 0600)
	fmt.Println("ECDSA keys saved to ecdsa_private.pem and ecdsa_public.pem")

	// Generate Ed25519 key pair
	fmt.Println("\n3. Generating Ed25519 key pair...")
	ed25519KeyPair, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		log.Fatal("Failed to generate Ed25519 key pair:", err)
	}

	ed25519PrivatePEM, _ := ed25519KeyPair.PrivateKeyToPEM()
	ed25519PublicPEM, _ := ed25519KeyPair.PublicKeyToPEM()

	fmt.Printf("Ed25519 Private Key (first 100 chars): %s...\n", string(ed25519PrivatePEM)[:100])
	fmt.Printf("Ed25519 Public Key (first 100 chars): %s...\n\n", string(ed25519PublicPEM)[:100])

	// Save Ed25519 keys to files
	os.WriteFile("ed25519_private.pem", ed25519PrivatePEM, 0600)
	os.WriteFile("ed25519_public.pem", ed25519PublicPEM, 0600)
	fmt.Println("Ed25519 keys saved to ed25519_private.pem and ed25519_public.pem")

	// Demonstrate loading keys from PEM
	fmt.Println("\n4. Loading RSA key from PEM...")
	loadedRSAPEM, err := os.ReadFile("rsa_private.pem")
	if err != nil {
		log.Fatal("Failed to load RSA private key:", err)
	}

	loadedRSAKeyPair, err := algo.RSAKeyPairFromPEM(loadedRSAPEM)
	if err != nil {
		log.Fatal("Failed to parse RSA key from PEM:", err)
	}

	fmt.Printf("Successfully loaded RSA key pair. Key size: %d bits\n", loadedRSAKeyPair.PrivateKey.Size()*8)

	fmt.Println("\n=== Example completed successfully ===")
}
