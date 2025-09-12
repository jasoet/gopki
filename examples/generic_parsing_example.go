package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"log"

	"github.com/jasoet/gopki/pkg/keypair"
)

func main() {
	fmt.Println("=== GoPKI Generic Parsing Example ===\n")

	// Generate different types of key pairs
	rsaKeyPair, err := keypair.GenerateRSAKeyPair(2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key pair:", err)
	}

	ecdsaKeyPair, err := keypair.GenerateECDSAKeyPair(keypair.P256)
	if err != nil {
		log.Fatal("Failed to generate ECDSA key pair:", err)
	}

	ed25519KeyPair, err := keypair.GenerateEd25519KeyPair()
	if err != nil {
		log.Fatal("Failed to generate Ed25519 key pair:", err)
	}

	// Convert to PEM
	rsaPrivatePEM, _ := rsaKeyPair.PrivateKeyToPEM()
	rsaPublicPEM, _ := rsaKeyPair.PublicKeyToPEM()

	ecdsaPrivatePEM, _ := ecdsaKeyPair.PrivateKeyToPEM()
	ecdsaPublicPEM, _ := ecdsaKeyPair.PublicKeyToPEM()

	ed25519PrivatePEM, _ := ed25519KeyPair.PrivateKeyToPEM()
	ed25519PublicPEM, _ := ed25519KeyPair.PublicKeyToPEM()

	fmt.Println("1. Type-safe RSA Key Parsing:")
	demonstrateRSAParsing(rsaPrivatePEM, rsaPublicPEM)

	fmt.Println("\n2. Type-safe ECDSA Key Parsing:")
	demonstrateECDSAParsing(ecdsaPrivatePEM, ecdsaPublicPEM)

	fmt.Println("\n3. Type-safe Ed25519 Key Parsing:")
	demonstrateEd25519Parsing(ed25519PrivatePEM, ed25519PublicPEM)

	fmt.Println("\n4. Error Handling with Wrong Type:")
	demonstrateTypeErrors(rsaPrivatePEM)

	fmt.Println("\n=== Generic parsing example completed ===")
}

func demonstrateRSAParsing(privatePEM, publicPEM []byte) {
	// Parse with type safety - no type assertions needed!
	privateKey, err := keypair.ParsePrivateKeyFromPEM[*rsa.PrivateKey](privatePEM)
	if err != nil {
		log.Fatal("Failed to parse RSA private key:", err)
	}

	publicKey, err := keypair.ParsePublicKeyFromPEM[*rsa.PublicKey](publicPEM)
	if err != nil {
		log.Fatal("Failed to parse RSA public key:", err)
	}

	// Direct access to RSA-specific methods without type assertions
	fmt.Printf("   RSA Private Key Size: %d bits\n", privateKey.Size()*8)
	fmt.Printf("   RSA Public Key Exponent: %d\n", publicKey.E)
	fmt.Printf("   RSA Key Modulus Length: %d bits\n", publicKey.N.BitLen())
}

func demonstrateECDSAParsing(privatePEM, publicPEM []byte) {
	// Parse with type safety
	privateKey, err := keypair.ParsePrivateKeyFromPEM[*ecdsa.PrivateKey](privatePEM)
	if err != nil {
		log.Fatal("Failed to parse ECDSA private key:", err)
	}

	publicKey, err := keypair.ParsePublicKeyFromPEM[*ecdsa.PublicKey](publicPEM)
	if err != nil {
		log.Fatal("Failed to parse ECDSA public key:", err)
	}

	// Direct access to ECDSA-specific methods
	fmt.Printf("   ECDSA Curve: %s\n", privateKey.Curve.Params().Name)
	fmt.Printf("   ECDSA Key Size: %d bits\n", privateKey.Curve.Params().BitSize)
	fmt.Printf("   ECDSA Public Key X coordinate length: %d bits\n", publicKey.X.BitLen())
}

func demonstrateEd25519Parsing(privatePEM, publicPEM []byte) {
	// Parse with type safety
	privateKey, err := keypair.ParsePrivateKeyFromPEM[ed25519.PrivateKey](privatePEM)
	if err != nil {
		log.Fatal("Failed to parse Ed25519 private key:", err)
	}

	publicKey, err := keypair.ParsePublicKeyFromPEM[ed25519.PublicKey](publicPEM)
	if err != nil {
		log.Fatal("Failed to parse Ed25519 public key:", err)
	}

	// Direct access to Ed25519-specific methods
	fmt.Printf("   Ed25519 Private Key Length: %d bytes\n", len(privateKey))
	fmt.Printf("   Ed25519 Public Key Length: %d bytes\n", len(publicKey))
	
	// Demonstrate that we can use the key directly
	derivedPublic := privateKey.Public().(ed25519.PublicKey)
	fmt.Printf("   Keys match: %t\n", string(derivedPublic) == string(publicKey))
}

func demonstrateTypeErrors(rsaPrivatePEM []byte) {
	// This will fail with a clear error message
	_, err := keypair.ParsePrivateKeyFromPEM[*ecdsa.PrivateKey](rsaPrivatePEM)
	if err != nil {
		fmt.Printf("   Expected error when parsing RSA key as ECDSA: %v\n", err)
	}

	// This will also fail with a clear error message
	_, err = keypair.ParsePrivateKeyFromPEM[ed25519.PrivateKey](rsaPrivatePEM)
	if err != nil {
		fmt.Printf("   Expected error when parsing RSA key as Ed25519: %v\n", err)
	}

	// But parsing with correct type works perfectly
	rsaKey, err := keypair.ParsePrivateKeyFromPEM[*rsa.PrivateKey](rsaPrivatePEM)
	if err != nil {
		log.Fatal("Failed to parse RSA key:", err)
	}
	fmt.Printf("   Success: Type-safe parsing with correct type, key size: %d bits\n", rsaKey.Size()*8)
}