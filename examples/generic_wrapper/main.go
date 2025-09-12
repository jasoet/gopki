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
	fmt.Println("=== GoPKI Generic Wrapper Example ===")

	// Example 1: Using new generic generation functions
	fmt.Println("\n1. Using Generic KeyPair Generation:")
	demonstrateGenericGeneration()

	// Example 2: Using explicit generics (full type control)
	fmt.Println("\n2. Using Explicit Generics (Advanced Type Control):")
	demonstrateExplicitGenerics()

	// Example 3: Generic PEM conversion and parsing
	fmt.Println("\n3. Generic PEM Operations:")
	demonstrateGenericPEMOperations()

	// Example 4: Algorithm detection and parsing
	fmt.Println("\n4. Algorithm Detection from PEM:")
	demonstrateAlgorithmDetection()

	// Example 5: File operations with generics
	fmt.Println("\n5. File Operations with Type Safety:")
	demonstrateFileOperations()

	fmt.Println("\n=== Generic wrapper example completed successfully ===")
}

func demonstrateGenericGeneration() {
	// These show the new generic GenerateKeyPair function

	// RSA key pair using generics
	rsaKeyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key pair:", err)
	}

	// You can immediately access RSA-specific methods
	fmt.Printf("   RSA key size: %d bits (no type assertion needed!)\n", rsaKeyPair.PrivateKey.Size()*8)
	fmt.Printf("   RSA public key exponent: %d\n", rsaKeyPair.PublicKey.E)

	// ECDSA key pair using generics
	ecdsaKeyPair, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
	if err != nil {
		log.Fatal("Failed to generate ECDSA key pair:", err)
	}

	// Direct access to ECDSA-specific methods
	fmt.Printf("   ECDSA curve: %s\n", ecdsaKeyPair.PrivateKey.Curve.Params().Name)
	fmt.Printf("   ECDSA public key X coordinate bit length: %d\n", ecdsaKeyPair.PublicKey.X.BitLen())

	// Ed25519 key pair using generics
	ed25519KeyPair, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
	if err != nil {
		log.Fatal("Failed to generate Ed25519 key pair:", err)
	}

	// Direct access to Ed25519 methods
	fmt.Printf("   Ed25519 private key length: %d bytes\n", len(ed25519KeyPair.PrivateKey))
	fmt.Printf("   Ed25519 public key length: %d bytes\n", len(ed25519KeyPair.PublicKey))
}

func demonstrateExplicitGenerics() {
	fmt.Println("   Using explicit generic type parameters:")

	// These show the basic usage of the new generic function
	rsaKeyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key:", err)
	}
	fmt.Printf("   ✓ RSA key pair generated: *algo.RSAKeyPair\n")

	ecdsaKeyPair, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P384)
	if err != nil {
		log.Fatal("Failed to generate ECDSA key:", err)
	}
	fmt.Printf("   ✓ ECDSA key pair generated: *algo.ECDSAKeyPair\n")

	ed25519KeyPair, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
	if err != nil {
		log.Fatal("Failed to generate Ed25519 key:", err)
	}
	fmt.Printf("   ✓ Ed25519 key pair generated: *algo.Ed25519KeyPair\n")

	// The power of generics - same function works for all types!
	showKeyInfo(rsaKeyPair.PrivateKey)
	showKeyInfo(ecdsaKeyPair.PrivateKey)
	showKeyInfo(ed25519KeyPair.PrivateKey)
}

func demonstrateGenericPEMOperations() {
	// Generate keys using new API
	rsaKeyPair, _ := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	ecdsaKeyPair, _ := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
	ed25519KeyPair, _ := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")

	// Convert to PEM using generics - same function for all types!
	rsaPEM, err := keypair.PrivateKeyToPEM(rsaKeyPair.PrivateKey)
	if err != nil {
		log.Fatal("Failed to convert RSA key to PEM:", err)
	}

	ecdsaPEM, err := keypair.PrivateKeyToPEM(ecdsaKeyPair.PrivateKey)
	if err != nil {
		log.Fatal("Failed to convert ECDSA key to PEM:", err)
	}

	ed25519PEM, err := keypair.PrivateKeyToPEM(ed25519KeyPair.PrivateKey)
	if err != nil {
		log.Fatal("Failed to convert Ed25519 key to PEM:", err)
	}

	fmt.Printf("   ✓ All keys converted to PEM using generic PrivateKeyToPEM[T]()\n")

	// Parse back with type safety
	parsedRSA, err := keypair.ParsePrivateKeyFromPEM[*rsa.PrivateKey](rsaPEM)
	if err != nil {
		log.Fatal("Failed to parse RSA PEM:", err)
	}

	parsedECDSA, err := keypair.ParsePrivateKeyFromPEM[*ecdsa.PrivateKey](ecdsaPEM)
	if err != nil {
		log.Fatal("Failed to parse ECDSA PEM:", err)
	}

	parsedEd25519, err := keypair.ParsePrivateKeyFromPEM[ed25519.PrivateKey](ed25519PEM)
	if err != nil {
		log.Fatal("Failed to parse Ed25519 PEM:", err)
	}

	// Verify keys match
	if parsedRSA.Size() == rsaKeyPair.PrivateKey.Size() {
		fmt.Printf("   ✓ RSA key round-trip successful\n")
	}
	if parsedECDSA.Curve.Params().Name == ecdsaKeyPair.PrivateKey.Curve.Params().Name {
		fmt.Printf("   ✓ ECDSA key round-trip successful\n")
	}
	if len(parsedEd25519) == len(ed25519KeyPair.PrivateKey) {
		fmt.Printf("   ✓ Ed25519 key round-trip successful\n")
	}

	// Demonstrate generic public key conversion
	rsaPublicPEM, err := keypair.PublicKeyToPEM(rsaKeyPair.PublicKey)
	if err != nil {
		log.Fatal("Failed to convert RSA public key to PEM:", err)
	}
	fmt.Printf("   ✓ Generic PublicKeyToPEM works! RSA public: %d bytes\n", len(rsaPublicPEM))
}

func demonstrateAlgorithmDetection() {
	// Generate keys of different types
	keys := generateSampleKeys()

	for name, keyPair := range keys {
		// Convert to PEM
		var pemData []byte
		var err error

		switch kp := keyPair.(type) {
		case *algo.RSAKeyPair:
			pemData, err = keypair.PrivateKeyToPEM(kp.PrivateKey)
		case *algo.ECDSAKeyPair:
			pemData, err = keypair.PrivateKeyToPEM(kp.PrivateKey)
		case *algo.Ed25519KeyPair:
			pemData, err = keypair.PrivateKeyToPEM(kp.PrivateKey)
		}

		if err != nil {
			log.Printf("Failed to convert %s key to PEM: %v", name, err)
			continue
		}

		// Try to detect algorithm by attempting different parsers
		var algorithm string
		if _, algo, err := keypair.PrivateKeyFromPEM[*rsa.PrivateKey](pemData); err == nil {
			algorithm = algo
		} else if _, algo, err := keypair.PrivateKeyFromPEM[*ecdsa.PrivateKey](pemData); err == nil {
			algorithm = algo
		} else if _, algo, err := keypair.PrivateKeyFromPEM[ed25519.PrivateKey](pemData); err == nil {
			algorithm = algo
		} else {
			log.Printf("Failed to detect algorithm for %s: %v", name, err)
			continue
		}

		fmt.Printf("   %s key detected as: %s ✓\n", name, algorithm)

		// Parse without knowing the type using the detection function
		var parsedKey interface{}
		var detectedAlgo string
		if parsedKey, detectedAlgo, err = keypair.PrivateKeyFromPEM[*rsa.PrivateKey](pemData); err == nil {
		} else if parsedKey, detectedAlgo, err = keypair.PrivateKeyFromPEM[*ecdsa.PrivateKey](pemData); err == nil {
		} else if parsedKey, detectedAlgo, err = keypair.PrivateKeyFromPEM[ed25519.PrivateKey](pemData); err == nil {
		} else {
			log.Printf("Failed to parse %s key: %v", name, err)
			continue
		}

		fmt.Printf("   %s key parsed as: %s, type: %T ✓\n", name, detectedAlgo, parsedKey)
	}
}

func demonstrateFileOperations() {
	// Generate a key pair
	rsaKeyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key:", err)
	}

	// Save using generic function
	privateFile := "demo_private.pem"
	publicFile := "demo_public.pem"

	err = keypair.KeyPairToFiles(rsaKeyPair, privateFile, publicFile)
	if err != nil {
		log.Fatal("Failed to save key pair:", err)
	}

	fmt.Printf("   ✓ Key pair saved to %s and %s\n", privateFile, publicFile)

	// Load and verify
	pemData, err := os.ReadFile(privateFile)
	if err != nil {
		log.Fatal("Failed to read private key file:", err)
	}

	// Parse with type safety
	loadedKey, err := keypair.ParsePrivateKeyFromPEM[*rsa.PrivateKey](pemData)
	if err != nil {
		log.Fatal("Failed to parse loaded key:", err)
	}

	if loadedKey.Size() == rsaKeyPair.PrivateKey.Size() {
		fmt.Printf("   ✓ Loaded key matches original (both %d-bit RSA)\n", loadedKey.Size()*8)
	}

	// Clean up
	os.Remove(privateFile)
	os.Remove(publicFile)
}

// Helper functions

func showKeyInfo(key interface{}) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		fmt.Printf("   RSA key info: %d-bit modulus\n", k.N.BitLen())
	case *ecdsa.PrivateKey:
		fmt.Printf("   ECDSA key info: %s curve\n", k.Curve.Params().Name)
	case ed25519.PrivateKey:
		fmt.Printf("   Ed25519 key info: %d-byte private key\n", len(k))
	}
}

func generateSampleKeys() map[string]interface{} {
	keys := make(map[string]interface{})

	if rsaKeyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048); err == nil {
		keys["RSA"] = rsaKeyPair
	}

	if ecdsaKeyPair, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256); err == nil {
		keys["ECDSA"] = ecdsaKeyPair
	}

	if ed25519KeyPair, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair](""); err == nil {
		keys["Ed25519"] = ed25519KeyPair
	}

	return keys
}