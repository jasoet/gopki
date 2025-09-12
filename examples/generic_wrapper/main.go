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

	// Example 1: Using convenience functions (returns specific types)
	fmt.Println("\n1. Using Convenience Functions (Type-Safe):")
	demonstrateConvenienceFunctions()

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

func demonstrateConvenienceFunctions() {
	// These return specific types directly - no type assertions needed!
	
	// RSA key pair - returns *rsa.PrivateKey
	rsaPrivateKey, err := keypair.NewRSAKeyPair(2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key pair:", err)
	}
	
	// You can immediately access RSA-specific methods
	fmt.Printf("   RSA key size: %d bits (no type assertion needed!)\n", rsaPrivateKey.Size()*8)
	rsaPublicKey := keypair.RSAPublicKeyFromPrivate(rsaPrivateKey)
	fmt.Printf("   RSA public key exponent: %d\n", rsaPublicKey.E)

	// ECDSA key pair - returns *ecdsa.PrivateKey
	ecdsaPrivateKey, err := keypair.NewECDSAKeyPair(algo.P256)
	if err != nil {
		log.Fatal("Failed to generate ECDSA key pair:", err)
	}
	
	// Direct access to ECDSA-specific methods
	fmt.Printf("   ECDSA curve: %s\n", ecdsaPrivateKey.Curve.Params().Name)
	ecdsaPublicKey := keypair.ECDSAPublicKeyFromPrivate(ecdsaPrivateKey)
	fmt.Printf("   ECDSA public key X coordinate bit length: %d\n", ecdsaPublicKey.X.BitLen())

	// Ed25519 key pair - returns ed25519.PrivateKey
	ed25519PrivateKey, err := keypair.NewEd25519KeyPair()
	if err != nil {
		log.Fatal("Failed to generate Ed25519 key pair:", err)
	}
	
	// Direct access to Ed25519 methods
	fmt.Printf("   Ed25519 private key length: %d bytes\n", len(ed25519PrivateKey))
	ed25519PublicKey := keypair.Ed25519PublicKeyFromPrivate(ed25519PrivateKey)
	fmt.Printf("   Ed25519 public key length: %d bytes\n", len(ed25519PublicKey))
}

func demonstrateExplicitGenerics() {
	fmt.Println("   Using explicit generic type parameters:")
	
	// These show the explicit generic syntax for advanced users
	rsaKey, err := keypair.GenerateRSAKeyPair[*rsa.PrivateKey](2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key:", err)
	}
	fmt.Printf("   ✓ RSA key generated with explicit generic: *rsa.PrivateKey\n")
	
	ecdsaKey, err := keypair.GenerateECDSAKeyPair[*ecdsa.PrivateKey](algo.P384)
	if err != nil {
		log.Fatal("Failed to generate ECDSA key:", err)
	}
	fmt.Printf("   ✓ ECDSA key generated with explicit generic: *ecdsa.PrivateKey\n")
	
	ed25519Key, err := keypair.GenerateEd25519KeyPair[ed25519.PrivateKey]()
	if err != nil {
		log.Fatal("Failed to generate Ed25519 key:", err)
	}
	fmt.Printf("   ✓ Ed25519 key generated with explicit generic: ed25519.PrivateKey\n")
	
	// The power of generics - same function works for all types!
	showKeyInfo(rsaKey)
	showKeyInfo(ecdsaKey)  
	showKeyInfo(ed25519Key)
}

func demonstrateGenericPEMOperations() {
	// Generate keys
	rsaKey, _ := keypair.NewRSAKeyPair(2048)
	ecdsaKey, _ := keypair.NewECDSAKeyPair(algo.P256)
	ed25519Key, _ := keypair.NewEd25519KeyPair()
	
	// Convert to PEM using generics - same function for all types!
	rsaPEM, err := keypair.PrivateKeyToPEM(rsaKey)
	if err != nil {
		log.Fatal("Failed to convert RSA key to PEM:", err)
	}
	
	ecdsaPEM, err := keypair.PrivateKeyToPEM(ecdsaKey)
	if err != nil {
		log.Fatal("Failed to convert ECDSA key to PEM:", err)
	}
	
	ed25519PEM, err := keypair.PrivateKeyToPEM(ed25519Key)
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
	if parsedRSA.Size() == rsaKey.Size() {
		fmt.Printf("   ✓ RSA key round-trip successful\n")
	}
	if parsedECDSA.Curve.Params().Name == ecdsaKey.Curve.Params().Name {
		fmt.Printf("   ✓ ECDSA key round-trip successful\n")
	}
	if len(parsedEd25519) == len(ed25519Key) {
		fmt.Printf("   ✓ Ed25519 key round-trip successful\n")
	}
	
	// Demonstrate generic KeyPairToPEM
	rsaPrivPEM, rsaPubPEM, err := keypair.KeyPairToPEM(rsaKey, keypair.RSAPublicKeyFromPrivate(rsaKey))
	if err != nil {
		log.Fatal("Failed to convert RSA key pair to PEM:", err)
	}
	fmt.Printf("   ✓ Generic KeyPairToPEM works! RSA private: %d bytes, public: %d bytes\n", 
		len(rsaPrivPEM), len(rsaPubPEM))
}

func demonstrateAlgorithmDetection() {
	// Generate keys of different types
	keys := generateSampleKeys()
	
	for name, key := range keys {
		// Convert to PEM
		var pemData []byte
		var err error
		
		switch k := key.(type) {
		case *rsa.PrivateKey:
			pemData, err = keypair.PrivateKeyToPEM(k)
		case *ecdsa.PrivateKey:
			pemData, err = keypair.PrivateKeyToPEM(k)
		case ed25519.PrivateKey:
			pemData, err = keypair.PrivateKeyToPEM(k)
		}
		
		if err != nil {
			log.Printf("Failed to convert %s key to PEM: %v", name, err)
			continue
		}
		
		// Detect algorithm without knowing the type beforehand
		algorithm, err := keypair.DetectAlgorithmFromPEM(pemData)
		if err != nil {
			log.Printf("Failed to detect algorithm for %s: %v", name, err)
			continue
		}
		
		fmt.Printf("   %s key detected as: %s ✓\n", name, algorithm)
		
		// Parse without knowing the type
		parsedKey, detectedAlgo, err := keypair.ParseAnyPrivateKeyFromPEM(pemData)
		if err != nil {
			log.Printf("Failed to parse %s key: %v", name, err)
			continue
		}
		
		fmt.Printf("   %s key parsed as: %s, type: %T ✓\n", name, detectedAlgo, parsedKey)
	}
}

func demonstrateFileOperations() {
	// Generate a key pair
	rsaKey, err := keypair.NewRSAKeyPair(2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key:", err)
	}
	rsaPublic := keypair.RSAPublicKeyFromPrivate(rsaKey)
	
	// Save using generic function
	privateFile := "demo_private.pem"
	publicFile := "demo_public.pem"
	
	err = keypair.SaveKeyPairToFiles(rsaKey, rsaPublic, privateFile, publicFile)
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
	
	if loadedKey.Size() == rsaKey.Size() {
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
	
	if rsaKey, err := keypair.NewRSAKeyPair(2048); err == nil {
		keys["RSA"] = rsaKey
	}
	
	if ecdsaKey, err := keypair.NewECDSAKeyPair(algo.P256); err == nil {
		keys["ECDSA"] = ecdsaKey
	}
	
	if ed25519Key, err := keypair.NewEd25519KeyPair(); err == nil {
		keys["Ed25519"] = ed25519Key
	}
	
	return keys
}