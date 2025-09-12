package main

import (
	"crypto/rsa"
	"fmt"
	"log"
	"os"

	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
	"github.com/jasoet/gopki/keypair/format"
)

func main() {
	fmt.Println("=== GoPKI Format Conversion Demo ===")

	// Create output directory
	if err := os.MkdirAll("format_output", 0755); err != nil {
		log.Fatal("Failed to create format_output directory:", err)
	}

	// Generate RSA key pair
	fmt.Println("\n1. Generating RSA key pair...")
	rsaKeyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key pair:", err)
	}

	// Convert to different formats
	fmt.Println("\n2. Converting to different formats...")
	
	// PEM format (original)
	pemData, err := keypair.PrivateKeyToPEM(rsaKeyPair.PrivateKey)
	if err != nil {
		log.Fatal("Failed to convert to PEM:", err)
	}
	
	// DER format (new!)
	derData, err := format.PrivateKeyToDER(rsaKeyPair.PrivateKey)
	if err != nil {
		log.Fatal("Failed to convert to DER:", err)
	}

	// Save to files
	fmt.Println("\n3. Saving to files...")
	
	err = os.WriteFile("format_output/private_key.pem", pemData, 0600)
	if err != nil {
		log.Fatal("Failed to save PEM file:", err)
	}

	err = os.WriteFile("format_output/private_key.der", derData, 0600)
	if err != nil {
		log.Fatal("Failed to save DER file:", err)
	}

	fmt.Printf("   ✓ PEM file: %d bytes\n", len(pemData))
	fmt.Printf("   ✓ DER file: %d bytes (%.1f%% smaller)\n", 
		len(derData), 
		100.0 * (1.0 - float64(len(derData))/float64(len(pemData))))

	// Demonstrate format detection
	fmt.Println("\n4. Format detection...")
	
	testFiles := map[string]string{
		"format_output/private_key.pem": "PEM",
		"format_output/private_key.der": "DER",
	}

	for filename, expectedFormat := range testFiles {
		data, err := os.ReadFile(filename)
		if err != nil {
			fmt.Printf("   ❌ Failed to read %s: %v\n", filename, err)
			continue
		}

		detectedFormat, err := format.DetectFormat(data)
		if err != nil {
			fmt.Printf("   ❌ Failed to detect format for %s: %v\n", filename, err)
			continue
		}

		fmt.Printf("   ✓ %s detected as %s (expected %s)\n", 
			filename, detectedFormat, expectedFormat)
	}

	// Demonstrate round-trip conversion
	fmt.Println("\n5. Round-trip conversion tests...")
	
	// PEM -> DER -> PEM
	fmt.Println("   Testing PEM → DER → PEM...")
	derFromPEM, err := format.ConvertPEMToDER(pemData)
	if err != nil {
		log.Fatal("PEM to DER conversion failed:", err)
	}

	pemFromDER, err := format.ConvertDERToPEM(derFromPEM, "RSA")
	if err != nil {
		log.Fatal("DER to PEM conversion failed:", err)
	}

	// Verify we can parse the result
	_, err = keypair.ParsePrivateKeyFromPEM[*rsa.PrivateKey](pemFromDER)
	if err != nil {
		log.Fatal("Failed to parse round-trip PEM:", err)
	}

	fmt.Println("   ✓ PEM → DER → PEM conversion successful!")

	// Test key type detection
	fmt.Println("\n6. Key algorithm detection from DER...")
	
	algorithms := []struct {
		name string
		generateDER func() ([]byte, error)
	}{
		{
			name: "RSA",
			generateDER: func() ([]byte, error) {
				kp, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
				if err != nil {
					return nil, err
				}
				return format.PrivateKeyToDER(kp.PrivateKey)
			},
		},
		{
			name: "ECDSA",
			generateDER: func() ([]byte, error) {
				kp, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
				if err != nil {
					return nil, err
				}
				return format.PrivateKeyToDER(kp.PrivateKey)
			},
		},
		{
			name: "Ed25519",
			generateDER: func() ([]byte, error) {
				kp, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
				if err != nil {
					return nil, err
				}
				return format.PrivateKeyToDER(kp.PrivateKey)
			},
		},
	}

	for _, alg := range algorithms {
		derData, err := alg.generateDER()
		if err != nil {
			fmt.Printf("   ❌ Failed to generate %s DER: %v\n", alg.name, err)
			continue
		}

		keyType, err := format.GetKeyTypeFromDER(derData)
		if err != nil {
			fmt.Printf("   ❌ Failed to detect %s key type: %v\n", alg.name, err)
			continue
		}

		fmt.Printf("   ✓ %s key correctly detected as: %s\n", alg.name, keyType)
	}

	fmt.Println("\n=== Format conversion demo completed! ===")
	fmt.Println("Check the 'format_output/' directory for generated files.")
	fmt.Println("\nNow you can convert between PEM and DER formats!")
	fmt.Println("• PEM: Human-readable, larger size, widely supported")
	fmt.Println("• DER: Binary format, compact, faster parsing")
}