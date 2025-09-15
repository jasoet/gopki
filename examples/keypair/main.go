package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
	"github.com/jasoet/gopki/keypair/format"
)

func main() {
	fmt.Println("=== GoPKI Examples ===")

	// Create outputs directory
	if err := os.MkdirAll("output", 0755); err != nil {
		log.Fatal("Failed to create output directory:", err)
	}

	// Example 1: RSA Key Generation
	fmt.Println("\n1. RSA Key Generation (2048-bit)")
	rsaExample()

	// Example 2: ECDSA Key Generation
	fmt.Println("\n2. ECDSA Key Generation (P-256)")
	ecdsaExample()

	// Example 3: Ed25519 Key Generation
	fmt.Println("\n3. Ed25519 Key Generation")
	ed25519Example()

	// Example 4: Basic Certificate Creation
	fmt.Println("\n4. Basic Certificate Creation")
	certificateExample()

	// Example 5: Key Algorithm Detection
	fmt.Println("\n5. Key Algorithm Detection")
	detectionExample()

	// Example 6: SSH Format Support
	fmt.Println("\n6. SSH Format Support")
	sshFormatExample()

	// Example 7: Format Conversion Matrix
	fmt.Println("\n7. Format Conversion Matrix")
	formatConversionExample()

	fmt.Println("\n=== All examples completed successfully! ===")
	fmt.Println("Generated files are in the 'output/' directory")
}

func rsaExample() {
	// Generate RSA key pair using the generic function
	keyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key pair:", err)
	}

	// Save keys to files
	err = keypair.ToFiles(keyPair, "output/rsa_private.pem", "output/rsa_public.pem")
	if err != nil {
		log.Fatal("Failed to save RSA keys:", err)
	}

	fmt.Printf("   ✓ RSA key pair generated (%d-bit)\n", keyPair.PrivateKey.Size()*8)
	fmt.Printf("   ✓ Saved to: output/rsa_private.pem, output/rsa_public.pem\n")
}

func ecdsaExample() {
	// Generate ECDSA key pair using the generic function
	keyPair, err := keypair.GenerateKeyPair[algo.ECDSACurve, *algo.ECDSAKeyPair](algo.P256)
	if err != nil {
		log.Fatal("Failed to generate ECDSA key pair:", err)
	}

	// Save keys to files
	err = keypair.ToFiles(keyPair, "output/ecdsa_private.pem", "output/ecdsa_public.pem")
	if err != nil {
		log.Fatal("Failed to save ECDSA keys:", err)
	}

	fmt.Printf("   ✓ ECDSA key pair generated (%s)\n", keyPair.PrivateKey.Curve.Params().Name)
	fmt.Printf("   ✓ Saved to: output/ecdsa_private.pem, output/ecdsa_public.pem\n")
}

func ed25519Example() {
	// Generate Ed25519 key pair using the generic function
	keyPair, err := keypair.GenerateKeyPair[algo.Ed25519Config, *algo.Ed25519KeyPair]("")
	if err != nil {
		log.Fatal("Failed to generate Ed25519 key pair:", err)
	}

	// Save keys to files
	err = keypair.ToFiles(keyPair, "output/ed25519_private.pem", "output/ed25519_public.pem")
	if err != nil {
		log.Fatal("Failed to save Ed25519 keys:", err)
	}

	fmt.Printf("   ✓ Ed25519 key pair generated (%d bytes)\n", len(keyPair.PrivateKey))
	fmt.Printf("   ✓ Saved to: output/ed25519_private.pem, output/ed25519_public.pem\n")
}

func certificateExample() {
	// Generate a key pair for the certificate
	keyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		log.Fatal("Failed to generate key pair:", err)
	}

	// Create a self-signed certificate
	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "example.com",
			Organization: []string{"Example Organization"},
			Country:      []string{"US"},
		},
		DNSNames: []string{"example.com", "www.example.com"},
		ValidFor: 365 * 24 * 60 * 60, // 1 year in seconds
	})
	if err != nil {
		log.Fatal("Failed to create certificate:", err)
	}

	// Save certificate to file
	err = certificate.SaveToFile("output/certificate.pem")
	if err != nil {
		log.Fatal("Failed to save certificate:", err)
	}

	fmt.Printf("   ✓ Self-signed certificate created for: %s\n", certificate.Certificate.Subject.CommonName)
	fmt.Printf("   ✓ Saved to: output/certificate.pem\n")
}

func detectionExample() {
	// Test files to check
	testFiles := map[string]string{
		"RSA":     "output/rsa_private.pem",
		"ECDSA":   "output/ecdsa_private.pem",
		"Ed25519": "output/ed25519_private.pem",
	}

	for expectedAlgo, filename := range testFiles {
		pemData, err := os.ReadFile(filename)
		if err != nil {
			fmt.Printf("   ❌ Failed to read %s: %v\n", filename, err)
			continue
		}

		// Use the generic detection function - try each type
		var algorithm string
		if _, alg, err := format.PrivateKeyFromPEM[*rsa.PrivateKey](pemData); err == nil {
			algorithm = alg
		} else if _, alg, err := format.PrivateKeyFromPEM[*ecdsa.PrivateKey](pemData); err == nil {
			algorithm = alg
		} else if _, alg, err := format.PrivateKeyFromPEM[ed25519.PrivateKey](pemData); err == nil {
			algorithm = alg
		} else {
			fmt.Printf("   ❌ Failed to detect %s: %v\n", expectedAlgo, err)
			continue
		}
		fmt.Printf("   ✓ %s detected as: %s\n", expectedAlgo, algorithm)
	}
}

func sshFormatExample() {
	// Generate RSA key pair for SSH demonstration
	keyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key pair for SSH:", err)
	}

	// Convert public key to SSH format
	sshPublicKey, err := format.PublicKeyToSSH(keyPair.PublicKey, "user@example.com")
	if err != nil {
		log.Fatal("Failed to convert to SSH public key:", err)
	}

	// Save SSH public key
	err = os.WriteFile("output/id_rsa.pub", []byte(sshPublicKey), 0644)
	if err != nil {
		log.Fatal("Failed to save SSH public key:", err)
	}

	// Convert private key to SSH format (OpenSSH)
	sshPrivateKey, err := format.PrivateKeyToSSH(keyPair.PrivateKey, "user@example.com", "")
	if err != nil {
		log.Fatal("Failed to convert to SSH private key:", err)
	}

	// Save SSH private key
	err = os.WriteFile("output/id_rsa", []byte(sshPrivateKey), 0600)
	if err != nil {
		log.Fatal("Failed to save SSH private key:", err)
	}

	fmt.Printf("   ✓ SSH public key generated: %d bytes\n", len(sshPublicKey))
	fmt.Printf("   ✓ SSH private key generated: %d bytes\n", len(sshPrivateKey))
	fmt.Printf("   ✓ Saved to: output/id_rsa, output/id_rsa.pub\n")

	// Demonstrate SSH public key parsing
	parsedKey, err := format.ParsePublicKeyFromSSH[*rsa.PublicKey](sshPublicKey)
	if err != nil {
		log.Fatal("Failed to parse SSH public key:", err)
	}

	fmt.Printf("   ✓ SSH public key parsed successfully (%d-bit)\n", parsedKey.Size()*8)
}

func formatConversionExample() {
	// Generate RSA key pair for format conversion demonstration
	keyPair, err := keypair.GenerateKeyPair[algo.KeySize, *algo.RSAKeyPair](2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key pair:", err)
	}

	// Convert to different formats
	fmt.Println("   Converting to different formats...")

	// PEM format (original)
	pemData, err := keypair.PrivateKeyToPEM(keyPair.PrivateKey)
	if err != nil {
		log.Fatal("Failed to convert to PEM:", err)
	}

	// DER format
	derData, err := format.PrivateKeyToDER(keyPair.PrivateKey)
	if err != nil {
		log.Fatal("Failed to convert to DER:", err)
	}

	// SSH format
	sshData, err := format.PublicKeyToSSH(keyPair.PublicKey, "conversion@example.com")
	if err != nil {
		log.Fatal("Failed to convert to SSH:", err)
	}

	// Save to files with different extensions
	files := map[string][]byte{
		"output/conversion.pem": pemData,
		"output/conversion.der": derData,
		"output/conversion.pub": []byte(sshData),
	}

	for filename, data := range files {
		perm := os.FileMode(0600)
		if strings.HasSuffix(filename, ".pub") {
			perm = 0644
		}
		err := os.WriteFile(filename, data, perm)
		if err != nil {
			log.Fatal("Failed to save", filename, ":", err)
		}
	}

	fmt.Printf("   ✓ PEM file: %d bytes\n", len(pemData))
	fmt.Printf("   ✓ DER file: %d bytes (%.1f%% smaller)\n",
		len(derData),
		100.0*(1.0-float64(len(derData))/float64(len(pemData))))
	fmt.Printf("   ✓ SSH file: %d bytes\n", len(sshData))

	// Demonstrate format detection
	fmt.Println("   Format detection:")

	testFiles := map[string]string{
		"output/conversion.pem": "PEM",
		"output/conversion.der": "DER",
		"output/conversion.pub": "SSH",
	}

	for filename, expected := range testFiles {
		data, err := os.ReadFile(filename)
		if err != nil {
			fmt.Printf("   ❌ Failed to read %s: %v\n", filename, err)
			continue
		}

		detected, err := format.DetectFormat(data)
		if err != nil {
			fmt.Printf("   ❌ Failed to detect format for %s: %v\n", filename, err)
			continue
		}

		fmt.Printf("   ✓ %s detected as %s (expected %s)\n",
			filename, detected, expected)
	}

	// Demonstrate round-trip conversion
	fmt.Println("   Round-trip conversion test (PEM → DER → PEM):")

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
}
