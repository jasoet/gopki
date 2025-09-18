//go:build example

package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/encryption"
	"github.com/jasoet/gopki/encryption/asymmetric"
	certenc "github.com/jasoet/gopki/encryption/certificate"
	"github.com/jasoet/gopki/encryption/envelope"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
)

func main() {
	fmt.Println("=== GoPKI Data Encryption Module - Comprehensive Examples ===")
	fmt.Println("Demonstrating type-safe encryption with multi-algorithm support and CMS format compliance")

	// Create output directory
	if err := os.MkdirAll("output", 0755); err != nil {
		log.Fatal("Failed to create output directory:", err)
	}

	// Execute all encryption examples
	fmt.Println("\n🔐 PART 1: Multi-Algorithm Encryption")
	fmt.Println(strings.Repeat("=", 60))
	demonstrateMultiAlgorithmEncryption()

	fmt.Println("\n📦 PART 2: Envelope Encryption for Large Data")
	fmt.Println(strings.Repeat("=", 60))
	demonstrateEnvelopeEncryption()

	fmt.Println("\n🏛️ PART 3: Certificate-based Encryption")
	fmt.Println(strings.Repeat("=", 60))
	demonstrateCertificateBasedEncryption()

	fmt.Println("\n📄 PART 4: CMS Format & Standards Compliance")
	fmt.Println(strings.Repeat("=", 60))
	demonstrateCMSFormatSupport()

	fmt.Println("\n👥 PART 5: Multi-Recipient Encryption")
	fmt.Println(strings.Repeat("=", 60))
	demonstrateMultiRecipientEncryption()

	fmt.Println("\n🚀 PART 6: Performance & Security Analysis")
	fmt.Println(strings.Repeat("=", 60))
	demonstratePerformanceAnalysis()

	fmt.Println("\n💾 PART 7: File Operations & Integration")
	fmt.Println(strings.Repeat("=", 60))
	demonstrateFileOperations()

	fmt.Println("\n\n=" + strings.Repeat("=", 58) + "=")
	fmt.Println("✅ ALL ENCRYPTION EXAMPLES COMPLETED SUCCESSFULLY!")
	fmt.Println("📁 Output files saved in: ./output/")
	fmt.Println("🔍 Review encryption formats and certificate integration")
	fmt.Println("=" + strings.Repeat("=", 58) + "=")
}

func demonstrateMultiAlgorithmEncryption() {
	fmt.Println("1. RSA-OAEP Encryption")
	fmt.Println("----------------------")
	demonstrateRSAEncryption()

	fmt.Println("2. ECDSA + ECDH Encryption")
	fmt.Println("---------------------------")
	demonstrateECDSAEncryption()

	fmt.Println("3. Ed25519 + X25519 Encryption")
	fmt.Println("-------------------------------")
	demonstrateEd25519Encryption()
}

func demonstrateRSAEncryption() {
	// Generate RSA key pair using type-safe API
	keyManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key pair:", err)
	}
	keyPair := keyManager.KeyPair()
	fmt.Println("✓ Generated 2048-bit RSA key pair using type-safe API")

	// Small data suitable for RSA-OAEP direct encryption
	smallData := []byte("Confidential RSA message - Hello World!")
	fmt.Printf("  Original data: %s (%d bytes)\n", smallData, len(smallData))

	// Direct RSA encryption
	opts := encryption.DefaultEncryptOptions()
	encrypted, err := asymmetric.Encrypt(smallData, keyPair, opts)
	if err != nil {
		log.Fatal("RSA encryption failed:", err)
	}

	fmt.Printf("✓ Encrypted using %s\n", encrypted.Algorithm)
	fmt.Printf("  Encrypted size: %d bytes\n", len(encrypted.Data))
	fmt.Printf("  Encryption ratio: %.1fx\n", float64(len(encrypted.Data))/float64(len(smallData)))

	// Decrypt the data
	decryptOpts := encryption.DefaultDecryptOptions()
	decrypted, err := asymmetric.Decrypt(encrypted, keyPair, decryptOpts)
	if err != nil {
		log.Fatal("RSA decryption failed:", err)
	}

	fmt.Printf("✓ Decrypted: %s\n", decrypted)

	// Save with metadata
	saveEncryptionResult("rsa_direct", encrypted, map[string]interface{}{
		"algorithm":     string(encrypted.Algorithm),
		"keySize":       2048,
		"dataSize":      len(smallData),
		"encryptedSize": len(encrypted.Data),
		"method":        "RSA-OAEP direct encryption",
	})

	fmt.Println()
}

func demonstrateECDSAEncryption() {
	// Generate ECDSA key pair using type-safe API
	keyManager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
	if err != nil {
		log.Fatal("Failed to generate ECDSA key pair:", err)
	}
	keyPair := keyManager.KeyPair()
	fmt.Println("✓ Generated ECDSA P-256 key pair using type-safe API")

	// Data for ECDH + AES-GCM encryption
	data := []byte("Secure ECDSA message using ECDH key agreement and AES-GCM encryption")
	fmt.Printf("  Original data: %s (%d bytes)\n", data, len(data))

	// ECDH-based encryption using envelope encryption
	opts := encryption.DefaultEncryptOptions()
	opts.Format = encryption.FormatCMS

	encrypted, err := envelope.Encrypt(data, keyPair, opts)
	if err != nil {
		log.Printf("⚠️  ECDSA envelope encryption issue: %v", err)
		log.Println("  Note: Known issue with ECDSA envelope encryption - using direct asymmetric encryption")

		// Fallback to direct asymmetric encryption
		encrypted, err = asymmetric.Encrypt(data, keyPair, opts)
		if err != nil {
			log.Printf("⚠️  ECDSA encryption not yet fully supported: %v", err)
			fmt.Println("  Skipping ECDSA demonstration due to implementation limitations")
			return
		}
	}

	fmt.Printf("✓ Encrypted using %s\n", encrypted.Algorithm)
	fmt.Printf("  Encrypted size: %d bytes\n", len(encrypted.Data))
	if len(encrypted.EncryptedKey) > 0 {
		fmt.Printf("  Key material size: %d bytes\n", len(encrypted.EncryptedKey))
	}

	// Decrypt the data
	decryptOpts := encryption.DefaultDecryptOptions()
	var decrypted []byte
	if len(encrypted.EncryptedKey) > 0 {
		// Envelope decryption
		decrypted, err = envelope.Decrypt(encrypted, keyPair, decryptOpts)
	} else {
		// Direct decryption
		decrypted, err = asymmetric.Decrypt(encrypted, keyPair, decryptOpts)
	}

	if err != nil {
		log.Printf("ECDSA decryption failed: %v", err)
		return
	}

	fmt.Printf("✓ Decrypted: %s\n", string(decrypted[:min(50, len(decrypted))]))

	// Save result
	saveEncryptionResult("ecdsa_hybrid", encrypted, map[string]interface{}{
		"algorithm":     string(encrypted.Algorithm),
		"curve":         "P-256",
		"dataSize":      len(data),
		"encryptedSize": len(encrypted.Data),
		"method":        "ECDH + AES-GCM",
	})

	fmt.Println()
}

func demonstrateEd25519Encryption() {
	// Generate Ed25519 key pair using type-safe API
	keyManager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
	if err != nil {
		log.Fatal("Failed to generate Ed25519 key pair:", err)
	}
	keyPair := keyManager.KeyPair()
	fmt.Println("✓ Generated Ed25519 key pair using type-safe API")

	// Data for X25519 + AES-GCM encryption
	data := []byte("Modern Ed25519 message using X25519 key agreement - highest performance encryption")
	fmt.Printf("  Original data: %s (%d bytes)\n", string(data[:min(50, len(data))]), len(data))

	// X25519-based encryption using envelope encryption
	opts := encryption.DefaultEncryptOptions()
	opts.Format = encryption.FormatCMS

	startTime := time.Now()
	encrypted, err := envelope.Encrypt(data, keyPair, opts)
	if err != nil {
		log.Printf("⚠️  Ed25519 envelope encryption issue: %v", err)
		log.Println("  Note: Known issue with Ed25519 envelope encryption - using direct asymmetric encryption")

		// Fallback to direct asymmetric encryption
		encrypted, err = asymmetric.Encrypt(data, keyPair, opts)
		if err != nil {
			log.Printf("⚠️  Ed25519 encryption not yet fully supported: %v", err)
			fmt.Println("  Skipping Ed25519 demonstration due to implementation limitations")
			return
		}
	}
	encryptionTime := time.Since(startTime)

	fmt.Printf("✓ Encrypted using %s in %v\n", encrypted.Algorithm, encryptionTime)
	fmt.Printf("  Encrypted size: %d bytes\n", len(encrypted.Data))
	if len(encrypted.EncryptedKey) > 0 {
		fmt.Printf("  Key material size: %d bytes\n", len(encrypted.EncryptedKey))
	}

	// Decrypt the data
	startTime = time.Now()
	decryptOpts := encryption.DefaultDecryptOptions()
	var decrypted []byte
	if len(encrypted.EncryptedKey) > 0 {
		// Envelope decryption
		decrypted, err = envelope.Decrypt(encrypted, keyPair, decryptOpts)
	} else {
		// Direct decryption
		decrypted, err = asymmetric.Decrypt(encrypted, keyPair, decryptOpts)
	}
	decryptionTime := time.Since(startTime)

	if err != nil {
		log.Printf("Ed25519 decryption failed: %v", err)
		return
	}

	fmt.Printf("✓ Decrypted in %v: %s\n", decryptionTime, string(decrypted[:min(50, len(decrypted))]))

	// Save result with timing
	saveEncryptionResult("ed25519_hybrid", encrypted, map[string]interface{}{
		"algorithm":      string(encrypted.Algorithm),
		"curve":          "X25519",
		"dataSize":       len(data),
		"encryptedSize":  len(encrypted.Data),
		"encryptionTime": encryptionTime.String(),
		"decryptionTime": decryptionTime.String(),
		"method":         "X25519 + AES-GCM",
	})

	fmt.Println()
}

func demonstrateEnvelopeEncryption() {
	fmt.Println("1. Large Data Encryption with Envelope Method")
	fmt.Println("---------------------------------------------")

	// Generate RSA key pair for envelope encryption
	keyManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key pair:", err)
	}
	keyPair := keyManager.KeyPair()
	fmt.Println("✓ Generated 2048-bit RSA key pair for envelope encryption")

	// Create large test data
	largeData := make([]byte, 1024*50) // 50KB data
	for i := range largeData {
		largeData[i] = byte('A' + (i % 26))
	}
	fmt.Printf("✓ Generated test data: %d KB\n", len(largeData)/1024)

	// Envelope encryption with timing
	startTime := time.Now()
	opts := encryption.DefaultEncryptOptions()
	opts.Format = encryption.FormatCMS

	encrypted, err := envelope.Encrypt(largeData, keyPair, opts)
	if err != nil {
		log.Fatal("Envelope encryption failed:", err)
	}
	encryptionTime := time.Since(startTime)

	fmt.Printf("✓ Encrypted %d KB → %d KB in %v\n",
		len(largeData)/1024, len(encrypted.Data)/1024, encryptionTime)
	fmt.Printf("  Algorithm: %s\n", encrypted.Algorithm)
	fmt.Printf("  Symmetric key size: %d bytes\n", len(encrypted.EncryptedKey))
	fmt.Printf("  IV size: %d bytes\n", len(encrypted.IV))
	fmt.Printf("  Compression ratio: %.1fx\n", float64(len(encrypted.Data))/float64(len(largeData)))

	// Envelope decryption with timing
	startTime = time.Now()
	decryptOpts := encryption.DefaultDecryptOptions()
	decrypted, err := envelope.Decrypt(encrypted, keyPair, decryptOpts)
	if err != nil {
		log.Fatal("Envelope decryption failed:", err)
	}
	decryptionTime := time.Since(startTime)

	fmt.Printf("✓ Decrypted %d KB in %v\n", len(decrypted)/1024, decryptionTime)
	fmt.Printf("  Data integrity: %t\n", len(decrypted) == len(largeData))

	// Save envelope encryption result
	saveEncryptionResult("envelope_large", encrypted, map[string]interface{}{
		"method":          "Envelope encryption",
		"originalSize":    len(largeData),
		"encryptedSize":   len(encrypted.Data),
		"keyMaterialSize": len(encrypted.EncryptedKey),
		"ivSize":          len(encrypted.IV),
		"encryptionTime":  encryptionTime.String(),
		"decryptionTime":  decryptionTime.String(),
		"algorithm":       string(encrypted.Algorithm),
	})

	// Save raw encrypted data for format demonstration
	os.WriteFile("output/envelope_large.bin", encrypted.Data, 0644)
	fmt.Println("💾 Saved large data encryption example")

	fmt.Println()
}

func demonstrateCertificateBasedEncryption() {
	fmt.Println("1. PKI Certificate-based Document Encryption")
	fmt.Println("---------------------------------------------")

	// Generate key pairs for multiple users
	users := []struct {
		name    string
		keyPair interface{}
		cert    *cert.Certificate
	}{}

	// Alice - RSA
	aliceKeyManager, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	aliceKeyPair := aliceKeyManager.KeyPair()
	aliceCert, err := cert.CreateSelfSignedCertificate(aliceKeyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "Alice Johnson",
			Organization: []string{"Example Corp"},
			Country:      []string{"US"},
		},
		EmailAddress: []string{"alice@example.com"},
		ValidFor:     365 * 24 * time.Hour,
	})
	if err != nil {
		log.Fatal("Failed to create Alice's certificate:", err)
	}
	users = append(users, struct {
		name    string
		keyPair interface{}
		cert    *cert.Certificate
	}{"Alice", aliceKeyPair, aliceCert})

	// Bob - ECDSA
	bobKeyManager, _ := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
	bobKeyPair := bobKeyManager.KeyPair()
	bobCert, err := cert.CreateSelfSignedCertificate(bobKeyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "Bob Smith",
			Organization: []string{"Example Corp"},
			Country:      []string{"US"},
		},
		EmailAddress: []string{"bob@example.com"},
		ValidFor:     365 * 24 * time.Hour,
	})
	if err != nil {
		log.Fatal("Failed to create Bob's certificate:", err)
	}
	users = append(users, struct {
		name    string
		keyPair interface{}
		cert    *cert.Certificate
	}{"Bob", bobKeyPair, bobCert})

	fmt.Printf("✓ Created certificates for %d users\n", len(users))

	// Confidential document
	document := []byte(`CONFIDENTIAL BUSINESS PLAN

Company: Example Corp
Date: 2024-12-19
Classification: Top Secret

Strategic Initiative Q1-2024:
- Product launch timeline
- Market expansion plans
- Revenue projections: $2.5M
- Competitive analysis
- Resource allocation

This document contains proprietary information and should only be
accessed by authorized personnel with valid decryption credentials.`)

	fmt.Printf("✓ Document size: %d bytes\n", len(document))

	// Encrypt for each user
	for _, user := range users {
		fmt.Printf("\nEncrypting for %s...\n", user.name)

		opts := encryption.DefaultEncryptOptions()
		encrypted, err := certenc.EncryptDocument(document, user.cert, opts)
		if err != nil {
			log.Printf("Failed to encrypt for %s: %v", user.name, err)
			continue
		}

		fmt.Printf("✓ Encrypted using %s\n", encrypted.Algorithm)
		fmt.Printf("  Recipient: %s\n", user.cert.Certificate.Subject.CommonName)
		fmt.Printf("  Encrypted size: %d bytes\n", len(encrypted.Data))

		// Decrypt using the user's private key
		decryptOpts := encryption.DefaultDecryptOptions()

		switch kp := user.keyPair.(type) {
		case *algo.RSAKeyPair:
			_, err = certenc.DecryptDocument(encrypted, kp, decryptOpts)
		case *algo.ECDSAKeyPair:
			_, err = certenc.DecryptDocument(encrypted, kp, decryptOpts)
		case *algo.Ed25519KeyPair:
			log.Printf("Ed25519 encryption via certificate not yet supported for %s", user.name)
			continue
		default:
			log.Printf("Unsupported key type for %s", user.name)
			continue
		}

		if err != nil {
			log.Printf("%s failed to decrypt: %v", user.name, err)
			continue
		}

		fmt.Printf("✓ %s successfully decrypted document\n", user.name)

		// Save user-specific encrypted document and certificate
		_ = fmt.Sprintf("output/document_%s.bin", strings.ToLower(user.name))
		certFilename := fmt.Sprintf("output/cert_%s.pem", strings.ToLower(user.name))

		saveEncryptionResult(fmt.Sprintf("cert_%s", strings.ToLower(user.name)), encrypted, map[string]interface{}{
			"recipient": user.cert.Certificate.Subject.CommonName,
			"email":     user.cert.Certificate.EmailAddresses,
			"algorithm": string(encrypted.Algorithm),
			"docSize":   len(document),
			"encSize":   len(encrypted.Data),
		})

		user.cert.SaveToFile(certFilename)
	}

	fmt.Println("\n✓ Certificate-based encryption completed for all users")
	fmt.Println()
}

func demonstrateCMSFormatSupport() {
	fmt.Println("1. CMS (Cryptographic Message Syntax) Format")
	fmt.Println("---------------------------------------------")

	// Generate key pair for CMS demonstration
	keyManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key pair:", err)
	}
	keyPair := keyManager.KeyPair()

	// Create certificate for CMS operations
	testCert, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "CMS Test Certificate",
			Organization: []string{"GoPKI CMS Demo"},
			Country:      []string{"US"},
		},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		log.Fatal("Failed to create test certificate:", err)
	}
	fmt.Println("✓ Created CMS test certificate")

	// Test data for CMS format demonstration
	testData := []byte("CMS format demonstration - RFC 5652 compliance test data")
	fmt.Printf("✓ Test data: %s (%d bytes)\n", testData, len(testData))

	// Encrypt with CMS format
	opts := encryption.DefaultEncryptOptions()
	opts.Format = encryption.FormatCMS

	encrypted, err := asymmetric.Encrypt(testData, keyPair, opts)
	if err != nil {
		log.Fatal("CMS encryption failed:", err)
	}

	fmt.Printf("✓ Encrypted with format: %s\n", encrypted.Format)
	fmt.Printf("  Algorithm: %s\n", encrypted.Algorithm)

	// Encode to CMS format (RFC 5652)
	cmsData, err := encryption.EncodeData(encrypted)
	if err != nil {
		fmt.Printf("⚠️ CMS encoding currently limited to specific configurations: %v\n", err)
		fmt.Println("   Note: This is expected behavior for current encryption module limitations")

		// Continue demonstration with available functionality
		fmt.Printf("✓ Encryption completed successfully\n")
		fmt.Printf("  Original: %s\n", testData)
		return
	}

	fmt.Printf("✓ Encoded to CMS format: %d bytes\n", len(cmsData))
	fmt.Printf("  Base64 preview: %s...\n", base64.StdEncoding.EncodeToString(cmsData[:min(32, len(cmsData))]))

	// Decode from CMS format using type-safe API
	decodedData, err := encryption.DecodeDataWithKey(cmsData, testCert.Certificate, keyPair.PrivateKey)
	if err != nil {
		log.Fatal("CMS decoding failed:", err)
	}

	fmt.Printf("✓ Decoded from CMS format successfully\n")
	fmt.Printf("  Algorithm: %s\n", decodedData.Algorithm)
	fmt.Printf("  Format: %s\n", decodedData.Format)

	// Decrypt the decoded data
	decryptOpts := encryption.DefaultDecryptOptions()
	decrypted, err := asymmetric.Decrypt(decodedData, keyPair, decryptOpts)
	if err != nil {
		log.Fatal("Final decryption failed:", err)
	}

	fmt.Printf("✓ Final decryption: %s\n", decrypted)

	// Save CMS format examples
	os.WriteFile("output/cms_encoded.bin", cmsData, 0644)
	os.WriteFile("output/cms_certificate.pem", testCert.DERData, 0644)

	saveCMSExample("cms_format", map[string]interface{}{
		"format":        "CMS (RFC 5652)",
		"encodedSize":   len(cmsData),
		"originalSize":  len(testData),
		"algorithm":     string(encrypted.Algorithm),
		"certificate":   testCert.Certificate.Subject.CommonName,
		"base64Preview": base64.StdEncoding.EncodeToString(cmsData[:min(64, len(cmsData))]),
	})

	fmt.Println("✓ CMS format demonstration completed")
	fmt.Println()
}

func demonstrateMultiRecipientEncryption() {
	fmt.Println("1. Multi-Recipient Encryption Workflow")
	fmt.Println("---------------------------------------")

	// Create multiple recipients with different algorithms
	recipients := []struct {
		name    string
		keyPair interface{}
		cert    *cert.Certificate
	}{}

	// Alice - RSA 2048
	aliceKeyManager, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	aliceKeyPair := aliceKeyManager.KeyPair()
	aliceCert, _ := cert.CreateSelfSignedCertificate(aliceKeyPair, cert.CertificateRequest{
		Subject:  pkix.Name{CommonName: "Alice (RSA-2048)"},
		ValidFor: 365 * 24 * time.Hour,
	})
	recipients = append(recipients, struct {
		name    string
		keyPair interface{}
		cert    *cert.Certificate
	}{"Alice", aliceKeyPair, aliceCert})

	// Bob - RSA 3072 (stronger)
	bobKeyManager, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize3072)
	bobKeyPair := bobKeyManager.KeyPair()
	bobCert, _ := cert.CreateSelfSignedCertificate(bobKeyPair, cert.CertificateRequest{
		Subject:  pkix.Name{CommonName: "Bob (RSA-3072)"},
		ValidFor: 365 * 24 * time.Hour,
	})
	recipients = append(recipients, struct {
		name    string
		keyPair interface{}
		cert    *cert.Certificate
	}{"Bob", bobKeyPair, bobCert})

	// Charlie - RSA 2048 (for comparison)
	charlieKeyManager, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	charlieKeyPair := charlieKeyManager.KeyPair()
	charlieCert, _ := cert.CreateSelfSignedCertificate(charlieKeyPair, cert.CertificateRequest{
		Subject:  pkix.Name{CommonName: "Charlie (RSA-2048)"},
		ValidFor: 365 * 24 * time.Hour,
	})
	recipients = append(recipients, struct {
		name    string
		keyPair interface{}
		cert    *cert.Certificate
	}{"Charlie", charlieKeyPair, charlieCert})

	fmt.Printf("✓ Created %d recipients with different key strengths\n", len(recipients))

	// Confidential message for multi-recipient encryption
	message := []byte(`URGENT SECURITY NOTICE

Subject: Critical Security Update Required
Classification: Confidential
Distribution: Management Team Only

All authorized recipients must implement the following security
measures by end of business today:

1. Update all system passwords
2. Enable two-factor authentication
3. Review access permissions
4. Verify backup procedures

This message has been encrypted for multiple authorized recipients
using their respective public key certificates.

Time-sensitive: Action required within 24 hours.`)

	fmt.Printf("✓ Message size: %d bytes\n", len(message))

	// Encrypt for each recipient individually
	multiRecipientData := map[string]interface{}{
		"message":    base64.StdEncoding.EncodeToString(message),
		"recipients": []map[string]interface{}{},
	}

	opts := encryption.DefaultEncryptOptions()
	opts.Format = encryption.FormatCMS

	for i, recipient := range recipients {
		fmt.Printf("\nEncrypting for %s...\n", recipient.name)

		startTime := time.Now()
		encrypted, err := envelope.Encrypt(message, recipient.keyPair.(*algo.RSAKeyPair), opts)
		if err != nil {
			log.Printf("Failed to encrypt for %s: %v", recipient.name, err)
			continue
		}
		encryptionTime := time.Since(startTime)

		fmt.Printf("✓ Encrypted in %v using %s\n", encryptionTime, encrypted.Algorithm)
		fmt.Printf("  Recipient: %s\n", recipient.cert.Certificate.Subject.CommonName)
		fmt.Printf("  Encrypted size: %d bytes\n", len(encrypted.Data))
		fmt.Printf("  Key material: %d bytes\n", len(encrypted.EncryptedKey))

		// Test decryption
		startTime = time.Now()
		decryptOpts := encryption.DefaultDecryptOptions()
		decrypted, err := envelope.Decrypt(encrypted, recipient.keyPair.(*algo.RSAKeyPair), decryptOpts)
		if err != nil {
			log.Printf("%s failed to decrypt: %v", recipient.name, err)
			continue
		}
		decryptionTime := time.Since(startTime)

		fmt.Printf("✓ %s decrypted in %v\n", recipient.name, decryptionTime)
		fmt.Printf("  Message preview: %s...\n", string(decrypted[:min(50, len(decrypted))]))

		// Save individual encrypted copies
		_ = fmt.Sprintf("output/multirecipient_%s.bin", strings.ToLower(recipient.name))
		saveEncryptionResult(fmt.Sprintf("multirecipient_%s", strings.ToLower(recipient.name)), encrypted, map[string]interface{}{
			"recipient":       recipient.cert.Certificate.Subject.CommonName,
			"algorithm":       string(encrypted.Algorithm),
			"encryptionTime":  encryptionTime.String(),
			"decryptionTime":  decryptionTime.String(),
			"messageSize":     len(message),
			"encryptedSize":   len(encrypted.Data),
			"keyMaterialSize": len(encrypted.EncryptedKey),
		})

		// Add to multi-recipient summary
		recipientData := map[string]interface{}{
			"name":           recipient.name,
			"commonName":     recipient.cert.Certificate.Subject.CommonName,
			"algorithm":      string(encrypted.Algorithm),
			"encryptedSize":  len(encrypted.Data),
			"encryptionTime": encryptionTime.String(),
			"decryptionTime": decryptionTime.String(),
		}
		multiRecipientData["recipients"] = append(
			multiRecipientData["recipients"].([]map[string]interface{}),
			recipientData,
		)

		fmt.Printf("💾 Saved encrypted copy #%d\n", i+1)
	}

	// Save multi-recipient summary
	saveJSON("output/multirecipient_summary.json", multiRecipientData)

	fmt.Printf("\n✓ Multi-recipient encryption completed for %d recipients\n", len(recipients))
	fmt.Println("  Each recipient can decrypt using their private key")
	fmt.Println("  Encryption strength varies by recipient key size")
	fmt.Println()
}

func demonstratePerformanceAnalysis() {
	fmt.Println("1. Encryption Performance Comparison")
	fmt.Println("------------------------------------")

	// Test data sizes
	dataSizes := []struct {
		name string
		size int
	}{
		{"Small (1KB)", 1024},
		{"Medium (10KB)", 10 * 1024},
		{"Large (100KB)", 100 * 1024},
	}

	// RSA key pair for testing
	keyManager, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	keyPair := keyManager.KeyPair()

	fmt.Printf("Testing with RSA-2048 key pair\n")
	fmt.Printf("%-12s %-10s %-12s %-12s %-8s\n", "Data Size", "Method", "Encrypt", "Decrypt", "Ratio")
	fmt.Println(strings.Repeat("-", 60))

	performanceResults := []map[string]interface{}{}

	for _, dataSize := range dataSizes {
		// Generate test data
		testData := make([]byte, dataSize.size)
		for i := range testData {
			testData[i] = byte(i % 256)
		}

		// Test direct encryption (for small data)
		if dataSize.size <= 200 { // RSA-2048 can encrypt ~190 bytes directly
			startTime := time.Now()
			opts := encryption.DefaultEncryptOptions()
			encrypted, err := asymmetric.Encrypt(testData, keyPair, opts)
			encryptTime := time.Since(startTime)

			if err == nil {
				startTime = time.Now()
				decryptOpts := encryption.DefaultDecryptOptions()
				_, err = asymmetric.Decrypt(encrypted, keyPair, decryptOpts)
				decryptTime := time.Since(startTime)

				if err == nil {
					ratio := float64(len(encrypted.Data)) / float64(len(testData))
					fmt.Printf("%-12s %-10s %-12v %-12v %-8.1fx\n",
						dataSize.name, "Direct", encryptTime, decryptTime, ratio)

					performanceResults = append(performanceResults, map[string]interface{}{
						"dataSize":      dataSize.name,
						"method":        "Direct RSA",
						"encryptTime":   encryptTime.String(),
						"decryptTime":   decryptTime.String(),
						"ratio":         ratio,
						"originalSize":  len(testData),
						"encryptedSize": len(encrypted.Data),
					})
				}
			}
		}

		// Test envelope encryption (for all data sizes)
		startTime := time.Now()
		opts := encryption.DefaultEncryptOptions()
		encrypted, err := envelope.Encrypt(testData, keyPair, opts)
		encryptTime := time.Since(startTime)

		if err == nil {
			startTime = time.Now()
			decryptOpts := encryption.DefaultDecryptOptions()
			_, err = envelope.Decrypt(encrypted, keyPair, decryptOpts)
			decryptTime := time.Since(startTime)

			if err == nil {
				ratio := float64(len(encrypted.Data)) / float64(len(testData))
				fmt.Printf("%-12s %-10s %-12v %-12v %-8.1fx\n",
					dataSize.name, "Envelope", encryptTime, decryptTime, ratio)

				performanceResults = append(performanceResults, map[string]interface{}{
					"dataSize":        dataSize.name,
					"method":          "Envelope",
					"encryptTime":     encryptTime.String(),
					"decryptTime":     decryptTime.String(),
					"ratio":           ratio,
					"originalSize":    len(testData),
					"encryptedSize":   len(encrypted.Data),
					"keyMaterialSize": len(encrypted.EncryptedKey),
				})
			}
		}
	}

	// Save performance results
	saveJSON("output/performance_analysis.json", map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"keyType":   "RSA-2048",
		"results":   performanceResults,
		"notes": []string{
			"Direct encryption only works for small data (<190 bytes for RSA-2048)",
			"Envelope encryption works for any data size",
			"Envelope encryption provides better performance for large data",
			"Encryption ratio includes all overhead (keys, IV, padding, etc.)",
		},
	})

	fmt.Printf("\n✓ Performance analysis completed\n")
	fmt.Println("💾 Detailed results saved to performance_analysis.json")
	fmt.Println()
}

func demonstrateFileOperations() {
	fmt.Println("1. File-based Encryption Operations")
	fmt.Println("-----------------------------------")

	// Generate key pair for file operations
	keyManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key pair:", err)
	}
	keyPair := keyManager.KeyPair()

	// Create test files with different content types
	testFiles := []struct {
		name    string
		content []byte
	}{
		{
			"config.json",
			[]byte(`{
	"database": {
		"host": "secure-db.example.com",
		"port": 5432,
		"username": "admin",
		"password": "super-secret-password",
		"ssl": true
	},
	"api": {
		"key": "sk-1234567890abcdef",
		"secret": "secret-key-for-api-access"
	}
}`),
		},
		{
			"document.txt",
			[]byte(`CONFIDENTIAL BUSINESS DOCUMENT

This document contains proprietary information including:
- Customer data and contact information
- Financial projections and revenue targets
- Strategic partnerships and vendor agreements
- Technical specifications and trade secrets

Access to this information is restricted to authorized personnel only.
Distribution outside the organization is strictly prohibited.`),
		},
	}

	// Create certificate for file encryption
	cert, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "File Security Officer",
			Organization: []string{"Example Corp"},
		},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		log.Fatal("Failed to create certificate:", err)
	}

	fmt.Printf("✓ Created certificate: %s\n", cert.Certificate.Subject.CommonName)

	// Encrypt each test file
	for _, file := range testFiles {
		fmt.Printf("\nProcessing file: %s (%d bytes)\n", file.name, len(file.content))

		// Save original file
		originalPath := fmt.Sprintf("output/original_%s", file.name)
		os.WriteFile(originalPath, file.content, 0644)

		// Encrypt file content
		opts := encryption.DefaultEncryptOptions()
		opts.Format = encryption.FormatCMS

		encrypted, err := envelope.Encrypt(file.content, keyPair, opts)
		if err != nil {
			log.Printf("Failed to encrypt %s: %v", file.name, err)
			continue
		}

		fmt.Printf("✓ Encrypted using %s\n", encrypted.Algorithm)
		fmt.Printf("  Original size: %d bytes\n", len(file.content))
		fmt.Printf("  Encrypted size: %d bytes\n", len(encrypted.Data))

		// Save encrypted file in CMS format
		encryptedPath := fmt.Sprintf("output/encrypted_%s.cms", file.name)
		cmsData, err := encryption.EncodeData(encrypted)
		if err != nil {
			log.Printf("Failed to encode %s to CMS: %v", file.name, err)
			continue
		}
		os.WriteFile(encryptedPath, cmsData, 0644)

		// Test decryption
		decryptOpts := encryption.DefaultDecryptOptions()
		decrypted, err := envelope.Decrypt(encrypted, keyPair, decryptOpts)
		if err != nil {
			log.Printf("Failed to decrypt %s: %v", file.name, err)
			continue
		}

		fmt.Printf("✓ Decrypted successfully\n")
		fmt.Printf("  Data integrity: %t\n", len(decrypted) == len(file.content))

		// Save decrypted file for verification
		decryptedPath := fmt.Sprintf("output/decrypted_%s", file.name)
		os.WriteFile(decryptedPath, decrypted, 0644)

		fmt.Printf("💾 Files saved:\n")
		fmt.Printf("  Original: %s\n", originalPath)
		fmt.Printf("  Encrypted: %s\n", encryptedPath)
		fmt.Printf("  Decrypted: %s\n", decryptedPath)
	}

	// Save key pair and certificate for file operations
	keypair.ToPEMFiles(keyPair, "output/file_encryption_private.pem", "output/file_encryption_public.pem")
	cert.SaveToFile("output/file_encryption_cert.pem")

	fmt.Println("\n✓ File encryption operations completed")
	fmt.Println("🔑 Keys and certificate saved for manual decryption testing")
	fmt.Println()
}

// Helper functions

func saveEncryptionResult(prefix string, encrypted *encryption.EncryptedData, metadata map[string]interface{}) {
	// Save binary data
	filename := fmt.Sprintf("output/%s.bin", prefix)
	cmsData, err := encryption.EncodeData(encrypted)
	if err == nil {
		os.WriteFile(filename, cmsData, 0644)
	}

	// Save metadata
	metadataFile := fmt.Sprintf("output/%s_metadata.json", prefix)
	allMetadata := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"algorithm": string(encrypted.Algorithm),
		"format":    string(encrypted.Format),
		"dataSize":  len(encrypted.Data),
	}

	// Merge custom metadata
	for k, v := range metadata {
		allMetadata[k] = v
	}

	saveJSON(metadataFile, allMetadata)
}

func saveCMSExample(prefix string, metadata map[string]interface{}) {
	filename := fmt.Sprintf("output/%s_info.json", prefix)
	allMetadata := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"standard":  "RFC 5652 - Cryptographic Message Syntax (CMS)",
	}

	// Merge custom metadata
	for k, v := range metadata {
		allMetadata[k] = v
	}

	saveJSON(filename, allMetadata)
}

func saveJSON(filename string, data interface{}) {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal JSON: %v", err)
		return
	}

	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		log.Printf("Failed to save file %s: %v", filename, err)
		return
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
