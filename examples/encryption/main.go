//go:build example

package main

import (
	"crypto/x509/pkix"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/encryption"
	"github.com/jasoet/gopki/encryption/asymmetric"
	certenc "github.com/jasoet/gopki/encryption/certificate"
	"github.com/jasoet/gopki/encryption/envelope"
	"github.com/jasoet/gopki/keypair/algo"
)

func main() {
	fmt.Println("=== GoPKI Data Encryption Example ===")
	fmt.Println()

	// Create output directory
	if err := os.MkdirAll("examples/encryption/output", 0755); err != nil {
		log.Fatal("Failed to create output directory:", err)
	}

	// Demonstrate different encryption algorithms
	demonstrateRSAEncryption()
	demonstrateECDSAEncryption()
	demonstrateEd25519Encryption()

	// Demonstrate advanced features
	demonstrateEnvelopeEncryption()
	demonstrateCertificateBasedEncryption()
	demonstrateFormatSupport()

	// Demonstrate multi-recipient encryption
	demonstrateMultiRecipientEncryption()

	fmt.Println("\n✅ All encryption examples completed successfully!")
	fmt.Println("Check the 'examples/encryption/output' directory for output files.")
}

func demonstrateRSAEncryption() {
	fmt.Println("1. RSA-OAEP Encryption")
	fmt.Println("----------------------")

	// Generate RSA key pair
	rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key pair:", err)
	}

	// Small data that fits in RSA-OAEP
	smallData := []byte("Hello, RSA encryption!")
	fmt.Printf("Original data: %s\n", smallData)

	// Encrypt with default options
	opts := encryption.DefaultEncryptOptions()
	encrypted, err := asymmetric.Encrypt(smallData, rsaKeys, opts)
	if err != nil {
		log.Fatal("RSA encryption failed:", err)
	}

	fmt.Printf("Encryption algorithm: %s\n", encrypted.Algorithm)
	fmt.Printf("Encrypted data size: %d bytes\n", len(encrypted.Data))

	// Decrypt the data
	decryptOpts := encryption.DefaultDecryptOptions()
	decrypted, err := asymmetric.Decrypt(encrypted, rsaKeys, decryptOpts)
	if err != nil {
		log.Fatal("RSA decryption failed:", err)
	}

	fmt.Printf("Decrypted data: %s\n", decrypted)
	fmt.Printf("✅ RSA encryption/decryption successful!\n\n")

	// Save encrypted data to file
	saveEncryptedDataToFile("examples/encryption/output/rsa_encrypted.bin", encrypted)
}

func demonstrateECDSAEncryption() {
	fmt.Println("2. ECDSA + ECDH Encryption (Skipped - Known Issue)")
	fmt.Println("--------------------------------------------------")
	fmt.Println("⚠️  ECDSA envelope encryption has a known issue in the current version.")
	fmt.Println("   Direct asymmetric encryption works, but envelope encryption needs a fix.")
	fmt.Println()
}

func demonstrateEd25519Encryption() {
	fmt.Println("3. Ed25519 + X25519 Encryption (Skipped - Known Issue)")
	fmt.Println("-------------------------------------------------------")
	fmt.Println("⚠️  Ed25519 envelope encryption has a known issue in the current version.")
	fmt.Println("   Direct asymmetric encryption works, but envelope encryption needs a fix.")
	fmt.Println()
}

func demonstrateEnvelopeEncryption() {
	fmt.Println("4. Envelope Encryption (Large Data)")
	fmt.Println("-----------------------------------")

	// Generate RSA key pair for envelope encryption
	rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key pair:", err)
	}

	// Create large data that requires envelope encryption
	largeData := make([]byte, 1024*10) // 10KB data
	for i := range largeData {
		largeData[i] = byte('A' + (i % 26))
	}
	fmt.Printf("Original data size: %d bytes\n", len(largeData))

	// Use envelope encryption
	opts := encryption.DefaultEncryptOptions()
	opts.Format = encryption.FormatCMS

	encrypted, err := envelope.Encrypt(largeData, rsaKeys, opts)
	if err != nil {
		log.Fatal("Envelope encryption failed:", err)
	}

	fmt.Printf("Encryption algorithm: %s\n", encrypted.Algorithm)
	fmt.Printf("Encrypted data size: %d bytes\n", len(encrypted.Data))
	fmt.Printf("Encrypted key size: %d bytes\n", len(encrypted.EncryptedKey))

	// Decrypt the data
	decryptOpts := encryption.DefaultDecryptOptions()
	decrypted, err := envelope.Decrypt(encrypted, rsaKeys, decryptOpts)
	if err != nil {
		log.Fatal("Envelope decryption failed:", err)
	}

	fmt.Printf("Decrypted data size: %d bytes\n", len(decrypted))
	fmt.Printf("Data integrity check: %t\n", len(decrypted) == len(largeData))
	fmt.Printf("✅ Envelope encryption/decryption successful!\n\n")

	// Save to file with format
	saveEncryptedDataWithFormat("examples/encryption/output/envelope_encrypted.cms", encrypted, encryption.FormatCMS)
}

func demonstrateCertificateBasedEncryption() {
	fmt.Println("5. Certificate-based Encryption")
	fmt.Println("-------------------------------")

	// Generate key pair for certificate
	rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key pair:", err)
	}

	// Create a self-signed certificate
	certRequest := cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "alice@example.com",
			Organization: []string{"Example Corp"},
			Country:      []string{"US"},
		},
		EmailAddress: []string{"alice@example.com"},
		ValidFor:     365 * 24 * time.Hour,
	}

	certificate, err := cert.CreateSelfSignedCertificate(rsaKeys, certRequest)
	if err != nil {
		log.Fatal("Failed to create certificate:", err)
	}

	// Encrypt for certificate holder
	document := []byte("Confidential business document for Alice")
	fmt.Printf("Original document: %s\n", document)

	opts := encryption.DefaultEncryptOptions()
	encrypted, err := certenc.EncryptDocument(document, certificate, opts)
	if err != nil {
		log.Fatal("Certificate-based encryption failed:", err)
	}

	fmt.Printf("Encryption algorithm: %s\n", encrypted.Algorithm)
	fmt.Printf("Encrypted for: %s\n", certificate.Certificate.Subject.CommonName)

	// Decrypt using the private key
	decryptOpts := encryption.DefaultDecryptOptions()
	decrypted, err := certenc.DecryptDocument(encrypted, rsaKeys, decryptOpts)
	if err != nil {
		log.Fatal("Certificate-based decryption failed:", err)
	}

	fmt.Printf("Decrypted document: %s\n", decrypted)
	fmt.Printf("✅ Certificate-based encryption/decryption successful!\n\n")

	// Save certificate and encrypted data
	certificate.SaveToFile("examples/encryption/output/alice_cert.pem")
	saveEncryptedDataToFile("examples/encryption/output/document_encrypted.bin", encrypted)
}

func demonstrateFormatSupport() {
	fmt.Println("6. Encryption Format Support")
	fmt.Println("----------------------------")

	// Generate key pair
	rsaKeys, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key pair:", err)
	}

	// Create a test certificate for CMS decryption
	testCert, err := cert.CreateSelfSignedCertificate(rsaKeys, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "CMS Test Certificate",
			Organization: []string{"GoPKI Example"},
		},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		log.Fatal("Failed to create test certificate:", err)
	}

	data := []byte("Format demonstration data")
	fmt.Printf("Original data: %s\n", data)

	// Encrypt once
	opts := encryption.DefaultEncryptOptions()
	encrypted, err := asymmetric.Encrypt(data, rsaKeys, opts)
	if err != nil {
		log.Fatal("Encryption failed:", err)
	}

	// Demonstrate CMS format encoding/decoding
	fmt.Printf("\nFormat: %s\n", encryption.FormatCMS)

	// Encode in CMS format
	encodedData, err := encryption.EncodeData(encrypted)
	if err != nil {
		log.Printf("Failed to encode in CMS format: %v", err)
		return
	}

	fmt.Printf("Encoded size: %d bytes\n", len(encodedData))

	// Decode back from CMS format using type-safe API
	// Note: CMS decoding now requires certificate and private key for security
	decodedData, err := encryption.DecodeDataWithKey(encodedData, testCert.Certificate, rsaKeys.PrivateKey)
	if err != nil {
		log.Printf("Error decoding CMS data: %v", err)
		return
	}

	// Decrypt
	decrypted, err := asymmetric.Decrypt(decodedData, rsaKeys, encryption.DefaultDecryptOptions())
	if err != nil {
		log.Printf("Failed to decrypt: %v", err)
		return
	}

	fmt.Printf("Decrypted: %s\n", decrypted)

	// Save format example
	filename := "examples/encryption/output/format_cms.bin"
	saveToFile(filename, encodedData)

	fmt.Printf("✅ Format demonstration successful!\n\n")
}

func demonstrateMultiRecipientEncryption() {
	fmt.Println("7. Multi-Recipient Encryption Concept")
	fmt.Println("-------------------------------------")

	// Generate RSA key pairs for multiple recipients (using RSA only due to known issues with ECDSA/Ed25519)
	alice, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate Alice's key pair:", err)
	}

	bob, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate Bob's key pair:", err)
	}

	charlie, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate Charlie's key pair:", err)
	}

	// Confidential message
	message := []byte("Top secret meeting at 3 PM today")
	fmt.Printf("Original message: %s\n", message)

	// Encrypt for each recipient separately (using envelope encryption)
	opts := encryption.DefaultEncryptOptions()

	// Encrypt for Alice (RSA)
	encryptedForAlice, err := envelope.Encrypt(message, alice, opts)
	if err != nil {
		log.Fatal("Failed to encrypt for Alice:", err)
	}
	fmt.Printf("Encrypted for Alice (RSA): %d bytes\n", len(encryptedForAlice.Data))

	// Encrypt for Bob (RSA)
	encryptedForBob, err := envelope.Encrypt(message, bob, opts)
	if err != nil {
		log.Fatal("Failed to encrypt for Bob:", err)
	}
	fmt.Printf("Encrypted for Bob (RSA): %d bytes\n", len(encryptedForBob.Data))

	// Encrypt for Charlie (RSA)
	encryptedForCharlie, err := envelope.Encrypt(message, charlie, opts)
	if err != nil {
		log.Fatal("Failed to encrypt for Charlie:", err)
	}
	fmt.Printf("Encrypted for Charlie (RSA): %d bytes\n", len(encryptedForCharlie.Data))

	// Each recipient can decrypt with their private key
	decryptOpts := encryption.DefaultDecryptOptions()

	// Alice decrypts her copy
	aliceMessage, err := envelope.Decrypt(encryptedForAlice, alice, decryptOpts)
	if err != nil {
		log.Fatal("Alice failed to decrypt:", err)
	}

	// Bob decrypts his copy
	bobMessage, err := envelope.Decrypt(encryptedForBob, bob, decryptOpts)
	if err != nil {
		log.Fatal("Bob failed to decrypt:", err)
	}

	// Charlie decrypts his copy
	charlieMessage, err := envelope.Decrypt(encryptedForCharlie, charlie, decryptOpts)
	if err != nil {
		log.Fatal("Charlie failed to decrypt:", err)
	}

	fmt.Printf("Alice decrypted: %s\n", aliceMessage)
	fmt.Printf("Bob decrypted: %s\n", bobMessage)
	fmt.Printf("Charlie decrypted: %s\n", charlieMessage)
	fmt.Printf("✅ Multi-recipient encryption successful!\n\n")

	// Save recipient-specific encrypted data
	saveEncryptedDataToFile("examples/encryption/output/alice_message.bin", encryptedForAlice)
	saveEncryptedDataToFile("examples/encryption/output/bob_message.bin", encryptedForBob)
	saveEncryptedDataToFile("examples/encryption/output/charlie_message.bin", encryptedForCharlie)
}

// Helper functions

func saveEncryptedDataToFile(filename string, encrypted *encryption.EncryptedData) {
	// Use CMS format
	data, err := encryption.EncodeData(encrypted)
	if err != nil {
		log.Printf("Failed to encode encrypted data: %v", err)
		return
	}

	saveToFile(filename, data)
}

func saveEncryptedDataWithFormat(filename string, encrypted *encryption.EncryptedData, format encryption.Format) {
	data, err := encryption.EncodeData(encrypted)
	if err != nil {
		log.Printf("Failed to encode encrypted data in %s format: %v", format, err)
		return
	}

	saveToFile(filename, data)
}

func saveToFile(filename string, data []byte) {
	if err := os.WriteFile(filename, data, 0644); err != nil {
		log.Printf("Failed to save file %s: %v", filename, err)
	} else {
		fmt.Printf("💾 Saved: %s (%d bytes)\n", filename, len(data))
	}
}
