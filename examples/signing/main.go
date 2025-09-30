//go:build example

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
	"github.com/jasoet/gopki/signing"
)

func main() {
	fmt.Println("=== GoPKI Document Signing Module - Comprehensive Examples ===")
	fmt.Println("Demonstrating hybrid approach: PKCS#7 for RSA/ECDSA, raw signatures for Ed25519 (not PKCS#7)")

	// Create output directory
	if err := os.MkdirAll("output", 0o755); err != nil {
		log.Fatal("Failed to create output directory:", err)
	}

	// Execute all signing examples
	fmt.Println("\n🔐 PART 1: Multi-Algorithm Document Signing")
	fmt.Println(strings.Repeat("=", 60))
	demonstrateMultiAlgorithmSigning()

	fmt.Println("\n📋 PART 2: Advanced Signing Options")
	fmt.Println(strings.Repeat("=", 60))
	demonstrateAdvancedSigningOptions()

	fmt.Println("\n✅ PART 3: Signature Verification & Security")
	fmt.Println(strings.Repeat("=", 60))
	demonstrateSignatureVerification()

	fmt.Println("\n📝 PART 4: Multi-Party Signatures (Co-signing)")
	fmt.Println(strings.Repeat("=", 60))
	demonstrateMultipleSignatures()

	fmt.Println("\n🔒 PART 5: PKCS#7 Format & Certificate Chains")
	fmt.Println(strings.Repeat("=", 60))
	demonstratePKCS7FormatExamples()

	fmt.Println("\n🚀 PART 6: Performance & Large Documents")
	fmt.Println(strings.Repeat("=", 60))
	demonstratePerformanceComparison()

	fmt.Println("\n📁 PART 7: File Operations & Detached Signatures")
	fmt.Println(strings.Repeat("=", 60))
	demonstrateFileOperations()

	fmt.Println("\n\n=" + strings.Repeat("=", 58) + "=")
	fmt.Println("✅ ALL EXAMPLES COMPLETED SUCCESSFULLY!")
	fmt.Println("📁 Output files saved in: ./output/")
	fmt.Println("🔍 Review signature formats and certificate integration")
	fmt.Println("=" + strings.Repeat("=", 58) + "=")
}

func demonstrateMultiAlgorithmSigning() {
	fmt.Println("1. RSA Document Signing (PKCS#7 Format)")
	fmt.Println("----------------------------------------")
	demonstrateRSASigning()

	fmt.Println("2. ECDSA Document Signing (PKCS#7 Format)")
	fmt.Println("-----------------------------------------")
	demonstrateECDSASigning()

	fmt.Println("3. Ed25519 Document Signing (Raw Signatures - Not PKCS#7)")
	fmt.Println("---------------------------------------------------------")
	demonstrateEd25519Signing()
}

func demonstrateRSASigning() {
	// Generate RSA key pair using the generic API
	keyManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key pair:", err)
	}
	keyPair := keyManager.KeyPair()
	fmt.Println("✓ Generated 2048-bit RSA key pair using type-safe API")

	// Create a certificate for signing
	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         "RSA Document Signer",
			Organization:       []string{"Example Corp"},
			OrganizationalUnit: []string{"Security Division"},
			Country:            []string{"US"},
		},
		EmailAddress: []string{"signer@example.com"},
		ValidFor:     365 * 24 * time.Hour,
	})
	if err != nil {
		log.Fatal("Failed to create certificate:", err)
	}
	fmt.Printf("✓ Created certificate for: %s\n", certificate.Certificate.Subject.CommonName)

	// Document to sign
	document := []byte(`{
		"title": "Important Contract",
		"date": "2024-01-15",
		"parties": ["Example Corp", "Client Inc"],
		"amount": 50000,
		"currency": "USD"
	}`)

	// Sign the document using PKCS#7 format
	signature, err := signing.SignData(document, keyPair, certificate)
	if err != nil {
		log.Fatal("Failed to sign document:", err)
	}
	fmt.Printf("✓ Signed document using %s with %s\n",
		signature.Algorithm,
		signing.HashAlgorithmToString(signature.HashAlgorithm))

	// Save signature with PKCS#7 format details
	saveSignature(signature, "output/rsa_signature.json")
	fmt.Printf("  Format: %s (industry standard)\n", signature.Format)

	// Verify the signature
	err = signing.VerifySignature(document, signature, signing.DefaultVerifyOptions())
	if err != nil {
		log.Fatal("Signature verification failed:", err)
	}
	fmt.Println("✓ Signature verification successful")

	// Save the certificate and keys
	certificate.SaveToFile("output/rsa_signer.crt")
	keypair.ToPEMFiles(keyPair, "output/rsa_private.pem", "output/rsa_public.pem")

	fmt.Println()
}

func demonstrateECDSASigning() {
	// Generate ECDSA key pair with P-256 curve using generic API
	keyManager, err := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
	if err != nil {
		log.Fatal("Failed to generate ECDSA key pair:", err)
	}
	keyPair := keyManager.KeyPair()
	fmt.Println("✓ Generated ECDSA key pair (P-256 curve) using type-safe API")

	// Create a certificate
	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "ECDSA Document Signer",
			Organization: []string{"Example Corp"},
		},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		log.Fatal("Failed to create certificate:", err)
	}
	fmt.Printf("✓ Created certificate for: %s\n", certificate.Certificate.Subject.CommonName)

	// Document to sign
	document := []byte("This is a confidential document that requires ECDSA signature.")

	// Sign with PKCS#7 detached format options
	opts := signing.SignOptions{
		HashAlgorithm:      crypto.SHA256,
		Format:             signing.FormatPKCS7Detached,
		IncludeCertificate: true,
		IncludeChain:       false,
		Detached:           true,
		Attributes: map[string]interface{}{
			"documentType": "confidential",
			"signedAt":     time.Now().Format(time.RFC3339),
		},
	}

	signature, err := signing.SignDocument(document, keyPair, certificate, opts)
	if err != nil {
		log.Fatal("Failed to sign document:", err)
	}
	fmt.Printf("✓ Signed document using %s with %s\n",
		signature.Algorithm,
		signing.HashAlgorithmToString(signature.HashAlgorithm))

	// Display signature size
	fmt.Printf("  Signature size: %d bytes\n", len(signature.Data))

	// Verify
	err = signing.VerifySignature(document, signature, signing.DefaultVerifyOptions())
	if err != nil {
		log.Fatal("Verification failed:", err)
	}
	fmt.Println("✓ Signature verification successful")

	// Save signature with format details
	saveSignature(signature, "output/ecdsa_signature.json")
	fmt.Printf("  Format: %s (detached PKCS#7)\n", signature.Format)

	fmt.Println()
}

func demonstrateEd25519Signing() {
	// Generate Ed25519 key pair using generic API
	keyManager, err := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
	if err != nil {
		log.Fatal("Failed to generate Ed25519 key pair:", err)
	}
	keyPair := keyManager.KeyPair()
	fmt.Println("✓ Generated Ed25519 key pair using type-safe API")

	// Create a certificate
	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "Ed25519 Document Signer",
			Organization: []string{"Example Corp"},
		},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		log.Fatal("Failed to create certificate:", err)
	}
	fmt.Printf("✓ Created certificate for: %s\n", certificate.Certificate.Subject.CommonName)

	// Large document to demonstrate performance
	largeDocument := make([]byte, 1024*10) // 10KB document
	for i := range largeDocument {
		largeDocument[i] = byte(i % 256)
	}

	// Measure signing time
	startTime := time.Now()
	signature, err := signing.SignData(largeDocument, keyPair, certificate)
	if err != nil {
		log.Fatal("Failed to sign document:", err)
	}
	signingTime := time.Since(startTime)

	fmt.Printf("✓ Signed 10KB document in %v\n", signingTime)
	fmt.Printf("  Algorithm: %s\n", signature.Algorithm)
	fmt.Printf("  Signature size: %d bytes\n", len(signature.Data))

	// Measure verification time
	startTime = time.Now()
	err = signing.VerifySignature(largeDocument, signature, signing.DefaultVerifyOptions())
	if err != nil {
		log.Fatal("Verification failed:", err)
	}
	verificationTime := time.Since(startTime)
	fmt.Printf("✓ Verified signature in %v\n", verificationTime)

	// Save signature with hybrid approach details
	saveSignature(signature, "output/ed25519_signature.json")
	fmt.Printf("  Format: %s (hybrid approach - raw signature stored in PKCS#7 format field)\n", signature.Format)
	fmt.Println("  Note: Ed25519 uses raw signatures, not PKCS#7, since RFC 8419 is not implemented by libraries")

	fmt.Println()
}

func demonstrateAdvancedSigningOptions() {
	fmt.Println("1. Certificate Chains & Advanced Options")
	fmt.Println("-----------------------------------------")

	// Generate key pair for CA
	caKeyManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize3072)
	if err != nil {
		log.Fatal("Failed to generate CA key pair:", err)
	}
	caKeyPair := caKeyManager.KeyPair()

	// Create CA certificate
	caCert, err := cert.CreateCACertificate(caKeyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "Example CA",
			Organization: []string{"Example Corp"},
			Country:      []string{"US"},
		},
		MaxPathLen: 1,
		ValidFor:   10 * 365 * 24 * time.Hour,
	})
	if err != nil {
		log.Fatal("Failed to create CA certificate:", err)
	}
	fmt.Println("✓ Created CA certificate")

	// Create signing certificate signed by CA
	signerKeyManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate signer key pair:", err)
	}
	signerKeyPair := signerKeyManager.KeyPair()

	signerCert, err := cert.SignCertificate(caCert, caKeyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "Document Signer",
			Organization: []string{"Example Corp"},
		},
		ValidFor: 2 * 365 * 24 * time.Hour,
	}, signerKeyPair.PublicKey)
	if err != nil {
		log.Fatal("Failed to create signer certificate:", err)
	}
	fmt.Println("✓ Created signer certificate signed by CA")

	// Document to sign
	document := []byte("Important document with certificate chain")

	// Sign with chain included
	opts := signing.SignOptions{
		HashAlgorithm:      crypto.SHA384, // Stronger hash for 3072-bit key
		Format:             signing.FormatPKCS7,
		IncludeCertificate: true,
		IncludeChain:       true,
		ExtraCertificates:  []*x509.Certificate{caCert.Certificate},
		Attributes: map[string]interface{}{
			"version":    "1.0",
			"author":     "John Doe",
			"department": "Legal",
		},
	}

	signature, err := signing.SignDocument(document, signerKeyPair, signerCert, opts)
	if err != nil {
		log.Fatal("Failed to sign document:", err)
	}
	fmt.Printf("✓ Signed with SHA-384 and certificate chain\n")

	// Display metadata
	if signature.Metadata != nil {
		fmt.Println("  Metadata included:")
		for key, value := range signature.Metadata {
			fmt.Printf("    %s: %v\n", key, value)
		}
	}

	// Verify with chain validation (create root pool with CA certificate)
	verifyOpts := signing.DefaultVerifyOptions()
	verifyOpts.VerifyChain = true
	verifyOpts.Roots = x509.NewCertPool()
	verifyOpts.Roots.AddCert(caCert.Certificate)
	err = signing.VerifySignature(document, signature, verifyOpts)
	if err != nil {
		log.Fatal("Verification failed:", err)
	}
	fmt.Println("✓ Verified signature with certificate chain")

	saveSignature(signature, "output/chain_signature.json")

	fmt.Println()
}

func demonstrateSignatureVerification() {
	fmt.Println("1. Security Testing & Tamper Detection")
	fmt.Println("--------------------------------------")

	// Generate key pair
	keyManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate key pair:", err)
	}
	keyPair := keyManager.KeyPair()

	// Create certificate with specific key usage
	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Security Test Signer",
		},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		log.Fatal("Failed to create certificate:", err)
	}

	document := []byte("Test document for verification scenarios")

	// Sign the document
	signature, err := signing.SignData(document, keyPair, certificate)
	if err != nil {
		log.Fatal("Failed to sign document:", err)
	}
	fmt.Println("✓ Document signed")

	// Test 1: Normal verification
	err = signing.VerifySignature(document, signature, signing.DefaultVerifyOptions())
	if err != nil {
		log.Fatal("Normal verification failed:", err)
	}
	fmt.Println("✓ Test 1: Normal verification passed")

	// Test 2: Tampered data detection
	tamperedDocument := append(document, []byte(" TAMPERED")...)
	err = signing.VerifySignature(tamperedDocument, signature, signing.DefaultVerifyOptions())
	if err == nil {
		log.Fatal("Expected verification to fail with tampered data")
	}
	fmt.Println("✓ Test 2: Tampered data detected")

	// Test 3: Modified signature detection
	originalSigData := signature.Data[0]
	signature.Data[0] ^= 0xFF
	err = signing.VerifySignature(document, signature, signing.DefaultVerifyOptions())
	if err == nil {
		log.Fatal("Expected verification to fail with modified signature")
	}
	signature.Data[0] = originalSigData // Restore
	fmt.Println("✓ Test 3: Modified signature detected")

	// Test 4: Wrong certificate
	wrongKeyManager, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	wrongKeyPair := wrongKeyManager.KeyPair()
	wrongCert, _ := cert.CreateSelfSignedCertificate(wrongKeyPair, cert.CertificateRequest{
		Subject:  pkix.Name{CommonName: "Wrong Signer"},
		ValidFor: 365 * 24 * time.Hour,
	})

	err = signing.VerifyWithCertificate(document, signature, wrongCert.Certificate, signing.DefaultVerifyOptions())
	if err == nil {
		log.Fatal("Expected verification to fail with wrong certificate")
	}
	fmt.Println("✓ Test 4: Wrong certificate detected")

	// Test 5: Get signature information
	fmt.Println("\nSignature Information:")
	info := signing.GetSignatureInfo(signature)
	fmt.Print(info)

	fmt.Println()
}

func demonstrateMultipleSignatures() {
	fmt.Println("1. Multi-Party Document Signing")
	fmt.Println("-------------------------------")

	document := []byte("Multi-party agreement requiring multiple signatures")

	// Create three different signers
	signers := []struct {
		name      string
		algorithm string
		keyPair   interface{}
		cert      *cert.Certificate
	}{}

	// Signer 1: RSA
	rsaKeyManager, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	rsaKeyPair := rsaKeyManager.KeyPair()
	rsaCert, _ := cert.CreateSelfSignedCertificate(rsaKeyPair, cert.CertificateRequest{
		Subject:  pkix.Name{CommonName: "Alice (RSA)"},
		ValidFor: 365 * 24 * time.Hour,
	})
	signers = append(signers, struct {
		name      string
		algorithm string
		keyPair   interface{}
		cert      *cert.Certificate
	}{"Alice", "RSA", rsaKeyPair, rsaCert})

	// Signer 2: ECDSA
	ecdsaKeyManager, _ := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
	ecdsaKeyPair := ecdsaKeyManager.KeyPair()
	ecdsaCert, _ := cert.CreateSelfSignedCertificate(ecdsaKeyPair, cert.CertificateRequest{
		Subject:  pkix.Name{CommonName: "Bob (ECDSA)"},
		ValidFor: 365 * 24 * time.Hour,
	})
	signers = append(signers, struct {
		name      string
		algorithm string
		keyPair   interface{}
		cert      *cert.Certificate
	}{"Bob", "ECDSA", ecdsaKeyPair, ecdsaCert})

	// Signer 3: Ed25519
	ed25519KeyManager, _ := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
	ed25519KeyPair := ed25519KeyManager.KeyPair()
	ed25519Cert, _ := cert.CreateSelfSignedCertificate(ed25519KeyPair, cert.CertificateRequest{
		Subject:  pkix.Name{CommonName: "Charlie (Ed25519)"},
		ValidFor: 365 * 24 * time.Hour,
	})
	signers = append(signers, struct {
		name      string
		algorithm string
		keyPair   interface{}
		cert      *cert.Certificate
	}{"Charlie", "Ed25519", ed25519KeyPair, ed25519Cert})

	// Collect signatures from all parties
	var signatures []*signing.Signature
	for _, signer := range signers {
		var sig *signing.Signature
		var err error

		switch kp := signer.keyPair.(type) {
		case *algo.RSAKeyPair:
			sig, err = signing.SignData(document, kp, signer.cert)
		case *algo.ECDSAKeyPair:
			sig, err = signing.SignData(document, kp, signer.cert)
		case *algo.Ed25519KeyPair:
			sig, err = signing.SignData(document, kp, signer.cert)
		}

		if err != nil {
			log.Fatalf("Failed to sign for %s: %v", signer.name, err)
		}

		signatures = append(signatures, sig)
		fmt.Printf("✓ %s signed using %s\n", signer.name, signer.algorithm)
	}

	// Verify all signatures
	fmt.Println("\nVerifying all signatures:")
	for i, sig := range signatures {
		err := signing.VerifySignature(document, sig, signing.DefaultVerifyOptions())
		if err != nil {
			log.Fatalf("Failed to verify signature from %s: %v", signers[i].name, err)
		}
		fmt.Printf("✓ Verified signature from %s\n", signers[i].name)
	}

	// Save multi-signature document
	multiSig := map[string]interface{}{
		"document":   base64.StdEncoding.EncodeToString(document),
		"signatures": []map[string]interface{}{},
	}

	for i, sig := range signatures {
		sigData := map[string]interface{}{
			"signer":    signers[i].name,
			"algorithm": string(sig.Algorithm),
			"hash":      signing.HashAlgorithmToString(sig.HashAlgorithm),
			"signature": base64.StdEncoding.EncodeToString(sig.Data),
			"digest":    base64.StdEncoding.EncodeToString(sig.Digest),
			"format":    string(sig.Format),
		}
		multiSig["signatures"] = append(multiSig["signatures"].([]map[string]interface{}), sigData)
	}

	saveJSON(multiSig, "output/multi_signature.json")
	fmt.Println("\n✓ Multi-signature document saved")

	fmt.Println()
}

func demonstratePKCS7FormatExamples() {
	fmt.Println("1. PKCS#7 Format Demonstrations")
	fmt.Println("-------------------------------")

	// Generate key pair and certificate
	keyManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate key pair:", err)
	}
	keyPair := keyManager.KeyPair()

	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "PKCS#7 Document Signer",
			Organization: []string{"Example Corp"},
		},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		log.Fatal("Failed to create certificate:", err)
	}
	fmt.Printf("✓ Created certificate for: %s\n", certificate.Certificate.Subject.CommonName)

	document := []byte("Important contract requiring PKCS#7 signature")

	// Test attached PKCS#7
	fmt.Println("\n--- Attached PKCS#7 ---")
	attachedOpts := signing.SignOptions{
		HashAlgorithm:      crypto.SHA256,
		Format:             signing.FormatPKCS7,
		IncludeCertificate: true,
		Detached:           false,
	}

	attachedSig, err := signing.SignDocument(document, keyPair, certificate, attachedOpts)
	if err != nil {
		log.Fatal("Failed to create attached PKCS#7:", err)
	}
	fmt.Printf("✓ Created attached PKCS#7 signature (%d bytes)\n", len(attachedSig.Data))

	// Verify attached PKCS#7
	err = signing.VerifySignature(document, attachedSig, signing.DefaultVerifyOptions())
	if err != nil {
		log.Fatal("Attached PKCS#7 verification failed:", err)
	}
	fmt.Println("✓ Attached PKCS#7 verified successfully")

	// Test detached PKCS#7
	fmt.Println("\n--- Detached PKCS#7 ---")
	detachedOpts := signing.SignOptions{
		HashAlgorithm:      crypto.SHA384,
		Format:             signing.FormatPKCS7Detached,
		IncludeCertificate: true,
		Detached:           true,
	}

	detachedSig, err := signing.SignDocument(document, keyPair, certificate, detachedOpts)
	if err != nil {
		log.Fatal("Failed to create detached PKCS#7:", err)
	}
	fmt.Printf("✓ Created detached PKCS#7 signature (%d bytes)\n", len(detachedSig.Data))

	// Verify detached PKCS#7
	err = signing.VerifySignature(document, detachedSig, signing.DefaultVerifyOptions())
	if err != nil {
		log.Fatal("Detached PKCS#7 verification failed:", err)
	}
	fmt.Println("✓ Detached PKCS#7 verified successfully")

	// Save PKCS#7 signatures
	os.WriteFile("output/pkcs7_attached.p7s", attachedSig.Data, 0o644)
	os.WriteFile("output/pkcs7_detached.p7s", detachedSig.Data, 0o644)
	fmt.Println("\n✓ PKCS#7 signatures saved to output/ directory")

	fmt.Println()
}

func demonstratePerformanceComparison() {
	fmt.Println("1. Algorithm Performance Comparison")
	fmt.Println("----------------------------------")

	// Test data - 100KB document
	testData := make([]byte, 100*1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}
	fmt.Printf("Testing with %d KB document\n", len(testData)/1024)

	algorithms := []struct {
		name    string
		keyPair interface{}
		cert    *cert.Certificate
	}{}

	// RSA
	rsaKeyManager, _ := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	rsaKeyPair := rsaKeyManager.KeyPair()
	rsaCert, _ := cert.CreateSelfSignedCertificate(rsaKeyPair, cert.CertificateRequest{
		Subject:  pkix.Name{CommonName: "RSA Perf Test"},
		ValidFor: 24 * time.Hour,
	})
	algorithms = append(algorithms, struct {
		name    string
		keyPair interface{}
		cert    *cert.Certificate
	}{"RSA-2048", rsaKeyPair, rsaCert})

	// ECDSA
	ecdsaKeyManager, _ := keypair.Generate[algo.ECDSACurve, *algo.ECDSAKeyPair, *ecdsa.PrivateKey, *ecdsa.PublicKey](algo.P256)
	ecdsaKeyPair := ecdsaKeyManager.KeyPair()
	ecdsaCert, _ := cert.CreateSelfSignedCertificate(ecdsaKeyPair, cert.CertificateRequest{
		Subject:  pkix.Name{CommonName: "ECDSA Perf Test"},
		ValidFor: 24 * time.Hour,
	})
	algorithms = append(algorithms, struct {
		name    string
		keyPair interface{}
		cert    *cert.Certificate
	}{"ECDSA-P256", ecdsaKeyPair, ecdsaCert})

	// Ed25519
	ed25519KeyManager, _ := keypair.Generate[algo.Ed25519Config, *algo.Ed25519KeyPair, ed25519.PrivateKey, ed25519.PublicKey](algo.Ed25519Default)
	ed25519KeyPair := ed25519KeyManager.KeyPair()
	ed25519Cert, _ := cert.CreateSelfSignedCertificate(ed25519KeyPair, cert.CertificateRequest{
		Subject:  pkix.Name{CommonName: "Ed25519 Perf Test"},
		ValidFor: 24 * time.Hour,
	})
	algorithms = append(algorithms, struct {
		name    string
		keyPair interface{}
		cert    *cert.Certificate
	}{"Ed25519", ed25519KeyPair, ed25519Cert})

	fmt.Printf("\n%-12s %-12s %-12s %-8s\n", "Algorithm", "Sign Time", "Verify Time", "Sig Size")
	fmt.Println(strings.Repeat("-", 50))

	for _, alg := range algorithms {
		var signature *signing.Signature
		var err error

		// Measure signing time
		startTime := time.Now()
		switch kp := alg.keyPair.(type) {
		case *algo.RSAKeyPair:
			signature, err = signing.SignData(testData, kp, alg.cert)
		case *algo.ECDSAKeyPair:
			signature, err = signing.SignData(testData, kp, alg.cert)
		case *algo.Ed25519KeyPair:
			signature, err = signing.SignData(testData, kp, alg.cert)
		}
		signTime := time.Since(startTime)

		if err != nil {
			log.Printf("Failed to sign with %s: %v", alg.name, err)
			continue
		}

		// Measure verification time
		startTime = time.Now()
		err = signing.VerifySignature(testData, signature, signing.DefaultVerifyOptions())
		verifyTime := time.Since(startTime)

		if err != nil {
			log.Printf("Failed to verify with %s: %v", alg.name, err)
			continue
		}

		fmt.Printf("%-12s %-12v %-12v %-8d\n",
			alg.name, signTime, verifyTime, len(signature.Data))
	}

	fmt.Println()
}

func demonstrateFileOperations() {
	fmt.Println("1. File Signing & Detached Signatures")
	fmt.Println("-------------------------------------")

	// Generate key pair
	keyManager, err := keypair.Generate[algo.KeySize, *algo.RSAKeyPair, *rsa.PrivateKey, *rsa.PublicKey](algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate key pair:", err)
	}
	keyPair := keyManager.KeyPair()

	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "File Signer",
		},
		ValidFor: 365 * 24 * time.Hour,
	})
	if err != nil {
		log.Fatal("Failed to create certificate:", err)
	}

	// Create a test file
	testFileContent := []byte(`This is a test document that will be signed.
It contains multiple lines and represents a real file that needs
digital signature protection for integrity and authenticity.`)

	err = os.WriteFile("output/test_document.txt", testFileContent, 0o644)
	if err != nil {
		log.Fatal("Failed to create test file:", err)
	}
	fmt.Println("✓ Created test document file")

	// Sign the file
	signature, err := signing.SignFile("output/test_document.txt", keyPair, certificate, signing.DefaultSignOptions())
	if err != nil {
		log.Fatal("Failed to sign file:", err)
	}
	fmt.Printf("✓ Signed file using %s\n", signature.Algorithm)

	// Save signature
	saveSignature(signature, "output/document_signature.json")

	// Verify file signature by reading the file again
	fileData, err := os.ReadFile("output/test_document.txt")
	if err != nil {
		log.Fatal("Failed to read test file:", err)
	}

	err = signing.VerifySignature(fileData, signature, signing.DefaultVerifyOptions())
	if err != nil {
		log.Fatal("File signature verification failed:", err)
	}
	fmt.Println("✓ File signature verified successfully")

	// Demonstrate detached signature verification
	fmt.Println("\n--- Detached Signature Test ---")

	// Create a raw signature for detached verification
	hasher := crypto.SHA256.New()
	hasher.Write(testFileContent)
	digest := hasher.Sum(nil)

	rawSigBytes, err := keyPair.PrivateKey.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		log.Fatal("Failed to create raw signature:", err)
	}

	// Save raw signature bytes
	err = os.WriteFile("output/test_document.sig", rawSigBytes, 0o644)
	if err != nil {
		log.Fatal("Failed to save signature file:", err)
	}
	fmt.Println("✓ Created detached signature file")

	// Verify detached signature
	err = signing.VerifyDetachedSignature(testFileContent, rawSigBytes, certificate.Certificate, crypto.SHA256)
	if err != nil {
		log.Fatal("Detached signature verification failed:", err)
	}
	fmt.Println("✓ Detached signature verified successfully")

	fmt.Println()
}

// Helper functions

func saveSignature(sig *signing.Signature, filename string) {
	data := map[string]interface{}{
		"algorithm":     string(sig.Algorithm),
		"hashAlgorithm": signing.HashAlgorithmToString(sig.HashAlgorithm),
		"format":        string(sig.Format),
		"signature":     base64.StdEncoding.EncodeToString(sig.Data),
		"digest":        base64.StdEncoding.EncodeToString(sig.Digest),
		"timestamp":     time.Now().Format(time.RFC3339),
	}

	if sig.Certificate != nil {
		data["signerCN"] = sig.Certificate.Subject.CommonName
		data["issuerCN"] = sig.Certificate.Issuer.CommonName
		data["validFrom"] = sig.Certificate.NotBefore.Format(time.RFC3339)
		data["validUntil"] = sig.Certificate.NotAfter.Format(time.RFC3339)
	}

	if sig.Metadata != nil {
		data["metadata"] = sig.Metadata
	}

	saveJSON(data, filename)
}

func saveJSON(data interface{}, filename string) {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Printf("Failed to marshal JSON: %v", err)
		return
	}

	err = os.WriteFile(filename, jsonData, 0o644)
	if err != nil {
		log.Printf("Failed to save file %s: %v", filename, err)
		return
	}
}
