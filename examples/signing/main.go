package main

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/keypair"
	"github.com/jasoet/gopki/keypair/algo"
	"github.com/jasoet/gopki/signing"
	"github.com/jasoet/gopki/signing/formats"
)

func main() {
	fmt.Println("=== GoPKI Document Signing Example ===")
	fmt.Println()

	// Create output directory
	if err := os.MkdirAll("examples/signing/output", 0755); err != nil {
		log.Fatal("Failed to create output directory:", err)
	}

	// Demonstrate different signing algorithms
	demonstrateRSASigning()
	demonstrateECDSASigning()
	demonstrateEd25519Signing()

	// Demonstrate advanced features
	demonstrateSigningWithOptions()
	demonstrateSignatureVerification()
	demonstrateMultipleSignatures()

	// Demonstrate PKCS#7 formats
	demonstratePKCS7Example()

	fmt.Println("\n✅ All examples completed successfully!")
	fmt.Println("Check the 'examples/signing/output' directory for output files.")
}

func demonstrateRSASigning() {
	fmt.Println("1. RSA Document Signing")
	fmt.Println("------------------------")

	// Generate RSA key pair
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key pair:", err)
	}
	fmt.Println("✓ Generated 2048-bit RSA key pair")

	// Create a certificate for signing
	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         "Document Signer",
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

	// Sign the document
	signature, err := signing.SignData(document, keyPair, certificate)
	if err != nil {
		log.Fatal("Failed to sign document:", err)
	}
	fmt.Printf("✓ Signed document using %s with %s\n",
		signature.Algorithm,
		signing.HashAlgorithmToString(signature.HashAlgorithm))

	// Save signature
	saveSignature(signature, "examples/signing/output/rsa_signature.json")

	// Verify the signature
	err = signing.VerifySignature(document, signature, signing.DefaultVerifyOptions())
	if err != nil {
		log.Fatal("Signature verification failed:", err)
	}
	fmt.Println("✓ Signature verification successful")

	// Save the certificate and keys
	certificate.SaveToFile("examples/signing/output/rsa_signer.crt")
	keypair.ToPEMFiles(keyPair, "examples/signing/output/rsa_private.pem", "examples/signing/output/rsa_public.pem")

	fmt.Println()
}

func demonstrateECDSASigning() {
	fmt.Println("2. ECDSA Document Signing")
	fmt.Println("-------------------------")

	// Generate ECDSA key pair with P-256 curve
	keyPair, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		log.Fatal("Failed to generate ECDSA key pair:", err)
	}
	fmt.Println("✓ Generated ECDSA key pair (P-256 curve)")

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

	// Sign with specific options
	opts := signing.SignOptions{
		HashAlgorithm:      crypto.SHA256,
		Format:             signing.FormatRaw,
		IncludeCertificate: true,
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

	// Save signature
	saveSignature(signature, "examples/signing/output/ecdsa_signature.json")

	fmt.Println()
}

func demonstrateEd25519Signing() {
	fmt.Println("3. Ed25519 Document Signing")
	fmt.Println("---------------------------")

	// Generate Ed25519 key pair
	keyPair, err := algo.GenerateEd25519KeyPair()
	if err != nil {
		log.Fatal("Failed to generate Ed25519 key pair:", err)
	}
	fmt.Println("✓ Generated Ed25519 key pair")

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

	// Save signature
	saveSignature(signature, "examples/signing/output/ed25519_signature.json")

	fmt.Println()
}

func demonstrateSigningWithOptions() {
	fmt.Println("4. Advanced Signing Options")
	fmt.Println("---------------------------")

	// Generate key pair
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize3072)
	if err != nil {
		log.Fatal("Failed to generate key pair:", err)
	}

	// Create CA certificate
	caCert, err := cert.CreateCACertificate(keyPair, cert.CertificateRequest{
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
	signerKeyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate signer key pair:", err)
	}

	signerCert, err := cert.SignCertificate(caCert, keyPair, cert.CertificateRequest{
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
		Format:             signing.FormatRaw,
		IncludeCertificate: true,
		IncludeChain:       true,
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

	fmt.Println()
}

func demonstrateSignatureVerification() {
	fmt.Println("5. Signature Verification Scenarios")
	fmt.Println("-----------------------------------")

	// Generate key pair
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate key pair:", err)
	}

	// Create certificate with specific key usage
	certificate, err := cert.CreateSelfSignedCertificate(keyPair, cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "Verification Test",
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
	wrongKeyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
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
	fmt.Println("6. Multiple Signatures (Co-signing)")
	fmt.Println("-----------------------------------")

	document := []byte("Multi-party agreement requiring multiple signatures")

	// Create three different signers
	signers := []struct {
		name      string
		algorithm string
		keyPair   interface{}
		cert      *cert.Certificate
	}{}

	// Signer 1: RSA
	rsaKeyPair, _ := algo.GenerateRSAKeyPair(algo.KeySize2048)
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
	ecdsaKeyPair, _ := algo.GenerateECDSAKeyPair(algo.P256)
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
	ed25519KeyPair, _ := algo.GenerateEd25519KeyPair()
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
		}
		multiSig["signatures"] = append(multiSig["signatures"].([]map[string]interface{}), sigData)
	}

	saveJSON(multiSig, "examples/signing/output/multi_signature.json")
	fmt.Println("\n✓ Multi-signature document saved")

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
	}

	if sig.Certificate != nil {
		data["signerCN"] = sig.Certificate.Subject.CommonName
		data["issuerCN"] = sig.Certificate.Issuer.CommonName
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

	err = os.WriteFile(filename, jsonData, 0644)
	if err != nil {
		log.Printf("Failed to save file %s: %v", filename, err)
		return
	}
}

func demonstratePKCS7Example() {
	fmt.Println("7. PKCS#7/CMS Format Examples")
	fmt.Println("=============================")

	// Generate key pair and certificate
	keyPair, err := algo.GenerateRSAKeyPair(algo.KeySize2048)
	if err != nil {
		log.Fatal("Failed to generate key pair:", err)
	}

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
	attachedFormat := formats.NewPKCS7Format(false)

	attachedOpts := formats.SignOptions{
		HashAlgorithm:      crypto.SHA256,
		IncludeCertificate: true,
	}

	attachedSig, err := attachedFormat.Sign(document, keyPair.PrivateKey, certificate.Certificate, attachedOpts)
	if err != nil {
		log.Fatal("Failed to create attached PKCS#7:", err)
	}
	fmt.Printf("✓ Created attached PKCS#7 signature (%d bytes)\n", len(attachedSig))

	// Verify attached PKCS#7
	attachedVerifyOpts := formats.VerifyOptions{}
	err = attachedFormat.Verify(document, attachedSig, certificate.Certificate, attachedVerifyOpts)
	if err != nil {
		log.Fatal("Attached PKCS#7 verification failed:", err)
	}
	fmt.Println("✓ Attached PKCS#7 verified successfully")

	// Test detached PKCS#7
	fmt.Println("\n--- Detached PKCS#7 ---")
	detachedFormat := formats.NewPKCS7Format(true)

	detachedOpts := formats.SignOptions{
		HashAlgorithm:      crypto.SHA384,
		IncludeCertificate: true,
	}

	detachedSig, err := detachedFormat.Sign(document, keyPair.PrivateKey, certificate.Certificate, detachedOpts)
	if err != nil {
		log.Fatal("Failed to create detached PKCS#7:", err)
	}
	fmt.Printf("✓ Created detached PKCS#7 signature (%d bytes)\n", len(detachedSig))

	// Verify detached PKCS#7
	detachedVerifyOpts := formats.VerifyOptions{}
	err = detachedFormat.Verify(document, detachedSig, certificate.Certificate, detachedVerifyOpts)
	if err != nil {
		log.Fatal("Detached PKCS#7 verification failed:", err)
	}
	fmt.Println("✓ Detached PKCS#7 verified successfully")

	// Parse and display info
	attachedInfo, _ := attachedFormat.Parse(attachedSig)
	detachedInfo, _ := detachedFormat.Parse(detachedSig)

	fmt.Printf("\nAttached PKCS#7 info:\n")
	fmt.Printf("  Algorithm: %s\n", attachedInfo.Algorithm)
	fmt.Printf("  Detached: %v\n", attachedInfo.Detached)
	fmt.Printf("  Certificate: %s\n", attachedInfo.Certificate.Subject.CommonName)

	fmt.Printf("\nDetached PKCS#7 info:\n")
	fmt.Printf("  Algorithm: %s\n", detachedInfo.Algorithm)
	fmt.Printf("  Detached: %v\n", detachedInfo.Detached)
	fmt.Printf("  Certificate: %s\n", detachedInfo.Certificate.Subject.CommonName)

	// Save PKCS#7 signatures
	os.WriteFile("examples/signing/output/pkcs7_attached.p7s", attachedSig, 0644)
	os.WriteFile("examples/signing/output/pkcs7_detached.p7s", detachedSig, 0644)
	fmt.Println("\n✓ PKCS#7 signatures saved to examples/signing/output/ directory")

	fmt.Println()
}
