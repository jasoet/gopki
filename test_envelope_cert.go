package main

import (
	"bytes"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"time"

	"github.com/jasoet/gopki/cert"
	"github.com/jasoet/gopki/encryption"
	"github.com/jasoet/gopki/encryption/certificate"
	"github.com/jasoet/gopki/encryption/envelope"
	"github.com/jasoet/gopki/keypair/algo"
)

func main() {
	data := []byte("Hello, envelope and certificate encryption!")

	// Test envelope encryption with RSA
	rsaKeys, err := algo.GenerateRSAKeyPair(2048)
	if err != nil {
		log.Fatal("Failed to generate RSA keys:", err)
	}

	opts := encryption.EncryptOptions{
		Algorithm: encryption.AlgorithmEnvelope,
		Format:    encryption.FormatCMS,
	}

	envelopeEncrypted, err := envelope.Encrypt(data, rsaKeys, opts)
	if err != nil {
		log.Fatal("Failed to encrypt with envelope (RSA):", err)
	}

	envelopeDecrypted, err := envelope.Decrypt(envelopeEncrypted, rsaKeys, encryption.DecryptOptions{})
	if err != nil {
		log.Fatal("Failed to decrypt envelope (RSA):", err)
	}

	if !bytes.Equal(envelopeDecrypted, data) {
		log.Fatal("Envelope (RSA) decrypted data doesn't match original")
	}
	fmt.Println("✓ Envelope encryption/decryption with RSA works!")

	// Test envelope encryption with ECDSA
	ecdsaKeys, err := algo.GenerateECDSAKeyPair(algo.P256)
	if err != nil {
		log.Fatal("Failed to generate ECDSA keys:", err)
	}

	envelopeEncryptedECDSA, err := envelope.Encrypt(data, ecdsaKeys, opts)
	if err != nil {
		log.Fatal("Failed to encrypt with envelope (ECDSA):", err)
	}

	envelopeDecryptedECDSA, err := envelope.Decrypt(envelopeEncryptedECDSA, ecdsaKeys, encryption.DecryptOptions{})
	if err != nil {
		log.Fatal("Failed to decrypt envelope (ECDSA):", err)
	}

	if !bytes.Equal(envelopeDecryptedECDSA, data) {
		log.Fatal("Envelope (ECDSA) decrypted data doesn't match original")
	}
	fmt.Println("✓ Envelope encryption/decryption with ECDSA works!")

	// Test certificate-based encryption
	// Create a test certificate
	certReq := cert.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "Test User",
			Organization: []string{"Test Org"},
			Country:      []string{"US"},
		},
		ValidFor: 365 * 24 * time.Hour,
	}

	testCert, err := cert.CreateSelfSignedCertificate(rsaKeys, certReq)
	if err != nil {
		log.Fatal("Failed to create test certificate:", err)
	}

	// Test certificate encryption
	certEncrypted, err := certificate.EncryptDocument(data, testCert, opts)
	if err != nil {
		log.Fatal("Failed to encrypt with certificate:", err)
	}

	certDecrypted, err := certificate.DecryptDocument(certEncrypted, rsaKeys, encryption.DecryptOptions{})
	if err != nil {
		log.Fatal("Failed to decrypt with certificate:", err)
	}

	if !bytes.Equal(certDecrypted, data) {
		log.Fatal("Certificate decrypted data doesn't match original")
	}
	fmt.Println("✓ Certificate-based encryption/decryption works!")

	// Test multi-recipient certificate encryption
	rsaKeys2, _ := algo.GenerateRSAKeyPair(2048)
	testCert2, _ := cert.CreateSelfSignedCertificate(rsaKeys2, certReq)

	certificates := []*cert.Certificate{testCert, testCert2}
	multiEncrypted, err := certificate.EncryptForMultipleCertificates(data, certificates, opts)
	if err != nil {
		log.Fatal("Failed to encrypt for multiple certificates:", err)
	}

	// Decrypt as first recipient
	multiDecrypted, err := certificate.DecryptForCertificateHolder(multiEncrypted, rsaKeys, 0, encryption.DecryptOptions{})
	if err != nil {
		log.Fatal("Failed to decrypt as first recipient:", err)
	}

	if !bytes.Equal(multiDecrypted, data) {
		log.Fatal("Multi-recipient decrypted data doesn't match original")
	}

	// Decrypt as second recipient
	multiDecrypted2, err := certificate.DecryptForCertificateHolder(multiEncrypted, rsaKeys2, 1, encryption.DecryptOptions{})
	if err != nil {
		log.Fatal("Failed to decrypt as second recipient:", err)
	}

	if !bytes.Equal(multiDecrypted2, data) {
		log.Fatal("Multi-recipient decrypted data (second) doesn't match original")
	}
	fmt.Println("✓ Multi-recipient certificate encryption works!")

	fmt.Println("\n✓ All envelope and certificate encryption tests passed!")
}